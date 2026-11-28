use super::WatchFileObservation;
use sunpack_usn_core::ChangeReasons;
use std::ffi::{c_void, OsStr};
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use windows_sys::Win32::Storage::FileSystem::{FILE_NAME_OPENED, VOLUME_NAME_GUID};

type Handle = *mut c_void;

const GENERIC_READ: u32 = 0x8000_0000;
const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const FILE_SHARE_DELETE: u32 = 0x0000_0004;
const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FSCTL_READ_FILE_USN_DATA: u32 = 0x0009_00eb;
const ERROR_SHARING_VIOLATION: i32 = 32;
const ERROR_LOCK_VIOLATION: i32 = 33;

#[repr(C)]
struct ReadFileUsnData {
    min_major_version: u16,
    max_major_version: u16,
}

#[link(name = "Kernel32")]
extern "system" {
    fn DeviceIoControl(
        device: Handle,
        control_code: u32,
        input_buffer: *const c_void,
        input_buffer_size: u32,
        output_buffer: *mut c_void,
        output_buffer_size: u32,
        bytes_returned: *mut u32,
        overlapped: *mut c_void,
    ) -> i32;
    fn GetVolumePathNameW(file_name: *const u16, volume_path: *mut u16, buffer_length: u32) -> i32;
    fn GetVolumeNameForVolumeMountPointW(
        volume_mount_point: *const u16,
        volume_name: *mut u16,
        buffer_length: u32,
    ) -> i32;
    fn GetVolumeInformationW(
        root_path_name: *const u16,
        volume_name: *mut u16,
        volume_name_size: u32,
        volume_serial_number: *mut u32,
        maximum_component_length: *mut u32,
        file_system_flags: *mut u32,
        file_system_name: *mut u16,
        file_system_name_size: u32,
    ) -> i32;
}

struct OwnedHandle {
    file: File,
    _resource: crate::io::resource_lifecycle::NativeResourceGuard,
}

pub(super) fn filesystem_type(path: &Path) -> io::Result<String> {
    let volume_path = volume_mount_path(path)?;
    let mut filesystem_name = [0u16; 64];
    if unsafe {
        GetVolumeInformationW(
            volume_path.as_ptr(),
            null_mut(),
            0,
            null_mut(),
            null_mut(),
            null_mut(),
            filesystem_name.as_mut_ptr(),
            filesystem_name.len() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(String::from_utf16_lossy(nul_terminated(&filesystem_name)))
}

pub(super) fn watch_file_observation(
    path: &Path,
    since_usn: Option<i64>,
) -> io::Result<WatchFileObservation> {
    let metadata = std::fs::metadata(path)?;
    watch_file_observation_known_kind(path, since_usn, metadata.is_dir())
}

pub(super) fn watch_file_observation_known_kind(
    path: &Path,
    since_usn: Option<i64>,
    is_directory: bool,
) -> io::Result<WatchFileObservation> {
    let (file, volume) = {
        let handle = open_path(path, FILE_READ_ATTRIBUTES, SHARE_ALL, is_directory)?;
        read_watch_observation(&handle.file, path, since_usn)?
    };
    Ok(file.with_reasons(file.change_reasons(volume.as_deref(), since_usn)))
}

pub(crate) struct WatchFileSnapshot<T> {
    pub(crate) metadata: std::fs::Metadata,
    file: FileUsn,
    pub(crate) change_reasons: Option<ChangeReasons>,
    pub(crate) captured: T,
}

impl<T> WatchFileSnapshot<T> {
    pub(crate) fn change_usn(&self) -> i64 {
        self.file.usn
    }

    pub(crate) fn observation(&self) -> WatchFileObservation {
        self.file.with_reasons(self.change_reasons)
    }
}

pub(crate) enum WatchSnapshotResult<T> {
    Ready(WatchFileSnapshot<T>),
    Busy,
    Unavailable,
}

impl<T> WatchSnapshotResult<T> {
    fn into_option(self) -> Option<WatchFileSnapshot<T>> {
        match self {
            Self::Ready(snapshot) => Some(snapshot),
            Self::Busy | Self::Unavailable => None,
        }
    }
}

enum WatchSnapshotMode {
    Observe { report_absent: bool },
    Ready,
}

/// Observe a file before admission, while its writer may still be open.
pub(crate) fn watch_observed_file_snapshot<T>(
    path: &Path,
    since_usn: Option<i64>,
    report_absent: bool,
    capture: impl FnOnce(&File, &std::fs::Metadata) -> io::Result<T>,
) -> io::Result<Option<WatchFileSnapshot<T>>> {
    watch_file_snapshot(
        path,
        since_usn,
        WatchSnapshotMode::Observe { report_absent },
        capture,
    ).map(WatchSnapshotResult::into_option)
}

/// Sample one file object while its sharing mode excludes writers and renames.
pub(crate) fn watch_ready_file_snapshot<T>(
    path: &Path,
    since_usn: Option<i64>,
    capture: impl FnOnce(&File, &std::fs::Metadata) -> io::Result<T>,
) -> io::Result<Option<WatchFileSnapshot<T>>> {
    watch_ready_file_snapshot_status(path, since_usn, capture)
        .map(WatchSnapshotResult::into_option)
}

/// Distinguish sharing conflicts at the strict open from empty or invalid inputs.
pub(crate) fn watch_ready_file_snapshot_status<T>(
    path: &Path,
    since_usn: Option<i64>,
    capture: impl FnOnce(&File, &std::fs::Metadata) -> io::Result<T>,
) -> io::Result<WatchSnapshotResult<T>> {
    watch_file_snapshot(path, since_usn, WatchSnapshotMode::Ready, capture)
}

fn watch_file_snapshot<T>(
    path: &Path,
    since_usn: Option<i64>,
    mode: WatchSnapshotMode,
    capture: impl FnOnce(&File, &std::fs::Metadata) -> io::Result<T>,
) -> io::Result<WatchSnapshotResult<T>> {
    let (metadata, captured, file, volume) = {
        let _resource = crate::io::resource_lifecycle::NativeResourceGuard::register(
            [path.to_path_buf()],
        )?;
        let (access, share, allow_directory) = match mode {
            WatchSnapshotMode::Observe { .. } => (FILE_READ_ATTRIBUTES, SHARE_ALL, true),
            WatchSnapshotMode::Ready => (GENERIC_READ, FILE_SHARE_READ, false),
        };
        let handle = match open_watch_path(path, access, share, allow_directory) {
            Ok(handle) => handle,
            Err(error) => return match mode {
                WatchSnapshotMode::Observe { report_absent } => {
                    let missing = matches!(
                        error.kind(), io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                    );
                    // Keep diagnostics for visible files whose identity cannot
                    // be read. This fallback classifies the error only.
                    if (missing && report_absent) || (!missing && std::fs::metadata(path)
                        .is_ok_and(|metadata| metadata.is_file() && metadata.len() > 0))
                    {
                        Err(error)
                    } else {
                        Ok(WatchSnapshotResult::Unavailable)
                    }
                }
                WatchSnapshotMode::Ready if matches!(
                    error.raw_os_error(),
                    Some(ERROR_SHARING_VIOLATION) | Some(ERROR_LOCK_VIOLATION)
                ) => Ok(WatchSnapshotResult::Busy),
                _ => Err(error),
            },
        };
        let metadata = handle.metadata()?;
        if !metadata.is_file() || metadata.len() == 0 {
            return Ok(WatchSnapshotResult::Unavailable);
        }
        let captured = capture(&handle, &metadata)?;
        let (file, volume) = read_watch_observation(&handle, path, since_usn)?;
        (metadata, captured, file, volume)
    };
    Ok(WatchSnapshotResult::Ready(WatchFileSnapshot {
        metadata,
        change_reasons: file.change_reasons(volume.as_deref(), since_usn),
        file,
        captured,
    }))
}

fn read_watch_observation(
    handle: &File,
    path: &Path,
    since_usn: Option<i64>,
) -> io::Result<(FileUsn, Option<String>)> {
    let file = read_file_usn(handle.as_raw_handle())?;
    let volume = since_usn
        .filter(|previous| *previous > 0 && *previous < file.usn)
        .and_then(|_| volume_for_handle(handle, path).ok());
    Ok((file, volume))
}

pub(super) fn directory_file_id(path: &Path, volume: &str) -> io::Result<[u8; 16]> {
    // Share deletion so promotion can query identity within its publication gate.
    let file = open_watch_path(path, FILE_READ_ATTRIBUTES, SHARE_ALL, true)?;
    let observation = read_file_usn(file.as_raw_handle())?;
    if !volume_for_handle(&file, path)?.eq_ignore_ascii_case(volume) {
        return Err(io::Error::other("directory changed volume"));
    }
    Ok(observation.id)
}

pub(super) fn watch_volume_device(path: &Path) -> io::Result<String> {
    match open_watch_path(path, 0, SHARE_ALL, true) {
        Ok(file) => volume_for_handle(&file, path),
        Err(_) => volume_device(path),
    }
}

fn volume_for_handle(file: &File, path: &Path) -> io::Result<String> {
    // VOLUME_NAME_GUID returns \\?\Volume{GUID}\, including through a mount
    // point. The opened name can skip normalization because only the prefix matters.
    crate::io::resource_lifecycle::with_handle_path(
        file,
        VOLUME_NAME_GUID | FILE_NAME_OPENED,
        |wide| {
            let suffix = wide.get(4..)?;
            let separator = suffix.iter().position(|unit| *unit == u16::from(b'\\'))?;
            Some(volume_key_from(&wide[..4 + separator]))
        },
    )
    .ok()
    .flatten()
    .map_or_else(|| volume_device(path), Ok)
}

pub(super) fn watch_file_is_readable(path: &Path, allow_writer: bool) -> io::Result<bool> {
    let share = if allow_writer { SHARE_ALL } else { FILE_SHARE_READ };
    match open_path(path, GENERIC_READ, share, false) {
        Ok(_handle) => Ok(true),
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(ERROR_SHARING_VIOLATION) | Some(ERROR_LOCK_VIOLATION)
            ) =>
        {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

fn open_path(
    path: &Path,
    desired_access: u32,
    share_mode: u32,
    is_directory: bool,
) -> io::Result<OwnedHandle> {
    let resource = crate::io::resource_lifecycle::NativeResourceGuard::register(
        [path.to_path_buf()],
    )?;
    let file = open_watch_path(path, desired_access, share_mode, is_directory)?;
    Ok(OwnedHandle {
        file,
        _resource: resource,
    })
}

fn open_watch_path(path: &Path, access: u32, share: u32, is_directory: bool) -> io::Result<File> {
    File::options()
        .access_mode(access)
        .share_mode(share)
        .custom_flags(if is_directory { FILE_FLAG_BACKUP_SEMANTICS } else { 0 })
        .open(path)
}

struct FileUsn {
    id: [u8; sunpack_usn_core::protocol::FILE_ID_BYTES],
    id_len: u8,
    usn: i64,
}

impl FileUsn {
    fn with_reasons(&self, change_reasons: Option<ChangeReasons>) -> WatchFileObservation {
        WatchFileObservation {
            file_id: sunpack_usn_core::protocol::format_file_id(&self.id[..usize::from(self.id_len)]),
            change_usn: self.usn,
            change_reasons,
        }
    }

    fn change_reasons(&self, volume: Option<&str>, since_usn: Option<i64>) -> Option<ChangeReasons> {
        let previous = since_usn.filter(|value| *value > 0)?;
        if self.usn == previous {
            Some(ChangeReasons::default())
        } else {
            sunpack_usn_core::broker_read_change_reasons(
                volume?, self.id, self.id_len, previous, self.usn,
            )
            .ok()
        }
    }
}

fn read_file_usn(handle: Handle) -> io::Result<FileUsn> {
    let request = ReadFileUsnData {
        min_major_version: 2,
        max_major_version: 3,
    };
    let mut output = [0u8; 4096];
    let mut bytes_returned = 0u32;
    if unsafe {
        DeviceIoControl(
            handle,
            FSCTL_READ_FILE_USN_DATA,
            &request as *const _ as *const c_void,
            std::mem::size_of::<ReadFileUsnData>() as u32,
            output.as_mut_ptr() as *mut c_void,
            output.len() as u32,
            &mut bytes_returned,
            null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    parse_file_usn_record(&output[..bytes_returned as usize])
}

fn parse_file_usn_record(bytes: &[u8]) -> io::Result<FileUsn> {
    if bytes.len() < 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "filesystem returned a truncated USN record",
        ));
    }
    let record_length = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
    let major_version = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
    if record_length > bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "filesystem returned an invalid USN record length",
        ));
    }
    let (file_id_end, usn_offset) = match major_version {
        2 => (16, 24),
        3 | 4 => (24, 40),
        version => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported USN record version {version}"),
            ))
        }
    };
    if record_length < usn_offset + 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "filesystem returned a truncated USN identity",
        ));
    }
    let change_usn = i64::from_le_bytes(bytes[usn_offset..usn_offset + 8].try_into().unwrap());
    // Zero is a valid per-file USN when no change has been journaled for it.
    // Journal availability is checked separately on the volume by the broker.
    if change_usn < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "filesystem returned a negative file USN",
        ));
    }
    let file_id = &bytes[8..file_id_end];
    let mut id = [0; sunpack_usn_core::protocol::FILE_ID_BYTES];
    id[..file_id.len()].copy_from_slice(file_id);
    Ok(FileUsn { id, id_len: file_id.len() as u8, usn: change_usn })
}

pub(super) fn validate_volume_journal(path: &Path) -> io::Result<()> {
    super::watch_volume_cursor(&volume_device(path)?).map(|_| ())
}

pub(super) fn volume_device(path: &Path) -> io::Result<String> {
    let mount_point = volume_mount_path(path)?;
    let mut volume_name = [0u16; 64];
    if unsafe {
        GetVolumeNameForVolumeMountPointW(
            mount_point.as_ptr(),
            volume_name.as_mut_ptr(),
            volume_name.len() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(volume_key_from(&volume_name))
}

fn volume_mount_path(path: &Path) -> io::Result<Vec<u16>> {
    let path = canonical_wide(path)?;
    // On a volume-resolved path the mount point is a prefix. Allow room for
    // its final separator when the input names the mount directory itself.
    let mut mount_point = vec![0u16; path.len() + 1];
    if unsafe {
        GetVolumePathNameW(
            path.as_ptr(),
            mount_point.as_mut_ptr(),
            mount_point.len() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(mount_point)
}

/// Volume identity for an output path that may not exist yet: the nearest existing
/// ancestor is canonicalized, which also resolves a junction or a volume mount point
/// down to its real device.
pub(super) fn resolve_output_volume(path: &Path) -> io::Result<String> {
    // The extraction directory already exists. Resolve its actual device in
    // one handle lookup, including when it is reached through a mount point.
    if let Ok(file) = open_watch_path(path, 0, SHARE_ALL, true) {
        return volume_for_handle(&file, path);
    }
    let anchor = nearest_existing_ancestor(path)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no existing ancestor"))?;
    volume_device(&anchor)
}

/// Walks up to the nearest ancestor that provably exists.
///
/// A metadata error must not be read as absence (`Path::exists()` would do exactly
/// that), and the walk must stop at the share or drive root: continuing past it
/// resolves against the process working directory, i.e. an unrelated volume.
fn nearest_existing_ancestor(path: &Path) -> io::Result<Option<PathBuf>> {
    let mut current: PathBuf = if path.as_os_str().is_empty() {
        std::env::current_dir()?
    } else {
        path.to_path_buf()
    };
    loop {
        match current.try_exists() {
            Ok(true) => return Ok(Some(current)),
            Ok(false) => {}
            // A query that cannot be answered is not evidence of absence.
            Err(error) => return Err(error),
        }
        let Some(parent) = current.parent() else {
            return Ok(None);
        };
        if parent == current || parent.as_os_str().is_empty() {
            return Ok(None);
        }
        if !is_fully_rooted(&parent) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no existing ancestor inside the target root",
            ));
        }
        current = parent.to_path_buf();
    }
}

/// True when the path still names a concrete rooted location: `C:` alone is
/// drive-relative and has no `RootDir`, while a UNC share root does have one.
fn is_fully_rooted(path: &Path) -> bool {
    path.components()
        .any(|component| matches!(component, std::path::Component::RootDir))
}

fn volume_key_from(volume_name: &[u16]) -> String {
    let mut volume = nul_terminated(volume_name);
    if volume.last() == Some(&('\\' as u16)) {
        volume = &volume[..volume.len() - 1];
    }
    let mut result = String::from_utf16_lossy(volume);
    result.make_ascii_lowercase();
    result
}

fn canonical_wide(path: &Path) -> io::Result<Vec<u16>> {
    let canonical = std::fs::canonicalize(path)?;
    Ok(OsStr::new(&canonical)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect())
}

fn nul_terminated(values: &[u16]) -> &[u16] {
    let length = values
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(values.len());
    &values[..length]
}

#[cfg(test)]
#[path = "../../tests/unit/filesystem/windows/tests.rs"]
mod tests;
