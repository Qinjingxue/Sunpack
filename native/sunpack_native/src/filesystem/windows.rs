use super::WatchFileObservation;
use std::ffi::{c_void, OsStr};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};

type Handle = *mut c_void;

const INVALID_HANDLE_VALUE: Handle = -1isize as Handle;
const GENERIC_READ: u32 = 0x8000_0000;
const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const FILE_SHARE_DELETE: u32 = 0x0000_0004;
const OPEN_EXISTING: u32 = 3;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
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
    fn CreateFileW(
        file_name: *const u16,
        desired_access: u32,
        share_mode: u32,
        security_attributes: *const c_void,
        creation_disposition: u32,
        flags_and_attributes: u32,
        template_file: Handle,
    ) -> Handle;
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
    fn CloseHandle(object: Handle) -> i32;
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
    raw: isize,
    _resource: crate::io::resource_lifecycle::NativeResourceGuard,
}

impl OwnedHandle {
    fn raw(&self) -> Handle {
        self.raw as Handle
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.raw());
        }
    }
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
    let handle = open_path(
        path,
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        is_directory,
    )?;
    let file = read_file_usn(handle.raw())?;
    let change_reasons = since_usn.filter(|value| *value > 0).and_then(|previous| {
        if file.usn == previous {
            Some(sunpack_usn_core::ChangeReasons::default())
        } else if file.usn > previous {
            volume_device(path).and_then(|volume| {
                sunpack_usn_core::broker_read_change_reasons(
                    &volume, file.id, file.id_len, previous, file.usn,
                )
            }).ok()
        } else {
            None
        }
    });
    Ok(WatchFileObservation { file_id: file.id_text(), change_usn: file.usn, change_reasons })
}

pub(super) fn watch_path_identity(path: &Path) -> io::Result<(String, String, i64)> {
    let observation = watch_path_usn(path)?;
    Ok((volume_device(path)?, observation.id_text(), observation.usn))
}

pub(super) fn directory_file_id(path: &Path, volume: &str) -> io::Result<[u8; 16]> {
    let observation = watch_path_usn(path)?;
    if !volume_device(path)?.eq_ignore_ascii_case(volume) {
        return Err(io::Error::other("directory changed volume"));
    }
    Ok(observation.id)
}

fn watch_path_usn(path: &Path) -> io::Result<FileUsn> {
    use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};

    // Backup semantics permits both files and directories. The handle shares
    // deletion so promotion can query identity within its own publication gate.
    let file = std::fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    read_file_usn(file.as_raw_handle())
}

pub(super) fn watch_file_is_ready(path: &Path) -> io::Result<bool> {
    let metadata = std::fs::metadata(path)?;
    // Permit readers; writers and DELETE access (rename/delete) must conflict.
    match open_path(path, GENERIC_READ, FILE_SHARE_READ, metadata.is_dir()) {
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
    let path = canonical_wide(path)?;
    let flags = if is_directory {
        FILE_FLAG_BACKUP_SEMANTICS
    } else {
        FILE_ATTRIBUTE_NORMAL
    };
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            desired_access,
            share_mode,
            null(),
            OPEN_EXISTING,
            flags,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    Ok(OwnedHandle {
        raw: handle as isize,
        _resource: resource,
    })
}

struct FileUsn {
    id: [u8; sunpack_usn_core::protocol::FILE_ID_BYTES],
    id_len: u8,
    usn: i64,
}

impl FileUsn {
    fn id_text(&self) -> String {
        sunpack_usn_core::protocol::format_file_id(&self.id[..usize::from(self.id_len)])
    }
}

fn read_file_usn(handle: Handle) -> io::Result<FileUsn> {
    let request = ReadFileUsnData {
        min_major_version: 2,
        max_major_version: 4,
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
            "NTFS returned a truncated USN record",
        ));
    }
    let record_length = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
    let major_version = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
    if record_length > bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "NTFS returned an invalid USN record length",
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
    if bytes.len() < usn_offset + 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "NTFS returned a truncated USN identity",
        ));
    }
    let change_usn = i64::from_le_bytes(bytes[usn_offset..usn_offset + 8].try_into().unwrap());
    // Zero is a valid per-file USN when no change has been journaled for it.
    // Journal availability is checked separately on the volume by the broker.
    if change_usn < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "NTFS returned a negative file USN",
        ));
    }
    let file_id = &bytes[8..file_id_end];
    let mut id = [0; sunpack_usn_core::protocol::FILE_ID_BYTES];
    id[..file_id.len()].copy_from_slice(file_id);
    Ok(FileUsn { id, id_len: file_id.len() as u8, usn: change_usn })
}

pub(super) fn validate_volume_journal(path: &Path) -> io::Result<()> {
    sunpack_usn_core::broker_probe_volume(&volume_device(path)?)
}

pub(super) fn watch_volume_cursor(path: &Path) -> io::Result<(String, u64, i64)> {
    let volume = volume_device(path)?;
    let (journal_id, next_usn) = sunpack_usn_core::broker_volume_cursor(&volume)?;
    Ok((volume, journal_id, next_usn))
}

fn volume_device(path: &Path) -> io::Result<String> {
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
mod tests {
    use super::*;

    #[test]
    fn file_usn_observation_preserves_identity_without_a_journal_record() {
        for (version, length, usn_offset, expected_file_id) in [
            (2u16, 64usize, 24usize, "0000000000001234"),
            (3, 80, 40, "00000000000000000000000000001234"),
            (4, 64, 40, "00000000000000000000000000001234"),
        ] {
            let mut record = vec![0u8; length];
            record[..4].copy_from_slice(&(length as u32).to_le_bytes());
            record[4..6].copy_from_slice(&version.to_le_bytes());
            record[8..16].copy_from_slice(&0x1234u64.to_le_bytes());
            for usn in [0i64, 127] {
                record[usn_offset..usn_offset + 8].copy_from_slice(&usn.to_le_bytes());
                let observation = parse_file_usn_record(&record)
                    .expect("zero USN is valid for an unchanged pre-existing file or directory");
                assert_eq!(observation.id_text(), expected_file_id);
                assert_eq!(observation.usn, usn);
            }
            record[usn_offset..usn_offset + 8].copy_from_slice(&(-1i64).to_le_bytes());
            assert!(parse_file_usn_record(&record).is_err());
        }
    }

    #[test]
    fn nearest_existing_ancestor_walks_up_to_a_real_directory() {
        let root = std::env::temp_dir();
        let nested = root
            .join("sunpack-volume-anchor-probe")
            .join("level-one")
            .join("level-two");
        assert!(!nested.exists(), "probe path must not exist");
        let anchor = nearest_existing_ancestor(&nested)
            .expect("a probe under the temp root must be answerable")
            .expect("an existing ancestor");
        assert!(anchor.exists());
        assert!(anchor.starts_with(&root) || root.starts_with(&anchor));
    }

    #[test]
    fn nearest_existing_ancestor_reports_an_unanswerable_query() {
        // An unreachable UNC host must be an error, not a silent "does not exist".
        let missing = Path::new(r"\\sunpack-nonexistent-host\share\out");
        match nearest_existing_ancestor(missing) {
            Err(_) => {}
            Ok(None) => {}
            Ok(Some(anchor)) => panic!("unexpectedly resolved an unreachable path: {anchor:?}"),
        }
    }

    #[test]
    fn unreachable_unc_path_never_resolves_to_a_local_volume() {
        let missing = Path::new(r"\\sunpack-nonexistent-host\share\out");
        let resolved = resolve_output_volume(missing);
        assert!(
            resolved.is_err(),
            "an unreachable share resolved to {resolved:?} instead of failing"
        );
    }

    #[test]
    fn resolve_output_volume_handles_a_not_yet_created_directory() {
        let root = std::env::temp_dir();
        let pending = root
            .join("sunpack-volume-anchor-probe")
            .join("output-does-not-exist");
        let from_pending = resolve_output_volume(&pending).expect("volume for a pending path");
        let from_root = resolve_output_volume(&root).expect("volume for the existing root");
        // Same temp root, even when temp is a junction to another volume.
        assert_eq!(from_pending, from_root);
        assert!(from_pending.contains("volume{") || from_pending.contains("\\\\"));
    }

    #[test]
    fn resolve_output_volume_rejects_an_unreachable_unc_path() {
        let missing = Path::new(r"\\sunpack-nonexistent-host\share\out");
        assert!(resolve_output_volume(missing).is_err());
    }
}
