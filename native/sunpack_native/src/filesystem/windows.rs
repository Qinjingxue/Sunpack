use super::WatchFileObservation;
use std::ffi::{c_void, OsStr};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
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
    let path = canonical_wide(path)?;
    let mut volume_path = vec![0u16; 32768];
    if unsafe {
        GetVolumePathNameW(
            path.as_ptr(),
            volume_path.as_mut_ptr(),
            volume_path.len() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut filesystem_name = vec![0u16; 64];
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
    let handle = open_path(
        path,
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        metadata.is_dir(),
    )?;
    let mut observation = read_file_usn(handle.raw())?;
    if let Some(previous_usn) = since_usn.filter(|value| *value > 0) {
        if observation.change_usn > previous_usn {
            match read_change_reasons(
                path,
                &observation.file_id,
                previous_usn,
                observation.change_usn,
            ) {
                Ok(reasons) => {
                    observation.change_reasons = reasons.all;
                    observation.change_reasons_without_close = reasons.without_close;
                    observation.change_reasons_known = true;
                }
                Err(error) => {
                    observation.change_reason_error = error.to_string();
                }
            }
        } else if observation.change_usn == previous_usn {
            observation.change_reasons_known = true;
        }
    }
    Ok(observation)
}

pub(super) fn watch_file_is_ready(path: &Path) -> io::Result<bool> {
    let metadata = std::fs::metadata(path)?;
    // Permit antivirus/indexer readers while still conflicting with any
    // handle that requested write access. Requiring share_mode=0 made a
    // completed archive wait several seconds for unrelated readers.
    match open_path(
        path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        metadata.is_dir(),
    ) {
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
        if is_directory {
            "directory_metadata_handle"
        } else {
            "file_metadata_handle"
        },
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

fn read_file_usn(handle: Handle) -> io::Result<WatchFileObservation> {
    let request = ReadFileUsnData {
        min_major_version: 2,
        max_major_version: 4,
    };
    let mut output = vec![0u8; 4096];
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
    let bytes = &output[..bytes_returned as usize];
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
    if change_usn <= 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "NTFS USN journal is unavailable for this path",
        ));
    }
    let file_id = bytes[8..file_id_end]
        .iter()
        .rev()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(WatchFileObservation {
        file_id,
        change_usn,
        change_reasons: 0,
        change_reasons_without_close: 0,
        change_reasons_known: false,
        change_reason_error: String::new(),
    })
}

fn read_change_reasons(
    path: &Path,
    expected_file_id: &str,
    previous_usn: i64,
    current_usn: i64,
) -> io::Result<sunpack_usn_core::ChangeReasons> {
    sunpack_usn_core::broker_read_change_reasons(
        &volume_device(path)?,
        expected_file_id,
        previous_usn,
        current_usn,
    )
}

pub(super) fn validate_volume_journal(path: &Path) -> io::Result<()> {
    sunpack_usn_core::broker_probe_volume(&volume_device(path)?)
}

fn volume_device(path: &Path) -> io::Result<String> {
    let path = canonical_wide(path)?;
    let mut mount_point = vec![0u16; 32768];
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
    let mut volume_name = vec![0u16; 64];
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
    let mut volume = nul_terminated(&volume_name).to_vec();
    if volume.last() == Some(&('\\' as u16)) {
        volume.pop();
    }
    Ok(String::from_utf16_lossy(&volume).to_ascii_lowercase())
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
