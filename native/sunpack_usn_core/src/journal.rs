use crate::protocol::FILE_ID_BYTES;
use crate::ChangeReasons;
use std::collections::{BTreeSet, HashMap};
use std::ffi::c_void;
use std::io;
use std::ptr::{null, null_mut};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::IO::DeviceIoControl;

const FSCTL_QUERY_USN_JOURNAL: u32 = 0x0009_00f4;
const FSCTL_READ_USN_JOURNAL: u32 = 0x0009_00bb;
const ALL_USN_REASONS: u32 = 0xffff_ffff;
#[cfg(test)]
const USN_REASON_CLOSE: u32 = 0x8000_0000;
const JOURNAL_BUFFER_BYTES: usize = 64 * 1024;
const MAX_JOURNAL_BYTES_PER_OBSERVATION: usize = 1024 * 1024;
const MAX_ROOT_RECOVERY_JOURNAL_BYTES: usize = 8 * 1024 * 1024;
const MAX_ROOT_RECOVERY_PATH_BYTES: usize = 64 * 1024;
const MAX_CACHED_VOLUME_CONTEXTS: usize = 64;
const VOLUME_CONTEXT_IDLE_TTL: Duration = Duration::from_secs(15 * 60);
const ERROR_INVALID_HANDLE: i32 = 6;
const ERROR_NOT_READY: i32 = 21;
const ERROR_DEVICE_NOT_CONNECTED: i32 = 1167;

#[repr(C)]
struct ReadUsnJournalData {
    start_usn: i64,
    reason_mask: u32,
    return_only_on_close: u32,
    timeout: u64,
    bytes_to_wait_for: u64,
    usn_journal_id: u64,
}

fn read_usn_journal_request(start_usn: i64, usn_journal_id: u64) -> ReadUsnJournalData {
    ReadUsnJournalData {
        start_usn,
        reason_mask: ALL_USN_REASONS,
        return_only_on_close: 0,
        timeout: 0,
        bytes_to_wait_for: 0,
        usn_journal_id,
    }
}

struct OwnedHandle(HANDLE);

unsafe impl Send for OwnedHandle {}

impl OwnedHandle {
    fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

struct VolumeContext {
    handle: OwnedHandle,
    last_used: Instant,
}

pub struct JournalReader {
    entries: HashMap<String, VolumeContext>,
}

impl Default for JournalReader {
    fn default() -> Self {
        Self::new()
    }
}

impl JournalReader {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    pub fn probe_volume(&mut self, volume_guid: &str) -> io::Result<(u64, i64)> {
        self.with_volume(volume_guid, |volume| {
            let (journal_id, next_usn) = query_journal(volume)?;
            let request = read_usn_journal_request(next_usn, journal_id);
            let mut output = vec![0u8; JOURNAL_BUFFER_BYTES];
            let bytes_returned = device_io_control(
                volume,
                FSCTL_READ_USN_JOURNAL,
                &request as *const _ as *const c_void,
                std::mem::size_of::<ReadUsnJournalData>() as u32,
                &mut output,
            )?;
            if bytes_returned < 8 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated USN journal reply",
                ));
            }
            Ok((journal_id, next_usn))
        })
    }

    pub fn read_change_reasons(
        &mut self,
        volume_guid: &str,
        expected_file_id: &[u8; FILE_ID_BYTES],
        expected_file_id_len: u8,
        previous_usn: i64,
        current_usn: i64,
    ) -> io::Result<(u64, ChangeReasons)> {
        if previous_usn <= 0
            || current_usn <= previous_usn
            || !matches!(expected_file_id_len, 8 | 16)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid USN reason query",
            ));
        }
        self.with_volume(volume_guid, |volume| {
            let (journal_id, _) = query_journal(volume)?;
            let reasons = read_change_reasons_from_volume(
                volume,
                journal_id,
                expected_file_id,
                expected_file_id_len as usize,
                previous_usn,
                current_usn,
            )?;
            Ok((journal_id, reasons))
        })
    }

    pub fn read_root_changes(
        &mut self,
        volume_guid: &str,
        root_file_id: &[u8; FILE_ID_BYTES],
        root_file_id_len: u8,
        start_usn: i64,
        end_usn: i64,
    ) -> io::Result<Vec<String>> {
        if start_usn <= 0 || end_usn <= start_usn || !matches!(root_file_id_len, 8 | 16) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid root recovery query"));
        }
        self.with_volume(volume_guid, |volume| {
            let (journal_id, next_usn) = query_journal(volume)?;
            if end_usn > next_usn {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "root recovery end USN is beyond journal head"));
            }
            read_root_changes_from_volume(
                volume,
                journal_id,
                root_file_id,
                root_file_id_len as usize,
                start_usn,
                end_usn,
            )
        })
    }

    pub fn context_count(&self) -> usize {
        self.entries.len()
    }

    fn with_volume<T>(
        &mut self,
        volume_guid: &str,
        operation: impl FnOnce(HANDLE) -> io::Result<T>,
    ) -> io::Result<T> {
        validate_volume_guid(volume_guid)?;
        let key = volume_guid.to_ascii_lowercase();
        let now = Instant::now();
        self.entries.retain(|_, context| {
            now.saturating_duration_since(context.last_used) < VOLUME_CONTEXT_IDLE_TTL
        });
        if !self.entries.contains_key(&key) {
            if self.entries.len() >= MAX_CACHED_VOLUME_CONTEXTS {
                if let Some(lru) = self
                    .entries
                    .iter()
                    .min_by_key(|(_, context)| context.last_used)
                    .map(|(key, _)| key.clone())
                {
                    self.entries.remove(&lru);
                }
            }
            self.entries.insert(
                key.clone(),
                VolumeContext {
                    handle: open_volume(volume_guid)?,
                    last_used: now,
                },
            );
        }
        let context = self.entries.get_mut(&key).expect("volume context inserted");
        context.last_used = now;
        let result = operation(context.handle.raw());
        if result.as_ref().err().is_some_and(stale_volume_handle_error) {
            self.entries.remove(&key);
        }
        result
    }
}

pub fn validate_volume_guid(value: &str) -> io::Result<()> {
    let bytes = value.as_bytes();
    let valid = bytes.len() == 48
        && value
            .get(..11)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(r"\\?\Volume{"))
        && bytes[47] == b'}'
        && [19usize, 24, 29, 34]
            .iter()
            .all(|index| bytes[*index] == b'-')
        && bytes[11..47]
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 8 | 13 | 18 | 23) || byte.is_ascii_hexdigit());
    if valid {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid NT volume GUID",
        ))
    }
}

fn open_volume(volume_guid: &str) -> io::Result<OwnedHandle> {
    let wide: Vec<u16> = volume_guid
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            0,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    Ok(OwnedHandle(handle))
}

fn query_journal(volume: HANDLE) -> io::Result<(u64, i64)> {
    let mut output = vec![0u8; 80];
    let bytes_returned =
        device_io_control(volume, FSCTL_QUERY_USN_JOURNAL, null(), 0, &mut output)?;
    if bytes_returned < 24 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated USN journal metadata",
        ));
    }
    Ok((
        u64::from_le_bytes(output[0..8].try_into().unwrap()),
        i64::from_le_bytes(output[16..24].try_into().unwrap()),
    ))
}

fn read_root_changes_from_volume(
    volume: HANDLE,
    journal_id: u64,
    root_file_id: &[u8; FILE_ID_BYTES],
    root_file_id_len: usize,
    start_usn: i64,
    end_usn: i64,
) -> io::Result<Vec<String>> {
    let mut cursor = start_usn;
    let mut scanned_bytes = 0usize;
    let mut payload_bytes = 0usize;
    let mut changed = BTreeSet::new();
    while cursor < end_usn {
        let request = read_usn_journal_request(cursor, journal_id);
        let mut output = vec![0u8; JOURNAL_BUFFER_BYTES];
        let bytes_returned = device_io_control(
            volume,
            FSCTL_READ_USN_JOURNAL,
            &request as *const _ as *const c_void,
            std::mem::size_of::<ReadUsnJournalData>() as u32,
            &mut output,
        )?;
        if bytes_returned < 8 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated USN journal reply"));
        }
        scanned_bytes = scanned_bytes.saturating_add(bytes_returned);
        if scanned_bytes > MAX_ROOT_RECOVERY_JOURNAL_BYTES {
            return Err(io::Error::other("USN root recovery exceeded scan budget"));
        }
        let returned_next = i64::from_le_bytes(output[0..8].try_into().unwrap());
        let mut offset = 8usize;
        while offset + 8 <= bytes_returned {
            let record_length = u32::from_le_bytes(output[offset..offset+4].try_into().unwrap()) as usize;
            if record_length < 8 || offset + record_length > bytes_returned {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid USN journal record"));
            }
            if let Some(name) = record_root_change_name(
                &output[offset..offset+record_length],
                root_file_id,
                root_file_id_len,
                start_usn,
                end_usn,
            )? {
                if changed.insert(name.clone()) {
                    payload_bytes = payload_bytes.saturating_add(4 + name.as_bytes().len());
                    if payload_bytes > MAX_ROOT_RECOVERY_PATH_BYTES {
                        return Err(io::Error::other("USN root recovery exceeded payload budget"));
                    }
                }
            }
            offset += record_length;
        }
        if returned_next <= cursor || returned_next >= end_usn {
            break;
        }
        cursor = returned_next;
    }
    Ok(changed.into_iter().collect())
}

fn record_root_change_name(
    record: &[u8],
    root_file_id: &[u8; FILE_ID_BYTES],
    root_file_id_len: usize,
    start_usn: i64,
    end_usn: i64,
) -> io::Result<Option<String>> {
    if record.len() < 8 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated USN record"));
    }
    let major = u16::from_le_bytes(record[4..6].try_into().unwrap());
    let (file_id_range, parent_id_range, usn_offset, name_length_offset, name_offset_offset) = match major {
        2 => (8usize..16usize, 16usize..24usize, 24usize, Some(56usize), Some(58usize)),
        3 => (8usize..24usize, 24usize..40usize, 40usize, Some(72usize), Some(74usize)),
        4 => (8usize..24usize, 24usize..40usize, 40usize, None, None),
        _ => return Ok(None),
    };
    if record.len() < usn_offset + 8 || record.len() < parent_id_range.end {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated USN root record"));
    }
    let usn = i64::from_le_bytes(record[usn_offset..usn_offset+8].try_into().unwrap());
    if usn < start_usn || usn >= end_usn {
        return Ok(None);
    }
    let exact_root = file_ids_equal(&record[file_id_range], root_file_id, root_file_id_len);
    let direct_child = file_ids_equal(&record[parent_id_range], root_file_id, root_file_id_len);
    if !exact_root && !direct_child {
        return Ok(None);
    }
    if exact_root {
        // Empty is a compact sentinel meaning the watched root path itself.
        return Ok(Some(String::new()));
    }
    let (Some(length_offset), Some(offset_offset)) = (name_length_offset, name_offset_offset) else {
        // V4 range-tracking records have no file name.  Falling back to one
        // shallow root scan is safer than guessing a path.
        return Err(io::Error::other("USN root recovery requires fallback scan for V4 record"));
    };
    if record.len() < offset_offset + 2 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated USN file name metadata"));
    }
    let byte_len = u16::from_le_bytes(record[length_offset..length_offset+2].try_into().unwrap()) as usize;
    let byte_offset = u16::from_le_bytes(record[offset_offset..offset_offset+2].try_into().unwrap()) as usize;
    if byte_len % 2 != 0 || byte_offset.saturating_add(byte_len) > record.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid USN file name range"));
    }
    let units = record[byte_offset..byte_offset+byte_len]
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    String::from_utf16(&units)
        .map(Some)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "USN file name is invalid UTF-16"))
}

fn read_change_reasons_from_volume(
    volume: HANDLE,
    journal_id: u64,
    expected_file_id: &[u8; FILE_ID_BYTES],
    expected_file_id_len: usize,
    previous_usn: i64,
    current_usn: i64,
) -> io::Result<ChangeReasons> {
    let mut next_usn = previous_usn;
    let mut scanned_bytes = 0usize;
    let mut reasons = ChangeReasons::default();
    let mut found = false;
    while next_usn <= current_usn {
        let request = read_usn_journal_request(next_usn, journal_id);
        let mut output = vec![0u8; JOURNAL_BUFFER_BYTES];
        let bytes_returned = device_io_control(
            volume,
            FSCTL_READ_USN_JOURNAL,
            &request as *const _ as *const c_void,
            std::mem::size_of::<ReadUsnJournalData>() as u32,
            &mut output,
        )?;
        if bytes_returned < 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated USN journal reply",
            ));
        }
        scanned_bytes = scanned_bytes.saturating_add(bytes_returned);
        if scanned_bytes > MAX_JOURNAL_BYTES_PER_OBSERVATION {
            return Err(io::Error::other(
                "USN journal observation exceeded scan budget",
            ));
        }
        let returned_next = i64::from_le_bytes(output[0..8].try_into().unwrap());
        let mut offset = 8usize;
        while offset + 8 <= bytes_returned {
            let record_length =
                u32::from_le_bytes(output[offset..offset + 4].try_into().unwrap()) as usize;
            if record_length < 8 || offset + record_length > bytes_returned {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid USN journal record",
                ));
            }
            if let Some(reason) = record_change_reason(
                &output[offset..offset + record_length],
                expected_file_id,
                expected_file_id_len,
                previous_usn,
                current_usn,
            )? {
                found = true;
                reasons.observe(reason);
            }
            offset += record_length;
        }
        if returned_next <= next_usn || returned_next > current_usn {
            break;
        }
        next_usn = returned_next;
    }
    if !found {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "USN journal did not contain the current file record",
        ));
    }
    Ok(reasons)
}

fn record_change_reason(
    record: &[u8],
    expected_file_id: &[u8; FILE_ID_BYTES],
    expected_file_id_len: usize,
    previous_usn: i64,
    current_usn: i64,
) -> io::Result<Option<u32>> {
    if record.len() < 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated USN record",
        ));
    }
    let major = u16::from_le_bytes(record[4..6].try_into().unwrap());
    let (file_id_end, usn_offset, reason_offset) = match major {
        2 => (16usize, 24usize, 40usize),
        3 => (24usize, 40usize, 56usize),
        4 => (24usize, 40usize, 48usize),
        _ => return Ok(None),
    };
    if record.len() < reason_offset + 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated USN record",
        ));
    }
    let usn = i64::from_le_bytes(record[usn_offset..usn_offset + 8].try_into().unwrap());
    if usn <= previous_usn
        || usn > current_usn
        || !file_ids_equal(
            &record[8..file_id_end],
            expected_file_id,
            expected_file_id_len,
        )
    {
        return Ok(None);
    }
    Ok(Some(u32::from_le_bytes(
        record[reason_offset..reason_offset + 4].try_into().unwrap(),
    )))
}

fn file_ids_equal(record: &[u8], expected: &[u8; FILE_ID_BYTES], expected_len: usize) -> bool {
    let mut record_end = record.len();
    while record_end > 0 && record[record_end - 1] == 0 {
        record_end -= 1;
    }
    let mut expected_end = expected_len;
    while expected_end > 0 && expected[expected_end - 1] == 0 {
        expected_end -= 1;
    }
    record[..record_end] == expected[..expected_end]
}

fn device_io_control(
    handle: HANDLE,
    code: u32,
    input_buffer: *const c_void,
    input_buffer_size: u32,
    output: &mut [u8],
) -> io::Result<usize> {
    let mut bytes_returned = 0u32;
    let ok = unsafe {
        DeviceIoControl(
            handle,
            code,
            input_buffer,
            input_buffer_size,
            output.as_mut_ptr() as *mut c_void,
            output.len() as u32,
            &mut bytes_returned,
            null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(bytes_returned as usize)
}

fn stale_volume_handle_error(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(ERROR_INVALID_HANDLE) | Some(ERROR_NOT_READY) | Some(ERROR_DEVICE_NOT_CONNECTED)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(major: u16, file_id: u128, usn: i64, reason: u32) -> Vec<u8> {
        let (length, file_id_end, usn_offset, reason_offset) = match major {
            2 => (60usize, 16usize, 24usize, 40usize),
            3 => (64usize, 24usize, 40usize, 56usize),
            4 => (64usize, 24usize, 40usize, 48usize),
            _ => unreachable!(),
        };
        let mut record = vec![0u8; length];
        record[0..4].copy_from_slice(&(length as u32).to_le_bytes());
        record[4..6].copy_from_slice(&major.to_le_bytes());
        record[8..file_id_end].copy_from_slice(&file_id.to_le_bytes()[..file_id_end - 8]);
        record[usn_offset..usn_offset + 8].copy_from_slice(&usn.to_le_bytes());
        record[reason_offset..reason_offset + 4].copy_from_slice(&reason.to_le_bytes());
        record
    }

    #[test]
    fn validates_only_volume_guid_device_paths() {
        assert!(validate_volume_guid(r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}").is_ok());
        assert!(validate_volume_guid(r"\\.\PhysicalDrive0").is_err());
        assert!(validate_volume_guid(r"C:").is_err());
    }

    #[test]
    fn compares_v2_and_zero_extended_v3_file_ids() {
        let mut expected = [0u8; FILE_ID_BYTES];
        expected[..8].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let mut record = [0u8; FILE_ID_BYTES];
        record[..8].copy_from_slice(&expected[..8]);
        assert!(file_ids_equal(&record, &expected, 8));
        assert_eq!(
            crate::protocol::format_file_id(&record),
            "00000000000000000807060504030201"
        );
    }

    #[test]
    fn parses_v2_v3_and_v4_reason_layouts_with_exclusive_lower_bound() {
        let expected = 0x1234u128.to_le_bytes();
        for major in [2u16, 3, 4] {
            let width = if major == 2 { 8 } else { 16 };
            let value = record(major, 0x1234, 101, 0x0000_0002);
            assert_eq!(
                record_change_reason(&value, &expected, width, 100, 101).unwrap(),
                Some(0x0000_0002)
            );
            assert_eq!(
                record_change_reason(&value, &expected, width, 101, 102).unwrap(),
                None
            );
        }
    }

    #[test]
    fn close_only_reason_is_excluded_from_non_close_aggregate() {
        let mut reasons = ChangeReasons::default();
        reasons.observe(USN_REASON_CLOSE | 0x0000_0001);
        assert_eq!(reasons.all, USN_REASON_CLOSE | 0x0000_0001);
        assert_eq!(reasons.without_close, 0);
        reasons.observe(0x0000_0002);
        assert_eq!(reasons.without_close, 0x0000_0002);
    }

    #[test]
    fn journal_request_preserves_record_aligned_start_usn() {
        let request = read_usn_journal_request(8_192, 42);
        assert_eq!(request.start_usn, 8_192);
        assert_eq!(request.usn_journal_id, 42);
    }
}
