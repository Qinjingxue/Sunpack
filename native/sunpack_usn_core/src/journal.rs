use crate::protocol::{FILE_ID_BYTES, JournalChange, VolumeChangeBatch, CHANGE_FIXED_BYTES, CHANGE_HEADER_BYTES, MAX_CHANGE_PAYLOAD_BYTES};
use crate::ChangeReasons;
use std::collections::HashMap;
use std::ffi::c_void;
use std::io;
use std::ptr::{null, null_mut};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, OpenFileById, GetFinalPathNameByHandleW, FILE_ID_DESCRIPTOR, FileIdType, ExtendedFileIdType,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::IO::DeviceIoControl;

const FSCTL_QUERY_USN_JOURNAL: u32 = 0x0009_00f4;
const FSCTL_READ_USN_JOURNAL: u32 = 0x0009_00bb;
const ALL_USN_REASONS: u32 = 0xffff_ffff;
#[cfg(test)]
const USN_REASON_CLOSE: u32 = 0x8000_0000;
const JOURNAL_BUFFER_BYTES: usize = 64 * 1024;
const MAX_JOURNAL_BYTES_PER_OBSERVATION: usize = 1024 * 1024;
const MAX_RECOVERY_JOURNAL_BYTES: usize = 256 * 1024;
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

    pub fn read_volume_changes(
        &mut self, volume_guid: &str, start_usn: i64, end_usn: i64,
    ) -> io::Result<VolumeChangeBatch> {
        if start_usn <= 0 || end_usn <= start_usn {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid volume recovery query"));
        }
        self.with_volume(volume_guid, |volume| {
            let (journal_id, next_usn) = query_journal(volume)?;
            if end_usn > next_usn {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "recovery end USN is beyond journal head"));
            }
            read_volume_changes_from_volume(volume, journal_id, start_usn, end_usn)
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

fn read_volume_changes_from_volume(
    volume: HANDLE, journal_id: u64, start_usn: i64, end_usn: i64,
) -> io::Result<VolumeChangeBatch> {
    let mut batch = VolumeChangeBatch { journal_id, next_usn: start_usn, dirty: false, changes: Vec::new() };
    let mut parents: HashMap<[u8; FILE_ID_BYTES], Option<String>> = HashMap::new();
    let mut merged: HashMap<([u8; FILE_ID_BYTES], Option<String>), usize> = HashMap::new();
    let mut scanned_bytes = 0usize;
    let mut payload_bytes = CHANGE_HEADER_BYTES;
    let mut output = vec![0u8; JOURNAL_BUFFER_BYTES];
    while batch.next_usn < end_usn && scanned_bytes < MAX_RECOVERY_JOURNAL_BYTES {
        let request = read_usn_journal_request(batch.next_usn, journal_id);
        let bytes_returned = device_io_control(volume, FSCTL_READ_USN_JOURNAL,
            &request as *const _ as *const c_void, std::mem::size_of::<ReadUsnJournalData>() as u32, &mut output)?;
        if bytes_returned < 8 { return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated USN journal reply")); }
        scanned_bytes += bytes_returned;
        let returned_next = i64::from_le_bytes(output[0..8].try_into().unwrap());
        if returned_next <= batch.next_usn { return Err(io::Error::other("USN recovery made no progress")); }
        let mut offset = 8usize;
        while offset < bytes_returned {
            if bytes_returned - offset < 8 { return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated USN record")); }
            let length = u32::from_le_bytes(output[offset..offset+4].try_into().unwrap()) as usize;
            if length < 8 || length > bytes_returned - offset { return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid USN record length")); }
            let record = &output[offset..offset+length];
            let Some((mut change, name)) = decode_volume_change(record)? else {
                // An unknown record layout cannot be mapped safely. Consume the
                // returned prefix only after reconciliation has been persisted.
                batch.dirty = true;
                offset += length;
                continue;
            };
            if change.usn >= end_usn { batch.next_usn = end_usn; return Ok(batch); }
            if change.usn < start_usn { offset += length; continue; }
            if let Some(name) = name {
                let parent = parents.entry(change.parent_id).or_insert_with(|| path_for_id(volume, &change.parent_id).ok());
                change.path = parent.as_ref().map(|parent| format!("{}\\{name}", parent.trim_end_matches('\\')));
            }
            let key = (change.file_id, change.path.clone());
            if let Some(index) = merged.get(&key) {
                let previous = &mut batch.changes[*index];
                previous.reason |= change.reason;
                previous.usn = previous.usn.max(change.usn);
            } else {
                let bytes = CHANGE_FIXED_BYTES + change.path.as_ref().map_or(0, String::len);
                if payload_bytes + bytes > MAX_CHANGE_PAYLOAD_BYTES {
                    if !batch.changes.is_empty() {
                        // The current record is not consumed. Its USN is the
                        // next request's inclusive lower bound.
                        batch.next_usn = change.usn;
                        return Ok(batch);
                    }
                    change.path = None;
                }
                payload_bytes += CHANGE_FIXED_BYTES + change.path.as_ref().map_or(0, String::len);
                batch.dirty |= change.path.is_none();
                merged.insert(key, batch.changes.len());
                batch.changes.push(change);
            }
            offset += length;
        }
        batch.next_usn = returned_next.min(end_usn);
    }
    Ok(batch)
}

// V2/V3 names and parent identities share one parser for all roots. V4 has
// identities/reasons but no name, so the consumed prefix requires reconciliation.
fn decode_volume_change(record: &[u8]) -> io::Result<Option<(JournalChange, Option<String>)>> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid USN change record");
    if record.len() < 8 { return Err(invalid()); }
    let major = u16::from_le_bytes(record[4..6].try_into().unwrap());
    let (width, parent_offset, usn_offset, reason_offset, attributes_offset, name_offsets) = match major {
        2 => (8, 16, 24, 40, Some(52), Some((56, 58))),
        3 => (16, 24, 40, 56, Some(68), Some((72, 74))),
        4 => (16, 24, 40, 48, None, None),
        _ => return Ok(None),
    };
    if record.len() < reason_offset + 4 || record.len() < parent_offset + width { return Err(invalid()); }
    let mut file_id = [0u8; FILE_ID_BYTES];
    let mut parent_id = [0u8; FILE_ID_BYTES];
    file_id[..width].copy_from_slice(&record[8..8+width]);
    parent_id[..width].copy_from_slice(&record[parent_offset..parent_offset+width]);
    let is_directory = if let Some(offset) = attributes_offset {
        if record.len() < offset + 4 { return Err(invalid()); }
        u32::from_le_bytes(record[offset..offset+4].try_into().unwrap()) & 0x10 != 0
    } else { false };
    let name = if let Some((length_offset, offset_offset)) = name_offsets {
        if record.len() < offset_offset + 2 { return Err(invalid()); }
        let length = u16::from_le_bytes(record[length_offset..length_offset+2].try_into().unwrap()) as usize;
        let offset = u16::from_le_bytes(record[offset_offset..offset_offset+2].try_into().unwrap()) as usize;
        if length == 0 || length % 2 != 0 || offset < offset_offset + 2 || offset + length > record.len() { return Err(invalid()); }
        let name = String::from_utf16(&record[offset..offset+length].chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0],pair[1]])).collect::<Vec<_>>()).map_err(|_| invalid())?;
        if name.contains(['\\', '/', '\0']) { return Err(invalid()); }
        Some(name)
    } else { None };
    Ok(Some((JournalChange {file_id, parent_id,
        usn: i64::from_le_bytes(record[usn_offset..usn_offset+8].try_into().unwrap()),
        reason: u32::from_le_bytes(record[reason_offset..reason_offset+4].try_into().unwrap()),
        is_directory, path: None}, name)))
}

fn path_for_id(volume: HANDLE, id: &[u8]) -> io::Result<String> {
    let id = if id.len() == 16 && id[8..].iter().all(|byte| *byte == 0) { &id[..8] } else { id };
    let mut descriptor = FILE_ID_DESCRIPTOR::default();
    descriptor.dwSize = std::mem::size_of::<FILE_ID_DESCRIPTOR>() as u32;
    if id.len() == 8 {
        descriptor.Type = FileIdType;
        descriptor.Anonymous.FileId = i64::from_le_bytes(id.try_into().unwrap());
    } else {
        descriptor.Type = ExtendedFileIdType;
        unsafe { descriptor.Anonymous.ExtendedFileId.Identifier.copy_from_slice(id); }
    }
    let handle = unsafe { OpenFileById(volume, &descriptor, 0, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                                      null(), FILE_FLAG_BACKUP_SEMANTICS) };
    if handle == INVALID_HANDLE_VALUE { return Err(io::Error::last_os_error()); }
    let handle = OwnedHandle(handle);
    let mut buffer = vec![0u16; 512];
    loop {
        let length = unsafe { GetFinalPathNameByHandleW(handle.raw(),buffer.as_mut_ptr(),buffer.len() as u32,0) } as usize;
        if length == 0 { return Err(io::Error::last_os_error()); }
        if length < buffer.len() { return String::from_utf16(&buffer[..length]).map(|path| path.strip_prefix(r"\\?\").unwrap_or(&path).to_owned()).map_err(|e| io::Error::new(io::ErrorKind::InvalidData,e)); }
        if length > 32768 { return Err(io::Error::new(io::ErrorKind::InvalidData,"USN path exceeds Windows path limit")); }
        buffer.resize(length+1,0);
    }
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

    #[test]
    fn recovery_layouts_preserve_identity_names_and_reject_broken_payloads() {
        // Live NTFS exercises V2. This inexpensive combined contract additionally
        // catches V3/V4 offsets and wire truncation that the live corpus cannot.
        for major in [2, 3, 4] {
            let mut raw = record(major, 0x1234, 101, 0x2000);
            let parent_offset = if major == 2 {16} else {24};
            raw[parent_offset] = 42;
            if major != 4 {
                let (attributes, length, offset, header) = if major == 2 {(52,56,58,60)} else {(68,72,74,76)};
                let name: Vec<u8> = "归档.part1".encode_utf16().flat_map(u16::to_le_bytes).collect();
                raw.resize(header, 0);
                raw[attributes] = 0x10;
                raw[length..length+2].copy_from_slice(&(name.len() as u16).to_le_bytes());
                raw[offset..offset+2].copy_from_slice(&(header as u16).to_le_bytes());
                raw.extend_from_slice(&name);
            }
            let (mut change, name) = decode_volume_change(&raw).unwrap().unwrap();
            assert_eq!(change.file_id, 0x1234u128.to_le_bytes());
            assert_eq!(change.parent_id[0], 42);
            assert_eq!(change.usn, 101);
            assert_eq!(change.reason, 0x2000);
            assert_eq!(name.as_deref(), if major == 4 {None} else {Some("归档.part1")});
            change.path = name;
            let batch = VolumeChangeBatch {journal_id: 7, next_usn: 200, dirty: major == 4, changes: vec![change]};
            let bytes = batch.encode().unwrap();
            let decoded = VolumeChangeBatch::decode(7, 200, &bytes).unwrap();
            assert_eq!(decoded.changes, batch.changes);
            assert_eq!(decoded.dirty, batch.dirty);
            assert!(VolumeChangeBatch::decode(7,200,&bytes[..bytes.len()-1]).is_err());
            assert!(decode_volume_change(&raw[..12]).is_err());
        }
    }
}
