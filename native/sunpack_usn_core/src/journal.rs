use crate::protocol::{FILE_ID_BYTES, MAX_DIRECTORY_RESPONSE_BYTES};
use crate::ChangeReasons;
use std::collections::{BTreeSet, HashMap};
use std::ffi::c_void;
use std::io;
use std::ptr::{null, null_mut};
use std::sync::Arc;
use windows_sys::Win32::Foundation::{
    CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::IO::DeviceIoControl;

const FSCTL_QUERY_USN_JOURNAL: u32 = 0x0009_00f4;
const FSCTL_CREATE_USN_JOURNAL: u32 = 0x0009_00e7;
const FSCTL_READ_USN_JOURNAL: u32 = 0x0009_00bb;
const ALL_USN_REASONS: u32 = 0xffff_ffff;
#[cfg(test)]
const USN_REASON_CLOSE: u32 = 0x8000_0000;
const JOURNAL_BUFFER_BYTES: usize = 64 * 1024;

pub struct DirectoryChangesPage {
    pub changes: BTreeSet<(u32, String)>,
    pub payload_bytes: usize,
    pub next_usn: i64,
    pub journal_id: u64,
}
const ERROR_INVALID_HANDLE: i32 = 6;
const ERROR_NOT_READY: i32 = 21;
const ERROR_DEVICE_NOT_CONNECTED: i32 = 1167;
const ERROR_JOURNAL_NOT_ACTIVE: i32 = 1179;

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

pub struct JournalReader {
    volume_guid: Arc<str>,
    handle: Option<OwnedHandle>,
}

impl JournalReader {
    pub fn new(volume_guid: Arc<str>) -> io::Result<Self> {
        validate_volume_guid(&volume_guid)?;
        Ok(Self {
            volume_guid,
            handle: None,
        })
    }

    pub fn probe_volume(&mut self) -> io::Result<(u64, i64)> {
        self.with_volume(|volume, volume_guid| {
            let (journal_id, next_usn) =
                query_or_create_journal(|| query_journal(volume), || create_journal(volume_guid))?;
            let mut output = vec![0u8; JOURNAL_BUFFER_BYTES];
            let bytes_returned = read_journal_page(volume, journal_id, next_usn, &mut output)?;
            split_journal_reply(&output, bytes_returned)?;
            Ok((journal_id, next_usn))
        })
    }

    pub fn read_change_reasons(
        &mut self,
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
        self.with_volume(|volume, _| {
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

    pub fn read_directories_changes(
        &mut self,
        expected_journal: u64,
        directories: &[[u8; FILE_ID_BYTES]],
        start_usn: i64,
        end_usn: i64,
    ) -> io::Result<DirectoryChangesPage> {
        if start_usn <= 0 || end_usn <= start_usn || directories.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid directory recovery query",
            ));
        }
        self.with_volume(|volume, _| {
            let (journal_id, first_usn, next_usn) = query_journal_bounds(volume)?;
            if expected_journal != journal_id || start_usn < first_usn {
                return Err(io::Error::from_raw_os_error(1178));
            }
            if end_usn > next_usn {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "recovery end USN is beyond journal head",
                ));
            }
            read_directories_changes_from_volume(
                volume,
                journal_id,
                directories,
                start_usn,
                end_usn,
            )
        })
    }

    fn with_volume<T>(
        &mut self,
        operation: impl FnOnce(HANDLE, &str) -> io::Result<T>,
    ) -> io::Result<T> {
        let handle = match &self.handle {
            Some(handle) => handle,
            None => self
                .handle
                .insert(open_volume(&self.volume_guid, GENERIC_READ)?),
        };
        let result = operation(handle.raw(), &self.volume_guid);
        if result.as_ref().err().is_some_and(stale_volume_handle_error) {
            self.handle = None;
        }
        result
    }
}

fn validate_volume_guid(value: &str) -> io::Result<()> {
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

fn open_volume(volume_guid: &str, access: u32) -> io::Result<OwnedHandle> {
    let wide: Vec<u16> = volume_guid
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            access,
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

// Only the first failed probe can create a journal; normal queries stay read-only.
fn query_or_create_journal(
    mut query: impl FnMut() -> io::Result<(u64, i64)>,
    create: impl FnOnce() -> io::Result<()>,
) -> io::Result<(u64, i64)> {
    match query() {
        Err(error) if error.raw_os_error() == Some(ERROR_JOURNAL_NOT_ACTIVE) => {
            create()?;
            query()
        }
        result => result,
    }
}

fn create_journal(volume_guid: &str) -> io::Result<()> {
    // Keep the cached query handle read-only; writable access is only needed
    // on this rare first-use path. Values match a 32 MiB / 8 MiB USN journal.
    let volume = open_volume(volume_guid, GENERIC_WRITE)?;
    let sizes = [32_u64 * 1024 * 1024, 8_u64 * 1024 * 1024];
    let mut returned = 0;
    let ok = unsafe {
        DeviceIoControl(
            volume.raw(),
            FSCTL_CREATE_USN_JOURNAL,
            sizes.as_ptr() as *const c_void,
            std::mem::size_of_val(&sizes) as u32,
            null_mut(),
            0,
            &mut returned,
            null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn query_journal(volume: HANDLE) -> io::Result<(u64, i64)> {
    query_journal_bounds(volume).map(|(journal, _, next)| (journal, next))
}
fn query_journal_bounds(volume: HANDLE) -> io::Result<(u64, i64, i64)> {
    let mut output = [0u8; 80];
    let bytes_returned =
        device_io_control(volume, FSCTL_QUERY_USN_JOURNAL, null(), 0, &mut output)?;
    if bytes_returned < 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated USN journal metadata",
        ));
    }
    Ok((
        u64::from_le_bytes(output[0..8].try_into().unwrap()),
        i64::from_le_bytes(output[8..16].try_into().unwrap())
            .max(i64::from_le_bytes(output[24..32].try_into().unwrap())),
        i64::from_le_bytes(output[16..24].try_into().unwrap()),
    ))
}

fn read_directories_changes_from_volume(
    volume: HANDLE,
    journal_id: u64,
    directories: &[[u8; FILE_ID_BYTES]],
    start_usn: i64,
    end_usn: i64,
) -> io::Result<DirectoryChangesPage> {
    scan_directories_page(
        journal_id,
        directories,
        start_usn,
        end_usn,
        |cursor, output| read_journal_page(volume, journal_id, cursor, output),
    )
}

fn read_journal_page(
    volume: HANDLE,
    journal_id: u64,
    cursor: i64,
    output: &mut [u8],
) -> io::Result<usize> {
    let request = read_usn_journal_request(cursor, journal_id);
    device_io_control(
        volume,
        FSCTL_READ_USN_JOURNAL,
        &request as *const _ as *const c_void,
        std::mem::size_of::<ReadUsnJournalData>() as u32,
        output,
    )
}

fn split_journal_reply(output: &[u8], bytes_returned: usize) -> io::Result<(i64, &[u8])> {
    if bytes_returned < 8 || bytes_returned > output.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated USN journal reply",
        ));
    }
    let next = i64::from_le_bytes(output[..8].try_into().unwrap());
    Ok((next, &output[8..bytes_returned]))
}

fn next_journal_record<'a>(records: &mut &'a [u8]) -> io::Result<&'a [u8]> {
    if records.len() < 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated USN journal record",
        ));
    }
    let length = u32::from_le_bytes(records[..4].try_into().unwrap()) as usize;
    if length < 8 || length > records.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid USN journal record",
        ));
    }
    let (record, remaining) = records.split_at(length);
    *records = remaining;
    Ok(record)
}

// Resume at the USN of an entire unconsumed record, never at the next buffer.
// A record may yield both a directory change and a child name; keep it atomic.
fn scan_directories_page(
    journal_id: u64,
    directories: &[[u8; FILE_ID_BYTES]],
    start_usn: i64,
    end_usn: i64,
    mut read: impl FnMut(i64, &mut [u8]) -> io::Result<usize>,
) -> io::Result<DirectoryChangesPage> {
    let parents: HashMap<_, _> = directories
        .iter()
        .enumerate()
        .map(|(index, id)| (*id, index as u32))
        .collect();
    let mut cursor = start_usn;
    let mut payload_bytes = 0usize;
    let mut changed = BTreeSet::new();
    // Page-local scratch; draining results retains capacity for the next record.
    let mut changes = Vec::new();
    let mut name_units = Vec::new();
    let mut output = vec![0u8; JOURNAL_BUFFER_BYTES];
    while cursor < end_usn {
        let bytes_returned = read(cursor, &mut output)?;
        let (returned_next, mut records) = split_journal_reply(&output, bytes_returned)?;
        while !records.is_empty() {
            let record = next_journal_record(&mut records)?;
            record_directory_changes(
                record,
                &parents,
                cursor,
                end_usn,
                &mut changes,
                &mut name_units,
            )?;
            changes.retain(|change| !changed.contains(change));
            let added: usize = changes.iter().map(|change| 8 + change.1.len()).sum();
            if added > MAX_DIRECTORY_RESPONSE_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "USN name exceeds response frame",
                ));
            }
            if payload_bytes + added > MAX_DIRECTORY_RESPONSE_BYTES {
                let major = u16::from_le_bytes(record[4..6].try_into().unwrap());
                let usn_offset = if major == 2 { 24 } else { 40 };
                let next_usn =
                    i64::from_le_bytes(record[usn_offset..usn_offset + 8].try_into().unwrap());
                if next_usn <= start_usn {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "non-progressing USN page",
                    ));
                }
                return Ok(DirectoryChangesPage {
                    changes: changed,
                    payload_bytes,
                    next_usn,
                    journal_id,
                });
            }
            payload_bytes += added;
            changed.extend(changes.drain(..));
        }
        if returned_next <= cursor {
            return Err(io::Error::other(
                "USN recovery made no progress; fallback scan required",
            ));
        }
        cursor = returned_next;
    }
    Ok(DirectoryChangesPage {
        changes: changed,
        payload_bytes,
        next_usn: end_usn,
        journal_id,
    })
}

fn record_directory_changes(
    record: &[u8],
    parents: &HashMap<[u8; FILE_ID_BYTES], u32>,
    start_usn: i64,
    end_usn: i64,
    changes: &mut Vec<(u32, String)>,
    name_units: &mut Vec<u16>,
) -> io::Result<()> {
    changes.clear();
    if record.len() < 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated USN record",
        ));
    }
    let major = u16::from_le_bytes(record[4..6].try_into().unwrap());
    let (width, usn_offset, name_offsets) = match major {
        2 => (8, 24, Some((56, 58))),
        3 => (16, 40, Some((72, 74))),
        4 => (16, 40, None),
        _ => {
            return Err(io::Error::other(
                "unknown USN record; fallback scan required",
            ))
        }
    };
    if record.len() < usn_offset + 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated USN directory record",
        ));
    }
    let usn = i64::from_le_bytes(record[usn_offset..usn_offset + 8].try_into().unwrap());
    if usn < start_usn || usn >= end_usn {
        return Ok(());
    }
    let mut file = [0u8; FILE_ID_BYTES];
    let mut parent = file;
    file[..width].copy_from_slice(&record[8..8 + width]);
    parent[..width].copy_from_slice(&record[8 + width..8 + 2 * width]);
    if let Some(index) = parents.get(&file) {
        changes.push((*index, String::new()));
    }
    if let Some(index) = parents.get(&parent) {
        let Some((length_offset, offset_offset)) = name_offsets else {
            return Err(io::Error::other("USN V4 record requires fallback scan"));
        };
        if record.len() < offset_offset + 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated USN file name metadata",
            ));
        }
        let length =
            u16::from_le_bytes(record[length_offset..length_offset + 2].try_into().unwrap())
                as usize;
        let offset =
            u16::from_le_bytes(record[offset_offset..offset_offset + 2].try_into().unwrap())
                as usize;
        if length == 0
            || length % 2 != 0
            || offset < offset_offset + 2
            || offset.saturating_add(length) > record.len()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid USN file name range",
            ));
        }
        name_units.clear();
        name_units.extend(
            record[offset..offset + length]
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]])),
        );
        let name = String::from_utf16(name_units)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid USN UTF-16"))?;
        if name.contains(['/', '\\']) || name == "." || name == ".." || name.contains('\0') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid USN child name",
            ));
        }
        changes.push((*index, name));
    }
    Ok(())
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
    let mut reasons = ChangeReasons::default();
    let mut found = false;
    let mut output = vec![0u8; JOURNAL_BUFFER_BYTES];
    while next_usn <= current_usn {
        let bytes_returned = read_journal_page(volume, journal_id, next_usn, &mut output)?;
        let (returned_next, mut records) = split_journal_reply(&output, bytes_returned)?;
        while !records.is_empty() {
            let record = next_journal_record(&mut records)?;
            if let Some(reason) = record_change_reason(
                record,
                expected_file_id,
                expected_file_id_len,
                previous_usn,
                current_usn,
            )? {
                found = true;
                reasons.observe(reason);
            }
        }
        if returned_next <= next_usn {
            return Err(io::Error::other("USN observation made no progress"));
        }
        if returned_next > current_usn {
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
    fn probe_creates_journal_only_for_not_active_error() {
        use std::cell::Cell;
        let queries = Cell::new(0);
        let creates = Cell::new(0);
        let result = query_or_create_journal(
            || {
                queries.set(queries.get() + 1);
                if queries.get() == 1 {
                    Err(io::Error::from_raw_os_error(ERROR_JOURNAL_NOT_ACTIVE))
                } else {
                    Ok((42, 100))
                }
            },
            || {
                creates.set(creates.get() + 1);
                Ok(())
            },
        );
        assert_eq!(result.unwrap(), (42, 100));
        assert_eq!((queries.get(), creates.get()), (2, 1));

        assert_eq!(
            query_or_create_journal(|| Ok((7, 50)), || panic!("journal already exists")).unwrap(),
            (7, 50)
        );
        let error = query_or_create_journal(
            || Err(io::Error::from_raw_os_error(5)),
            || panic!("unrelated errors must not create journals"),
        )
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(5));
    }

    #[test]
    fn probe_propagates_create_or_requery_failures() {
        let error = query_or_create_journal(
            || Err(io::Error::from_raw_os_error(ERROR_JOURNAL_NOT_ACTIVE)),
            || Err(io::Error::from_raw_os_error(5)),
        )
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(5));

        let queries = std::cell::Cell::new(0);
        let error = query_or_create_journal(
            || {
                queries.set(queries.get() + 1);
                Err(io::Error::from_raw_os_error(ERROR_JOURNAL_NOT_ACTIVE))
            },
            || Ok(()),
        )
        .unwrap_err();
        assert_eq!(queries.get(), 2);
        assert_eq!(error.raw_os_error(), Some(ERROR_JOURNAL_NOT_ACTIVE));
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
    fn directory_recovery_dispatches_ids_and_requires_reliable_names() {
        // Reason parsing tests never exercise parent dispatch, both rename names,
        // or nameless/unknown records. This one in-memory case covers that gap.
        let parents = HashMap::from([(11u128.to_le_bytes(), 0), (22u128.to_le_bytes(), 1)]);
        let mut changes = Vec::new();
        let mut name_units = Vec::new();
        for major in [2, 3] {
            let width = if major == 2 { 8 } else { 16 };
            let base = if major == 2 { 60 } else { 76 };
            let length_offset = if major == 2 { 56 } else { 72 };
            for name in ["Old.opaque", "New.001", "新🔐.002"] {
                let mut row = record(major, 22, 100, 0x1000);
                row.resize(base, 0);
                row[8 + width..8 + 2 * width].copy_from_slice(&11u128.to_le_bytes()[..width]);
                let encoded: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
                row[length_offset..length_offset + 2]
                    .copy_from_slice(&(encoded.len() as u16).to_le_bytes());
                row[length_offset + 2..length_offset + 4]
                    .copy_from_slice(&(base as u16).to_le_bytes());
                row.extend_from_slice(&encoded);
                record_directory_changes(&row, &parents, 100, 101, &mut changes, &mut name_units)
                    .unwrap();
                assert_eq!(changes, vec![(1, String::new()), (0, name.to_owned())]);
                record_directory_changes(&row, &parents, 99, 100, &mut changes, &mut name_units)
                    .unwrap();
                assert!(changes.is_empty());
                row[base..base + 2].copy_from_slice(&0xdc00u16.to_le_bytes());
                assert!(record_directory_changes(
                    &row,
                    &parents,
                    100,
                    101,
                    &mut changes,
                    &mut name_units
                )
                .is_err());
                row[length_offset..length_offset + 2].copy_from_slice(&1u16.to_le_bytes());
                assert!(record_directory_changes(
                    &row,
                    &parents,
                    100,
                    101,
                    &mut changes,
                    &mut name_units
                )
                .is_err());
            }
        }
        let mut nameless = record(4, 33, 100, 1);
        nameless[24..40].copy_from_slice(&11u128.to_le_bytes());
        assert!(record_directory_changes(
            &nameless,
            &parents,
            100,
            101,
            &mut changes,
            &mut name_units
        )
        .is_err());
        nameless[4..6].copy_from_slice(&5u16.to_le_bytes());
        assert!(record_directory_changes(
            &nameless,
            &parents,
            100,
            101,
            &mut changes,
            &mut name_units
        )
        .is_err());
    }

    #[test]
    fn directory_recovery_pages_preserve_names_and_resume_whole_records() {
        // Record-only tests cannot catch lost entries when a reused buffer is
        // drained across journal reads or a response page ends mid-buffer.
        let mut records = Vec::new();
        let mut expected = BTreeSet::from([(1, String::new())]);
        for index in 0..600 {
            let name = format!("{index:04}-{}-新🔐.001", "x".repeat(120));
            expected.insert((0, name.clone()));
            for _ in 0..2 {
                let mut row = record(2, 22, records.len() as i64 + 1, 0x1000);
                row[16..24].copy_from_slice(&11u64.to_le_bytes());
                let encoded: Vec<_> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
                row[56..58].copy_from_slice(&(encoded.len() as u16).to_le_bytes());
                row[58..60].copy_from_slice(&60u16.to_le_bytes());
                row.extend_from_slice(&encoded);
                let length = row.len() as u32;
                row[..4].copy_from_slice(&length.to_le_bytes());
                records.push(row);
            }
        }
        let end_usn = records.len() as i64 + 1;
        let mut cursor = 1;
        let mut actual = BTreeSet::new();
        let mut pages = 0;
        while cursor < end_usn {
            let page = scan_directories_page(
                42,
                &[11u128.to_le_bytes(), 22u128.to_le_bytes()],
                cursor,
                end_usn,
                |start, output| {
                    let mut index = (start - 1) as usize;
                    let mut used = 8;
                    while let Some(row) = records.get(index) {
                        if used + row.len() > output.len() {
                            break;
                        }
                        output[used..used + row.len()].copy_from_slice(row);
                        used += row.len();
                        index += 1;
                    }
                    output[..8].copy_from_slice(&(index as i64 + 1).to_le_bytes());
                    Ok(used)
                },
            )
            .unwrap();
            assert_eq!(page.journal_id, 42);
            assert!(page.next_usn > cursor && page.next_usn <= end_usn);
            assert_eq!(
                page.changes
                    .iter()
                    .map(|(_, name)| 8 + name.len())
                    .sum::<usize>(),
                page.payload_bytes,
            );
            assert!(page.payload_bytes <= MAX_DIRECTORY_RESPONSE_BYTES);
            actual.extend(page.changes);
            cursor = page.next_usn;
            pages += 1;
        }
        assert!(pages > 1);
        assert_eq!(actual, expected);
    }

    #[test]
    fn journal_request_preserves_record_aligned_start_usn() {
        let request = read_usn_journal_request(8_192, 42);
        assert_eq!(request.start_usn, 8_192);
        assert_eq!(request.usn_journal_id, 42);
    }
}
