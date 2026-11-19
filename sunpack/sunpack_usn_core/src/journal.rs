use crate::protocol::{FILE_ID_BYTES, MAX_DIRECTORY_RESPONSE_BYTES};
use crate::ChangeReasons;
use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::io;
use std::ops::ControlFlow::{self, Break, Continue};
use std::ptr::{null, null_mut};
use std::sync::{Arc, Mutex};
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
    pub changes: HashSet<(u32, String)>,
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
    min_major_version: u16,
    max_major_version: u16,
}

fn read_usn_journal_request(start_usn: i64, usn_journal_id: u64) -> ReadUsnJournalData {
    ReadUsnJournalData {
        start_usn,
        reason_mask: ALL_USN_REASONS,
        return_only_on_close: 0,
        timeout: 0,
        bytes_to_wait_for: 0,
        usn_journal_id,
        // READ_USN_JOURNAL_DATA_V1: ReFS needs the full 128-bit V3 IDs.
        // V2/V3 carry names; V4 extent records cannot drive directory recovery.
        min_major_version: 2,
        max_major_version: 3,
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

    pub fn volume_guid(&self) -> &Arc<str> {
        &self.volume_guid
    }

    pub fn has_open_volume(&self) -> bool {
        self.handle.is_some()
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
            let reasons = scan_change_reasons(
                file_id_value(&expected_file_id[..usize::from(expected_file_id_len)]),
                previous_usn,
                current_usn,
                |cursor, output| read_journal_page(volume, journal_id, cursor, output),
            )?;
            Ok((journal_id, reasons))
        })
    }

    pub fn read_directories_changes(
        &mut self,
        expected_journal: u64,
        parents: &HashMap<[u8; FILE_ID_BYTES], u32>,
        start_usn: i64,
        end_usn: i64,
    ) -> io::Result<DirectoryChangesPage> {
        if start_usn < 0 || end_usn <= start_usn || parents.is_empty() {
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
            scan_directories_page(journal_id, parents, start_usn, end_usn, |cursor, output| {
                read_journal_page(volume, journal_id, cursor, output)
            })
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
            // Independent read handles can probe the same inactive journal.
            // Serialize creation only, since creating an active journal can
            // change its size settings.
            static CREATE: Mutex<()> = Mutex::new(());
            let _creating = CREATE
                .lock()
                .map_err(|_| io::Error::other("journal creation lock poisoned"))?;
            match query() {
                Err(error) if error.raw_os_error() == Some(ERROR_JOURNAL_NOT_ACTIVE) => {}
                result => return result,
            }
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
    parents: &HashMap<[u8; FILE_ID_BYTES], u32>,
    start_usn: i64,
    end_usn: i64,
    mut read: impl FnMut(i64, &mut [u8]) -> io::Result<usize>,
) -> io::Result<DirectoryChangesPage> {
    let mut cursor = start_usn;
    let mut payload_bytes = 0usize;
    let mut changed = HashSet::new();
    let mut scratch = Default::default();
    let mut output = vec![0u8; JOURNAL_BUFFER_BYTES];
    'journal: while cursor < end_usn {
        let bytes_returned = read(cursor, &mut output)?;
        let (returned_next, mut records) = split_journal_reply(&output, bytes_returned)?;
        if returned_next <= cursor {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "USN recovery made no progress; fallback scan required",
            ));
        }
        while !records.is_empty() {
            let record = next_journal_record(&mut records)?;
            let record = record_directory_changes(
                record,
                parents,
                cursor,
                end_usn,
                &mut scratch,
            )?;
            if record.usn >= end_usn {
                break 'journal;
            }
            let changes = record.changes.map(|change| change.filter(|item| !changed.contains(*item)));
            let added: usize = changes.iter().flatten().map(|change| 8 + change.1.len()).sum();
            if added > MAX_DIRECTORY_RESPONSE_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "USN name exceeds response frame",
                ));
            }
            if payload_bytes + added > MAX_DIRECTORY_RESPONSE_BYTES {
                let next_usn = record.usn;
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
            changed.extend(changes.into_iter().flatten().cloned());
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

type DirectoryChange = (u32, String);

struct DirectoryRecord<'a> {
    usn: i64,
    changes: [Option<&'a DirectoryChange>; 2],
}

fn record_directory_changes<'a>(
    record: &[u8],
    parents: &HashMap<[u8; FILE_ID_BYTES], u32>,
    start_usn: i64,
    end_usn: i64,
    scratch: &'a mut [DirectoryChange; 2],
) -> io::Result<DirectoryRecord<'a>> {
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
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
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
    let mut result = DirectoryRecord { usn, changes: [None; 2] };
    if usn < start_usn || usn >= end_usn {
        return Ok(result);
    }
    let file = file_id_value(&record[8..8 + width]).to_le_bytes();
    let parent = file_id_value(&record[8 + width..8 + 2 * width]).to_le_bytes();
    let [directory, child] = scratch;
    if let Some(index) = parents.get(&file) {
        directory.0 = *index;
        result.changes[0] = Some(directory);
    }
    if let Some(index) = parents.get(&parent) {
        let Some((length_offset, offset_offset)) = name_offsets else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "USN V4 record requires fallback scan",
            ));
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
        // Retain scratch capacity when a journal repeats the same child name.
        // The page only allocates an owned copy for a new directory/name pair.
        child.0 = *index;
        child.1.clear();
        child.1.reserve(length / 2);
        let units = record[offset..offset + length]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]));
        for ch in char::decode_utf16(units) {
            child.1.push(ch.map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid USN UTF-16"))?);
        }
        let name = child.1.as_str();
        if name.contains(['/', '\\', '\0']) || name == "." || name == ".." {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid USN child name",
            ));
        }
        result.changes[1] = Some(child);
    }
    Ok(result)
}

fn scan_change_reasons(
    expected_file_id: u128,
    previous_usn: i64,
    current_usn: i64,
    mut read: impl FnMut(i64, &mut [u8]) -> io::Result<usize>,
) -> io::Result<ChangeReasons> {
    let mut next_usn = previous_usn;
    let mut reasons = ChangeReasons::default();
    let mut found_current = false;
    let mut output = vec![0u8; JOURNAL_BUFFER_BYTES];
    'journal: while next_usn <= current_usn {
        let bytes_returned = read(next_usn, &mut output)?;
        let (returned_next, mut records) = split_journal_reply(&output, bytes_returned)?;
        if returned_next <= next_usn {
            return Err(io::Error::other("USN observation made no progress"));
        }
        while !records.is_empty() {
            let record = next_journal_record(&mut records)?;
            match record_change_reason(record, expected_file_id, previous_usn, current_usn)? {
                Break(()) => break 'journal,
                Continue(Some((usn, reason))) => {
                    found_current |= usn == current_usn;
                    reasons.observe(reason);
                }
                Continue(None) => {}
            }
        }
        next_usn = returned_next;
    }
    if !found_current {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "USN journal did not contain the current file record",
        ));
    }
    Ok(reasons)
}

fn record_change_reason(
    record: &[u8],
    expected_file_id: u128,
    previous_usn: i64,
    current_usn: i64,
) -> io::Result<ControlFlow<(), Option<(i64, u32)>>> {
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
        _ => return Ok(Continue(None)),
    };
    if record.len() < reason_offset + 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated USN record",
        ));
    }
    let usn = i64::from_le_bytes(record[usn_offset..usn_offset + 8].try_into().unwrap());
    // The kernel returns journal order. Equal USNs still belong to this query.
    if usn > current_usn {
        return Ok(Break(()));
    }
    if usn <= previous_usn || file_id_value(&record[8..file_id_end]) != expected_file_id {
        return Ok(Continue(None));
    }
    let reason = u32::from_le_bytes(record[reason_offset..reason_offset + 4].try_into().unwrap());
    Ok(Continue(Some((usn, reason))))
}

fn file_id_value(bytes: &[u8]) -> u128 {
    match bytes.len() {
        8 => u128::from(u64::from_le_bytes(bytes.try_into().unwrap())),
        FILE_ID_BYTES => u128::from_le_bytes(bytes.try_into().unwrap()),
        _ => unreachable!(),
    }
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
#[path = "../tests/unit/journal/tests.rs"]
mod tests;
