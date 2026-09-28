use crate::io::resource_lifecycle::TrackedFile;
use crate::password::zip::{zip_password_bytes, ZipCryptoDecryptor};
use crate::verification::archive_manifest::{ManifestEntry, NativeArchiveManifest};
use encoding_rs::{BIG5, GBK, SHIFT_JIS, UTF_8};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::sync::Arc;

const COPY_CHUNK_SIZE: usize = 1024 * 1024;
const EOCD_SIG: &[u8] = b"PK\x05\x06";
const CD_SIG: &[u8] = b"PK\x01\x02";
const LFH_SIG: &[u8] = b"PK\x03\x04";
const ZIP_UNICODE_PATH_EXTRA_FIELD: u16 = 0x7075;

#[pyfunction]
#[pyo3(signature = (source, max_items=200000, password=None, codepage=None))]
pub(crate) fn archive_state_zip_manifest_native(
    py: Python<'_>,
    source: &Bound<'_, PyDict>,
    max_items: usize,
    password: Option<String>,
    codepage: Option<String>,
) -> PyResult<NativeArchiveManifest> {
    let segments = build_segments(source)?;
    py.detach(move || {
        let mut reader = SegmentReader::new(segments);
        zip_manifest_from_reader(
            &mut reader,
            max_items,
            password.as_deref(),
            codepage.as_deref(),
        )
    })
}

#[pyfunction]
#[pyo3(signature = (source, max_items=200000))]
pub(crate) fn archive_state_tar_manifest_native(
    py: Python<'_>,
    source: &Bound<'_, PyDict>,
    max_items: usize,
) -> PyResult<NativeArchiveManifest> {
    let segments = build_segments(source)?;
    py.detach(move || {
        let mut reader = SegmentReader::new(segments);
        tar_manifest_from_reader(&mut reader, max_items)
    })
}

#[derive(Debug, Clone)]
pub(crate) enum Segment {
    Range { path: String, start: u64, len: u64 },
}

impl Segment {
    pub(crate) fn len(&self) -> u64 {
        match self {
            Segment::Range { len, .. } => *len,
        }
    }
}

struct SegmentReader {
    segments: Vec<Segment>,
    starts: Vec<u64>,
    total: u64,
    file_index: Option<usize>,
    file: Option<TrackedFile>,
}

impl SegmentReader {
    fn new(segments: Vec<Segment>) -> Self {
        let mut starts = Vec::with_capacity(segments.len());
        let mut total = 0u64;
        for segment in &segments {
            starts.push(total);
            total = total.saturating_add(segment.len());
        }
        Self {
            segments,
            starts,
            total,
            file_index: None,
            file: None,
        }
    }

    fn locate(&self, offset: u64) -> Option<(usize, u64)> {
        if offset >= self.total {
            return None;
        }
        let index = match self.starts.binary_search(&offset) {
            Ok(index) => index,
            Err(index) => index.checked_sub(1)?,
        };
        let start = *self.starts.get(index)?;
        if offset < start.saturating_add(self.segments[index].len()) {
            Some((index, offset - start))
        } else {
            None
        }
    }

    fn read_exact_at(&mut self, offset: u64, output: &mut [u8]) -> PyResult<()> {
        let end = offset.checked_add(output.len() as u64).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err("archive state logical read offset overflow")
        })?;
        if end > self.total {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "archive state logical read exceeds input",
            ));
        }
        let mut cursor = offset;
        let mut written = 0usize;
        while written < output.len() {
            let (index, within) = self.locate(cursor).ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err("archive state logical read segment is missing")
            })?;
            let available = (self.segments[index].len() - within) as usize;
            let take = available.min(output.len() - written);
            match self.segments[index].clone() {
                Segment::Range { path, start, .. } => {
                    if self.file_index != Some(index) {
                        let file = TrackedFile::open(&path, "archive_state_segment_file")?;
                        self.file = Some(file);
                        self.file_index = Some(index);
                    }
                    let file = self.file.as_mut().ok_or_else(|| {
                        pyo3::exceptions::PyRuntimeError::new_err("archive state source file is unavailable")
                    })?;
                    file.seek(SeekFrom::Start(start.saturating_add(within)))?;
                    file.read_exact(&mut output[written..written + take])?;
                }
            }
            cursor = cursor.saturating_add(take as u64);
            written += take;
        }
        Ok(())
    }

    fn read_vec_at(&mut self, offset: u64, len: usize) -> PyResult<Vec<u8>> {
        let mut output = vec![0u8; len];
        self.read_exact_at(offset, &mut output)?;
        Ok(output)
    }

    fn has_nonzero_at(&mut self, offset: u64) -> PyResult<bool> {
        if offset >= self.total {
            return Ok(false);
        }
        let mut cursor = offset;
        let mut buffer = vec![0u8; 64 * 1024];
        while cursor < self.total {
            let length = ((self.total - cursor) as usize).min(buffer.len());
            self.read_exact_at(cursor, &mut buffer[..length])?;
            if buffer[..length].iter().any(|byte| *byte != 0) {
                return Ok(true);
            }
            cursor = cursor.saturating_add(length as u64);
        }
        Ok(false)
    }
}

fn tar_manifest_from_reader(
    reader: &mut SegmentReader,
    max_items: usize,
) -> PyResult<NativeArchiveManifest> {
    const BLOCK: u64 = 512;
    let mut offset = 0u64;
    let mut item_count = 0usize;
    let mut file_count = 0usize;
    let mut total_unpacked_size = 0u64;
    let mut zero_blocks = 0usize;
    let mut entries = Vec::<ManifestEntry>::new();
    let mut used_paths = HashSet::<String>::new();
    let mut global_pax = HashMap::<String, String>::new();
    let mut next_pax = HashMap::<String, String>::new();
    let mut long_name = None::<String>;
    let mut error = None::<String>;
    let mut checksum_error = false;

    while offset.saturating_add(BLOCK) <= reader.total {
        let mut header = [0u8; 512];
        reader.read_exact_at(offset, &mut header)?;
        if header.iter().all(|byte| *byte == 0) {
            zero_blocks += 1;
            offset = offset.saturating_add(BLOCK);
            if zero_blocks >= 2 {
                break;
            }
            continue;
        }
        zero_blocks = 0;

        let stored = tar_number(&header[148..156]);
        let raw_size = tar_number(&header[124..136]);
        let checksum = tar_checksum(&header);
        if stored.is_none() || raw_size.is_none() || stored != Some(checksum) {
            checksum_error = stored.is_some() && stored != Some(checksum);
            error = Some("invalid TAR member header".to_string());
            break;
        }
        let raw_size = raw_size.unwrap_or(0);
        let typeflag = header[156];
        let (sparse_extension_span, oldgnu_sparse_extent_end) = if typeflag == b'S' {
            match tar_sparse_extension_span(reader, &header, offset)? {
                Some(value) => value,
                None => {
                    error = Some("invalid old GNU sparse extension map".to_string());
                    break;
                }
            }
        } else {
            (0, 0)
        };
        let raw_end = offset
            .checked_add(BLOCK)
            .and_then(|value| value.checked_add(sparse_extension_span))
            .and_then(|value| value.checked_add(raw_size));
        let Some(raw_end) = raw_end else {
            error = Some("TAR member payload is truncated".to_string());
            break;
        };
        let raw_next = raw_end.checked_add(tar_padding(raw_size));
        let Some(raw_next) = raw_next else {
            error = Some("TAR member payload is truncated".to_string());
            break;
        };
        let raw_payload_truncated = raw_next > reader.total;
        let payload_start = offset
            .checked_add(BLOCK)
            .and_then(|value| value.checked_add(sparse_extension_span))
            .unwrap_or(reader.total);

        if matches!(typeflag, b'x' | b'g') {
            if raw_payload_truncated {
                error = Some("TAR metadata member payload is truncated".to_string());
                break;
            }
            let payload = reader.read_vec_at(payload_start, raw_size as usize)?;
            let Some(parsed) = tar_pax(&payload) else {
                error = Some("invalid PAX extended header".to_string());
                break;
            };
            if typeflag == b'g' {
                for (key, value) in parsed {
                    if value.is_empty() {
                        global_pax.remove(&key);
                    } else {
                        global_pax.insert(key, value);
                    }
                }
            } else {
                next_pax = parsed;
            }
            item_count += 1;
            offset = raw_next;
            continue;
        }
        if typeflag == b'L' || typeflag == b'K' {
            if raw_payload_truncated {
                error = Some(
                    if typeflag == b'L' {
                        "GNU longname payload is truncated"
                    } else {
                        "GNU longlink payload is truncated"
                    }
                    .to_string(),
                );
                break;
            }
            // A GNU longlink only names a link target, which is not part of the
            // regular-file manifest; its payload is skipped like any member.
            if typeflag == b'L' {
                let payload = reader.read_vec_at(payload_start, raw_size as usize)?;
                long_name = Some(tar_text(&payload));
            }
            item_count += 1;
            offset = raw_next;
            continue;
        }

        let mut effective = global_pax.clone();
        for (key, value) in &next_pax {
            if value.is_empty() {
                effective.remove(key);
            } else {
                effective.insert(key.clone(), value.clone());
            }
        }
        let mut physical_size = raw_size;
        let has_sparse_pax = effective.keys().any(|key| key.starts_with("GNU.sparse."));
        if let Some(value) = effective.get("size") {
            if !has_sparse_pax {
                match tar_extended_size(value) {
                    Some(size) => physical_size = size,
                    None => error = Some("invalid TAR extended size: size".to_string()),
                }
            }
        }
        let member_next = offset
            .checked_add(BLOCK)
            .and_then(|value| value.checked_add(sparse_extension_span))
            .and_then(|value| value.checked_add(physical_size))
            .and_then(|value| value.checked_add(tar_padding(physical_size)));
        let Some(member_next) = member_next else {
            error = Some("TAR extended member payload is truncated".to_string());
            break;
        };
        let member_payload_truncated = member_next > reader.total;
        if member_payload_truncated {
            error = Some("TAR extended member payload is truncated".to_string());
        }

        let prefix = tar_text(&header[345..500]);
        let raw_name = tar_text(&header[0..100]);
        let path = long_name
            .clone()
            .or_else(|| effective.get("path").cloned())
            .unwrap_or_else(|| {
                if prefix.is_empty() {
                    raw_name.clone()
                } else {
                    format!("{prefix}/{raw_name}")
                }
            });
        let mut logical_size = raw_size;
        for key in ["GNU.sparse.realsize", "GNU.sparse.size", "size"] {
            if let Some(value) = effective.get(key) {
                if let Some(size) = tar_extended_size(value) {
                    logical_size = size;
                } else {
                    error = Some(format!("invalid TAR extended size: {key}"));
                }
                break;
            }
        }
        if typeflag == b'S' {
            if let Some(oldgnu_size) = tar_number(&header[483..495]) {
                logical_size = oldgnu_size;
            }
            if oldgnu_sparse_extent_end > logical_size {
                error = Some("old GNU sparse extent exceeds logical size".to_string());
            }
        }
        let sparse_valid = match effective.get("GNU.sparse.map") {
            Some(value) => tar_sparse_map(value)
                .map(|extents| {
                    extents.iter().all(|(start, length)| {
                        start
                            .checked_add(*length)
                            .is_some_and(|end| end <= logical_size)
                    })
                })
                .unwrap_or(false),
            None => true,
        };
        if !sparse_valid {
            error = Some("invalid GNU sparse extent map".to_string());
        }

        item_count += 1;
        if !matches!(typeflag, b'5' | b'3' | b'4' | b'6') && !path.is_empty() {
            file_count += 1;
            let archive_path = path.clone();
            let mut projected = archive_path.clone();
            let mut index = 1usize;
            while used_paths.contains(&tar_path_key(&projected)) {
                projected = tar_duplicate_path(&archive_path, index);
                index += 1;
            }
            used_paths.insert(tar_path_key(&projected));
            let size = if matches!(typeflag, b'1' | b'2') {
                0
            } else {
                logical_size
            };
            total_unpacked_size = total_unpacked_size.saturating_add(size);
            if entries.len() < max_items {
                let raw_path = (projected != archive_path).then_some(archive_path);
                entries.push(ManifestEntry {
                    path: projected,
                    raw_path,
                    size,
                    crc32: None,
                });
            }
        }
        next_pax.clear();
        long_name = None;
        offset = member_next;
        if error.is_some() || raw_payload_truncated || member_payload_truncated {
            if error.is_none() {
                error = Some("TAR member payload is truncated".to_string());
            }
            break;
        }
    }

    if error.is_none()
        && offset < reader.total
        && zero_blocks < 2
        && reader.has_nonzero_at(offset)?
    {
        error = Some("TAR ends with a partial header or non-zero trailing data".to_string());
    }
    let damaged = error.is_some();
    let status = if damaged { 2 } else { 0 };
    let message = error.unwrap_or_else(|| {
        if zero_blocks >= 2 {
            "TAR source manifest walked to canonical end".to_string()
        } else {
            "TAR source manifest walked to EOF".to_string()
        }
    });
    Ok(NativeArchiveManifest {
        status,
        is_archive: item_count > 0,
        damaged,
        checksum_error,
        item_count,
        file_count,
        total_unpacked_size,
        message,
        archive_type: "tar".to_string(),
        source: "archive_state_tar_native".to_string(),
        archive_walk_complete: !damaged,
        verified_item_count: if damaged { 0 } else { item_count },
        failure_kind: if damaged { "corrupted_data" } else { "" }.to_string(),
        entries: Arc::new(entries),
    })
}

fn tar_number(field: &[u8]) -> Option<u64> {
    if field.is_empty() {
        return None;
    }
    if field[0] & 0x80 != 0 {
        let mut value = (field[0] & 0x7f) as u64;
        for byte in &field[1..] {
            value = value.checked_mul(256)?.checked_add(*byte as u64)?;
        }
        return Some(value);
    }
    let mut end = field.len();
    while end > 0 && matches!(field[end - 1], 0 | b' ') {
        end -= 1;
    }
    let mut start = 0usize;
    while start < end && field[start] == b' ' {
        start += 1;
    }
    if start == end {
        return Some(0);
    }
    let mut value = 0u64;
    for byte in &field[start..end] {
        if !(b'0'..=b'7').contains(byte) {
            return None;
        }
        value = value.checked_mul(8)?.checked_add((byte - b'0') as u64)?;
    }
    Some(value)
}

fn tar_checksum(header: &[u8; 512]) -> u64 {
    let mut sum = header[..148].iter().map(|byte| *byte as u64).sum::<u64>();
    sum += 32 * 8;
    sum + header[156..].iter().map(|byte| *byte as u64).sum::<u64>()
}

fn tar_padding(size: u64) -> u64 {
    (BLOCK_SIZE_TAR - (size % BLOCK_SIZE_TAR)) % BLOCK_SIZE_TAR
}

const BLOCK_SIZE_TAR: u64 = 512;

fn tar_text(field: &[u8]) -> String {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

fn tar_extended_size(value: &str) -> Option<u64> {
    let parsed = value.parse::<i128>().ok()?;
    if parsed <= 0 {
        Some(0)
    } else {
        u64::try_from(parsed).ok()
    }
}

fn tar_pax(payload: &[u8]) -> Option<HashMap<String, String>> {
    let mut records = HashMap::new();
    let mut cursor = 0usize;
    while cursor < payload.len() {
        let space = payload[cursor..].iter().position(|byte| *byte == b' ')? + cursor;
        if space <= cursor
            || !payload[cursor..space]
                .iter()
                .all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        let length = std::str::from_utf8(&payload[cursor..space])
            .ok()?
            .parse::<usize>()
            .ok()?;
        if length == 0 {
            return None;
        }
        let end = cursor.checked_add(length)?;
        if end > payload.len() || payload.get(end - 1) != Some(&b'\n') {
            return None;
        }
        let record = &payload[space + 1..end - 1];
        let equal = record.iter().position(|byte| *byte == b'=')?;
        let key = String::from_utf8(record[..equal].to_vec()).ok()?;
        let value = String::from_utf8(record[equal + 1..].to_vec()).ok()?;
        records.insert(key, value);
        cursor = end;
    }
    Some(records)
}

fn tar_sparse_extension_span(
    reader: &mut SegmentReader,
    header: &[u8; 512],
    header_offset: u64,
) -> PyResult<Option<(u64, u64)>> {
    let mut previous_end = 0u64;
    if !tar_validate_sparse_block(header, 386, 4, &mut previous_end) {
        return Ok(None);
    }
    let mut span = 0u64;
    let mut extended = header[482] != 0 && header[482] != b'0';
    while extended {
        if span >= 512 * 65536 {
            return Ok(None);
        }
        let extension_offset = header_offset
            .checked_add(512)
            .and_then(|value| value.checked_add(span))
            .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("TAR sparse offset overflow"))?;
        let mut extension = [0u8; 512];
        if reader
            .read_exact_at(extension_offset, &mut extension)
            .is_err()
        {
            return Ok(None);
        }
        if !tar_validate_sparse_block(&extension, 0, 21, &mut previous_end) {
            return Ok(None);
        }
        span += 512;
        extended = extension[504] != 0 && extension[504] != b'0';
    }
    Ok(Some((span, previous_end)))
}

fn tar_validate_sparse_block(
    block: &[u8],
    start: usize,
    count: usize,
    previous_end: &mut u64,
) -> bool {
    for index in 0..count {
        let base = start + index * 24;
        let Some(offset_field) = block.get(base..base + 12) else {
            return false;
        };
        let Some(sparse_offset) = tar_number(offset_field) else {
            return false;
        };
        let Some(length_field) = block.get(base + 12..base + 24) else {
            return false;
        };
        let Some(sparse_length) = tar_number(length_field) else {
            return false;
        };
        if sparse_offset == 0 && sparse_length == 0 {
            continue;
        }
        let Some(end) = sparse_offset.checked_add(sparse_length) else {
            return false;
        };
        if sparse_offset < *previous_end {
            return false;
        }
        *previous_end = end;
    }
    true
}

fn tar_sparse_map(value: &str) -> Option<Vec<(u64, u64)>> {
    let fields: Vec<&str> = value.split(',').collect();
    if fields.is_empty() || fields.len() % 2 != 0 {
        return None;
    }
    let mut extents = Vec::with_capacity(fields.len() / 2);
    let mut previous_end = 0u64;
    for pair in fields.chunks_exact(2) {
        let offset = pair[0].parse::<u64>().ok()?;
        let length = pair[1].parse::<u64>().ok()?;
        let end = offset.checked_add(length)?;
        if offset < previous_end {
            return None;
        }
        extents.push((offset, length));
        previous_end = end;
    }
    Some(extents)
}

fn tar_path_key(path: &str) -> String {
    path.replace('\\', "/").to_lowercase()
}

fn tar_duplicate_path(path: &str, index: usize) -> String {
    let slash = path.rfind('/');
    let prefix = slash.map(|value| &path[..=value]).unwrap_or("");
    let name = slash.map(|value| &path[value + 1..]).unwrap_or(path);
    let dot = name.rfind('.');
    let suffix = match dot {
        Some(value) if value > 0 => &name[value..],
        _ => "",
    };
    let stem = &name[..name.len() - suffix.len()];
    format!("{prefix}{stem}({index}){suffix}")
}

pub(crate) fn build_segments(source: &Bound<'_, PyDict>) -> PyResult<Vec<Segment>> {
    Ok(source_segments(source)?
        .into_iter()
        .filter(|segment| segment.len() > 0)
        .collect())
}

fn source_segments(source: &Bound<'_, PyDict>) -> PyResult<Vec<Segment>> {
    let entry_path = optional_string(source, "entry_path")?.unwrap_or_default();
    let open_mode = optional_string(source, "open_mode")?.unwrap_or_else(|| "file".to_string());
    if open_mode == "file_range" {
        if let Some(parts) = source.get_item("parts")? {
            let parts = parts.cast::<PyList>()?;
            if let Some(first) = parts.iter().next() {
                let item = first.cast::<PyDict>()?;
                let path = optional_string(item, "path")?.unwrap_or_else(|| entry_path.clone());
                let start = optional_u64(item, "start")?.unwrap_or(0);
                let end = optional_u64(item, "end")?;
                return Ok(vec![range_segment(&path, start, end)?]);
            }
        }
        if let Some(segment) = source.get_item("segment")? {
            let segment = segment.cast::<PyDict>()?;
            let start = optional_u64(segment, "start")?.unwrap_or(0);
            let end = optional_u64(segment, "end")?;
            return Ok(vec![range_segment(&entry_path, start, end)?]);
        }
    }
    if open_mode == "concat_ranges" {
        if let Some(ranges) = source.get_item("ranges")? {
            let ranges = ranges.cast::<PyList>()?;
            let mut output = Vec::new();
            for item in ranges.iter() {
                let item = item.cast::<PyDict>()?;
                let path = optional_string(item, "path")?.unwrap_or_else(|| entry_path.clone());
                let start = optional_u64(item, "start")?.unwrap_or(0);
                let end = optional_u64(item, "end")?;
                output.push(range_segment(&path, start, end)?);
            }
            if !output.is_empty() {
                return Ok(output);
            }
        }
    }
    if let Some(parts) = source.get_item("parts")? {
        let parts = parts.cast::<PyList>()?;
        let mut output = Vec::new();
        for item in parts.iter() {
            let item = item.cast::<PyDict>()?;
            let path = optional_string(item, "path")?.unwrap_or_else(|| entry_path.clone());
            let start = optional_u64(item, "start")?.unwrap_or(0);
            let end = optional_u64(item, "end")?;
            if start != 0 || end.is_some() {
                output.push(range_segment(&path, start, end)?);
            } else if !path.is_empty() {
                output.push(range_segment(&path, 0, None)?);
            }
        }
        if !output.is_empty() {
            return Ok(output);
        }
    }
    Ok(vec![range_segment(&entry_path, 0, None)?])
}

fn range_segment(path: &str, start: u64, end: Option<u64>) -> PyResult<Segment> {
    let size = fs::metadata(path)?.len();
    if start > size {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "range start is beyond input size",
        ));
    }
    let effective_end = end.unwrap_or(size).min(size);
    if effective_end < start {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "range end is before range start",
        ));
    }
    Ok(Segment::Range {
        path: path.to_string(),
        start,
        len: effective_end - start,
    })
}

fn zip_manifest_from_reader(
    reader: &mut SegmentReader,
    max_items: usize,
    password: Option<&str>,
    codepage: Option<&str>,
) -> PyResult<NativeArchiveManifest> {
    let password = password.map(zip_password_bytes);
    let mut manifest = NativeArchiveManifest {
        status: 2,
        is_archive: true,
        damaged: true,
        checksum_error: false,
        item_count: 0,
        file_count: 0,
        total_unpacked_size: 0,
        message: "Archive state is not a readable ZIP: EOCD not found".to_string(),
        archive_type: "zip".to_string(),
        source: "archive_state_native_zip_central_directory".to_string(),
        archive_walk_complete: false,
        verified_item_count: 0,
        failure_kind: String::new(),
        entries: Arc::new(Vec::new()),
    };
    let Some(eocd) = find_eocd(reader)? else {
        manifest.is_archive = looks_like_zip(reader)?;
        return Ok(manifest);
    };
    let total = reader.total;
    let cd_start = eocd.cd_offset as u64;
    let expected_end = cd_start.saturating_add(eocd.cd_size as u64);
    // Every header read below stays inside [cd_start, expected_end + 46) and
    // inside the input, so one bounded buffer holds the whole directory walk.
    let directory = if cd_start < total {
        reader.read_vec_at(cd_start, (expected_end.saturating_add(46).min(total) - cd_start) as usize)?
    } else {
        Vec::new()
    };
    let mut entries = Vec::new();
    let mut cursor = cd_start;
    let mut item_count = 0usize;
    let mut file_count = 0usize;
    let mut total_unpacked_size = 0u64;
    let mut damaged = false;
    let mut checksum_error = false;
    let mut wrong_password = false;
    let mut message = "Archive-state ZIP manifest loaded by native parser".to_string();
    let mut payload = ZipPayloadVerifier::new();
    while cursor + 46 <= total && cursor < expected_end {
        let at = (cursor - cd_start) as usize;
        if &directory[at..at + 4] != CD_SIG {
            damaged = true;
            message = "Archive state ZIP central directory stopped before expected end"
                .to_string();
            break;
        }
        let flags = u16_le(&directory, at + 8);
        let method = u16_le(&directory, at + 10);
        let crc32 = u32_le(&directory, at + 16);
        let compressed_size = u32_le(&directory, at + 20) as u64;
        let uncompressed_size = u32_le(&directory, at + 24) as u64;
        let name_len = u16_le(&directory, at + 28) as usize;
        let extra_len = u16_le(&directory, at + 30) as usize;
        let comment_len = u16_le(&directory, at + 32) as usize;
        let local_offset = u32_le(&directory, at + 42) as u64;
        let name_start = at + 46;
        let name_end = name_start + name_len;
        let extra_end = name_end + extra_len;
        let record_end = cursor + 46 + (name_len + extra_len + comment_len) as u64;
        if record_end > total || record_end > expected_end {
            damaged = true;
            message = "Archive state ZIP central directory entry is truncated".to_string();
            break;
        }
        item_count += 1;
        let name = decode_zip_filename(
            &directory[name_start..name_end],
            &directory[name_end..extra_end],
            flags,
            codepage,
        )?;
        // Encrypted entries are only checkable with a password; WinZip AES
        // entries use method 99 and are left to the extraction worker.
        let entry_password = if flags & 0x1 != 0 { password.as_deref() } else { None };
        if matches!(method, 0 | 8) && (flags & 0x1 == 0 || entry_password.is_some()) {
            match payload.verify(
                reader,
                local_offset,
                method,
                crc32,
                compressed_size,
                uncompressed_size,
                entry_password,
            )? {
                PayloadCheck::Valid => {}
                PayloadCheck::Corrupt => {
                    damaged = true;
                    checksum_error = true;
                    message = format!("Archive state ZIP payload CRC failed at: {name}");
                }
                PayloadCheck::WrongPassword => {
                    if !wrong_password && !damaged {
                        message = format!("Archive state ZIP password does not match: {name}");
                    }
                    wrong_password = true;
                }
            }
        }
        if !name.ends_with('/') {
            file_count += 1;
            total_unpacked_size = total_unpacked_size.saturating_add(uncompressed_size);
            if entries.len() < max_items {
                entries.push(ManifestEntry {
                    path: name,
                    raw_path: None,
                    size: uncompressed_size,
                    crc32: Some(crc32),
                });
            }
        }
        cursor = record_end;
    }
    if cursor != expected_end {
        damaged = true;
    }
    let walk_complete = !damaged && !wrong_password;
    manifest.status = if damaged {
        2
    } else if wrong_password {
        1
    } else {
        0
    };
    manifest.damaged = damaged;
    manifest.checksum_error = checksum_error;
    manifest.item_count = item_count;
    manifest.file_count = file_count;
    manifest.total_unpacked_size = total_unpacked_size;
    manifest.message = message;
    manifest.archive_walk_complete = walk_complete;
    manifest.verified_item_count = if walk_complete { item_count } else { 0 };
    manifest.entries = Arc::new(entries);
    Ok(manifest)
}

fn decode_zip_filename(
    raw: &[u8],
    extra: &[u8],
    flags: u16,
    codepage: Option<&str>,
) -> PyResult<String> {
    const ZIP_UTF8_FLAG: u16 = 1 << 11;
    if flags & ZIP_UTF8_FLAG != 0 {
        return String::from_utf8(raw.to_vec())
            .map(|value| value.replace('\\', "/"))
            .map_err(|err| pyo3::exceptions::PyValueError::new_err(err.to_string()));
    }
    if let Some(unicode_name) = valid_unicode_path_name(raw, extra) {
        return Ok(unicode_name.replace('\\', "/"));
    }
    if let Some(codepage) = codepage.filter(|value| !value.is_empty()) {
        let encoding = match codepage {
            "65001" => UTF_8,
            "932" => SHIFT_JIS,
            "936" => GBK,
            "950" => BIG5,
            other => {
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "unsupported ZIP filename codepage: {other}"
                )))
            }
        };
        let (decoded, _, had_errors) = encoding.decode(raw);
        if had_errors {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "ZIP filename is invalid for codepage {codepage}"
            )));
        }
        return Ok(decoded.replace('\\', "/"));
    }
    Ok(raw
        .iter()
        .map(|byte| cp437_char(*byte))
        .collect::<String>()
        .replace('\\', "/"))
}

/// Return the Info-ZIP Unicode Path Extra Field only when its version, raw-name
/// CRC32, and UTF-8 payload are all valid. Invalid fields are ignored so the
/// explicit codepage / CP437 fallback remains available.
fn valid_unicode_path_name<'a>(raw: &[u8], extra: &'a [u8]) -> Option<&'a str> {
    let mut offset = 0usize;
    while offset + 4 <= extra.len() {
        let field_id = u16_le(extra, offset);
        let field_len = u16_le(extra, offset + 2) as usize;
        let data_start = offset + 4;
        let data_end = data_start.checked_add(field_len)?;
        if data_end > extra.len() {
            return None;
        }
        if field_id == ZIP_UNICODE_PATH_EXTRA_FIELD {
            let field = &extra[data_start..data_end];
            if field.len() >= 6 && field[0] == 1 && u32_le(field, 1) == crc32fast::hash(raw) {
                if let Ok(name) = std::str::from_utf8(&field[5..]) {
                    if !name.is_empty() {
                        return Some(name);
                    }
                }
            }
        }
        offset = data_end;
    }
    None
}

fn cp437_char(byte: u8) -> char {
    if byte < 0x80 {
        return byte as char;
    }
    const CP437_HIGH: [char; 128] = [
        '\u{00C7}', '\u{00FC}', '\u{00E9}', '\u{00E2}', '\u{00E4}', '\u{00E0}', '\u{00E5}',
        '\u{00E7}', '\u{00EA}', '\u{00EB}', '\u{00E8}', '\u{00EF}', '\u{00EE}', '\u{00EC}',
        '\u{00C4}', '\u{00C5}', '\u{00C9}', '\u{00E6}', '\u{00C6}', '\u{00F4}', '\u{00F6}',
        '\u{00F2}', '\u{00FB}', '\u{00F9}', '\u{00FF}', '\u{00D6}', '\u{00DC}', '\u{00A2}',
        '\u{00A3}', '\u{00A5}', '\u{20A7}', '\u{0192}', '\u{00E1}', '\u{00ED}', '\u{00F3}',
        '\u{00FA}', '\u{00F1}', '\u{00D1}', '\u{00AA}', '\u{00BA}', '\u{00BF}', '\u{2310}',
        '\u{00AC}', '\u{00BD}', '\u{00BC}', '\u{00A1}', '\u{00AB}', '\u{00BB}', '\u{2591}',
        '\u{2592}', '\u{2593}', '\u{2502}', '\u{2524}', '\u{2561}', '\u{2562}', '\u{2556}',
        '\u{2555}', '\u{2563}', '\u{2551}', '\u{2557}', '\u{255D}', '\u{255C}', '\u{255B}',
        '\u{2510}', '\u{2514}', '\u{2534}', '\u{252C}', '\u{251C}', '\u{2500}', '\u{253C}',
        '\u{255E}', '\u{255F}', '\u{255A}', '\u{2554}', '\u{2569}', '\u{2566}', '\u{2560}',
        '\u{2550}', '\u{256C}', '\u{2567}', '\u{2568}', '\u{2564}', '\u{2565}', '\u{2559}',
        '\u{2558}', '\u{2552}', '\u{2553}', '\u{256B}', '\u{256A}', '\u{2518}', '\u{250C}',
        '\u{2588}', '\u{2584}', '\u{258C}', '\u{2590}', '\u{2580}', '\u{03B1}', '\u{00DF}',
        '\u{0393}', '\u{03C0}', '\u{03A3}', '\u{03C3}', '\u{00B5}', '\u{03C4}', '\u{03A6}',
        '\u{0398}', '\u{03A9}', '\u{03B4}', '\u{221E}', '\u{03C6}', '\u{03B5}', '\u{2229}',
        '\u{2261}', '\u{00B1}', '\u{2265}', '\u{2264}', '\u{2320}', '\u{2321}', '\u{00F7}',
        '\u{2248}', '\u{00B0}', '\u{2219}', '\u{00B7}', '\u{221A}', '\u{207F}', '\u{00B2}',
        '\u{25A0}', '\u{00A0}',
    ];
    CP437_HIGH[(byte - 0x80) as usize]
}

#[cfg(test)]
mod tests {
    use super::decode_zip_filename;

    #[test]
    fn zip_filename_decoder_uses_cp437_when_utf8_flag_is_absent() {
        assert_eq!(
            decode_zip_filename(b"caf\x82.txt", b"", 0, None).unwrap(),
            "café.txt"
        );
        assert_eq!(
            decode_zip_filename(b"dir\\file.txt", b"", 0, None).unwrap(),
            "dir/file.txt"
        );
    }

    #[test]
    fn zip_filename_decoder_uses_utf8_when_flag_is_set() {
        assert_eq!(
            decode_zip_filename("目录/文件.txt".as_bytes(), b"", 1 << 11, None).unwrap(),
            "目录/文件.txt"
        );
    }

    #[test]
    fn zip_filename_decoder_uses_selected_shift_jis_codepage() {
        assert_eq!(
            decode_zip_filename(b"\x93\xfa\x96{\x8c\xea.txt", b"", 0, Some("932")).unwrap(),
            "日本語.txt"
        );
    }

    #[test]
    fn zip_filename_decoder_uses_selected_utf8_codepage_without_flag() {
        assert_eq!(
            decode_zip_filename("日本語.txt".as_bytes(), b"", 0, Some("65001")).unwrap(),
            "日本語.txt"
        );
    }

    #[test]
    fn zip_filename_decoder_prefers_valid_unicode_path_extra_field() {
        let raw = b"\x93\xfa\x96{\x8c\xea.txt";
        let unicode = "日本語.txt".as_bytes();
        let mut extra = Vec::new();
        extra.extend_from_slice(&0x7075u16.to_le_bytes());
        extra.extend_from_slice(&((5 + unicode.len()) as u16).to_le_bytes());
        extra.push(1);
        extra.extend_from_slice(&crc32fast::hash(raw).to_le_bytes());
        extra.extend_from_slice(unicode);

        assert_eq!(
            decode_zip_filename(raw, &extra, 0, None).unwrap(),
            "日本語.txt"
        );
        extra[5] ^= 1;
        assert_ne!(
            decode_zip_filename(raw, &extra, 0, None).unwrap(),
            "日本語.txt"
        );
    }
}

#[derive(Debug)]
struct EocdRecord {
    cd_size: u32,
    cd_offset: u32,
}

/// Search the logical input backwards for the last EOCD record whose comment
/// fits inside the input, reading bounded windows instead of the whole input.
fn find_eocd(reader: &mut SegmentReader) -> PyResult<Option<EocdRecord>> {
    const WINDOW: u64 = 1024 * 1024;
    let total = reader.total;
    if total < EOCD_SIG.len() as u64 {
        return Ok(None);
    }
    let overlap = EOCD_SIG.len() as u64 - 1;
    let mut window_end = total;
    let mut buffer = Vec::new();
    loop {
        let window_start = window_end.saturating_sub(WINDOW);
        let read_end = window_end.saturating_add(overlap).min(total);
        buffer.resize((read_end - window_start) as usize, 0);
        reader.read_exact_at(window_start, &mut buffer)?;
        let mut index = (window_end - window_start) as usize;
        while index > 0 {
            index -= 1;
            if index + EOCD_SIG.len() > buffer.len() || &buffer[index..index + 4] != EOCD_SIG {
                continue;
            }
            let pos = window_start + index as u64;
            if pos + 22 > total {
                continue;
            }
            let mut record = [0u8; 22];
            reader.read_exact_at(pos, &mut record)?;
            let comment_len = u16_le(&record, 20) as u64;
            if pos + 22 + comment_len <= total {
                return Ok(Some(EocdRecord {
                    cd_size: u32_le(&record, 12),
                    cd_offset: u32_le(&record, 16),
                }));
            }
        }
        if window_start == 0 {
            return Ok(None);
        }
        window_end = window_start;
    }
}

enum PayloadCheck {
    Valid,
    Corrupt,
    WrongPassword,
}

/// Streams stored / deflated ZIP payloads through fixed buffers for CRC checks,
/// decrypting ZipCrypto entries on the fly when a password is supplied.
struct ZipPayloadVerifier {
    input: Vec<u8>,
    output: Vec<u8>,
}

impl ZipPayloadVerifier {
    fn new() -> Self {
        Self {
            input: vec![0u8; COPY_CHUNK_SIZE],
            output: vec![0u8; 64 * 1024],
        }
    }

    fn verify(
        &mut self,
        reader: &mut SegmentReader,
        local_offset: u64,
        method: u16,
        expected_crc: u32,
        compressed_size: u64,
        uncompressed_size: u64,
        password: Option<&[u8]>,
    ) -> PyResult<PayloadCheck> {
        let total = reader.total;
        if local_offset + 30 > total {
            return Ok(PayloadCheck::Corrupt);
        }
        let mut header = [0u8; 30];
        reader.read_exact_at(local_offset, &mut header)?;
        if &header[..4] != LFH_SIG {
            return Ok(PayloadCheck::Corrupt);
        }
        let flags = u16_le(&header, 6);
        let name_len = u16_le(&header, 26) as u64;
        let extra_len = u16_le(&header, 28) as u64;
        let mut data_start = local_offset + 30 + name_len + extra_len;
        let mut data_len = compressed_size;
        if data_start.saturating_add(data_len) > total {
            return Ok(PayloadCheck::Corrupt);
        }
        let mut decryptor = None;
        if let Some(password) = password {
            if data_len < 12 {
                return Ok(PayloadCheck::Corrupt);
            }
            let mut encryption_header = [0u8; 12];
            reader.read_exact_at(data_start, &mut encryption_header)?;
            // Same check byte 7-Zip uses: the local header's time with a data
            // descriptor, otherwise the high byte of the local header CRC.
            let check_byte = if flags & 0x0008 != 0 {
                (u16_le(&header, 10) >> 8) as u8
            } else {
                (u32_le(&header, 14) >> 24) as u8
            };
            let Some(state) = ZipCryptoDecryptor::new(password, &encryption_header, check_byte)
            else {
                return Ok(PayloadCheck::WrongPassword);
            };
            decryptor = Some(state);
            data_start += 12;
            data_len -= 12;
        }
        let valid = match method {
            0 => {
                if data_len != uncompressed_size {
                    return Ok(PayloadCheck::Corrupt);
                }
                let mut crc = crc32fast::Hasher::new();
                let mut fed = 0u64;
                while fed < data_len {
                    let take = ((data_len - fed) as usize).min(self.input.len());
                    self.read_payload(reader, data_start + fed, take, &mut decryptor)?;
                    crc.update(&self.input[..take]);
                    fed += take as u64;
                }
                crc.finalize() == expected_crc
            }
            8 => self.verify_deflate(
                reader,
                data_start,
                data_len,
                expected_crc,
                uncompressed_size,
                &mut decryptor,
            )?,
            _ => true,
        };
        Ok(if valid {
            PayloadCheck::Valid
        } else {
            PayloadCheck::Corrupt
        })
    }

    fn read_payload(
        &mut self,
        reader: &mut SegmentReader,
        offset: u64,
        take: usize,
        decryptor: &mut Option<ZipCryptoDecryptor>,
    ) -> PyResult<()> {
        reader.read_exact_at(offset, &mut self.input[..take])?;
        if let Some(decryptor) = decryptor {
            decryptor.decrypt(&mut self.input[..take]);
        }
        Ok(())
    }

    fn verify_deflate(
        &mut self,
        reader: &mut SegmentReader,
        start: u64,
        length: u64,
        expected_crc: u32,
        expected_size: u64,
        decryptor: &mut Option<ZipCryptoDecryptor>,
    ) -> PyResult<bool> {
        use flate2::{Decompress, FlushDecompress, Status};
        let mut decompressor = Decompress::new(false);
        let mut crc = crc32fast::Hasher::new();
        let mut fed = 0u64;
        let mut pending = 0..0;
        loop {
            if pending.is_empty() && fed < length {
                let take = ((length - fed) as usize).min(self.input.len());
                self.read_payload(reader, start + fed, take, decryptor)?;
                fed += take as u64;
                pending = 0..take;
            }
            let before_in = decompressor.total_in();
            let before_out = decompressor.total_out();
            let Ok(status) = decompressor.decompress(
                &self.input[pending.clone()],
                &mut self.output,
                FlushDecompress::None,
            ) else {
                return Ok(false);
            };
            let consumed = (decompressor.total_in() - before_in) as usize;
            let produced = (decompressor.total_out() - before_out) as usize;
            pending.start += consumed;
            if produced > 0 {
                crc.update(&self.output[..produced]);
            }
            if status == Status::StreamEnd {
                return Ok(decompressor.total_in() == length
                    && decompressor.total_out() == expected_size
                    && crc.finalize() == expected_crc);
            }
            if consumed == 0 && produced == 0 {
                // Input exhausted (or a stuck stream) before the deflate end marker.
                return Ok(false);
            }
        }
    }
}

fn looks_like_zip(reader: &mut SegmentReader) -> PyResult<bool> {
    if reader.total < 4 {
        return Ok(false);
    }
    let mut head = [0u8; 4];
    reader.read_exact_at(0, &mut head)?;
    Ok(&head[..] == LFH_SIG || &head[..] == EOCD_SIG)
}

fn u16_le(data: &[u8], offset: usize) -> u16 {
    let mut bytes = [0u8; 2];
    bytes.copy_from_slice(&data[offset..offset + 2]);
    u16::from_le_bytes(bytes)
}

fn u32_le(data: &[u8], offset: usize) -> u32 {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&data[offset..offset + 4]);
    u32::from_le_bytes(bytes)
}

fn optional_string(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<String>> {
    match dict.get_item(key)? {
        Some(value) if !value.is_none() => Ok(Some(value.extract::<String>()?)),
        _ => Ok(None),
    }
}

fn optional_u64(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<u64>> {
    match dict.get_item(key)? {
        Some(value) if !value.is_none() => Ok(Some(value.extract::<u64>()?)),
        _ => Ok(None),
    }
}

