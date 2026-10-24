use crate::formats::tar::{self, TarState};
use crate::io::resource_lifecycle::TrackedFile;
use crate::password::zip::{zip_password_bytes, ZipCryptoDecryptor};
use crate::verification::archive_manifest::{ManifestEntry, NativeArchiveManifest};
use crate::verification::paths::OutputPathAllocator;
use encoding_rs::{BIG5, GBK, SHIFT_JIS, UTF_8};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
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

    fn read_exact_at(&mut self, offset: u64, output: &mut [u8]) -> std::io::Result<()> {
        let end = offset
            .checked_add(output.len() as u64)
            .ok_or_else(|| std::io::Error::other("archive state logical read offset overflow"))?;
        if end > self.total {
            return Err(std::io::Error::other(
                "archive state logical read exceeds input",
            ));
        }
        let mut cursor = offset;
        let mut written = 0usize;
        while written < output.len() {
            let (index, within) = self.locate(cursor).ok_or_else(|| {
                std::io::Error::other("archive state logical read segment is missing")
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
                        std::io::Error::other("archive state source file is unavailable")
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

    fn read_vec_at(&mut self, offset: u64, len: usize) -> std::io::Result<Vec<u8>> {
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
    let mut output_paths = OutputPathAllocator::default();
    let mut state = TarState::default();
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

        let retain = entries.len() < max_items;
        let total = reader.total;
        let record = match state.advance(&header, offset, total, retain, &mut |start, size| {
            reader.read_vec_at(start, size)
        }) {
            Ok(record) => record,
            Err(fault) => {
                if !matches!(
                    fault.kind(),
                    std::io::ErrorKind::InvalidData | std::io::ErrorKind::UnexpectedEof
                ) {
                    return Err(fault.into());
                }
                checksum_error =
                    tar::number(&header[148..156]).is_some_and(|n| n != tar::checksum(&header));
                error = Some(fault.to_string());
                break;
            }
        };
        item_count += 1;
        offset = record.next;
        if let Some(member) = record.member {
            // Once retention is full, only aggregate; no later entry uses names.
            let projected = member
                .path
                .as_deref()
                .map(|path| output_paths.project(path, member.is_directory));
            if member.is_file {
                file_count += 1;
                total_unpacked_size = total_unpacked_size.saturating_add(member.size);
                if let (Some(path), Some(projected)) = (member.path, projected) {
                    let raw_path = (projected != path).then_some(path);
                    entries.push(ManifestEntry {
                        path: projected,
                        raw_path,
                        size: member.size,
                        crc32: None,
                    });
                }
            }
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
        verified_item_count: if !damaged { item_count } else { 0 },
        failure_kind: if damaged { "corrupted_data" } else { "" }.to_string(),
        entries: Arc::new(entries),
    })
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
        reader.read_vec_at(
            cd_start,
            (expected_end.saturating_add(46).min(total) - cd_start) as usize,
        )?
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
    let mut output_paths = OutputPathAllocator::default();
    while cursor + 46 <= total && cursor < expected_end {
        let at = (cursor - cd_start) as usize;
        if &directory[at..at + 4] != CD_SIG {
            damaged = true;
            message = "Archive state ZIP central directory stopped before expected end".to_string();
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
        let entry_password = if flags & 0x1 != 0 {
            password.as_deref()
        } else {
            None
        };
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
        let is_directory = name.ends_with('/');
        let projected = output_paths.project(&name, is_directory);
        if !is_directory {
            file_count += 1;
            total_unpacked_size = total_unpacked_size.saturating_add(uncompressed_size);
            if entries.len() < max_items {
                entries.push(ManifestEntry {
                    raw_path: (projected != name).then_some(name),
                    path: projected,
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
