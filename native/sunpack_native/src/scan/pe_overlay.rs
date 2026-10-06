use crate::analysis_native::inspect_zip_local_header;
use crate::io::read_fault::{read_exact_field, seek_field, FieldLocation, ReadFault};
use crate::io::reader::ManagedReader;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::borrow::Cow;

const OVERLAY_SCAN_WINDOW_BYTES: u64 = 65_536;
const PE_SIGNATURE: &[u8] = b"PE\x00\x00";
const SECTION_HEADER_SIZE: usize = 40;

const ARCHIVE_MAGICS: &[(&[u8], &str, &str)] = &[
    (b"7z\xbc\xaf\x27\x1c", "7z", ".7z"),
    (b"Rar!\x1a\x07\x01\x00", "rar", ".rar"),
    (b"Rar!\x1a\x07\x00", "rar", ".rar"),
    (b"PK\x03\x04", "zip", ".zip"),
    (b"\x1f\x8b\x08", "gzip", ".gz"),
    (b"BZh", "bzip2", ".bz2"),
    (b"\xfd7zXZ\x00", "xz", ".xz"),
    (b"\x28\xb5\x2f\xfd", "zstd", ".zst"),
    (crate::formats::lz4::MAGIC, "lz4", ".lz4"),
    (crate::formats::lz4::LEGACY, "lz4", ".lz4"),
];

/// PE structure facts only; SFX classification belongs to Relations.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum PeState {
    #[default]
    None,
    Candidate,
    Confirmed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PeFacts {
    pub(crate) image_end: u64,
    pe_header_offset: u64,
    section_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PeProbe {
    NotPe,
    NeedMore,
    Confirmed(PeFacts),
}

impl PeProbe {
    pub(crate) fn state(self) -> PeState {
        match self {
            Self::NotPe => PeState::None,
            Self::NeedMore => PeState::Candidate,
            Self::Confirmed(_) => PeState::Confirmed,
        }
    }

    pub(crate) fn image_end(self) -> Option<u64> {
        match self {
            Self::Confirmed(facts) => Some(facts.image_end),
            _ => None,
        }
    }
}

/// The only PE parser. Prefix and I/O callers supply bytes to the same proof.
/// Missing prefix bytes mean Candidate; out-of-file structure means NotPe.
fn inspect_pe_headers<'a, E>(
    actual_size: u64,
    mut read: impl FnMut(u64, usize) -> Result<Option<Cow<'a, [u8]>>, E>,
) -> Result<PeProbe, E> {
    macro_rules! field {
        ($offset:expr, $len:expr) => {{
            let offset: u64 = $offset;
            let len: usize = $len;
            if offset
                .checked_add(len as u64)
                .is_none_or(|end| end > actual_size)
            {
                return Ok(PeProbe::NotPe);
            }
            let Some(bytes) = read(offset, len)? else {
                return Ok(PeProbe::NeedMore);
            };
            bytes
        }};
    }
    let magic = field!(0, 2);
    if magic.as_ref() != b"MZ" {
        return Ok(PeProbe::NotPe);
    }
    let dos = field!(0, 64);
    let pe_header_offset = u32_le(&dos, 0x3c) as u64;
    if pe_header_offset < 64 {
        return Ok(PeProbe::NotPe);
    }
    let signature = field!(pe_header_offset, 4);
    if signature.as_ref() != PE_SIGNATURE {
        return Ok(PeProbe::NotPe);
    }
    let coff = field!(pe_header_offset, 24);
    if u16_le(&coff, 4) == 0 {
        return Ok(PeProbe::NotPe);
    }
    let section_count = u16_le(&coff, 6) as usize;
    let optional_size = u16_le(&coff, 20) as usize;
    if section_count == 0 || optional_size < 64 {
        return Ok(PeProbe::NotPe);
    }
    let optional_offset = pe_header_offset + 24;
    let optional = field!(optional_offset, optional_size);
    let (fixed_size, directory_count_offset) = match u16_le(&optional, 0) {
        0x10b => (96, 92),
        0x20b => (112, 108),
        _ => return Ok(PeProbe::NotPe),
    };
    if optional_size < fixed_size
        || u32_le(&optional, directory_count_offset) as usize > (optional_size - fixed_size) / 8
    {
        return Ok(PeProbe::NotPe);
    }
    let table_offset = optional_offset + optional_size as u64;
    let table_size = section_count * SECTION_HEADER_SIZE;
    let sections = field!(table_offset, table_size);
    let table_end = table_offset + table_size as u64;
    let headers_size = u32_le(&optional, 60) as u64;
    if headers_size < table_end || headers_size > actual_size {
        return Ok(PeProbe::NotPe);
    }
    let mut image_end = headers_size;
    for section in sections.chunks_exact(SECTION_HEADER_SIZE) {
        let raw_size = u32_le(section, 16) as u64;
        let raw_pointer = u32_le(section, 20) as u64;
        if raw_size != 0 {
            let end = raw_pointer + raw_size;
            if raw_pointer < headers_size || end > actual_size {
                return Ok(PeProbe::NotPe);
            }
            image_end = image_end.max(end);
        }
    }
    Ok(PeProbe::Confirmed(PeFacts {
        image_end,
        pe_header_offset,
        section_count: section_count as u64,
    }))
}

/// Zero I/O: filesystem must only use the bounded prefix it already owns.
pub(crate) fn probe_pe_prefix(prefix: &[u8], actual_size: u64) -> PeProbe {
    inspect_pe_headers::<std::convert::Infallible>(actual_size, |offset, len| {
        Ok(usize::try_from(offset).ok().and_then(|start| {
            start
                .checked_add(len)
                .and_then(|end| prefix.get(start..end))
                .map(Cow::Borrowed)
        }))
    })
    .unwrap()
}

fn inspect_pe_image_reader(
    reader: &ManagedReader,
    actual_size: u64,
    prefix: &[u8],
) -> Result<PeProbe, ReadFault> {
    let mut file = reader.cursor();
    inspect_pe_headers(actual_size, |offset, len| {
        if let Ok(start) = usize::try_from(offset) {
            if let Some(bytes) = start
                .checked_add(len)
                .and_then(|end| prefix.get(start..end))
            {
                return Ok(Some(Cow::Borrowed(bytes)));
            }
        }
        let mut bytes = vec![0; len];
        seek_field(
            &mut file,
            offset,
            actual_size,
            "pe.image_headers",
            FieldLocation::Head,
        )?;
        read_exact_field(
            &mut file,
            &mut bytes,
            actual_size,
            "pe.image_headers",
            FieldLocation::Head,
        )?;
        Ok(Some(Cow::Owned(bytes)))
    })
}

pub(crate) fn inspect_pe_image_native(path: &str) -> std::io::Result<PeProbe> {
    let reader = ManagedReader::open(path)?;
    inspect_pe_image_reader(&reader, reader.len(), &[])
        .map_err(|fault| std::io::Error::new(fault.io_kind, fault))
}

/// Python fallback consumes only PE identity; production facts stay in Rust.
#[pyfunction]
pub(crate) fn inspect_pe_image(py: Python<'_>, path: &str) -> PyResult<bool> {
    Ok(matches!(
        py.detach(|| inspect_pe_image_native(path))?,
        PeProbe::Confirmed(_)
    ))
}

#[derive(Default)]
pub(crate) struct PeOverlayStructure {
    pub(crate) is_pe: bool,
    pub(crate) has_overlay: bool,
    pub(crate) archive_like: bool,
    pub(crate) pe_header_offset: u64,
    pub(crate) section_count: u64,
    pub(crate) overlay_offset: u64,
    pub(crate) overlay_size: u64,
    pub(crate) archive_offset: u64,
    pub(crate) offset_delta_from_overlay: u64,
    pub(crate) format: &'static str,
    detected_ext: &'static str,
    confidence: &'static str,
    error: &'static str,
    evidence: Vec<&'static str>,
    read_fault: Option<ReadFault>,
}

impl PeOverlayStructure {
    fn failed(error: &'static str) -> Self {
        Self {
            error,
            confidence: "none",
            ..Default::default()
        }
    }
}

pub(crate) fn inspect_pe_overlay_native(
    path: &str,
    file_size: Option<i64>,
    magic_bytes: Option<&[u8]>,
) -> PeOverlayStructure {
    let Ok(reader) = ManagedReader::open(path) else {
        return PeOverlayStructure::failed("os_error");
    };
    let actual_size = match file_size {
        Some(value) if value >= 0 => value as u64,
        _ => reader.len(),
    };
    let facts = match inspect_pe_image_reader(&reader, actual_size, magic_bytes.unwrap_or(&[])) {
        Ok(PeProbe::Confirmed(facts)) => facts,
        Ok(_) => return PeOverlayStructure::failed("pe_structure_not_confirmed"),
        Err(fault) => {
            let mut out = PeOverlayStructure::failed("pe_header_read_failed");
            out.read_fault = Some(fault);
            return out;
        }
    };
    let mut result = inspect_pe_overlay_reader(&reader, actual_size, facts.image_end);
    result.pe_header_offset = facts.pe_header_offset;
    result.section_count = facts.section_count;
    result
}

/// Relations consumes a confirmed image boundary without parsing headers again.
pub(crate) fn inspect_pe_overlay_from_image_end(
    path: &str,
    file_size: u64,
    image_end: u64,
) -> PeOverlayStructure {
    let Ok(reader) = ManagedReader::open(path) else {
        return PeOverlayStructure::failed("os_error");
    };
    inspect_pe_overlay_reader(&reader, file_size, image_end)
}

fn inspect_pe_overlay_reader(
    reader: &ManagedReader,
    actual_size: u64,
    pe_end: u64,
) -> PeOverlayStructure {
    let mut result = PeOverlayStructure::default();
    result.is_pe = true;
    result.overlay_offset = pe_end;
    result.overlay_size = actual_size.saturating_sub(pe_end);
    result.evidence.push("pe:valid_headers");

    if pe_end == 0 || pe_end >= actual_size {
        result.error = "overlay_not_found";
        return result;
    }
    result.has_overlay = true;
    result.evidence.push("pe:overlay_present");

    let sample_size = OVERLAY_SCAN_WINDOW_BYTES.min(actual_size - pe_end);
    // Keep reusable PE header blocks; the overlay search sample is one-shot.
    let mut file = reader.probe_reader().cursor();
    let mut sample = vec![0; sample_size as usize];
    if let Err(fault) = seek_field(
        &mut file,
        pe_end,
        actual_size,
        "pe.overlay.sample",
        FieldLocation::Body,
    )
    .and_then(|_| {
        read_exact_field(
            &mut file,
            &mut sample,
            actual_size,
            "pe.overlay.sample",
            FieldLocation::Body,
        )
    }) {
        result.error = "overlay_sample_read_failed";
        result.read_fault = Some(fault);
        return result;
    }

    let Some((archive_format, detected_ext, relative_offset)) = find_archive_magic(&sample) else {
        result.error = "overlay_archive_magic_not_found";
        return result;
    };
    let archive_offset = pe_end + relative_offset as u64;
    result.archive_like = true;
    result.error = "";
    result.archive_offset = archive_offset;
    result.offset_delta_from_overlay = relative_offset as u64;
    result.format = archive_format;
    result.detected_ext = detected_ext;
    result.confidence = if relative_offset == 0 {
        "strong"
    } else {
        "medium"
    };
    result.evidence.push(if relative_offset == 0 {
        "overlay:archive_magic_at_start"
    } else {
        "overlay:archive_magic_near_start"
    });

    result
}

#[pyfunction]
#[pyo3(signature = (path, file_size=None, magic_bytes=None))]
pub(crate) fn inspect_pe_overlay_structure(
    py: Python<'_>,
    path: &str,
    file_size: Option<i64>,
    magic_bytes: Option<&[u8]>,
) -> PyResult<Py<PyDict>> {
    let facts = py.detach(|| inspect_pe_overlay_native(path, file_size, magic_bytes));
    let result = empty_result(py, facts.error)?;
    result.set_item("is_pe", facts.is_pe)?;
    result.set_item("has_overlay", facts.has_overlay)?;
    result.set_item("archive_like", facts.archive_like)?;
    result.set_item("pe_header_offset", facts.pe_header_offset)?;
    result.set_item("section_count", facts.section_count)?;
    result.set_item("overlay_offset", facts.overlay_offset)?;
    result.set_item("overlay_size", facts.overlay_size)?;
    result.set_item("archive_offset", facts.archive_offset)?;
    result.set_item("offset_delta_from_overlay", facts.offset_delta_from_overlay)?;
    result.set_item("format", facts.format)?;
    result.set_item("detected_ext", facts.detected_ext)?;
    result.set_item("confidence", facts.confidence)?;
    let evidence = PyList::new(py, facts.evidence)?;
    result.set_item("evidence", &evidence)?;
    if let Some(fault) = facts.read_fault {
        write_read_fault(&result, &fault)?;
    }
    if facts.archive_like && facts.detected_ext == ".zip" {
        let header = inspect_zip_local_header(py, path, facts.archive_offset as i64)?;
        let plausible = header
            .bind(py)
            .get_item("plausible")?
            .and_then(|v| v.extract::<bool>().ok())
            .unwrap_or(false);
        result.set_item("zip_local_header", header)?;
        evidence.append(if plausible {
            "zip_local_header:plausible"
        } else {
            "zip_local_header:implausible"
        })?;
        if !plausible {
            result.set_item("confidence", "medium")?;
        }
    }
    Ok(result.unbind())
}

fn write_read_fault(result: &Bound<'_, PyDict>, fault: &ReadFault) -> PyResult<()> {
    fault.write_python(result)?;
    let mut flags = vec!["read_error"];
    if fault.code == "unexpected_eof" {
        flags.push("input_truncated");
    }
    if fault.possible_missing_volume() {
        flags.push("missing_volume");
    }
    result.set_item("damage_flags", PyList::new(result.py(), flags)?)
}

fn empty_result<'py>(py: Python<'py>, error: &str) -> PyResult<Bound<'py, PyDict>> {
    let result = PyDict::new(py);
    result.set_item("is_pe", false)?;
    result.set_item("has_overlay", false)?;
    result.set_item("archive_like", false)?;
    result.set_item("error", error)?;
    for key in [
        "pe_header_offset",
        "section_count",
        "overlay_offset",
        "overlay_size",
        "archive_offset",
        "offset_delta_from_overlay",
    ] {
        result.set_item(key, 0)?;
    }
    result.set_item("format", "")?;
    result.set_item("detected_ext", "")?;
    result.set_item("confidence", "none")?;
    result.set_item("evidence", PyList::empty(py))?;
    result.set_item("zip_local_header", PyDict::new(py))?;
    Ok(result)
}

fn find_archive_magic(sample: &[u8]) -> Option<(&'static str, &'static str, usize)> {
    let mut best: Option<(&'static str, &'static str, usize)> = None;
    for (magic, archive_format, detected_ext) in ARCHIVE_MAGICS {
        let Some(index) = find_subslice(sample, magic) else {
            continue;
        };
        if best.is_none_or(|(_, _, best_index)| index < best_index) {
            best = Some((archive_format, detected_ext, index));
        }
    }
    if let Some(offset) = memchr::memmem::find_iter(sample, b"\x2a\x4d\x18")
        .filter_map(|offset| offset.checked_sub(1))
        .find(|offset| (0x50..=0x5f).contains(&sample[*offset]))
    {
        if best.is_none_or(|(_, _, best_index)| offset < best_index) {
            best = Some(("lz4", ".lz4", offset));
        }
    }
    best
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn u16_le(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn u32_le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(pe_offset: usize, pe64: bool) -> Vec<u8> {
        let optional_size = if pe64 { 240 } else { 224 };
        let optional = pe_offset + 24;
        let section = optional + optional_size;
        let headers_size = (section + 40 + 511) & !511;
        let mut bytes = vec![0; headers_size + 32];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&(pe_offset as u32).to_le_bytes());
        bytes[pe_offset..pe_offset + 4].copy_from_slice(PE_SIGNATURE);
        bytes[pe_offset + 4..pe_offset + 6].copy_from_slice(&0x14cu16.to_le_bytes());
        bytes[pe_offset + 6..pe_offset + 8].copy_from_slice(&1u16.to_le_bytes());
        bytes[pe_offset + 20..pe_offset + 22]
            .copy_from_slice(&(optional_size as u16).to_le_bytes());
        bytes[optional..optional + 2]
            .copy_from_slice(&(if pe64 { 0x20bu16 } else { 0x10b }).to_le_bytes());
        bytes[optional + 60..optional + 64].copy_from_slice(&(headers_size as u32).to_le_bytes());
        bytes[section + 16..section + 20].copy_from_slice(&32u32.to_le_bytes());
        bytes[section + 20..section + 24].copy_from_slice(&(headers_size as u32).to_le_bytes());
        bytes
    }

    #[test]
    fn prefix_confirms_pe32_and_pe64_without_io() {
        for pe64 in [false, true] {
            let bytes = image(0x80, pe64);
            let probe = probe_pe_prefix(&bytes[..512], bytes.len() as u64);
            assert_eq!(probe.state(), PeState::Confirmed);
            assert_eq!(probe.image_end(), Some(bytes.len() as u64));
        }
    }

    #[test]
    fn missing_buffer_and_missing_file_structure_are_distinct() {
        for pe_offset in [0x180, 0x800] {
            let bytes = image(pe_offset, false);
            assert_eq!(
                probe_pe_prefix(&bytes[..512], bytes.len() as u64),
                PeProbe::NeedMore
            );
            assert_eq!(probe_pe_prefix(&bytes[..512], 512), PeProbe::NotPe);
            let path = crate::test_support::temp_file("pe_delayed_header", &bytes);
            assert_eq!(
                inspect_pe_image_native(path.to_str().unwrap()).unwrap(),
                probe_pe_prefix(&bytes, bytes.len() as u64)
            );
            std::fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn malformed_headers_and_raw_ranges_do_not_confirm_pe() {
        let original = image(0x80, false);
        for (offset, replacement) in [
            (0x3c, vec![0xff; 4]),
            (0x80, vec![0]),
            (0x84, vec![0; 2]),
            (0x86, vec![0; 2]),
            (0x94, vec![0; 2]),
            (0x98, vec![0; 2]),
            (0xd4, vec![0; 4]),
            (0xf4, vec![0xff; 4]),
            (0x188, vec![0xff; 4]),
            (0x18c, vec![0; 4]),
        ] {
            let mut bytes = original.clone();
            bytes[offset..offset + replacement.len()].copy_from_slice(&replacement);
            assert_eq!(
                probe_pe_prefix(&bytes, bytes.len() as u64),
                PeProbe::NotPe,
                "offset {offset:x}"
            );
        }
        assert_eq!(probe_pe_prefix(b"MZ", 2), PeProbe::NotPe);
        assert_eq!(probe_pe_prefix(b"ordinary", 8), PeProbe::NotPe);
    }

    #[test]
    fn full_detector_reads_only_header_regions_even_with_a_distant_pe_header() {
        let bytes = image(0x800, true);
        let mut ranges = Vec::new();
        let result =
            inspect_pe_headers::<std::convert::Infallible>(bytes.len() as u64, |offset, len| {
                ranges.push((offset, len));
                Ok(Some(Cow::Borrowed(
                    &bytes[offset as usize..offset as usize + len],
                )))
            })
            .unwrap();
        assert_eq!(result.image_end(), Some(bytes.len() as u64));
        assert!(ranges.iter().all(|(_, len)| *len <= 240));
        assert!(ranges
            .iter()
            .all(|(offset, len)| *offset != 0 || *len <= 64));
    }

    #[test]
    fn filesystem_probe_keeps_pe_facts_without_sfx_or_extra_reads() {
        for offset in [0x80, 0x800] {
            let bytes = image(offset, false);
            let anchor = crate::analysis_native::volume_anchor::probe_volume_anchor_from_head(
                "no_such_file.jpg",
                bytes.len() as u64,
                &bytes,
            );
            assert_eq!(anchor.bytes_read, 512);
            assert!(!anchor.sfx);
            assert!(anchor.format.is_empty());
            assert_eq!(
                anchor.pe_state,
                if offset == 0x80 {
                    PeState::Confirmed
                } else {
                    PeState::Candidate
                }
            );
            assert_eq!(
                anchor.pe_image_end,
                (offset == 0x80).then_some(bytes.len() as u64)
            );
        }
    }
}
