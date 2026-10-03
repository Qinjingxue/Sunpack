use crate::analysis_native::inspect_zip_local_header;
use crate::io::read_fault::{read_exact_field, seek_field, FieldLocation, ReadFault};
use crate::io::reader::ManagedReader;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

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
];

/// Validate the bounded PE header region already read by a caller.
///
/// This is deliberately only the header/section-table proof.  It does not
/// inspect an overlay or look for an embedded archive, so relation handling
/// can distinguish a real launcher from an arbitrary file beginning with
/// `MZ` without introducing another binary scan path.
pub(crate) fn pe_headers_plausible(prefix: &[u8], actual_size: u64) -> bool {
    if prefix.len() < 64 || !prefix.starts_with(b"MZ") {
        return false;
    }
    let pe_header_offset = u32_le(prefix, 0x3C) as usize;
    let Some(coff_end) = pe_header_offset.checked_add(24) else {
        return false;
    };
    if pe_header_offset < 64
        || coff_end as u64 > actual_size
        || coff_end > prefix.len()
        || prefix.get(pe_header_offset..pe_header_offset + PE_SIGNATURE.len()) != Some(PE_SIGNATURE)
    {
        return false;
    }

    let section_count = u16_le(prefix, pe_header_offset + 6) as usize;
    let optional_header_size = u16_le(prefix, pe_header_offset + 20) as usize;
    let Some(section_table_offset) = coff_end.checked_add(optional_header_size) else {
        return false;
    };
    let Some(section_table_size) = section_count.checked_mul(SECTION_HEADER_SIZE) else {
        return false;
    };
    let Some(section_table_end) = section_table_offset.checked_add(section_table_size) else {
        return false;
    };
    section_count > 0
        && section_table_end as u64 <= actual_size
        && section_table_end <= prefix.len()
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
    let mut file = reader.cursor();
    let actual_size = match file_size {
        Some(value) if value >= 0 => value as u64,
        _ => reader.len(),
    };

    let mut prefix = magic_bytes.unwrap_or(&[]).to_vec();
    if prefix.len() < 64 {
        prefix.resize(actual_size.min(64) as usize, 0);
        if let Err(fault) = seek_field(
            &mut file,
            0,
            actual_size,
            "pe.dos_header",
            FieldLocation::Head,
        )
        .and_then(|_| {
            read_exact_field(
                &mut file,
                &mut prefix,
                actual_size,
                "pe.dos_header",
                FieldLocation::Head,
            )
        }) {
            let mut out = PeOverlayStructure::failed("dos_header_read_failed");
            out.read_fault = Some(fault);
            return out;
        }
    }
    if prefix.len() < 64 || !prefix.starts_with(b"MZ") {
        return PeOverlayStructure::failed("mz_magic_not_found");
    }

    let pe_header_offset = u32_le(&prefix, 0x3C) as u64;
    if pe_header_offset < 64 || pe_header_offset + 24 > actual_size {
        return PeOverlayStructure::failed("pe_header_offset_out_of_range");
    }

    let mut pe_header = [0u8; 24];
    if let Err(fault) = seek_field(
        &mut file,
        pe_header_offset,
        actual_size,
        "pe.coff_header",
        FieldLocation::Head,
    )
    .and_then(|_| {
        read_exact_field(
            &mut file,
            &mut pe_header,
            actual_size,
            "pe.coff_header",
            FieldLocation::Head,
        )
    }) {
        let mut out = PeOverlayStructure::failed("pe_header_read_failed");
        out.read_fault = Some(fault);
        return out;
    }
    if &pe_header[0..4] != PE_SIGNATURE {
        return PeOverlayStructure::failed("pe_signature_not_found");
    }

    let section_count = u16_le(&pe_header, 6) as u64;
    let optional_header_size = u16_le(&pe_header, 20) as u64;
    let section_table_offset = pe_header_offset + 24 + optional_header_size;
    let section_table_size = section_count * SECTION_HEADER_SIZE as u64;
    if section_count == 0 || section_table_offset + section_table_size > actual_size {
        return PeOverlayStructure::failed("section_table_out_of_range");
    }

    let mut section_table = vec![0; section_table_size as usize];
    if let Err(fault) = seek_field(
        &mut file,
        section_table_offset,
        actual_size,
        "pe.section_table",
        FieldLocation::Head,
    )
    .and_then(|_| {
        read_exact_field(
            &mut file,
            &mut section_table,
            actual_size,
            "pe.section_table",
            FieldLocation::Head,
        )
    }) {
        let mut out = PeOverlayStructure::failed("section_table_read_failed");
        out.read_fault = Some(fault);
        return out;
    }

    let mut pe_end = 0u64;
    for index in 0..section_count as usize {
        let start = index * SECTION_HEADER_SIZE;
        let section = &section_table[start..start + SECTION_HEADER_SIZE];
        let raw_size = u32_le(section, 16) as u64;
        let raw_pointer = u32_le(section, 20) as u64;
        if raw_pointer != 0 && raw_size != 0 {
            pe_end = pe_end.max(raw_pointer + raw_size);
        }
    }

    let mut result = PeOverlayStructure::default();
    result.is_pe = true;
    result.pe_header_offset = pe_header_offset;
    result.section_count = section_count;
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
