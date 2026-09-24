use std::io::Cursor;
use crate::scan::compression_stream::{
    validate_bzip2_structure, validate_gzip_structure, validate_xz_structure_exact,
    validate_zstd_structure, StructureValidation,
};

const EAGER_STREAM_INTEGRITY_MAX_BYTES: u64 = 4 * 1024 * 1024;
const STREAM_STRUCTURE_DECODE_MAX_BYTES: u64 = 8 * 1024 * 1024;

const GZIP_FIELDS: &[&str] = &[
    "member.header.magic",
    "member.header.compression_method",
    "member.header.flags",
    "member.header.mtime_xfl_os",
    "member.header.extra_length",
    "member.header.extra",
    "member.header.name",
    "member.header.comment",
    "member.header.crc16",
    "member.deflate.blocks",
    "member.deflate.final_block",
    "member.decoded_content",
    "member.trailer.crc32",
    "member.trailer.isize",
    "member.boundary",
    "member.next_member",
    "archive.trailing_data",
];
const BZIP2_FIELDS: &[&str] = &[
    "stream.magic",
    "stream.block_size_100k",
    "block.marker",
    "block.crc32",
    "block.randomized",
    "block.orig_ptr",
    "block.huffman_tables",
    "block.encoded_data",
    "block.decoded_content",
    "block.sequence",
    "stream.end_marker",
    "stream.combined_crc32",
    "archive.trailing_data",
];
const XZ_FIELDS: &[&str] = &[
    "stream.header.magic",
    "stream.header.flags",
    "stream.header.crc32",
    "block.header.size",
    "block.header.flags",
    "block.header.compressed_size",
    "block.header.uncompressed_size",
    "block.header.filters",
    "block.header.crc32",
    "block.compressed_data",
    "block.uncompressed_data",
    "block.padding",
    "block.check",
    "block.sequence",
    "index.indicator",
    "index.record_count",
    "index.records.unpadded_size",
    "index.records.uncompressed_size",
    "index.padding",
    "index.crc32",
    "stream.footer.crc32",
    "stream.footer.backward_size",
    "stream.footer.flags",
    "stream.footer.magic",
    "stream.padding",
    "archive.stream_sequence",
    "archive.trailing_data",
];
const ZSTD_FIELDS: &[&str] = &[
    "frame.magic",
    "frame.header.descriptor",
    "frame.header.content_size_flag",
    "frame.header.single_segment_flag",
    "frame.header.checksum_flag",
    "frame.header.dictionary_id_flag",
    "frame.header.window_descriptor",
    "frame.header.dictionary_id",
    "frame.header.content_size",
    "block.header.last_block",
    "block.header.type",
    "block.header.size",
    "block.content",
    "block.literals",
    "block.sequences",
    "block.previous_window",
    "block.previous_entropy_tables",
    "frame.decoded_content",
    "frame.content_checksum",
    "frame.sequence",
    "skippable.magic",
    "skippable.frame_size",
    "skippable.user_data",
    "archive.trailing_data",
];

#[derive(Clone, Copy)]
enum StructuralStreamKind {
    Gzip,
    Bzip2,
    Xz,
    Zstd,
}


const IDENTITY_PROBE_MAX_BYTES: u64 = 64 * 1024;

fn compression_identity_result(
    py: Python<'_>,
    format: &str,
    ext: &str,
    magic_matched: bool,
    file_size: u64,
    bytes_read: u64,
    plausible: bool,
    error: &str,
    evidence: &[&str],
) -> PyResult<Py<PyDict>> {
    let d = compression_base(py, format, ext, magic_matched)?;
    d.set_item("plausible", plausible)?;
    d.set_item("confidence", if plausible { "strong" } else { "none" })?;
    d.set_item("identity_strong", plausible)?;
    d.set_item("validation_scope", "format_identity")?;
    d.set_item("validation_cost", "bounded")?;
    d.set_item("identity_bytes_read", bytes_read)?;
    d.set_item("file_size", file_size)?;
    d.set_item("structure_status", "incomplete")?;
    d.set_item("structure_validation_complete", false)?;
    d.set_item("boundary_exact", false)?;
    d.set_item("integrity_status", "deferred")?;
    d.set_item("integrity_validation_complete", false)?;
    d.set_item("segment_end", Option::<u64>::None)?;
    d.set_item("damage_flags", PyList::empty(py))?;
    d.set_item("error", error)?;
    d.set_item("evidence", PyList::new(py, evidence)?)?;
    Ok(d.unbind())
}

fn inspect_compression_stream_identity_impl(
    py: Python<'_>,
    path: &str,
) -> PyResult<Py<PyDict>> {
    let reader = match ManagedReader::open(path) {
        Ok(value) => value,
        Err(_) => {
            return compression_identity_result(
                py, "", "", false, 0, 0, false, "os_error", &[],
            )
        }
    };
    let file_size = reader.len();
    let read_size = file_size.min(32) as usize;
    let mut data = match reader.read_at(0, read_size) {
        Ok(value) => value,
        Err(_) => {
            return compression_identity_result(
                py, "", "", false, file_size, 0, false, "os_error", &[],
            )
        }
    };

    if data.starts_with(b"\x1f\x8b")
        && data.get(3).is_some_and(|flags| flags & 0x1e != 0)
        && file_size > data.len() as u64
    {
        let expanded = file_size.min(IDENTITY_PROBE_MAX_BYTES) as usize;
        data = match reader.read_at(0, expanded) {
            Ok(value) => value,
            Err(_) => {
                return compression_identity_result(
                    py, "gzip", ".gz", true, file_size, data.len() as u64,
                    false, "gzip_header_read_failed", &["gzip:magic"],
                )
            }
        };
    }
    let base_bytes_read = data.len() as u64;

    if data.starts_with(b"\x1f\x8b") {
        let (payload_start, flags) = match parse_gzip_header(&data, 0) {
            Ok(value) => value,
            Err(error) => {
                return compression_identity_result(
                    py,
                    "gzip",
                    ".gz",
                    true,
                    file_size,
                    base_bytes_read,
                    false,
                    error,
                    &["gzip:magic"],
                )
            }
        };
        let mut evidence = vec!["gzip:magic", "gzip:header"];
        if flags & 0x02 != 0 {
            let Some(crc_offset) = payload_start.checked_sub(2) else {
                return compression_identity_result(
                    py, "gzip", ".gz", true, file_size, base_bytes_read, false,
                    "gzip_header_crc_missing", &["gzip:magic"],
                );
            };
            let Some(stored_bytes) = data.get(crc_offset..crc_offset + 2) else {
                return compression_identity_result(
                    py, "gzip", ".gz", true, file_size, base_bytes_read, false,
                    "gzip_header_crc_missing", &["gzip:magic"],
                );
            };
            let stored = u16::from_le_bytes([stored_bytes[0], stored_bytes[1]]);
            let computed = (crc32(&data[..crc_offset]) & 0xffff) as u16;
            if stored != computed {
                return compression_identity_result(
                    py, "gzip", ".gz", true, file_size, base_bytes_read, false,
                    "gzip_header_crc_bad", &["gzip:magic", "gzip:header"],
                );
            }
            evidence.push("gzip:header_crc16");
        }
        if payload_start as u64 >= file_size {
            return compression_identity_result(
                py, "gzip", ".gz", true, file_size, base_bytes_read, false,
                "gzip_deflate_missing", &evidence,
            );
        }
        let block_probe = reader
            .read_at(
                payload_start as u64,
                file_size.saturating_sub(payload_start as u64).min(8) as usize,
            )
            .unwrap_or_default();
        if block_probe.is_empty() {
            return compression_identity_result(
                py, "gzip", ".gz", true, file_size, base_bytes_read, false,
                "gzip_deflate_missing", &evidence,
            );
        }
        let block_type = (block_probe[0] >> 1) & 0x03;
        if block_type == 3 {
            return compression_identity_result(
                py, "gzip", ".gz", true, file_size,
                base_bytes_read + block_probe.len() as u64, false,
                "gzip_deflate_reserved_block_type", &evidence,
            );
        }
        if block_type == 0 {
            if block_probe.len() < 5 {
                return compression_identity_result(
                    py, "gzip", ".gz", true, file_size,
                    base_bytes_read + block_probe.len() as u64, false,
                    "gzip_stored_block_header_short", &evidence,
                );
            }
            let len = u16::from_le_bytes([block_probe[1], block_probe[2]]);
            let nlen = u16::from_le_bytes([block_probe[3], block_probe[4]]);
            if len ^ nlen != 0xffff {
                return compression_identity_result(
                    py, "gzip", ".gz", true, file_size,
                    base_bytes_read + block_probe.len() as u64, false,
                    "gzip_stored_block_length_mismatch", &evidence,
                );
            }
            evidence.push("gzip:deflate_stored_length");
        } else if block_type == 2 {
            if block_probe.len() < 3 {
                return compression_identity_result(
                    py, "gzip", ".gz", true, file_size,
                    base_bytes_read + block_probe.len() as u64, false,
                    "gzip_dynamic_block_header_short", &evidence,
                );
            }
            let bits = u32::from_le_bytes([
                block_probe[0],
                block_probe[1],
                block_probe[2],
                *block_probe.get(3).unwrap_or(&0),
            ]) >> 3;
            if bits & 0x1f > 29 {
                return compression_identity_result(
                    py, "gzip", ".gz", true, file_size,
                    base_bytes_read + block_probe.len() as u64, false,
                    "gzip_dynamic_hlit_invalid", &evidence,
                );
            }
            evidence.push("gzip:deflate_dynamic_header");
        } else {
            evidence.push("gzip:deflate_fixed_header");
        }
        return compression_identity_result(
            py,
            "gzip",
            ".gz",
            true,
            file_size,
            base_bytes_read + block_probe.len() as u64,
            true,
            "",
            &evidence,
        );
    }

    if data.starts_with(b"BZh") {
        if data.len() < 14 || !matches!(data[3], b'1'..=b'9') {
            return compression_identity_result(
                py, "bzip2", ".bz2", true, file_size, base_bytes_read, false,
                "bzip2_header_invalid", &["bzip2:magic"],
            );
        }
        const BLOCK_MAGIC: &[u8; 6] = b"\x31\x41\x59\x26\x53\x59";
        const END_MAGIC: &[u8; 6] = b"\x17\x72\x45\x38\x50\x90";
        let marker = &data[4..10];
        if marker != BLOCK_MAGIC && marker != END_MAGIC {
            return compression_identity_result(
                py, "bzip2", ".bz2", true, file_size, base_bytes_read, false,
                "bzip2_first_marker_invalid", &["bzip2:magic", "bzip2:block_size"],
            );
        }
        let evidence = if marker == BLOCK_MAGIC {
            vec!["bzip2:magic", "bzip2:block_size", "bzip2:first_block_marker"]
        } else {
            vec!["bzip2:magic", "bzip2:block_size", "bzip2:end_marker"]
        };
        return compression_identity_result(
            py, "bzip2", ".bz2", true, file_size, base_bytes_read, true, "", &evidence,
        );
    }

    if data.starts_with(XZ_MAGIC) {
        if data.len() < 12 || file_size < 24 {
            return compression_identity_result(
                py, "xz", ".xz", true, file_size, base_bytes_read, false,
                "xz_header_or_footer_missing", &["xz:magic"],
            );
        }
        let flags = [data[6], data[7]];
        let check_id = flags[1] & 0x0f;
        let stored = u32::from_le_bytes(data[8..12].try_into().unwrap());
        if flags[0] != 0
            || flags[1] & 0xf0 != 0
            || !matches!(check_id, 0 | 1 | 4 | 10)
            || stored != crc32(&flags)
        {
            return compression_identity_result(
                py, "xz", ".xz", true, file_size, base_bytes_read, false,
                "xz_stream_header_invalid", &["xz:magic"],
            );
        }
        return compression_identity_result(
            py, "xz", ".xz", true, file_size, base_bytes_read, true, "",
            &["xz:magic", "xz:stream_flags", "xz:header_crc32"],
        );
    }

    if data.starts_with(ZSTD_MAGIC) {
        if data.len() < 8 {
            return compression_identity_result(
                py, "zstd", ".zst", true, file_size, base_bytes_read, false,
                "zstd_frame_header_short", &["zstd:magic"],
            );
        }
        let descriptor = data[4];
        if descriptor & 0x18 != 0 {
            return compression_identity_result(
                py, "zstd", ".zst", true, file_size, base_bytes_read, false,
                "zstd_reserved_or_unused_bit_set", &["zstd:magic"],
            );
        }
        let single = descriptor & 0x20 != 0;
        let dict_size = match descriptor & 0x03 {
            0 => 0usize,
            1 => 1,
            2 => 2,
            _ => 4,
        };
        let mut cursor = 5usize;
        if !single {
            if cursor >= data.len() {
                return compression_identity_result(
                    py, "zstd", ".zst", true, file_size, base_bytes_read, false,
                    "zstd_window_descriptor_missing", &["zstd:magic", "zstd:frame_descriptor"],
                );
            }
            cursor += 1;
        }
        let fcs_flag = descriptor >> 6;
        let fcs_size = zstd_field_size(fcs_flag, single, single || fcs_flag != 0);
        let Some(block_header_offset) = cursor
            .checked_add(dict_size)
            .and_then(|value| value.checked_add(fcs_size))
        else {
            return compression_identity_result(
                py, "zstd", ".zst", true, file_size, base_bytes_read, false,
                "zstd_frame_header_overflow", &["zstd:magic", "zstd:frame_descriptor"],
            );
        };
        if block_header_offset + 3 > data.len() {
            return compression_identity_result(
                py, "zstd", ".zst", true, file_size, base_bytes_read, false,
                "zstd_first_block_header_missing", &["zstd:magic", "zstd:frame_descriptor"],
            );
        }
        let block_header = u32::from(data[block_header_offset])
            | (u32::from(data[block_header_offset + 1]) << 8)
            | (u32::from(data[block_header_offset + 2]) << 16);
        let block_type = (block_header >> 1) & 0x03;
        let block_size = u64::from(block_header >> 3);
        if block_type == 3 || block_size > 128 * 1024 {
            return compression_identity_result(
                py, "zstd", ".zst", true, file_size, base_bytes_read, false,
                "zstd_first_block_header_invalid",
                &["zstd:magic", "zstd:frame_descriptor"],
            );
        }
        let stored_size = if block_type == 1 { 1 } else { block_size };
        if (block_header_offset as u64)
            .checked_add(3)
            .and_then(|value| value.checked_add(stored_size))
            .map_or(true, |end| end > file_size)
        {
            return compression_identity_result(
                py, "zstd", ".zst", true, file_size, base_bytes_read, false,
                "zstd_first_block_out_of_range",
                &["zstd:magic", "zstd:frame_descriptor"],
            );
        }
        return compression_identity_result(
            py, "zstd", ".zst", true, file_size, base_bytes_read, true, "",
            &["zstd:magic", "zstd:frame_descriptor", "zstd:first_block_header"],
        );
    }

    compression_identity_result(
        py,
        "",
        "",
        false,
        file_size,
        base_bytes_read,
        false,
        "compression_stream_magic_not_found",
        &[],
    )
}

fn inspect_large_structural_stream(
    py: Python<'_>,
    path: &str,
    file_size: u64,
    kind: StructuralStreamKind,
) -> PyResult<Py<PyDict>> {
    let (format, ext, magic, fields, cost) = match kind {
        StructuralStreamKind::Gzip => ("gzip", ".gz", b"\x1f\x8b".as_slice(), GZIP_FIELDS, "compressed_token_linear"),
        StructuralStreamKind::Bzip2 => ("bzip2", ".bz2", b"BZh".as_slice(), BZIP2_FIELDS, "compressed_bitstream_linear"),
        StructuralStreamKind::Xz => ("xz", ".xz", XZ_MAGIC, XZ_FIELDS, "metadata_linear_payload_skipped"),
        StructuralStreamKind::Zstd => ("zstd", ".zst", ZSTD_MAGIC, ZSTD_FIELDS, "block_header_linear_payload_skipped"),
    };
    let reader = match ManagedReader::open(path) {
        Ok(value) => value,
        Err(_) => return compression_empty(py, "os_error", format, ext, false),
    };
    let head = reader.read_at(0, magic.len()).unwrap_or_default();
    let magic_matched = head.starts_with(magic);
    let d = compression_base(py, format, ext, magic_matched)?;
    for field in fields {
        d.set_item(*field, "not_decoded")?;
    }
    d.set_item("validation_scope", "complete_structure")?;
    d.set_item("validation_cost", cost)?;
    d.set_item("file_size", file_size)?;
    let validation = match kind {
        StructuralStreamKind::Gzip => validate_gzip_structure(&reader, 0, file_size),
        StructuralStreamKind::Bzip2 => validate_bzip2_structure(&reader, 0, file_size),
        StructuralStreamKind::Xz => validate_xz_structure_exact(&reader, 0, file_size),
        StructuralStreamKind::Zstd => validate_zstd_structure(&reader, 0, file_size),
    };
    let structure = match validation {
        Ok(value) => value,
        Err(error) => {
            let code = error.code();
            d.set_item("structure_status", "invalid")?;
            d.set_item("structure_validation_complete", false)?;
            d.set_item("boundary_exact", false)?;
            d.set_item("integrity_status", "failed")?;
            d.set_item("integrity_validation_complete", true)?;
            d.set_item("plausible", false)?;
            d.set_item("confidence", "none")?;
            d.set_item("error", code)?;
            d.set_item("damage_flags", PyList::new(py, [code])?)?;
            finish_fields(&d, fields)?;
            return Ok(d.unbind());
        }
    };
    project_structural_validation(&d, &structure, file_size)?;
    let trailing = file_size.saturating_sub(structure.end_offset);
    let damage_flags = if trailing > 0 { vec!["trailing_junk"] } else { Vec::new() };
    d.set_item("plausible", true)?;
    d.set_item("confidence", "strong")?;
    d.set_item("structure_status", "complete")?;
    d.set_item("structure_validation_complete", true)?;
    d.set_item("boundary_exact", true)?;
    d.set_item("segment_end", structure.end_offset)?;
    d.set_item("archive.trailing_data", trailing)?;
    d.set_item("trailing_data_verified", true)?;
    d.set_item("integrity_status", structure.integrity.as_str())?;
    d.set_item("integrity_validation_complete", false)?;
    d.set_item("checksum_present", structure.checksum_present)?;
    d.set_item("damage_flags", PyList::new(py, damage_flags)?)?;
    finish_fields(&d, fields)?;
    Ok(d.unbind())
}

fn project_structural_validation(
    d: &Bound<'_, PyDict>,
    structure: &StructureValidation,
    file_size: u64,
) -> PyResult<()> {
    d.set_item("structure.stream_count", structure.stream_count)?;
    d.set_item("structure.block_count", structure.block_count)?;
    d.set_item("structure.compressed_bytes", structure.end_offset.min(file_size))?;
    d.set_item("structure.decoded_size", structure.decoded_size)?;
    Ok(())
}

fn apply_structural_contract(
    d: &Bound<'_, PyDict>,
    path: &str,
    file_size: u64,
    validation_limit: u64,
    kind: StructuralStreamKind,
    integrity_verified: bool,
    damage_flags: &mut Vec<&'static str>,
) -> PyResult<()> {
    let reader = match ManagedReader::open(path) {
        Ok(value) => value,
        Err(_) => {
            d.set_item("structure_status", "invalid")?;
            d.set_item("structure_validation_complete", false)?;
            d.set_item("boundary_exact", false)?;
            return Ok(());
        }
    };
    let validation = match kind {
        StructuralStreamKind::Gzip => validate_gzip_structure(&reader, 0, validation_limit),
        StructuralStreamKind::Bzip2 => validate_bzip2_structure(&reader, 0, validation_limit),
        StructuralStreamKind::Xz => validate_xz_structure_exact(&reader, 0, validation_limit),
        StructuralStreamKind::Zstd => validate_zstd_structure(&reader, 0, validation_limit),
    };
    match validation {
        Ok(structure) => {
            let trailing = file_size.saturating_sub(structure.end_offset);
            if trailing > 0 && !damage_flags.contains(&"trailing_junk") {
                damage_flags.push("trailing_junk");
            }
            let integrity = if integrity_verified && structure.checksum_present {
                "verified"
            } else {
                structure.integrity.as_str()
            };
            d.set_item("validation_scope", "complete_structure")?;
            d.set_item("structure_status", "complete")?;
            d.set_item("structure_validation_complete", true)?;
            d.set_item("boundary_exact", true)?;
            d.set_item("segment_end", structure.end_offset)?;
            d.set_item("archive.trailing_data", trailing)?;
            d.set_item("trailing_data_verified", true)?;
            d.set_item("integrity_status", integrity)?;
            d.set_item("integrity_validation_complete", integrity == "verified")?;
            d.set_item("checksum_present", structure.checksum_present)?;
            project_structural_validation(d, &structure, file_size)?;
        }
        Err(error) => {
            let code = error.code();
            if !damage_flags.contains(&code) {
                damage_flags.push(code);
            }
            d.set_item("structure_status", "invalid")?;
            d.set_item("structure_validation_complete", false)?;
            d.set_item("boundary_exact", false)?;
            d.set_item("integrity_status", "failed")?;
            d.set_item("integrity_validation_complete", true)?;
            d.set_item("plausible", false)?;
            d.set_item("confidence", "none")?;
            d.set_item("error", code)?;
        }
    }
    Ok(())
}

fn compression_base<'py>(
    py: Python<'py>,
    format: &str,
    ext: &str,
    magic: bool,
) -> PyResult<Bound<'py, PyDict>> {
    let d = dict(py)?;
    d.set_item("plausible", false)?;
    d.set_item("error", "")?;
    d.set_item("magic_matched", magic)?;
    d.set_item("format", format)?;
    d.set_item("detected_ext", ext)?;
    d.set_item("confidence", "none")?;
    d.set_item("evidence", PyList::empty(py))?;
    Ok(d)
}

fn finish_fields(d: &Bound<'_, PyDict>, fields: &[&str]) -> PyResult<()> {
    let missing = PyList::empty(d.py());
    for field in fields {
        if !d.contains(field)? {
            d.set_item(field, "unavailable")?;
            missing.append(field)?;
        }
    }
    d.set_item("semantic_field_count", fields.len())?;
    d.set_item("semantic_fields", PyList::new(d.py(), fields)?)?;
    d.set_item("semantic_missing_fields", missing)?;
    Ok(())
}

fn compression_empty(
    py: Python<'_>,
    error: &str,
    format: &str,
    ext: &str,
    magic: bool,
) -> PyResult<Py<PyDict>> {
    let d = compression_base(py, format, ext, magic)?;
    d.set_item("error", error)?;
    Ok(d.unbind())
}

fn hex_bytes(value: &[u8]) -> String {
    value.iter().map(|b| format!("{b:02x}")).collect()
}

fn c_string(data: &[u8], cursor: &mut usize) -> Option<String> {
    let start = *cursor;
    let rel = data.get(start..)?.iter().position(|b| *b == 0)?;
    *cursor = start + rel + 1;
    Some(String::from_utf8_lossy(&data[start..start + rel]).into_owned())
}

fn parse_gzip_header(data: &[u8], start: usize) -> Result<(usize, u8), &'static str> {
    if data.len() < start + 10 {
        return Err("short_gzip_header");
    }
    if &data[start..start + 3] != b"\x1f\x8b\x08" {
        return Err("gzip_magic_not_found");
    }
    let flags = data[start + 3];
    if flags & 0xe0 != 0 {
        return Err("gzip_reserved_flags_set");
    }
    let mut cursor = start + 10;
    if flags & 0x04 != 0 {
        if data.len() < cursor + 2 {
            return Err("gzip_extra_length_missing");
        }
        let length = u16::from_le_bytes([data[cursor], data[cursor + 1]]) as usize;
        cursor += 2;
        if data.len() < cursor + length {
            return Err("gzip_extra_out_of_range");
        }
        cursor += length;
    }
    if flags & 0x08 != 0 {
        c_string(data, &mut cursor).ok_or("gzip_name_unterminated")?;
    }
    if flags & 0x10 != 0 {
        c_string(data, &mut cursor).ok_or("gzip_comment_unterminated")?;
    }
    if flags & 0x02 != 0 {
        if data.len() < cursor + 2 {
            return Err("gzip_header_crc_missing");
        }
        cursor += 2;
    }
    Ok((cursor, flags))
}

fn inspect_gzip(py: Python<'_>, path: &str, header: &[u8], file_size: u64) -> PyResult<Py<PyDict>> {
    if file_size > EAGER_STREAM_INTEGRITY_MAX_BYTES {
        return inspect_large_structural_stream(py, path, file_size, StructuralStreamKind::Gzip);
    }
    let data = match ManagedReader::open(path).and_then(|reader| reader.read_all()) {
        Ok(data) => data,
        Err(_) => {
            return compression_empty(
                py,
                "os_error",
                "gzip",
                ".gz",
                header.starts_with(b"\x1f\x8b"),
            )
        }
    };
    let d = compression_base(py, "gzip", ".gz", data.starts_with(b"\x1f\x8b"))?;
    let mut damage_flags = Vec::new();
    d.set_item(
        "member.header.magic",
        hex_bytes(data.get(0..2).unwrap_or(&[])),
    )?;
    let (payload_start, flags) = match parse_gzip_header(&data, 0) {
        Ok(value) => value,
        Err(error) => {
            d.set_item("error", error)?;
            finish_fields(&d, GZIP_FIELDS)?;
            return Ok(d.unbind());
        }
    };
    d.set_item("member.header.compression_method", data[2])?;
    d.set_item("member.header.flags", flags)?;
    d.set_item(
        "member.header.mtime_xfl_os",
        format!("mtime={};xfl={};os={}", u32_le(&data, 4), data[8], data[9]),
    )?;
    let mut cursor = 10usize;
    if flags & 0x04 != 0 {
        let length = u16_le(&data, cursor) as usize;
        d.set_item("member.header.extra_length", length)?;
        cursor += 2;
        d.set_item(
            "member.header.extra",
            hex_bytes(&data[cursor..cursor + length]),
        )?;
        cursor += length;
    } else {
        d.set_item("member.header.extra_length", 0)?;
        d.set_item("member.header.extra", "absent")?;
    }
    if flags & 0x08 != 0 {
        d.set_item(
            "member.header.name",
            c_string(&data, &mut cursor).unwrap_or_default(),
        )?;
    } else {
        d.set_item("member.header.name", "absent")?;
    }
    if flags & 0x10 != 0 {
        d.set_item(
            "member.header.comment",
            c_string(&data, &mut cursor).unwrap_or_default(),
        )?;
    } else {
        d.set_item("member.header.comment", "absent")?;
    }
    if flags & 0x02 != 0 {
        let stored = u16_le(&data, cursor);
        let computed = (crc32(&data[..cursor]) & 0xffff) as u16;
        let ok = stored == computed;
        d.set_item(
            "member.header.crc16",
            format!("stored={stored};computed={computed};ok={ok}"),
        )?;
        if !ok {
            damage_flags.push("gzip_header_crc_bad");
        }
    } else {
        d.set_item("member.header.crc16", "absent")?;
    }

    let inflater = flate2::read::DeflateDecoder::new(Cursor::new(&data[payload_start..]));
    let mut limited_inflater = inflater.take(STREAM_STRUCTURE_DECODE_MAX_BYTES + 1);
    let mut decoded = Vec::new();
    let status = limited_inflater.read_to_end(&mut decoded);
    let inflater = limited_inflater.into_inner();
    let decode_limited = decoded.len() as u64 > STREAM_STRUCTURE_DECODE_MAX_BYTES;
    let deflate_len = inflater.total_in() as usize;
    let boundary = payload_start.saturating_add(deflate_len).saturating_add(8);
    let stream_end = status.is_ok() && !decode_limited && boundary <= data.len();
    d.set_item(
        "member.deflate.blocks",
        format!("compressed_bytes={deflate_len};decoder_status={status:?}"),
    )?;
    d.set_item("member.deflate.final_block", stream_end)?;
    d.set_item("member.decoded_content", decoded.len())?;
    if stream_end && boundary <= data.len() && boundary >= 8 {
        let trailer = boundary - 8;
        let stored_crc = u32_le(&data, trailer);
        let stored_size = u32_le(&data, trailer + 4);
        let footer_ok = stored_crc == crc32(&decoded) && stored_size == decoded.len() as u32;
        d.set_item(
            "member.trailer.crc32",
            format!(
                "stored={stored_crc};computed={};ok={}",
                crc32(&decoded),
                stored_crc == crc32(&decoded)
            ),
        )?;
        d.set_item(
            "member.trailer.isize",
            format!(
                "stored={stored_size};decoded_mod={};ok={}",
                decoded.len() as u32,
                stored_size == decoded.len() as u32
            ),
        )?;
        if !footer_ok {
            damage_flags.push("gzip_footer_bad");
        }
    }
    d.set_item("member.boundary", boundary.min(data.len()))?;
    let next_member =
        stream_end && boundary + 2 <= data.len() && &data[boundary..boundary + 2] == b"\x1f\x8b";
    d.set_item("member.next_member", next_member)?;
    let trailing = if decode_limited || next_member {
        0
    } else {
        data.len().saturating_sub(boundary)
    };
    d.set_item("archive.trailing_data", trailing)?;
    if trailing > 0 {
        damage_flags.push("trailing_junk");
    }
    d.set_item("trailing_data_verified", stream_end)?;
    d.set_item(
        "plausible",
        stream_end || (decode_limited && data.starts_with(b"\x1f\x8b\x08")),
    )?;
    d.set_item("confidence", if stream_end { "strong" } else { "medium" })?;
    if !stream_end && !decode_limited {
        d.set_item("error", "gzip_deflate_or_trailer_incomplete")?;
        damage_flags.push("probably_truncated");
    }
    apply_structural_contract(
        &d,
        path,
        file_size,
        file_size,
        StructuralStreamKind::Gzip,
        stream_end && !damage_flags.contains(&"gzip_footer_bad"),
        &mut damage_flags,
    )?;
    d.set_item("damage_flags", PyList::new(py, damage_flags)?)?;
    d.set_item("file_size", file_size)?;
    finish_fields(&d, GZIP_FIELDS)?;
    Ok(d.unbind())
}

struct BitReader<'a> {
    data: &'a [u8],
    bit: usize,
}
impl<'a> BitReader<'a> {
    fn read(&mut self, bits: usize) -> Option<u64> {
        if self.bit + bits > self.data.len() * 8 {
            return None;
        }
        let mut value = 0u64;
        for _ in 0..bits {
            value = (value << 1) | ((self.data[self.bit / 8] >> (7 - self.bit % 8)) & 1) as u64;
            self.bit += 1;
        }
        Some(value)
    }
}

fn marker_positions(data: &[u8], marker: u64) -> Vec<usize> {
    let mut output = Vec::new();
    let mut window = 0u64;
    for bit in 0..data.len() * 8 {
        window = ((window << 1) | ((data[bit / 8] >> (7 - bit % 8)) & 1) as u64) & 0xffff_ffff_ffff;
        if bit >= 47 && window == marker {
            output.push(bit + 1 - 48);
        }
    }
    output
}

fn bzip_huffman_summary(data: &[u8], start_bit: usize) -> String {
    let mut reader = BitReader {
        data,
        bit: start_bit,
    };
    let mut groups = 0usize;
    if let Some(in_use16) = reader.read(16) {
        let mut symbols = 0usize;
        for group in 0..16 {
            if in_use16 & (1 << (15 - group)) != 0 {
                if let Some(bits) = reader.read(16) {
                    symbols += bits.count_ones() as usize;
                } else {
                    return "truncated".into();
                }
            }
        }
        groups = reader.read(3).unwrap_or(0) as usize;
        let selectors = reader.read(15).unwrap_or(0);
        return format!("symbols={symbols};groups={groups};selectors={selectors}");
    }
    format!("groups={groups};truncated")
}

fn inspect_bzip2(
    py: Python<'_>,
    path: &str,
    header: &[u8],
    file_size: u64,
) -> PyResult<Py<PyDict>> {
    if file_size > EAGER_STREAM_INTEGRITY_MAX_BYTES {
        return inspect_large_structural_stream(py, path, file_size, StructuralStreamKind::Bzip2);
    }
    let data = match ManagedReader::open(path).and_then(|reader| reader.read_all()) {
        Ok(data) => data,
        Err(_) => {
            return compression_empty(py, "os_error", "bzip2", ".bz2", header.starts_with(b"BZh"))
        }
    };
    let magic = data.starts_with(b"BZh") && data.get(3).is_some_and(|v| b"123456789".contains(v));
    let d = compression_base(py, "bzip2", ".bz2", magic)?;
    let mut damage_flags = Vec::new();
    d.set_item(
        "stream.magic",
        String::from_utf8_lossy(data.get(0..3).unwrap_or(&[])).to_string(),
    )?;
    d.set_item(
        "stream.block_size_100k",
        data.get(3).map(|v| v.saturating_sub(b'0')).unwrap_or(0),
    )?;
    if !magic {
        d.set_item("error", "bzip2_magic_not_found")?;
        finish_fields(&d, BZIP2_FIELDS)?;
        return Ok(d.unbind());
    }
    let blocks = marker_positions(&data, 0x314159265359);
    let ends = marker_positions(&data, 0x177245385090);
    d.set_item(
        "block.marker",
        blocks.first().map(|v| *v as u64).unwrap_or(u64::MAX),
    )?;
    d.set_item("block.sequence", blocks.len())?;
    if let Some(bit) = blocks.first() {
        let mut reader = BitReader {
            data: &data,
            bit: bit + 48,
        };
        let block_crc = reader.read(32).unwrap_or(0) as u32;
        let randomized = reader.read(1).unwrap_or(0) != 0;
        let orig_ptr = reader.read(24).unwrap_or(0);
        d.set_item("block.crc32", block_crc)?;
        d.set_item("block.randomized", randomized)?;
        d.set_item("block.orig_ptr", orig_ptr)?;
        d.set_item(
            "block.huffman_tables",
            bzip_huffman_summary(&data, reader.bit),
        )?;
        let end_bit = blocks
            .get(1)
            .copied()
            .or_else(|| ends.first().copied())
            .unwrap_or(data.len() * 8);
        d.set_item("block.encoded_data", end_bit.saturating_sub(reader.bit))?;
    }
    d.set_item("stream.end_marker", !ends.is_empty())?;
    if let Some(bit) = ends.first() {
        let mut reader = BitReader {
            data: &data,
            bit: bit + 48,
        };
        d.set_item("stream.combined_crc32", reader.read(32).unwrap_or(0) as u32)?;
    }
    let decoder = bzip2::read::BzDecoder::new(Cursor::new(data.as_slice()));
    let mut limited_decoder = decoder.take(STREAM_STRUCTURE_DECODE_MAX_BYTES + 1);
    let mut decoded = Vec::new();
    let decode_status = limited_decoder.read_to_end(&mut decoded);
    let decoder = limited_decoder.into_inner();
    let decode_limited = decoded.len() as u64 > STREAM_STRUCTURE_DECODE_MAX_BYTES;
    let decode_ok = decode_status.is_ok() && !decode_limited;
    let marker_boundary = ends
        .first()
        .map(|bit| (bit + 48 + 32 + 7) / 8)
        .unwrap_or(data.len());
    let consumed = decoder.get_ref().position() as usize;
    d.set_item("block.decoded_content", decoded.len())?;
    let trailing = if decode_limited {
        0
    } else {
        data.len().saturating_sub(marker_boundary.min(consumed))
    };
    d.set_item("archive.trailing_data", trailing)?;
    if trailing > 0 {
        damage_flags.push("trailing_junk");
    }
    d.set_item("trailing_data_verified", decode_ok)?;
    d.set_item(
        "plausible",
        (decode_ok && !ends.is_empty()) || (decode_limited && magic),
    )?;
    d.set_item("confidence", if decode_ok { "strong" } else { "medium" })?;
    if ends.is_empty() && !decode_limited {
        damage_flags.push("probably_truncated");
    }
    if !decode_ok && !decode_limited {
        d.set_item("error", "bzip2_decode_failed")?;
        damage_flags.push("bzip2_block_bad");
    }
    apply_structural_contract(
        &d,
        path,
        file_size,
        file_size,
        StructuralStreamKind::Bzip2,
        decode_ok,
        &mut damage_flags,
    )?;
    d.set_item("damage_flags", PyList::new(py, damage_flags)?)?;
    d.set_item("file_size", file_size)?;
    finish_fields(&d, BZIP2_FIELDS)?;
    Ok(d.unbind())
}

fn read_vli(data: &[u8], cursor: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    let mut shift = 0usize;
    loop {
        let byte = *data.get(*cursor)?;
        *cursor += 1;
        if shift >= 63 || (shift > 0 && byte == 0) {
            return None;
        }
        value |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
        shift += 7;
    }
}

fn xz_check_size(check_type: u8) -> usize {
    match check_type {
        0 => 0,
        1 => 4,
        4 => 8,
        10 => 32,
        _ => 0,
    }
}

fn inspect_xz(py: Python<'_>, path: &str, header: &[u8], file_size: u64) -> PyResult<Py<PyDict>> {
    if file_size > EAGER_STREAM_INTEGRITY_MAX_BYTES {
        return inspect_large_structural_stream(py, path, file_size, StructuralStreamKind::Xz);
    }
    let data = match ManagedReader::open(path).and_then(|reader| reader.read_all()) {
        Ok(data) => data,
        Err(_) => {
            return compression_empty(py, "os_error", "xz", ".xz", header.starts_with(XZ_MAGIC))
        }
    };
    let d = compression_base(py, "xz", ".xz", data.starts_with(XZ_MAGIC))?;
    let mut damage_flags = Vec::new();
    d.set_item(
        "stream.header.magic",
        hex_bytes(data.get(..6).unwrap_or(&[])),
    )?;
    if data.len() < 24 || !data.starts_with(XZ_MAGIC) {
        d.set_item("error", "xz_header_or_footer_missing")?;
        finish_fields(&d, XZ_FIELDS)?;
        return Ok(d.unbind());
    }
    let flags = &data[6..8];
    let header_crc = u32_le(&data, 8);
    d.set_item("stream.header.flags", hex_bytes(flags))?;
    d.set_item(
        "stream.header.crc32",
        format!(
            "stored={header_crc};computed={};ok={}",
            crc32(flags),
            header_crc == crc32(flags)
        ),
    )?;
    if header_crc != crc32(flags) {
        damage_flags.push("xz_header_crc_bad");
    }

    let footer_start = (10..data.len())
        .rev()
        .find_map(|magic_end| {
            if data.get(magic_end - 1..=magic_end) != Some(b"YZ".as_slice()) || magic_end + 1 < 12 {
                return None;
            }
            let start = magic_end + 1 - 12;
            let footer = &data[start..start + 12];
            (u32_le(footer, 0) == crc32(&footer[4..10])).then_some(start)
        })
        .unwrap_or(data.len() - 12);
    let footer = &data[footer_start..];
    let footer_crc = u32_le(footer, 0);
    let backward_size = (u32_le(footer, 4) as u64 + 1) * 4;
    d.set_item(
        "stream.footer.crc32",
        format!(
            "stored={footer_crc};computed={};ok={}",
            crc32(&footer[4..10]),
            footer_crc == crc32(&footer[4..10])
        ),
    )?;
    if footer_crc != crc32(&footer[4..10]) {
        damage_flags.push("xz_footer_crc_bad");
    }
    if &footer[8..10] != flags {
        damage_flags.push("xz_stream_flags_mismatch");
    }
    d.set_item("stream.footer.backward_size", backward_size)?;
    d.set_item("stream.footer.flags", hex_bytes(&footer[8..10]))?;
    d.set_item("stream.footer.magic", hex_bytes(&footer[10..12]))?;
    let index_start = footer_start
        .checked_sub(backward_size as usize)
        .unwrap_or(0);
    let mut index_cursor = index_start;
    let index_valid_start = data.get(index_cursor) == Some(&0);
    d.set_item("index.indicator", index_valid_start)?;
    if !index_valid_start {
        damage_flags.push("xz_index_bad");
    }
    index_cursor = index_cursor.saturating_add(1);
    let record_count = read_vli(&data, &mut index_cursor).unwrap_or(0) as usize;
    d.set_item("index.record_count", record_count)?;
    let mut records = Vec::new();
    for _ in 0..record_count {
        let unpadded = read_vli(&data, &mut index_cursor).unwrap_or(0);
        let uncompressed = read_vli(&data, &mut index_cursor).unwrap_or(0);
        records.push((unpadded, uncompressed));
    }
    d.set_item(
        "index.records.unpadded_size",
        records.iter().map(|r| r.0).sum::<u64>(),
    )?;
    d.set_item(
        "index.records.uncompressed_size",
        records.iter().map(|r| r.1).sum::<u64>(),
    )?;
    let index_crc_pos = footer_start.saturating_sub(4);
    d.set_item("index.padding", index_crc_pos.saturating_sub(index_cursor))?;
    if index_crc_pos + 4 <= data.len() && index_start <= index_crc_pos {
        let stored = u32_le(&data, index_crc_pos);
        let ok = stored == crc32(&data[index_start..index_crc_pos]);
        d.set_item(
            "index.crc32",
            format!(
                "stored={stored};computed={};ok={ok}",
                crc32(&data[index_start..index_crc_pos])
            ),
        )?;
        if !ok {
            damage_flags.push("xz_index_bad");
        }
    }

    let mut block_cursor = 12usize;
    let mut block_count = 0usize;
    let mut total_compressed = 0u64;
    let mut total_padding = 0usize;
    let mut first_filters = String::new();
    let check_size = xz_check_size(flags[1] & 0x0f);
    for (unpadded, expected_uncompressed) in &records {
        if block_cursor >= index_start {
            break;
        }
        let header_size = (data[block_cursor] as usize + 1) * 4;
        if block_cursor + header_size > data.len() || header_size < 8 {
            break;
        }
        let block_flags = data[block_cursor + 1];
        let mut c = block_cursor + 2;
        let declared_compressed = if block_flags & 0x40 != 0 {
            read_vli(&data, &mut c)
        } else {
            None
        };
        let declared_uncompressed = if block_flags & 0x80 != 0 {
            read_vli(&data, &mut c)
        } else {
            None
        };
        let filter_count = (block_flags & 0x03) as usize + 1;
        let mut filters = Vec::new();
        for _ in 0..filter_count {
            let id = read_vli(&data, &mut c).unwrap_or(0);
            let prop_size = read_vli(&data, &mut c).unwrap_or(0) as usize;
            let props_end = c
                .saturating_add(prop_size)
                .min(block_cursor + header_size - 4);
            filters.push(format!("id={id}:props={}", hex_bytes(&data[c..props_end])));
            c = props_end;
        }
        if first_filters.is_empty() {
            first_filters = filters.join(",");
        }
        let stored_header_crc = u32_le(&data, block_cursor + header_size - 4);
        if block_count == 0 {
            d.set_item("block.header.size", header_size)?;
            d.set_item("block.header.flags", block_flags)?;
            d.set_item(
                "block.header.compressed_size",
                declared_compressed
                    .unwrap_or(unpadded.saturating_sub(header_size as u64 + check_size as u64)),
            )?;
            d.set_item(
                "block.header.uncompressed_size",
                declared_uncompressed.unwrap_or(*expected_uncompressed),
            )?;
            d.set_item(
                "block.header.crc32",
                format!(
                    "stored={stored_header_crc};computed={};ok={}",
                    crc32(&data[block_cursor..block_cursor + header_size - 4]),
                    stored_header_crc == crc32(&data[block_cursor..block_cursor + header_size - 4])
                ),
            )?;
        }
        let compressed_size = declared_compressed
            .unwrap_or(unpadded.saturating_sub(header_size as u64 + check_size as u64));
        total_compressed += compressed_size;
        let unpadded_actual = header_size as u64 + compressed_size + check_size as u64;
        let padding = ((4 - unpadded_actual % 4) % 4) as usize;
        total_padding += padding;
        block_cursor = block_cursor.saturating_add(unpadded_actual as usize + padding);
        block_count += 1;
    }
    d.set_item("block.header.filters", first_filters)?;
    d.set_item("block.compressed_data", total_compressed)?;
    d.set_item("block.padding", total_padding)?;
    d.set_item(
        "block.check",
        format!("type={};size={check_size}", flags[1] & 0x0f),
    )?;
    d.set_item("block.sequence", block_count)?;
    let decoder = xz2::read::XzDecoder::new(Cursor::new(data.as_slice()));
    let mut limited_decoder = decoder.take(STREAM_STRUCTURE_DECODE_MAX_BYTES + 1);
    let mut decoded = Vec::new();
    let decode_status = limited_decoder.read_to_end(&mut decoded);
    let decode_limited = decoded.len() as u64 > STREAM_STRUCTURE_DECODE_MAX_BYTES;
    let decode_ok = decode_status.is_ok() && !decode_limited;
    d.set_item("block.uncompressed_data", decoded.len())?;
    let stream_count = data.windows(6).filter(|w| *w == XZ_MAGIC).count();
    d.set_item("archive.stream_sequence", stream_count)?;
    let after_footer = footer_start + 12;
    let zero_padding = data[after_footer..].iter().take_while(|b| **b == 0).count();
    let aligned_padding = zero_padding - zero_padding % 4;
    d.set_item("stream.padding", aligned_padding)?;
    let trailing = data.len().saturating_sub(after_footer + aligned_padding);
    d.set_item("archive.trailing_data", trailing)?;
    if trailing > 0 {
        damage_flags.push("trailing_junk");
    }
    let valid = (decode_ok || decode_limited)
        && &footer[10..12] == b"YZ"
        && &footer[8..10] == flags
        && index_valid_start;
    d.set_item("plausible", valid)?;
    d.set_item("confidence", if valid { "strong" } else { "medium" })?;
    if !valid {
        d.set_item("error", "xz_structural_validation_failed")?;
    }
    apply_structural_contract(
        &d,
        path,
        file_size,
        (after_footer + aligned_padding) as u64,
        StructuralStreamKind::Xz,
        decode_ok,
        &mut damage_flags,
    )?;
    d.set_item("damage_flags", PyList::new(py, damage_flags)?)?;
    d.set_item("file_size", file_size)?;
    finish_fields(&d, XZ_FIELDS)?;
    Ok(d.unbind())
}

fn zstd_field_size(flag: u8, single: bool, content_size: bool) -> usize {
    if !content_size {
        return 0;
    }
    match flag {
        0 if single => 1,
        0 => 0,
        1 => 2,
        2 => 4,
        _ => 8,
    }
}

fn little_uint(data: &[u8]) -> u64 {
    data.iter()
        .enumerate()
        .fold(0u64, |v, (i, b)| v | ((*b as u64) << (8 * i)))
}

fn inspect_zstd(py: Python<'_>, path: &str, header: &[u8], file_size: u64) -> PyResult<Py<PyDict>> {
    if file_size > EAGER_STREAM_INTEGRITY_MAX_BYTES {
        return inspect_large_structural_stream(py, path, file_size, StructuralStreamKind::Zstd);
    }
    let data = match ManagedReader::open(path).and_then(|reader| reader.read_all()) {
        Ok(data) => data,
        Err(_) => {
            return compression_empty(
                py,
                "os_error",
                "zstd",
                ".zst",
                header.starts_with(ZSTD_MAGIC),
            )
        }
    };
    let d = compression_base(py, "zstd", ".zst", data.starts_with(ZSTD_MAGIC))?;
    let mut damage_flags = Vec::new();
    d.set_item("frame.magic", hex_bytes(data.get(..4).unwrap_or(&[])))?;
    if data.len() < 6 || !data.starts_with(ZSTD_MAGIC) {
        d.set_item("error", "zstd_magic_or_header_missing")?;
        finish_fields(&d, ZSTD_FIELDS)?;
        return Ok(d.unbind());
    }
    let descriptor = data[4];
    let fcs_flag = descriptor >> 6;
    let single = descriptor & 0x20 != 0;
    let checksum = descriptor & 0x04 != 0;
    let dict_flag = descriptor & 0x03;
    d.set_item("frame.header.descriptor", descriptor)?;
    d.set_item("frame.header.content_size_flag", fcs_flag)?;
    d.set_item("frame.header.single_segment_flag", single)?;
    d.set_item("frame.header.checksum_flag", checksum)?;
    d.set_item("frame.header.dictionary_id_flag", dict_flag)?;
    let mut cursor = 5usize;
    if !single {
        let wd = data[cursor];
        cursor += 1;
        let exponent = (wd >> 3) as u32;
        let base = 1u64 << (10 + exponent);
        let window = base + (base / 8) * (wd & 7) as u64;
        d.set_item(
            "frame.header.window_descriptor",
            format!("raw={wd};window={window}"),
        )?;
    } else {
        d.set_item("frame.header.window_descriptor", "absent(single_segment)")?;
    }
    let dict_size = match dict_flag {
        0 => 0,
        1 => 1,
        2 => 2,
        _ => 4,
    };
    let dict_end = cursor.saturating_add(dict_size).min(data.len());
    d.set_item(
        "frame.header.dictionary_id",
        if dict_size == 0 {
            0
        } else {
            little_uint(&data[cursor..dict_end])
        },
    )?;
    cursor = dict_end;
    let fcs_size = zstd_field_size(fcs_flag, single, single || fcs_flag != 0);
    let fcs_end = cursor.saturating_add(fcs_size).min(data.len());
    let mut content_size = little_uint(&data[cursor..fcs_end]);
    if fcs_flag == 1 {
        content_size += 256;
    }
    d.set_item(
        "frame.header.content_size",
        if fcs_size == 0 {
            "absent".to_string()
        } else {
            content_size.to_string()
        },
    )?;
    cursor = fcs_end;
    let mut blocks = 0usize;
    let mut total_content = 0usize;
    let mut last = false;
    let mut first_type = 0u8;
    let mut first_size = 0usize;
    while cursor + 3 <= data.len() && !last {
        let h =
            data[cursor] as u32 | (data[cursor + 1] as u32) << 8 | (data[cursor + 2] as u32) << 16;
        cursor += 3;
        last = h & 1 != 0;
        let block_type = ((h >> 1) & 3) as u8;
        let block_size = (h >> 3) as usize;
        if blocks == 0 {
            first_type = block_type;
            first_size = block_size;
        }
        let stored_size = if block_type == 1 { 1 } else { block_size };
        if block_type == 3 || cursor + stored_size > data.len() {
            break;
        }
        total_content += stored_size;
        cursor += stored_size;
        blocks += 1;
    }
    d.set_item("block.header.last_block", last)?;
    d.set_item("block.header.type", first_type)?;
    d.set_item("block.header.size", first_size)?;
    d.set_item("block.content", total_content)?;
    d.set_item(
        "block.literals",
        if first_type == 2 {
            "compressed_block_literals_section"
        } else {
            "not_compressed_layout"
        },
    )?;
    d.set_item(
        "block.sequences",
        if first_type == 2 {
            "compressed_block_sequences_section"
        } else {
            "not_compressed_layout"
        },
    )?;
    d.set_item(
        "block.previous_window",
        if dict_size > 0 {
            "dictionary_or_previous_block"
        } else {
            "previous_blocks"
        },
    )?;
    d.set_item(
        "block.previous_entropy_tables",
        if first_type == 2 {
            "repeat_mode_possible"
        } else {
            "not_used"
        },
    )?;
    if checksum && cursor + 4 <= data.len() {
        d.set_item("frame.content_checksum", u32_le(&data, cursor))?;
        cursor += 4;
    } else {
        d.set_item("frame.content_checksum", "absent")?;
    }
    let mut decoded = Vec::new();
    let (decode_ok, decode_limited) =
        match zstd::stream::read::Decoder::new(Cursor::new(&data[..cursor])) {
            Ok(decoder) => {
                let mut limited_decoder = decoder.take(STREAM_STRUCTURE_DECODE_MAX_BYTES + 1);
                let status = limited_decoder.read_to_end(&mut decoded);
                let limited = decoded.len() as u64 > STREAM_STRUCTURE_DECODE_MAX_BYTES;
                (status.is_ok() && !limited, limited)
            }
            Err(_) => (false, false),
        };
    d.set_item("frame.decoded_content", decoded.len())?;
    d.set_item(
        "frame.sequence",
        data.windows(4).filter(|w| *w == ZSTD_MAGIC).count(),
    )?;
    let mut skippable_count = 0usize;
    let mut skip_size = 0usize;
    let mut skip_data = 0usize;
    let mut scan = 0usize;
    while scan + 8 <= data.len() {
        let magic = u32_le(&data, scan);
        if (0x184d2a50..=0x184d2a5f).contains(&magic) {
            let size = u32_le(&data, scan + 4) as usize;
            skippable_count += 1;
            skip_size += size;
            skip_data += size.min(data.len().saturating_sub(scan + 8));
            scan = scan.saturating_add(8 + size);
            continue;
        }
        scan += 1;
    }
    d.set_item("skippable.magic", skippable_count)?;
    d.set_item("skippable.frame_size", skip_size)?;
    d.set_item("skippable.user_data", skip_data)?;
    let trailing = data.len().saturating_sub(cursor);
    d.set_item("archive.trailing_data", trailing)?;
    if trailing > 0 {
        damage_flags.push("trailing_junk");
    }
    let valid = (decode_ok || decode_limited) && last && descriptor & 0x08 == 0;
    d.set_item("plausible", valid)?;
    d.set_item("confidence", if valid { "strong" } else { "medium" })?;
    if descriptor & 0x08 != 0 {
        d.set_item("error", "zstd_reserved_bit_set")?;
        damage_flags.push("zstd_reserved_bit_set");
    } else if !valid {
        d.set_item("error", "zstd_frame_validation_failed")?;
        damage_flags.push(if !last {
            "probably_truncated"
        } else {
            "zstd_frame_bad"
        });
    }
    apply_structural_contract(
        &d,
        path,
        file_size,
        file_size,
        StructuralStreamKind::Zstd,
        decode_ok && checksum,
        &mut damage_flags,
    )?;
    d.set_item("damage_flags", PyList::new(py, damage_flags)?)?;
    d.set_item("file_size", file_size)?;
    finish_fields(&d, ZSTD_FIELDS)?;
    Ok(d.unbind())
}
