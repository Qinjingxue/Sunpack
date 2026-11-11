use crate::scan::compression_stream::{
    analyze_gzip_structure, validate_bzip2_identity, validate_bzip2_structure,
    validate_gzip_structure, validate_xz_identity, validate_xz_structure_exact,
    validate_zstd_structure, StructureValidation, BZIP2_IDENTITY_BYTES,
};
use std::io::Cursor;

const EAGER_STREAM_INTEGRITY_MAX_BYTES: u64 = 4 * 1024 * 1024;
const STREAM_STRUCTURE_DECODE_MAX_BYTES: u64 = 8 * 1024 * 1024;

// Integrity probes need a byte count, not the expanded payload. Retain only a
// fixed buffer, including when many archives reach the decode limit together.
fn count_decoded(reader: &mut impl Read) -> (u64, std::io::Result<()>) {
    let mut limited = reader.take(STREAM_STRUCTURE_DECODE_MAX_BYTES + 1);
    let mut buffer = [0u8; 8192];
    let mut count = 0u64;
    loop {
        match limited.read(&mut buffer) {
            Ok(0) => return (count, Ok(())),
            Ok(size) => count += size as u64,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return (count, Err(error)),
        }
    }
}

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

impl StructuralStreamKind {
    fn from_header(header: &[u8]) -> Option<Self> {
        if header.starts_with(b"\x1f\x8b") {
            Some(Self::Gzip)
        } else if header.starts_with(b"BZh") {
            Some(Self::Bzip2)
        } else if header.starts_with(XZ_MAGIC) {
            Some(Self::Xz)
        } else if header.starts_with(ZSTD_MAGIC) {
            Some(Self::Zstd)
        } else {
            None
        }
    }

    fn validate(
        self,
        reader: &ManagedReader,
        limit: u64,
    ) -> Result<StructureValidation, crate::scan::compression_stream::ValidationError> {
        match self {
            Self::Gzip => validate_gzip_structure(reader, 0, limit),
            Self::Bzip2 => validate_bzip2_structure(reader, 0, limit),
            Self::Xz => validate_xz_structure_exact(reader, 0, limit),
            Self::Zstd => validate_zstd_structure(reader, 0, limit),
        }
    }
}

const IDENTITY_PROBE_MAX_BYTES: u64 = 64 * 1024;

struct CompressionIdentityResult {
    format: &'static str,
    plausible: bool,
    error: &'static str,
}

fn compression_identity_result(
    format: &'static str,
    _ext: &'static str,
    _magic_matched: bool,
    _file_size: u64,
    _bytes_read: u64,
    plausible: bool,
    error: &'static str,
    _evidence: &[&'static str],
) -> CompressionIdentityResult {
    CompressionIdentityResult {
        format,
        plausible,
        error,
    }
}

const GZIP_IDENTITY_PAYLOAD_BYTES: usize = 1024;

fn validate_gzip_identity_payload(input: &[u8]) -> Result<(), &'static str> {
    use flate2::{Decompress, FlushDecompress, Status};

    let mut decoder = Decompress::new(false);
    let mut output = [0; GZIP_IDENTITY_PAYLOAD_BYTES];
    let status = decoder
        .decompress(input, &mut output, FlushDecompress::None)
        .map_err(|_| "gzip_deflate_prefix_invalid")?;
    let produced = decoder.total_out() as usize;
    if status == Status::StreamEnd {
        let tail = decoder.total_in() as usize;
        if let Some(trailer) = input[tail..].first_chunk::<8>() {
            if trailer[..4] != crc32(&output[..produced]).to_le_bytes()
                || trailer[4..] != (produced as u32).to_le_bytes()
            {
                return Err("gzip_trailer_mismatch");
            }
            return Ok(());
        }
        return Err("gzip_trailer_missing");
    }
    if produced == 0 {
        return Err("gzip_deflate_prefix_unconfirmed");
    }
    Ok(())
}

fn inspect_compression_stream_identity_impl(path: &str) -> CompressionIdentityResult {
    let reader = match ManagedReader::open(path) {
        Ok(value) => value,
        Err(_) => return compression_identity_result("", "", false, 0, 0, false, "os_error", &[]),
    };
    let file_size = reader.len();
    let read_size = file_size.min(BZIP2_IDENTITY_BYTES as u64) as usize;
    let mut data = match reader.read_direct_at(0, read_size) {
        Ok(value) => value,
        Err(_) => {
            return compression_identity_result("", "", false, file_size, 0, false, "os_error", &[])
        }
    };

    if data.starts_with(b"\x1f\x8b")
        && data.get(3).is_some_and(|flags| flags & 0x1e != 0)
        && file_size > data.len() as u64
    {
        let expanded = file_size.min(IDENTITY_PROBE_MAX_BYTES) as usize;
        data = match reader.read_direct_at(0, expanded) {
            Ok(value) => value,
            Err(_) => {
                return compression_identity_result(
                    "gzip",
                    ".gz",
                    true,
                    file_size,
                    data.len() as u64,
                    false,
                    "gzip_header_read_failed",
                    &["gzip:magic"],
                )
            }
        };
    }
    let base_bytes_read = data.len() as u64;
    if crate::formats::lz4::leading(&data) {
        let identity = crate::formats::lz4::identity(&reader, 0);
        // Skippable magic is shared with Zstandard and does not establish LZ4.
        if identity != Ok(false) {
            let (valid, error) = match identity {
                Ok(valid) => (valid, ""),
                Err(e) => (false, e),
            };
            let bytes_read = reader
                .stats()
                .map(|s| s.read_bytes)
                .unwrap_or(base_bytes_read);
            return compression_identity_result(
                "lz4",
                ".lz4",
                true,
                file_size,
                bytes_read,
                valid,
                error,
                &["lz4:header"],
            );
        }
    }

    if data.starts_with(b"\x1f\x8b") {
        let parsed = match crate::scan::compression_stream::gzip_header_from_slice(&data, 0) {
            Ok(value) => value,
            Err(error) => {
                return compression_identity_result(
                    "gzip",
                    ".gz",
                    true,
                    file_size,
                    base_bytes_read,
                    false,
                    error.code(),
                    &["gzip:magic"],
                )
            }
        };
        let (bytes_read, payload) = {
            let wanted = (file_size - parsed.payload_start)
                .min((GZIP_IDENTITY_PAYLOAD_BYTES + 8) as u64) as usize;
            let available = &data[parsed.payload_start as usize..];
            if available.len() >= wanted {
                (
                    base_bytes_read,
                    std::borrow::Cow::Borrowed(&available[..wanted]),
                )
            } else {
                match reader.read_direct_at(parsed.payload_start, wanted) {
                    Ok(bytes) => (
                        base_bytes_read + bytes.len() as u64,
                        std::borrow::Cow::Owned(bytes),
                    ),
                    Err(_) => {
                        return compression_identity_result(
                            "gzip",
                            ".gz",
                            true,
                            file_size,
                            base_bytes_read,
                            false,
                            "os_error",
                            &["gzip:header"],
                        )
                    }
                }
            }
        };
        let result = validate_gzip_identity_payload(&payload);
        return compression_identity_result(
            "gzip",
            ".gz",
            true,
            file_size,
            bytes_read,
            result.is_ok(),
            result.err().unwrap_or(""),
            &[],
        );
    }

    if data.starts_with(b"BZh") {
        let (plausible, error, evidence): (_, _, &[_]) =
            match validate_bzip2_identity(&data, file_size) {
                Ok(true) => (
                    true,
                    "",
                    &["bzip2:magic", "bzip2:block_size", "bzip2:end_marker"],
                ),
                Ok(false) => (
                    true,
                    "",
                    &[
                        "bzip2:magic",
                        "bzip2:block_size",
                        "bzip2:first_block_marker",
                        "bzip2:first_block_header",
                    ],
                ),
                Err(error) => (false, error.code(), &["bzip2:magic"]),
            };
        return compression_identity_result(
            "bzip2",
            ".bz2",
            true,
            file_size,
            base_bytes_read,
            plausible,
            error,
            evidence,
        );
    }

    if data.starts_with(XZ_MAGIC) {
        let result = validate_xz_identity(&data, file_size, |size| reader.read_direct_at(12, size));
        let (plausible, error, extra) = match result {
            Ok(extra) => (true, "", extra as u64),
            Err(error) => (false, error.code(), 0),
        };
        return compression_identity_result(
            "xz",
            ".xz",
            true,
            file_size,
            base_bytes_read + extra,
            plausible,
            error,
            if plausible {
                &[
                    "xz:magic",
                    "xz:header_crc32",
                    "xz:first_block_or_empty_index",
                ]
            } else {
                &["xz:magic"]
            },
        );
    }

    if data.starts_with(ZSTD_MAGIC) {
        if data.len() < 8 {
            return compression_identity_result(
                "zstd",
                ".zst",
                true,
                file_size,
                base_bytes_read,
                false,
                "zstd_frame_header_short",
                &["zstd:magic"],
            );
        }
        let descriptor = data[4];
        if descriptor & 0x18 != 0 {
            return compression_identity_result(
                "zstd",
                ".zst",
                true,
                file_size,
                base_bytes_read,
                false,
                "zstd_reserved_or_unused_bit_set",
                &["zstd:magic"],
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
                    "zstd",
                    ".zst",
                    true,
                    file_size,
                    base_bytes_read,
                    false,
                    "zstd_window_descriptor_missing",
                    &["zstd:magic", "zstd:frame_descriptor"],
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
                "zstd",
                ".zst",
                true,
                file_size,
                base_bytes_read,
                false,
                "zstd_frame_header_overflow",
                &["zstd:magic", "zstd:frame_descriptor"],
            );
        };
        if block_header_offset + 3 > data.len() {
            return compression_identity_result(
                "zstd",
                ".zst",
                true,
                file_size,
                base_bytes_read,
                false,
                "zstd_first_block_header_missing",
                &["zstd:magic", "zstd:frame_descriptor"],
            );
        }
        let block_header = u32::from(data[block_header_offset])
            | (u32::from(data[block_header_offset + 1]) << 8)
            | (u32::from(data[block_header_offset + 2]) << 16);
        let block_type = (block_header >> 1) & 0x03;
        let block_size = u64::from(block_header >> 3);
        if block_type == 3 || block_size > 128 * 1024 {
            return compression_identity_result(
                "zstd",
                ".zst",
                true,
                file_size,
                base_bytes_read,
                false,
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
                "zstd",
                ".zst",
                true,
                file_size,
                base_bytes_read,
                false,
                "zstd_first_block_out_of_range",
                &["zstd:magic", "zstd:frame_descriptor"],
            );
        }
        return compression_identity_result(
            "zstd",
            ".zst",
            true,
            file_size,
            base_bytes_read,
            true,
            "",
            &[
                "zstd:magic",
                "zstd:frame_descriptor",
                "zstd:first_block_header",
            ],
        );
    }

    compression_identity_result(
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

fn inspect_structural_stream(
    reader: &ManagedReader,
    kind: StructuralStreamKind,
) -> std::io::Result<DiagnosticFields> {
    let file_size = reader.len();
    let (format, ext, fields, cost) = match kind {
        StructuralStreamKind::Gzip => ("gzip", ".gz", GZIP_FIELDS, "compressed_token_linear"),
        StructuralStreamKind::Bzip2 => {
            ("bzip2", ".bz2", BZIP2_FIELDS, "compressed_bitstream_linear")
        }
        StructuralStreamKind::Xz => ("xz", ".xz", XZ_FIELDS, "metadata_linear_payload_skipped"),
        StructuralStreamKind::Zstd => (
            "zstd",
            ".zst",
            ZSTD_FIELDS,
            "block_header_linear_payload_skipped",
        ),
    };
    let mut d = compression_base(format, ext, true)?;
    for field in fields {
        d.put(*field, "not_decoded")?;
    }
    d.put("validation_scope", "complete_structure")?;
    d.put("validation_cost", cost)?;
    d.put("file_size", file_size)?;
    let validation = kind.validate(reader, file_size);
    let structure = match validation {
        Ok(value) => value,
        Err(error) => {
            if let crate::scan::compression_stream::ValidationError::Io(error) = error {
                return Err(crate::io::resource_error::to_io_error(error));
            }
            let code = error.code();
            d.put("structure_status", "invalid")?;
            d.put("structure_validation_complete", false)?;
            d.put("boundary_exact", false)?;
            d.put("integrity_status", "failed")?;
            d.put("integrity_validation_complete", true)?;
            d.put("plausible", false)?;
            d.put("confidence", "none")?;
            d.put("error", code)?;
            d.put("damage_flags", [code])?;
            finish_fields(&mut d, fields)?;
            return Ok(d);
        }
    };
    project_structural_validation(&mut d, &structure, file_size)?;
    let trailing = file_size.saturating_sub(structure.end_offset);
    let damage_flags = if trailing > 0 {
        vec!["trailing_junk"]
    } else {
        Vec::new()
    };
    d.put("plausible", true)?;
    d.put("confidence", "strong")?;
    d.put("structure_status", "complete")?;
    d.put("structure_validation_complete", true)?;
    d.put("boundary_exact", true)?;
    d.put("segment_end", structure.end_offset)?;
    d.put("archive.trailing_data", trailing)?;
    d.put("trailing_data_verified", true)?;
    d.put("integrity_status", structure.integrity.as_str())?;
    d.put("integrity_validation_complete", false)?;
    d.put("checksum_present", structure.checksum_present)?;
    d.put("damage_flags", damage_flags)?;
    finish_fields(&mut d, fields)?;
    Ok(d)
}

fn project_structural_validation(
    d: &mut DiagnosticFields,
    structure: &StructureValidation,
    file_size: u64,
) -> std::io::Result<()> {
    d.put("structure.stream_count", structure.stream_count)?;
    d.put("structure.block_count", structure.block_count)?;
    d.put(
        "structure.compressed_bytes",
        structure.end_offset.min(file_size),
    )?;
    d.put("structure.decoded_size", structure.decoded_size)?;
    Ok(())
}

fn apply_structural_contract(
    d: &mut DiagnosticFields,
    reader: &ManagedReader,
    validation_limit: u64,
    kind: StructuralStreamKind,
    // End offset of the prefix the eager decoder checked; integrity is only
    // verified when that prefix covers the whole validated structure.
    integrity_verified_end: Option<u64>,
    damage_flags: &mut Vec<&'static str>,
) -> std::io::Result<()> {
    let file_size = reader.len();
    let validation = kind.validate(reader, validation_limit);
    match validation {
        Ok(structure) => {
            let trailing = file_size.saturating_sub(structure.end_offset);
            if trailing > 0 && !damage_flags.contains(&"trailing_junk") {
                damage_flags.push("trailing_junk");
            }
            let integrity = if integrity_verified_end.is_some_and(|end| end >= structure.end_offset)
                && structure.checksum_present
            {
                "verified"
            } else {
                structure.integrity.as_str()
            };
            d.put("validation_scope", "complete_structure")?;
            d.put("structure_status", "complete")?;
            d.put("structure_validation_complete", true)?;
            d.put("boundary_exact", true)?;
            d.put("segment_end", structure.end_offset)?;
            d.put("archive.trailing_data", trailing)?;
            d.put("trailing_data_verified", true)?;
            d.put("integrity_status", integrity)?;
            d.put("integrity_validation_complete", integrity == "verified")?;
            d.put("checksum_present", structure.checksum_present)?;
            project_structural_validation(d, &structure, file_size)?;
        }
        Err(error) => {
            if let crate::scan::compression_stream::ValidationError::Io(error) = error {
                return Err(crate::io::resource_error::to_io_error(error));
            }
            let code = error.code();
            if !damage_flags.contains(&code) {
                damage_flags.push(code);
            }
            d.put("structure_status", "invalid")?;
            d.put("structure_validation_complete", false)?;
            d.put("boundary_exact", false)?;
            d.put("integrity_status", "failed")?;
            d.put("integrity_validation_complete", true)?;
            d.put("plausible", false)?;
            d.put("confidence", "none")?;
            d.put("error", code)?;
        }
    }
    Ok(())
}

fn compression_base(format: &str, ext: &str, magic: bool) -> std::io::Result<DiagnosticFields> {
    let mut d = dict()?;
    d.put("plausible", false)?;
    d.put("error", "")?;
    d.put("magic_matched", magic)?;
    d.put("format", format)?;
    d.put("detected_ext", ext)?;
    d.put("confidence", "none")?;
    d.put("evidence", Vec::<&str>::new())?;
    Ok(d)
}

fn finish_fields(d: &mut DiagnosticFields, fields: &[&str]) -> std::io::Result<()> {
    let mut missing = Vec::<&str>::new();
    for field in fields {
        if !d.contains_key(*field) {
            d.put(field, "unavailable")?;
            missing.push(*field);
        }
    }
    d.put("semantic_field_count", fields.len())?;
    d.put("semantic_fields", fields)?;
    d.put("semantic_missing_fields", missing)?;
    Ok(())
}

fn compression_empty(
    error: &str,
    format: &str,
    ext: &str,
    magic: bool,
) -> std::io::Result<DiagnosticFields> {
    let mut d = compression_base(format, ext, magic)?;
    d.put("error", error)?;
    Ok(d)
}

fn hex_bytes(value: &[u8]) -> String {
    value.iter().map(|b| format!("{b:02x}")).collect()
}

fn inspect_gzip(reader: &ManagedReader) -> std::io::Result<DiagnosticFields> {
    let file_size = reader.len();
    let data = (reader.read_all()).map_err(crate::io::resource_error::to_io_error)?;
    let mut d = compression_base("gzip", ".gz", data.starts_with(b"\x1f\x8b"))?;
    let mut damage_flags = Vec::new();
    d.put(
        "member.header.magic",
        hex_bytes(data.get(0..2).unwrap_or(&[])),
    )?;
    let parsed = match crate::scan::compression_stream::gzip_header_from_slice(&data, 0) {
        Ok(value) => value,
        Err(error) => {
            d.put("error", error.code())?;
            d.put("damage_flags", [error.code()])?;
            finish_fields(&mut d, GZIP_FIELDS)?;
            return Ok(d);
        }
    };
    d.put("member.header.compression_method", data[2])?;
    d.put("member.header.flags", parsed.flags)?;
    d.put(
        "member.header.mtime_xfl_os",
        format!("mtime={};xfl={};os={}", u32_le(&data, 4), data[8], data[9]),
    )?;
    if let Some(range) = parsed.extra {
        d.put("member.header.extra_length", range.len())?;
        d.put("member.header.extra", hex_bytes(&data[range]))?;
    } else {
        d.put("member.header.extra_length", 0)?;
        d.put("member.header.extra", "absent")?;
    }
    for (key, range) in [
        ("member.header.name", parsed.name),
        ("member.header.comment", parsed.comment),
    ] {
        d.put(
            key,
            range
                .map(|range| String::from_utf8_lossy(&data[range]).into_owned())
                .unwrap_or_else(|| "absent".to_string()),
        )?;
    }
    d.put(
        "member.header.crc16",
        parsed
            .crc16
            .map(|crc| format!("stored={crc};computed={crc};ok=true"))
            .unwrap_or_else(|| "absent".to_string()),
    )?;

    // Move the bounded compressed input into the canonical reader so the structural
    // walk and integrity observer share one byte source without cloning the file.
    let reader = ManagedReader::from_bytes(data, crate::io::reader::ReaderConfig::default());
    let analysis =
        match analyze_gzip_structure(&reader, 0, file_size, STREAM_STRUCTURE_DECODE_MAX_BYTES) {
            Ok(value) => value,
            Err(error) => {
                let code = error.code();
                if !damage_flags.contains(&code) {
                    damage_flags.push(code);
                }
                d.put("structure_status", "invalid")?;
                d.put("structure_validation_complete", false)?;
                d.put("boundary_exact", false)?;
                d.put("integrity_status", "failed")?;
                d.put("integrity_validation_complete", true)?;
                d.put("plausible", false)?;
                d.put("confidence", "none")?;
                d.put("error", code)?;
                d.put("damage_flags", damage_flags)?;
                d.put("file_size", file_size)?;
                finish_fields(&mut d, GZIP_FIELDS)?;
                return Ok(d);
            }
        };
    let structure = &analysis.structure;
    let integrity = structure.integrity.as_str();
    if integrity == "failed" && !damage_flags.contains(&"gzip_footer_bad") {
        damage_flags.push("gzip_footer_bad");
    }

    d.put(
        "member.deflate.blocks",
        format!(
            "compressed_bytes={};block_count={};decoder_status=Ok(())",
            analysis.first_member_compressed_bytes, analysis.first_member_block_count
        ),
    )?;
    d.put("member.deflate.final_block", true)?;
    d.put("member.decoded_content", analysis.first_member_decoded_size)?;
    if let Some(computed) = analysis.first_member_computed_crc32 {
        d.put(
            "member.trailer.crc32",
            format!(
                "stored={};computed={computed};ok={}",
                analysis.first_member_stored_crc32,
                analysis.first_member_stored_crc32 == computed
            ),
        )?;
    } else {
        d.put(
            "member.trailer.crc32",
            format!(
                "stored={};computed=deferred;ok=deferred",
                analysis.first_member_stored_crc32
            ),
        )?;
    }
    d.put(
        "member.trailer.isize",
        format!(
            "stored={};decoded_mod={};ok=true",
            analysis.first_member_stored_size, analysis.first_member_decoded_size as u32
        ),
    )?;
    d.put("member.boundary", analysis.first_member_end)?;
    d.put("member.next_member", structure.stream_count > 1)?;

    let trailing = file_size.saturating_sub(structure.end_offset);
    d.put("archive.trailing_data", trailing)?;
    if trailing > 0 && !damage_flags.contains(&"trailing_junk") {
        damage_flags.push("trailing_junk");
    }
    d.put("trailing_data_verified", true)?;
    d.put("plausible", true)?;
    d.put("confidence", "strong")?;
    d.put("validation_scope", "complete_structure")?;
    d.put(
        "validation_cost",
        "compressed_token_linear+bounded_integrity",
    )?;
    d.put("structure_status", "complete")?;
    d.put("structure_validation_complete", true)?;
    d.put("boundary_exact", true)?;
    d.put("segment_end", structure.end_offset)?;
    d.put("integrity_status", integrity)?;
    d.put(
        "integrity_validation_complete",
        integrity == "verified" || integrity == "failed",
    )?;
    d.put("checksum_present", structure.checksum_present)?;
    project_structural_validation(&mut d, structure, file_size)?;
    d.put("damage_flags", damage_flags)?;
    d.put("file_size", file_size)?;
    finish_fields(&mut d, GZIP_FIELDS)?;
    Ok(d)
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
    let aligned = marker.to_be_bytes();
    let finder = memchr::memmem::Finder::new(&aligned[2..]);
    let mut start = 0;
    while let Some(index) = finder.find(&data[start..]) {
        let index = start + index;
        output.push(index * 8);
        start = index + 1;
    }
    if data.len() < 7 {
        return output;
    }
    // A non-byte-aligned 48-bit marker spans seven bytes. Search its five
    // complete middle bytes, then check the two partial bytes. Searching all
    // eight alignments retains markers crossing block and stream boundaries.
    for shift in 1usize..8 {
        let pattern = (marker << (8 - shift)).to_be_bytes();
        let finder = memchr::memmem::Finder::new(&pattern[2..7]);
        let mut start = 1;
        while let Some(index) = finder.find(&data[start..]) {
            let index = start + index;
            if index + 5 < data.len()
                && data[index - 1] & ((1u8 << (8 - shift)) - 1) == pattern[1]
                && data[index + 5] & (u8::MAX << (8 - shift)) == pattern[7]
            {
                output.push((index - 1) * 8 + shift);
            }
            // Preserve overlapping matches too; callers receive bit order.
            start = index + 1;
        }
    }
    output.sort_unstable();
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

fn inspect_bzip2(reader: &ManagedReader) -> std::io::Result<DiagnosticFields> {
    let file_size = reader.len();
    let data = (reader.read_all()).map_err(crate::io::resource_error::to_io_error)?;
    let magic = data.starts_with(b"BZh") && data.get(3).is_some_and(|v| b"123456789".contains(v));
    let mut d = compression_base("bzip2", ".bz2", magic)?;
    let mut damage_flags = Vec::new();
    d.put(
        "stream.magic",
        String::from_utf8_lossy(data.get(0..3).unwrap_or(&[])).to_string(),
    )?;
    d.put(
        "stream.block_size_100k",
        data.get(3).map(|v| v.saturating_sub(b'0')).unwrap_or(0),
    )?;
    if !magic {
        d.put("error", "bzip2_magic_not_found")?;
        finish_fields(&mut d, BZIP2_FIELDS)?;
        return Ok(d);
    }
    let (blocks, ends) = (|| {
        (
            marker_positions(&data, 0x314159265359),
            marker_positions(&data, 0x177245385090),
        )
    })();
    d.put(
        "block.marker",
        blocks.first().map(|v| *v as u64).unwrap_or(u64::MAX),
    )?;
    d.put("block.sequence", blocks.len())?;
    if let Some(bit) = blocks.first() {
        let mut reader = BitReader {
            data: &data,
            bit: bit + 48,
        };
        let block_crc = reader.read(32).unwrap_or(0) as u32;
        let randomized = reader.read(1).unwrap_or(0) != 0;
        let orig_ptr = reader.read(24).unwrap_or(0);
        d.put("block.crc32", block_crc)?;
        d.put("block.randomized", randomized)?;
        d.put("block.orig_ptr", orig_ptr)?;
        d.put(
            "block.huffman_tables",
            bzip_huffman_summary(&data, reader.bit),
        )?;
        let end_bit = blocks
            .get(1)
            .copied()
            .or_else(|| ends.first().copied())
            .unwrap_or(data.len() * 8);
        d.put("block.encoded_data", end_bit.saturating_sub(reader.bit))?;
    }
    d.put("stream.end_marker", !ends.is_empty())?;
    if let Some(bit) = ends.first() {
        let mut reader = BitReader {
            data: &data,
            bit: bit + 48,
        };
        d.put("stream.combined_crc32", reader.read(32).unwrap_or(0) as u32)?;
    }
    let mut decoder = bzip2::read::BzDecoder::new(Cursor::new(data.as_slice()));
    let (decoded_size, decode_status) = count_decoded(&mut decoder);
    let decode_limited = decoded_size > STREAM_STRUCTURE_DECODE_MAX_BYTES;
    let decode_ok = decode_status.is_ok() && !decode_limited;
    let marker_boundary = ends
        .first()
        .map(|bit| (bit + 48 + 32 + 7) / 8)
        .unwrap_or(data.len());
    let consumed = decoder.get_ref().position() as usize;
    d.put("block.decoded_content", decoded_size)?;
    let trailing = if decode_limited {
        0
    } else {
        data.len().saturating_sub(marker_boundary.min(consumed))
    };
    // The single-stream decoder stops at the first end marker; concatenated
    // streams are not trailing data.  The structural contract below walks every
    // stream and owns the trailing_junk decision.
    d.put("archive.trailing_data", trailing)?;
    d.put("trailing_data_verified", decode_ok)?;
    d.put(
        "plausible",
        (decode_ok && !ends.is_empty()) || (decode_limited && magic),
    )?;
    d.put("confidence", if decode_ok { "strong" } else { "medium" })?;
    if ends.is_empty() && !decode_limited {
        damage_flags.push("probably_truncated");
    }
    if !decode_ok && !decode_limited {
        d.put("error", "bzip2_decode_failed")?;
        damage_flags.push("bzip2_block_bad");
    }
    apply_structural_contract(
        &mut d,
        reader,
        file_size,
        StructuralStreamKind::Bzip2,
        decode_ok.then_some(marker_boundary as u64),
        &mut damage_flags,
    )?;
    d.put("damage_flags", damage_flags)?;
    d.put("file_size", file_size)?;
    finish_fields(&mut d, BZIP2_FIELDS)?;
    Ok(d)
}

fn read_vli(data: &[u8], cursor: &mut usize) -> Option<u64> {
    crate::scan::compression_stream::read_vli_slice(data, cursor).ok()
}

struct XzIndexRecords<'a> {
    data: &'a [u8],
    start: usize,
    count: u64,
    unpadded: u64,
    uncompressed: u64,
    padded: u64,
}

impl XzIndexRecords<'_> {
    fn iter(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        let mut cursor = self.start;
        (0..self.count).map(move |_| {
            // The immutable record slice was validated when building totals.
            (
                read_vli(self.data, &mut cursor).unwrap(),
                read_vli(self.data, &mut cursor).unwrap(),
            )
        })
    }
}

fn xz_index_records<'a>(
    data: &'a [u8],
    cursor: &mut usize,
    count: u64,
) -> Option<XzIndexRecords<'a>> {
    if count > (data.len().saturating_sub(*cursor) / 2) as u64 {
        return None;
    }
    let mut records = XzIndexRecords {
        data,
        start: *cursor,
        count,
        unpadded: 0,
        uncompressed: 0,
        padded: 0,
    };
    for _ in 0..count {
        let unpadded = read_vli(data, cursor)?;
        let uncompressed = read_vli(data, cursor)?;
        if unpadded == 0 {
            return None;
        }
        records.unpadded = records.unpadded.checked_add(unpadded)?;
        records.uncompressed = records.uncompressed.checked_add(uncompressed)?;
        records.padded = records
            .padded
            .checked_add(unpadded)?
            .checked_add((4 - unpadded % 4) % 4)?;
    }
    Some(records)
}

fn xz_block_header_fields(header: &[u8]) -> Option<(Option<u64>, Option<u64>, Vec<String>)> {
    // The caller excludes the header CRC; no VLI or property may consume it
    // (or compressed bytes belonging to the following block payload).
    let flags = *header.get(1)?;
    let mut cursor = 2;
    let compressed = if flags & 0x40 != 0 {
        Some(read_vli(header, &mut cursor)?)
    } else {
        None
    };
    let uncompressed = if flags & 0x80 != 0 {
        Some(read_vli(header, &mut cursor)?)
    } else {
        None
    };
    let mut filters = Vec::new();
    for _ in 0..(flags & 0x03) + 1 {
        let id = read_vli(header, &mut cursor)?;
        let prop_size = usize::try_from(read_vli(header, &mut cursor)?).ok()?;
        let end = cursor.checked_add(prop_size)?;
        let props = header.get(cursor..end)?;
        filters.push(format!("id={id}:props={}", hex_bytes(props)));
        cursor = end;
    }
    Some((compressed, uncompressed, filters))
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

#[cfg(test)]
mod xz_bounds_tests {
    use super::*;
    use std::io::Write;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn bzip_markers_preserve_bit_alignments_and_truncated_edges() {
        let mut data = (0..65544usize)
            .map(|i| (i * 73 + 19) as u8)
            .collect::<Vec<_>>();
        for (marker, base) in [(0x314159265359u64, 32), (0x177245385090, 1024)] {
            for shift in 0..8 {
                let start = base + shift * 128 + shift;
                for bit in 0..48 {
                    let mask = 1u8 << (7 - (start + bit) % 8);
                    let byte = &mut data[(start + bit) / 8];
                    *byte = (*byte & !mask) | (((marker >> (47 - bit)) as u8 & 1) * mask);
                }
            }
        }
        // A marker straddling a common read window must keep its physical bit offset.
        let edge = 65536 * 8 - 3;
        for bit in 0..48 {
            let mask = 1u8 << (7 - (edge + bit) % 8);
            let byte = &mut data[(edge + bit) / 8];
            *byte = (*byte & !mask) | (((0x314159265359u64 >> (47 - bit)) as u8 & 1) * mask);
        }
        for length in (0..=32).chain([edge / 8 + 6, edge / 8 + 7, data.len()]) {
            for marker in [0x314159265359, 0x177245385090] {
                let sample = &data[..length];
                let mut expected = Vec::new();
                let mut window = 0u64;
                for bit in 0..sample.len() * 8 {
                    window = ((window << 1) | u64::from((sample[bit / 8] >> (7 - bit % 8)) & 1))
                        & 0xffff_ffff_ffff;
                    if bit >= 47 && window == marker {
                        expected.push(bit + 1 - 48);
                    }
                }
                assert_eq!(marker_positions(sample, marker), expected);
            }
        }
        assert!(marker_positions(&data, 0x314159265359).contains(&edge));
    }

    #[test]
    fn index_count_and_records_are_bounded_by_available_bytes() {
        let mut largest_vli = [0xff; 9];
        largest_vli[8] = 0x7f;
        assert_eq!(read_vli(&largest_vli, &mut 0), Some((1 << 63) - 1));
        assert_eq!(read_vli(&[0xff; 9], &mut 0), None);
        assert!(xz_index_records(&[1, 1], &mut 0, 1 << 56).is_none());
        assert!(xz_index_records(&[1, 0x80], &mut 0, 1).is_none());
        assert!(xz_index_records(&[0, 0], &mut 0, 1).is_none());
        assert!(xz_index_records(&[1, 1], &mut 3, 1).is_none());
        assert_eq!(
            xz_index_records(&[12, 3, 16, 5], &mut 0, 2).map(|r| r.iter().collect::<Vec<_>>()),
            Some(vec![(12, 3), (16, 5)])
        );
    }

    #[test]
    fn block_fields_cannot_read_past_header_payload() {
        for header in [
            &[1, 0, 0x80, 0x80][..],    // Filter ID spills into the CRC.
            &[1, 0, 0x21, 0x80][..],    // Property length spills into the CRC.
            &[1, 0, 0x21, 1][..],       // Property itself is absent.
            &[1, 0x40, 0x80, 0x80][..], // Declared size spills into the CRC.
            &[1, 0x80, 0x80, 0x80][..],
            &[1, 1, 0x21, 0][..], // Second filter is absent.
        ] {
            assert!(xz_block_header_fields(header).is_none(), "{header:?}");
        }
        let fields = xz_block_header_fields(&[2, 0, 0x21, 1, 0x16, 0, 0, 0]).unwrap();
        assert_eq!(fields.2, vec!["id=33:props=16"]);
    }

    fn malformed_stream(block: &[u8], index: &[u8]) -> Vec<u8> {
        let mut data = XZ_MAGIC.to_vec();
        data.extend_from_slice(&[0, 0]);
        data.extend_from_slice(&crc32(&[0, 0]).to_le_bytes());
        data.extend_from_slice(block);
        let index_start = data.len();
        data.extend_from_slice(index);
        while (data.len() - index_start) % 4 != 0 {
            data.push(0);
        }
        data.extend_from_slice(&crc32(&data[index_start..]).to_le_bytes());
        let backward = ((data.len() - index_start) / 4 - 1) as u32;
        let mut footer = backward.to_le_bytes().to_vec();
        footer.extend_from_slice(&[0, 0]);
        data.extend_from_slice(&crc32(&footer).to_le_bytes());
        data.extend_from_slice(&footer);
        data.extend_from_slice(b"YZ");
        data
    }

    fn inspect_fixture(data: &[u8], check: impl FnOnce(&DiagnosticFields)) {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "sunpack-xz-bounds-{}-{}.bin",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::write(&path, data).unwrap();
        let result = inspect_compression_stream_structure(path.to_str().unwrap()).unwrap();
        check(&result);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn public_inspector_rejects_huge_index_and_spilling_block_header() {
        let huge_count =
            malformed_stream(&[], &[0, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 1]);
        let spilling_header = malformed_stream(&[1, 0, 0x80, 0x80, 1, 1, 0, 0], &[0, 1, 8, 0]);
        for (data, flag) in [
            (huge_count, "xz_index_bad"),
            (spilling_header, "xz_block_header_bad"),
        ] {
            inspect_fixture(&data, |result| {
                let flags: Vec<String> =
                    serde_json::from_value(result["damage_flags"].clone()).unwrap();
                assert!(flags.iter().any(|value| value == flag), "{flags:?}");
                assert_eq!(result.get("block.sequence").unwrap().as_u64().unwrap(), 0);
            });
        }
    }

    #[test]
    fn public_inspector_keeps_valid_xz_records_and_properties() {
        let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 1);
        encoder.write_all(b"payload").unwrap();
        inspect_fixture(&encoder.finish().unwrap(), |result| {
            assert!(result.get("plausible").unwrap().as_bool().unwrap());
            assert_eq!(
                result.get("index.record_count").unwrap().as_u64().unwrap(),
                1
            );
            assert_eq!(result.get("block.sequence").unwrap().as_u64().unwrap(), 1);
            assert_eq!(
                result
                    .get("index.records.uncompressed_size")
                    .unwrap()
                    .as_u64()
                    .unwrap(),
                7
            );
        });
    }
}

fn inspect_xz(reader: &ManagedReader) -> std::io::Result<DiagnosticFields> {
    let file_size = reader.len();
    let data = (reader.read_all()).map_err(crate::io::resource_error::to_io_error)?;
    let mut d = compression_base("xz", ".xz", data.starts_with(XZ_MAGIC))?;
    let mut damage_flags = Vec::new();
    d.put(
        "stream.header.magic",
        hex_bytes(data.get(..6).unwrap_or(&[])),
    )?;
    if data.len() < 24 || !data.starts_with(XZ_MAGIC) {
        d.put("error", "xz_header_or_footer_missing")?;
        finish_fields(&mut d, XZ_FIELDS)?;
        return Ok(d);
    }
    let flags = &data[6..8];
    let header_crc = u32_le(&data, 8);
    d.put("stream.header.flags", hex_bytes(flags))?;
    d.put(
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

    let footer_start = (|| {
        (10..data.len())
            .rev()
            .find_map(|magic_end| {
                if data.get(magic_end - 1..=magic_end) != Some(b"YZ".as_slice())
                    || magic_end + 1 < 12
                {
                    return None;
                }
                let start = magic_end + 1 - 12;
                let footer = &data[start..start + 12];
                (u32_le(footer, 0) == crc32(&footer[4..10])).then_some(start)
            })
            .unwrap_or(data.len() - 12)
    })();
    let footer = &data[footer_start..];
    let footer_crc = u32_le(footer, 0);
    let backward_size = (u32_le(footer, 4) as u64 + 1) * 4;
    d.put(
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
    // Concatenated streams may use different checks. The canonical structural
    // walk compares each footer to its own header.
    d.put("stream.footer.backward_size", backward_size)?;
    d.put("stream.footer.flags", hex_bytes(&footer[8..10]))?;
    d.put("stream.footer.magic", hex_bytes(&footer[10..12]))?;
    let index_start = footer_start
        .checked_sub(backward_size as usize)
        .unwrap_or(0);
    let index_crc_pos = footer_start.saturating_sub(4);
    let index_data = &data[..index_crc_pos];
    let mut index_cursor = index_start;
    let index_valid_start = index_start >= 12 && index_data.get(index_cursor) == Some(&0);
    d.put("index.indicator", index_valid_start)?;
    if !index_valid_start {
        damage_flags.push("xz_index_bad");
    }
    index_cursor = index_cursor.saturating_add(1);
    let record_count = read_vli(index_data, &mut index_cursor);
    d.put("index.record_count", record_count.unwrap_or(0))?;
    let records = record_count
        .filter(|_| index_valid_start)
        .and_then(|count| xz_index_records(index_data, &mut index_cursor, count))
        .unwrap_or_else(|| {
            damage_flags.push("xz_index_bad");
            XzIndexRecords {
                data: &[],
                start: 0,
                count: 0,
                unpadded: 0,
                uncompressed: 0,
                padded: 0,
            }
        });
    d.put("index.records.unpadded_size", records.unpadded)?;
    d.put("index.records.uncompressed_size", records.uncompressed)?;
    d.put("index.padding", index_crc_pos.saturating_sub(index_cursor))?;
    if index_crc_pos + 4 <= data.len() && index_start <= index_crc_pos {
        let stored = u32_le(&data, index_crc_pos);
        let computed = crc32(&data[index_start..index_crc_pos]);
        let ok = stored == computed;
        d.put(
            "index.crc32",
            format!("stored={stored};computed={};ok={ok}", computed),
        )?;
        if !ok {
            damage_flags.push("xz_index_bad");
        }
    }

    let mut block_cursor = index_start.saturating_sub(records.padded as usize);
    let mut block_count = 0usize;
    let mut total_compressed = 0u64;
    let mut total_padding = 0usize;
    let mut first_filters = String::new();
    let check_size = xz_check_size(footer[9] & 0x0f);
    let mut first_header = None;
    (|| {
        for (unpadded, expected_uncompressed) in records.iter() {
            if block_cursor >= index_start {
                break;
            }
            let header_size = (data[block_cursor] as usize + 1) * 4;
            if block_cursor + header_size > index_start || header_size < 8 {
                damage_flags.push("xz_block_header_bad");
                break;
            }
            let block_flags = data[block_cursor + 1];
            let Some((declared_compressed, declared_uncompressed, filters)) =
                xz_block_header_fields(&data[block_cursor..block_cursor + header_size - 4])
            else {
                damage_flags.push("xz_block_header_bad");
                break;
            };
            if first_filters.is_empty() {
                first_filters = filters.join(",");
            }
            let stored_header_crc = u32_le(&data, block_cursor + header_size - 4);
            if block_count == 0 {
                first_header = Some((
                    header_size,
                    block_flags,
                    declared_compressed
                        .unwrap_or(unpadded.saturating_sub(header_size as u64 + check_size as u64)),
                    declared_uncompressed.unwrap_or(expected_uncompressed),
                    stored_header_crc,
                    crc32(&data[block_cursor..block_cursor + header_size - 4]),
                ));
            }
            let compressed_size = declared_compressed
                .unwrap_or(unpadded.saturating_sub(header_size as u64 + check_size as u64));
            total_compressed = total_compressed.saturating_add(compressed_size);
            let unpadded_actual = header_size as u64 + compressed_size + check_size as u64;
            let padding = ((4 - unpadded_actual % 4) % 4) as usize;
            total_padding += padding;
            block_cursor = block_cursor.saturating_add(unpadded_actual as usize + padding);
            block_count += 1;
        }
    })();
    if let Some((size, flags, compressed, uncompressed, stored, computed)) = first_header {
        d.put("block.header.size", size)?;
        d.put("block.header.flags", flags)?;
        d.put("block.header.compressed_size", compressed)?;
        d.put("block.header.uncompressed_size", uncompressed)?;
        d.put(
            "block.header.crc32",
            format!(
                "stored={stored};computed={computed};ok={}",
                stored == computed
            ),
        )?;
    }
    d.put("block.header.filters", first_filters)?;
    d.put("block.compressed_data", total_compressed)?;
    d.put("block.padding", total_padding)?;
    d.put(
        "block.check",
        format!("type={};size={check_size}", flags[1] & 0x0f),
    )?;
    d.put("block.sequence", block_count)?;
    let after_footer = footer_start + 12;
    let zero_padding = data[after_footer..].iter().take_while(|b| **b == 0).count();
    let aligned_padding = zero_padding - zero_padding % 4;
    // Structure analysis does not need an LZMA dictionary. The Index already
    // provides decoded sizes; payload checks remain deferred until extraction.
    d.put("block.uncompressed_data", records.uncompressed)?;
    let stream_count = data.windows(6).filter(|w| *w == XZ_MAGIC).count();
    d.put("archive.stream_sequence", stream_count)?;
    d.put("stream.padding", aligned_padding)?;
    let trailing = data.len().saturating_sub(after_footer + aligned_padding);
    d.put("archive.trailing_data", trailing)?;
    if trailing > 0 {
        damage_flags.push("trailing_junk");
    }
    let valid = &footer[10..12] == b"YZ" && index_valid_start;
    d.put("plausible", valid)?;
    d.put("confidence", if valid { "strong" } else { "medium" })?;
    if !valid {
        d.put("error", "xz_structural_validation_failed")?;
    }
    apply_structural_contract(
        &mut d,
        reader,
        (after_footer + aligned_padding) as u64,
        StructuralStreamKind::Xz,
        None,
        &mut damage_flags,
    )?;
    if let Some(size) = d.get("structure.decoded_size").cloned() {
        d.put("block.uncompressed_data", size)?;
    }
    d.put("damage_flags", damage_flags)?;
    d.put("file_size", file_size)?;
    finish_fields(&mut d, XZ_FIELDS)?;
    Ok(d)
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

fn inspect_zstd(reader: &ManagedReader) -> std::io::Result<DiagnosticFields> {
    let file_size = reader.len();
    let data = (reader.read_all()).map_err(crate::io::resource_error::to_io_error)?;
    let mut d = compression_base("zstd", ".zst", data.starts_with(ZSTD_MAGIC))?;
    let mut damage_flags = Vec::new();
    d.put("frame.magic", hex_bytes(data.get(..4).unwrap_or(&[])))?;
    if data.len() < 6 || !data.starts_with(ZSTD_MAGIC) {
        d.put("error", "zstd_magic_or_header_missing")?;
        finish_fields(&mut d, ZSTD_FIELDS)?;
        return Ok(d);
    }
    let descriptor = data[4];
    let fcs_flag = descriptor >> 6;
    let single = descriptor & 0x20 != 0;
    let checksum = descriptor & 0x04 != 0;
    let dict_flag = descriptor & 0x03;
    d.put("frame.header.descriptor", descriptor)?;
    d.put("frame.header.content_size_flag", fcs_flag)?;
    d.put("frame.header.single_segment_flag", single)?;
    d.put("frame.header.checksum_flag", checksum)?;
    d.put("frame.header.dictionary_id_flag", dict_flag)?;
    let mut cursor = 5usize;
    if !single {
        let wd = data[cursor];
        cursor += 1;
        let exponent = (wd >> 3) as u32;
        let base = 1u64 << (10 + exponent);
        let window = base + (base / 8) * (wd & 7) as u64;
        d.put(
            "frame.header.window_descriptor",
            format!("raw={wd};window={window}"),
        )?;
    } else {
        d.put("frame.header.window_descriptor", "absent(single_segment)")?;
    }
    let dict_size = match dict_flag {
        0 => 0,
        1 => 1,
        2 => 2,
        _ => 4,
    };
    let dict_end = cursor.saturating_add(dict_size).min(data.len());
    d.put(
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
    d.put(
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
    (|| {
        while cursor + 3 <= data.len() && !last {
            let h = data[cursor] as u32
                | (data[cursor + 1] as u32) << 8
                | (data[cursor + 2] as u32) << 16;
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
    })();
    d.put("block.header.last_block", last)?;
    d.put("block.header.type", first_type)?;
    d.put("block.header.size", first_size)?;
    d.put("block.content", total_content)?;
    d.put(
        "block.literals",
        if first_type == 2 {
            "compressed_block_literals_section"
        } else {
            "not_compressed_layout"
        },
    )?;
    d.put(
        "block.sequences",
        if first_type == 2 {
            "compressed_block_sequences_section"
        } else {
            "not_compressed_layout"
        },
    )?;
    d.put(
        "block.previous_window",
        if dict_size > 0 {
            "dictionary_or_previous_block"
        } else {
            "previous_blocks"
        },
    )?;
    d.put(
        "block.previous_entropy_tables",
        if first_type == 2 {
            "repeat_mode_possible"
        } else {
            "not_used"
        },
    )?;
    if checksum && cursor + 4 <= data.len() {
        d.put("frame.content_checksum", u32_le(&data, cursor))?;
        cursor += 4;
    } else {
        d.put("frame.content_checksum", "absent")?;
    }
    // Inspect frame/block headers without allocating the advertised window.
    d.put("frame.decoded_content", "not_decoded")?;
    d.put(
        "frame.sequence",
        data.windows(4).filter(|w| *w == ZSTD_MAGIC).count(),
    )?;
    let mut skippable_count = 0usize;
    let mut skip_size = 0usize;
    let mut skip_data = 0usize;
    let mut scan = 0usize;
    (|| {
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
    })();
    d.put("skippable.magic", skippable_count)?;
    d.put("skippable.frame_size", skip_size)?;
    d.put("skippable.user_data", skip_data)?;
    let trailing = data.len().saturating_sub(cursor);
    d.put("archive.trailing_data", trailing)?;
    // The canonical walk below owns the tail: subsequent frames and skippable
    // frames are part of this logical stream, not trailing junk.
    let valid = last && descriptor & 0x08 == 0;
    d.put("plausible", valid)?;
    d.put("confidence", if valid { "strong" } else { "medium" })?;
    if descriptor & 0x08 != 0 {
        d.put("error", "zstd_reserved_bit_set")?;
        damage_flags.push("zstd_reserved_bit_set");
    } else if !valid {
        d.put("error", "zstd_frame_validation_failed")?;
        damage_flags.push(if !last {
            "probably_truncated"
        } else {
            "zstd_frame_bad"
        });
    }
    apply_structural_contract(
        &mut d,
        reader,
        file_size,
        StructuralStreamKind::Zstd,
        None,
        &mut damage_flags,
    )?;
    d.put("damage_flags", damage_flags)?;
    d.put("file_size", file_size)?;
    finish_fields(&mut d, ZSTD_FIELDS)?;
    Ok(d)
}
