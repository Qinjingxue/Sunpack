use crate::scan::compression_stream::{
    analyze_gzip_structure, validate_bzip2_identity, validate_bzip2_structure,
    validate_gzip_structure, validate_xz_identity, validate_xz_structure_exact,
    validate_zstd_structure, IntegrityStatus, ValidationError, BZIP2_IDENTITY_BYTES,
};
use std::io;

const EAGER_STREAM_INTEGRITY_MAX_BYTES: u64 = 4 * 1024 * 1024;
const STREAM_STRUCTURE_DECODE_MAX_BYTES: u64 = 8 * 1024 * 1024;

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

    fn format(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Bzip2 => "bzip2",
            Self::Xz => "xz",
            Self::Zstd => "zstd",
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
    plausible: bool,
    error: &'static str,
) -> CompressionIdentityResult {
    CompressionIdentityResult { format, plausible, error }
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
        Err(_) => return compression_identity_result("", false, "os_error"),
    };
    let file_size = reader.len();
    let read_size = file_size.min(BZIP2_IDENTITY_BYTES as u64) as usize;
    let mut data = match reader.read_direct_at(0, read_size) {
        Ok(value) => value,
        Err(_) => {
            return compression_identity_result("", false, "os_error")
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
                return compression_identity_result("gzip", false, "gzip_header_read_failed")
            }
        };
    }
    if crate::formats::lz4::leading(&data) {
        let identity = crate::formats::lz4::identity(&reader, 0);
        // Skippable magic is shared with Zstandard and does not establish LZ4.
        if identity != Ok(false) {
            let (valid, error) = match identity {
                Ok(valid) => (valid, ""),
                Err(e) => (false, e),
            };
            return compression_identity_result("lz4", valid, error);
        }
    }

    if data.starts_with(b"\x1f\x8b") {
        let payload_start = match crate::scan::compression_stream::gzip_payload_offset_from_slice(&data, 0) {
            Ok(value) => value,
            Err(error) => {
                return compression_identity_result("gzip", false, error.code())
            }
        };
        let payload = {
            let wanted = (file_size - payload_start)
                .min((GZIP_IDENTITY_PAYLOAD_BYTES + 8) as u64) as usize;
            let available = &data[payload_start as usize..];
            if available.len() >= wanted {
                std::borrow::Cow::Borrowed(&available[..wanted])
            } else {
                match reader.read_direct_at(payload_start, wanted) {
                    Ok(bytes) => std::borrow::Cow::Owned(bytes),
                    Err(_) => {
                        return compression_identity_result("gzip", false, "os_error")
                    }
                }
            }
        };
        let result = validate_gzip_identity_payload(&payload);
        return compression_identity_result("gzip", result.is_ok(), result.err().unwrap_or(""));
    }

    if data.starts_with(b"BZh") {
        let (plausible, error) = match validate_bzip2_identity(&data, file_size) {
            Ok(_) => (true, ""),
            Err(error) => (false, error.code()),
        };
        return compression_identity_result("bzip2", plausible, error);
    }

    if data.starts_with(XZ_MAGIC) {
        let result = validate_xz_identity(&data, file_size, |size| reader.read_direct_at(12, size));
        let (plausible, error) = match result {
            Ok(_) => (true, ""),
            Err(error) => (false, error.code()),
        };
        return compression_identity_result("xz", plausible, error);
    }

    if data.starts_with(ZSTD_MAGIC) {
        if data.len() < 8 {
            return compression_identity_result("zstd", false, "zstd_frame_header_short");
        }
        let descriptor = data[4];
        if descriptor & 0x18 != 0 {
            return compression_identity_result("zstd", false, "zstd_reserved_or_unused_bit_set");
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
                return compression_identity_result("zstd", false, "zstd_window_descriptor_missing");
            }
            cursor += 1;
        }
        let fcs_flag = descriptor >> 6;
        let fcs_size = zstd_field_size(fcs_flag, single, single || fcs_flag != 0);
        let Some(block_header_offset) = cursor
            .checked_add(dict_size)
            .and_then(|value| value.checked_add(fcs_size))
        else {
            return compression_identity_result("zstd", false, "zstd_frame_header_overflow");
        };
        if block_header_offset + 3 > data.len() {
            return compression_identity_result("zstd", false, "zstd_first_block_header_missing");
        }
        let block_header = u32::from(data[block_header_offset])
            | (u32::from(data[block_header_offset + 1]) << 8)
            | (u32::from(data[block_header_offset + 2]) << 16);
        let block_type = (block_header >> 1) & 0x03;
        let block_size = u64::from(block_header >> 3);
        if block_type == 3 || block_size > 128 * 1024 {
            return compression_identity_result("zstd", false, "zstd_first_block_header_invalid");
        }
        let stored_size = if block_type == 1 { 1 } else { block_size };
        if (block_header_offset as u64)
            .checked_add(3)
            .and_then(|value| value.checked_add(stored_size))
            .map_or(true, |end| end > file_size)
        {
            return compression_identity_result("zstd", false, "zstd_first_block_out_of_range");
        }
        return compression_identity_result("zstd", true, "");
    }

    compression_identity_result("", false, "compression_stream_magic_not_found")
}

fn complete_structural_stream(
    reader: &ManagedReader,
    kind: StructuralStreamKind,
) -> io::Result<Option<&'static str>> {
    let size = reader.len();
    let eager_integrity = size <= EAGER_STREAM_INTEGRITY_MAX_BYTES;
    let validation = match kind {
        StructuralStreamKind::Gzip if eager_integrity => {
            analyze_gzip_structure(reader, 0, size, STREAM_STRUCTURE_DECODE_MAX_BYTES)
        }
        StructuralStreamKind::Gzip => validate_gzip_structure(reader, 0, size),
        StructuralStreamKind::Bzip2 => validate_bzip2_structure(reader, 0, size),
        StructuralStreamKind::Xz => validate_xz_structure_exact(reader, 0, size),
        StructuralStreamKind::Zstd => validate_zstd_structure(reader, 0, size),
    };
    match validation {
        Ok(facts) if facts.end_offset == size && facts.integrity != IntegrityStatus::Failed => {}
        Ok(_) | Err(ValidationError::Invalid(_)) => return Ok(None),
        Err(ValidationError::Io(error)) => return Err(crate::io::resource_error::to_io_error(error)),
    }

    if eager_integrity && matches!(kind, StructuralStreamKind::Bzip2) {
        // The structural walk checks stored checksums against their block
        // headers. Preserve eager verification of the first member's decoded
        // content, reading through the same bounded reader.
        let decoder = bzip2::read::BzDecoder::new(reader.cursor());
        let mut bounded = decoder.take(STREAM_STRUCTURE_DECODE_MAX_BYTES + 1);
        match io::copy(&mut bounded, &mut io::sink()) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof
                || error.get_ref().is_some_and(|cause| cause.is::<bzip2::Error>()) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(crate::io::resource_error::to_io_error(error)),
        }
    }
    Ok(Some(kind.format()))
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

#[cfg(test)]
mod complete_stream_tests {
    use super::*;
    use std::io::Write;

    fn complete_format(bytes: Vec<u8>) -> Option<&'static str> {
        let reader = ManagedReader::from_bytes(bytes, crate::io::reader::ReaderConfig::default());
        let head = reader.read_cached_at(0, 32).unwrap();
        match inspect_compression_stream_reader(&reader, &head).unwrap() {
            Some(StreamStructure::Complete(format)) => Some(format),
            _ => None,
        }
    }

    #[test]
    fn complete_streams_use_canonical_boundaries_and_preserve_eager_integrity() {
        let payload = b"typed stream facts";
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(payload).unwrap();
        let gzip = gzip.finish().unwrap();
        let mut bzip = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
        bzip.write_all(payload).unwrap();
        let mut bzip = bzip.finish().unwrap();
        let mut xz = xz2::write::XzEncoder::new(Vec::new(), 1);
        xz.write_all(payload).unwrap();
        let zstd = zstd::stream::encode_all(&payload[..], 1).unwrap();
        for (format, mut bytes) in [
            ("gzip", gzip.clone()), ("bzip2", bzip.clone()),
            ("xz", xz.finish().unwrap()), ("zstd", zstd),
        ] {
            assert_eq!(complete_format(bytes.clone()), Some(format));
            bytes.extend_from_slice(b"trailing bytes");
            assert_eq!(complete_format(bytes), None, "{format}");
        }
        let mut damaged = gzip;
        let crc = damaged.len() - 8;
        damaged[crc] ^= 1;
        assert_eq!(complete_format(damaged), None);

        // Make the stored block CRC and combined CRC agree with each other,
        // while disagreeing with the actual decoded payload.
        let limit = bzip.len() * 8;
        let end_marker = (limit - 87..=limit - 80).find(|&start| {
            (start..start + 48).fold(0u64, |value, bit| {
                (value << 1) | u64::from((bzip[bit / 8] >> (7 - bit % 8)) & 1)
            }) == 0x177245385090
        }).unwrap();
        let combined_crc = end_marker + 48;
        bzip[combined_crc / 8] ^= 1 << (7 - combined_crc % 8);
        bzip[10] ^= 0x80;
        let reader = ManagedReader::from_bytes(bzip.clone(), crate::io::reader::ReaderConfig::default());
        assert!(validate_bzip2_structure(&reader, 0, reader.len()).is_ok());
        assert_eq!(complete_format(bzip), None);
    }

    fn malformed_xz_stream(block: &[u8], index: &[u8]) -> Vec<u8> {
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

    #[test]
    fn whole_stream_planning_rejects_huge_xz_index_and_spilling_block_header() {
        let huge_count =
            malformed_xz_stream(&[], &[0, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 1]);
        let spilling_header = malformed_xz_stream(&[1, 0, 0x80, 0x80, 1, 1, 0, 0], &[0, 1, 8, 0]);
        for data in [huge_count, spilling_header] {
            assert_eq!(complete_format(data), None);
        }
    }
}
