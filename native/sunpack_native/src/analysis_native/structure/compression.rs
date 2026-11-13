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

fn inspect_structural_stream(
    reader: &ManagedReader,
    kind: StructuralStreamKind,
) -> std::io::Result<StreamObservation> {
    let file_size = reader.len();
    let format = match kind {
        StructuralStreamKind::Gzip => "gzip",
        StructuralStreamKind::Bzip2 => "bzip2",
        StructuralStreamKind::Xz => "xz",
        StructuralStreamKind::Zstd => "zstd",
    };
    let mut d = compression_base(format, true);
    let validation = kind.validate(reader, file_size);
    let structure = match validation {
        Ok(value) => value,
        Err(error) => {
            if let crate::scan::compression_stream::ValidationError::Io(error) = error {
                return Err(crate::io::resource_error::to_io_error(error));
            }
            let code = error.code();

            d.structure_complete = false;
            d.boundary_exact = false;

            d.plausible = false;

            d.error = code.into();
            d.damage_flags = ([code]).into_iter().map(str::to_owned).collect();
            return Ok(d);
        }
    };
    d.stream_count = structure.stream_count;
    let trailing = file_size.saturating_sub(structure.end_offset);
    let damage_flags = if trailing > 0 {
        vec!["trailing_junk"]
    } else {
        Vec::new()
    };
    d.plausible = true;

    d.structure_complete = true;
    d.boundary_exact = true;
    d.segment_end = Some(structure.end_offset);
    d.trailing_bytes = Some(trailing as u64);

    d.damage_flags = damage_flags.into_iter().map(str::to_owned).collect();
    Ok(d)
}

fn apply_structural_contract(
    d: &mut StreamObservation,
    reader: &ManagedReader,
    validation_limit: u64,
    kind: StructuralStreamKind,
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

            d.structure_complete = true;
            d.boundary_exact = true;
            d.segment_end = Some(structure.end_offset);
            d.trailing_bytes = Some(trailing as u64);

            d.stream_count = structure.stream_count;
        }
        Err(error) => {
            if let crate::scan::compression_stream::ValidationError::Io(error) = error {
                return Err(crate::io::resource_error::to_io_error(error));
            }
            let code = error.code();
            if !damage_flags.contains(&code) {
                damage_flags.push(code);
            }

            d.structure_complete = false;
            d.boundary_exact = false;

            d.plausible = false;

            d.error = code.into();
        }
    }
    Ok(())
}

/// Only facts consumed by format selection and segment planning. Diagnostics
/// for decoded fields are not serialized on this internal analysis path.
#[derive(Default)]
pub(crate) struct StreamObservation {
    pub(crate) format: String,
    pub(crate) magic_matched: bool,
    pub(crate) plausible: bool,
    pub(crate) error: String,
    pub(crate) damage_flags: Vec<String>,
    pub(crate) structure_complete: bool,
    pub(crate) boundary_exact: bool,
    pub(crate) segment_end: Option<u64>,
    pub(crate) trailing_bytes: Option<u64>,
    pub(crate) stream_count: usize,
}

fn compression_base(format: &str, magic_matched: bool) -> StreamObservation {
    StreamObservation { format: format.into(), magic_matched, ..StreamObservation::default() }
}

fn compression_empty(error: &str, format: &str, magic_matched: bool) -> StreamObservation {
    StreamObservation { error: error.into(), ..compression_base(format, magic_matched) }
}

fn inspect_gzip(reader: &ManagedReader) -> std::io::Result<StreamObservation> {
    let file_size = reader.len();
    let data = (reader.read_all()).map_err(crate::io::resource_error::to_io_error)?;
    let mut d = compression_base("gzip", data.starts_with(b"\x1f\x8b"));
    let mut damage_flags = Vec::new();

    if let Err(error) = crate::scan::compression_stream::gzip_payload_offset_from_slice(&data, 0) {
        d.error = error.code().into();
        d.damage_flags = vec![error.code().into()];
        return Ok(d);
    }

    // Move the bounded compressed input into the canonical reader so the structural
    // walk and integrity observer share one byte source without cloning the file.
    let reader = ManagedReader::from_bytes(data, crate::io::reader::ReaderConfig::default());
    let structure =
        match analyze_gzip_structure(&reader, 0, file_size, STREAM_STRUCTURE_DECODE_MAX_BYTES) {
            Ok(value) => value,
            Err(error) => {
                let code = error.code();
                if !damage_flags.contains(&code) {
                    damage_flags.push(code);
                }

                d.structure_complete = false;
                d.boundary_exact = false;

                d.plausible = false;

                d.error = code.into();
                d.damage_flags = damage_flags.into_iter().map(str::to_owned).collect();
                return Ok(d);
            }
        };
    let integrity = structure.integrity.as_str();
    if integrity == "failed" && !damage_flags.contains(&"gzip_footer_bad") {
        damage_flags.push("gzip_footer_bad");
    }

    let trailing = file_size.saturating_sub(structure.end_offset);
    d.trailing_bytes = Some(trailing as u64);
    if trailing > 0 && !damage_flags.contains(&"trailing_junk") {
        damage_flags.push("trailing_junk");
    }

    d.plausible = true;

    d.structure_complete = true;
    d.boundary_exact = true;
    d.segment_end = Some(structure.end_offset);

    d.stream_count = structure.stream_count;
    d.damage_flags = damage_flags.into_iter().map(str::to_owned).collect();
    Ok(d)
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

fn inspect_bzip2(reader: &ManagedReader) -> std::io::Result<StreamObservation> {
    let file_size = reader.len();
    let data = (reader.read_all()).map_err(crate::io::resource_error::to_io_error)?;
    let magic = data.starts_with(b"BZh") && data.get(3).is_some_and(|v| b"123456789".contains(v));
    let mut d = compression_base("bzip2", magic);
    let mut damage_flags = Vec::new();

    if !magic {
        d.error = "bzip2_magic_not_found".into();
        return Ok(d);
    }
    let ends = marker_positions(&data, 0x177245385090);
    let mut decoder = bzip2::read::BzDecoder::new(Cursor::new(data.as_slice()));
    let (decoded_size, decode_status) = count_decoded(&mut decoder);
    let decode_limited = decoded_size > STREAM_STRUCTURE_DECODE_MAX_BYTES;
    let decode_ok = decode_status.is_ok() && !decode_limited;
    let marker_boundary = ends
        .first()
        .map(|bit| (bit + 48 + 32 + 7) / 8)
        .unwrap_or(data.len());
    let consumed = decoder.get_ref().position() as usize;

    let trailing = if decode_limited {
        0
    } else {
        data.len().saturating_sub(marker_boundary.min(consumed))
    };
    // The single-stream decoder stops at the first end marker; concatenated
    // streams are not trailing data.  The structural contract below walks every
    // stream and owns the trailing_junk decision.
    d.trailing_bytes = Some(trailing as u64);

    d.plausible = (decode_ok && !ends.is_empty()) || (decode_limited && magic);

    if ends.is_empty() && !decode_limited {
        damage_flags.push("probably_truncated");
    }
    if !decode_ok && !decode_limited {
        d.error = "bzip2_decode_failed".into();
        damage_flags.push("bzip2_block_bad");
    }
    apply_structural_contract(
        &mut d,
        reader,
        file_size,
        StructuralStreamKind::Bzip2,
        &mut damage_flags,
    )?;
    d.damage_flags = damage_flags.into_iter().map(str::to_owned).collect();
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

fn xz_block_compressed_size(header: &[u8]) -> Option<Option<u64>> {
    // The caller excludes the header CRC; no VLI or property may consume it
    // (or compressed bytes belonging to the following block payload).
    let flags = *header.get(1)?;
    let mut cursor = 2;
    let compressed = if flags & 0x40 != 0 {
        Some(read_vli(header, &mut cursor)?)
    } else {
        None
    };
    if flags & 0x80 != 0 {
        read_vli(header, &mut cursor)?;
    }
    for _ in 0..(flags & 0x03) + 1 {
        read_vli(header, &mut cursor)?;
        let prop_size = usize::try_from(read_vli(header, &mut cursor)?).ok()?;
        let end = cursor.checked_add(prop_size)?;
        header.get(cursor..end)?;
        cursor = end;
    }
    Some(compressed)
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
            assert!(xz_block_compressed_size(header).is_none(), "{header:?}");
        }
        let fields = xz_block_compressed_size(&[2, 0, 0x21, 1, 0x16, 0, 0, 0]).unwrap();
        assert_eq!(fields, None);
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

    fn inspect_fixture(data: &[u8], check: impl FnOnce(&StreamObservation)) {
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
                let flags = &result.damage_flags;
                assert!(flags.iter().any(|value| value == flag), "{flags:?}");
            });
        }
    }

    #[test]
    fn typed_stream_observations_preserve_boundaries_and_damage() {
        // The report consumes these facts rather than the former diagnostic
        // dictionaries. Cover every stream producer at that shared boundary.
        let payload = b"typed stream facts";
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(payload).unwrap();
        let gzip = gzip.finish().unwrap();
        let mut bzip = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
        bzip.write_all(payload).unwrap();
        let mut xz = xz2::write::XzEncoder::new(Vec::new(), 1);
        xz.write_all(payload).unwrap();
        let zstd = zstd::stream::encode_all(&payload[..], 1).unwrap();
        for (format, bytes) in [
            ("gzip", gzip.clone()), ("bzip2", bzip.finish().unwrap()),
            ("xz", xz.finish().unwrap()), ("zstd", zstd),
        ] {
            let length = bytes.len() as u64;
            let reader = ManagedReader::from_bytes(bytes, crate::io::reader::ReaderConfig::default());
            let head = reader.read_cached_at(0, 32).unwrap();
            let facts = inspect_compression_stream_reader(&reader, &head).unwrap();
            assert_eq!(facts.format, format);
            assert!(facts.magic_matched && facts.plausible && facts.structure_complete);
            assert!(facts.boundary_exact && facts.error.is_empty() && facts.damage_flags.is_empty());
            assert_eq!(facts.segment_end, Some(length));
            assert_eq!(facts.trailing_bytes, Some(0));
        }
        let mut damaged = gzip;
        let crc = damaged.len() - 8;
        damaged[crc] ^= 1;
        let reader = ManagedReader::from_bytes(damaged, crate::io::reader::ReaderConfig::default());
        let head = reader.read_cached_at(0, 32).unwrap();
        let facts = inspect_compression_stream_reader(&reader, &head).unwrap();
        assert!(facts.damage_flags.iter().any(|flag| flag == "gzip_footer_bad"));
    }

    #[test]
    fn public_inspector_keeps_valid_xz_records_and_properties() {
        let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 1);
        encoder.write_all(b"payload").unwrap();
        inspect_fixture(&encoder.finish().unwrap(), |result| {
            assert!(result.plausible);
            assert!(result.structure_complete);
            assert_eq!(result.trailing_bytes, Some(0));
            assert!(result.damage_flags.is_empty());
            assert!(result.segment_end.is_some());
        });
    }
}

fn inspect_xz(reader: &ManagedReader) -> std::io::Result<StreamObservation> {
    let data = (reader.read_all()).map_err(crate::io::resource_error::to_io_error)?;
    let mut d = compression_base("xz", data.starts_with(XZ_MAGIC));
    let mut damage_flags = Vec::new();

    if data.len() < 24 || !data.starts_with(XZ_MAGIC) {
        d.error = "xz_header_or_footer_missing".into();
        return Ok(d);
    }
    let flags = &data[6..8];
    let header_crc = u32_le(&data, 8);

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

    if footer_crc != crc32(&footer[4..10]) {
        damage_flags.push("xz_footer_crc_bad");
    }
    // Concatenated streams may use different checks. The canonical structural
    // walk compares each footer to its own header.

    let index_start = footer_start
        .checked_sub(backward_size as usize)
        .unwrap_or(0);
    let index_crc_pos = footer_start.saturating_sub(4);
    let index_data = &data[..index_crc_pos];
    let mut index_cursor = index_start;
    let index_valid_start = index_start >= 12 && index_data.get(index_cursor) == Some(&0);

    if !index_valid_start {
        damage_flags.push("xz_index_bad");
    }
    index_cursor = index_cursor.saturating_add(1);
    let record_count = read_vli(index_data, &mut index_cursor);

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

    if index_crc_pos + 4 <= data.len() && index_start <= index_crc_pos {
        let stored = u32_le(&data, index_crc_pos);
        let computed = crc32(&data[index_start..index_crc_pos]);
        let ok = stored == computed;

        if !ok {
            damage_flags.push("xz_index_bad");
        }
    }

    let mut block_cursor = index_start.saturating_sub(records.padded as usize);
    let check_size = xz_check_size(footer[9] & 0x0f);
    (|| {
        for (unpadded, _) in records.iter() {
            if block_cursor >= index_start {
                break;
            }
            let header_size = (data[block_cursor] as usize + 1) * 4;
            if block_cursor + header_size > index_start || header_size < 8 {
                damage_flags.push("xz_block_header_bad");
                break;
            }
            let Some(declared_compressed) =
                xz_block_compressed_size(&data[block_cursor..block_cursor + header_size - 4])
            else {
                damage_flags.push("xz_block_header_bad");
                break;
            };
            let compressed_size = declared_compressed
                .unwrap_or(unpadded.saturating_sub(header_size as u64 + check_size as u64));
            let unpadded_actual = header_size as u64 + compressed_size + check_size as u64;
            let padding = ((4 - unpadded_actual % 4) % 4) as usize;
            block_cursor = block_cursor.saturating_add(unpadded_actual as usize + padding);
        }
    })();
    let after_footer = footer_start + 12;
    let zero_padding = data[after_footer..].iter().take_while(|b| **b == 0).count();
    let aligned_padding = zero_padding - zero_padding % 4;
    // Structure analysis does not need an LZMA dictionary. The Index already
    // provides decoded sizes; payload checks remain deferred until extraction.

    let trailing = data.len().saturating_sub(after_footer + aligned_padding);
    d.trailing_bytes = Some(trailing as u64);
    if trailing > 0 {
        damage_flags.push("trailing_junk");
    }
    let valid = &footer[10..12] == b"YZ" && index_valid_start;
    d.plausible = valid;

    if !valid {
        d.error = "xz_structural_validation_failed".into();
    }
    apply_structural_contract(
        &mut d,
        reader,
        (after_footer + aligned_padding) as u64,
        StructuralStreamKind::Xz,
        &mut damage_flags,
    )?;
    d.damage_flags = damage_flags.into_iter().map(str::to_owned).collect();
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

fn inspect_zstd(reader: &ManagedReader) -> std::io::Result<StreamObservation> {
    let file_size = reader.len();
    let data = (reader.read_all()).map_err(crate::io::resource_error::to_io_error)?;
    let mut d = compression_base("zstd", data.starts_with(ZSTD_MAGIC));
    let mut damage_flags = Vec::new();

    if data.len() < 6 || !data.starts_with(ZSTD_MAGIC) {
        d.error = "zstd_magic_or_header_missing".into();
        return Ok(d);
    }
    let descriptor = data[4];
    let fcs_flag = descriptor >> 6;
    let single = descriptor & 0x20 != 0;
    let checksum = descriptor & 0x04 != 0;
    let dict_flag = descriptor & 0x03;

    let mut cursor = 5usize;
    if !single {
        cursor += 1;
    }
    let dict_size = match dict_flag {
        0 => 0,
        1 => 1,
        2 => 2,
        _ => 4,
    };
    let dict_end = cursor.saturating_add(dict_size).min(data.len());

    cursor = dict_end;
    let fcs_size = zstd_field_size(fcs_flag, single, single || fcs_flag != 0);
    let fcs_end = cursor.saturating_add(fcs_size).min(data.len());
    cursor = fcs_end;
    let mut last = false;
    (|| {
        while cursor + 3 <= data.len() && !last {
            let h = data[cursor] as u32
                | (data[cursor + 1] as u32) << 8
                | (data[cursor + 2] as u32) << 16;
            cursor += 3;
            last = h & 1 != 0;
            let block_type = ((h >> 1) & 3) as u8;
            let block_size = (h >> 3) as usize;
            let stored_size = if block_type == 1 { 1 } else { block_size };
            if block_type == 3 || cursor + stored_size > data.len() {
                break;
            }
            cursor += stored_size;
        }
    })();

    if checksum && cursor + 4 <= data.len() {

        cursor += 4;
    }
    // Inspect frame/block headers without allocating the advertised window.

    let trailing = data.len().saturating_sub(cursor);
    d.trailing_bytes = Some(trailing as u64);
    // The canonical walk below owns the tail: subsequent frames and skippable
    // frames are part of this logical stream, not trailing junk.
    let valid = last && descriptor & 0x08 == 0;
    d.plausible = valid;

    if descriptor & 0x08 != 0 {
        d.error = "zstd_reserved_bit_set".into();
        damage_flags.push("zstd_reserved_bit_set");
    } else if !valid {
        d.error = "zstd_frame_validation_failed".into();
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
        &mut damage_flags,
    )?;
    d.damage_flags = damage_flags.into_iter().map(str::to_owned).collect();
    Ok(d)
}
