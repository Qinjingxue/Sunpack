use super::*;
use crate::io::reader::ReaderConfig;
pub(super) fn frame(
    payload: &[u8],
    flags: u8,
    bd: u8,
    size: Option<u64>,
    dict: Option<u32>,
) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&[flags, bd]);
    if let Some(size) = size {
        out.extend_from_slice(&size.to_le_bytes());
    }
    if let Some(id) = dict {
        out.extend_from_slice(&id.to_le_bytes());
    }
    out.push((xxh32(&out[4..]) >> 8) as u8);
    if !payload.is_empty() {
        out.extend_from_slice(&(0x80000000 | payload.len() as u32).to_le_bytes());
        out.extend_from_slice(payload);
        if flags & 16 != 0 {
            out.extend_from_slice(&xxh32(payload).to_le_bytes());
        }
    }
    out.extend_from_slice(&0u32.to_le_bytes());
    if flags & 4 != 0 {
        out.extend_from_slice(&xxh32(payload).to_le_bytes());
    }
    out
}
pub(super) fn index(data: Vec<u8>, start: u64) -> Index {
    let reader = ManagedReader::from_bytes(data, ReaderConfig::default());
    walk(&reader, start, reader.len())
}
// Small codec fixtures cannot expose archive-wide count quotas. These
// compact empty records cross both former quotas without decoding data.
#[test]
fn long_streams_end_on_structure_instead_of_record_quotas() {
    let count = 1_000_001;
    let empty = frame(b"", 0x60, 0x40, None, None);
    let mut bytes = empty[..empty.len() - 4].to_vec();
    bytes.extend([0, 0, 0, 0x80].repeat(count));
    bytes.extend([0; 4]);
    let end = bytes.len();
    bytes.extend(b"carrier tail");
    let parsed = index(bytes, 0);
    assert!(parsed.complete, "{parsed:?}");
    assert_eq!((parsed.blocks, parsed.end), (count, end as u64));

    let skip = [0x50, 0x2a, 0x4d, 0x18, 0, 0, 0, 0];
    let mut bytes = skip.repeat(65_537);
    bytes.extend(empty.repeat(65_537));
    let source = ManagedReader::from_bytes(bytes, ReaderConfig::default());
    assert_eq!(identity(&source, 0), Ok(true));
    let parsed = walk(&source, 0, source.len());
    assert!(parsed.complete);
    assert_eq!((parsed.skips, parsed.frames), (65_537, 65_537));
    assert!(!walk(&source, 0, source.len() - 1).complete);
}

#[test]
fn empty_raw_block_and_partial_next_skippable_are_distinct() {
    let mut bytes = frame(b"", 0x5c, 0x40, Some(0), None);
    let at = parse_header(&bytes).unwrap().len;
    let mut block = 0x80000000u32.to_le_bytes().to_vec();
    block.extend_from_slice(&xxh32(b"").to_le_bytes());
    bytes.splice(at..at, block);
    let parsed = index(bytes.clone(), 0);
    assert!(parsed.complete);
    assert_eq!(parsed.blocks, 1);
    decode_into(std::io::Cursor::new(&bytes), std::io::sink()).unwrap();
    for magic in 0x50..=0x5fu8 {
        for n in 1..4 {
            let mut truncated = bytes.clone();
            truncated.extend_from_slice(&[magic, 0x2a, 0x4d][..n]);
            assert_eq!(index(truncated, 0).error, "lz4_stream_truncated");
        }
    }
}
#[test]
fn all_header_layouts_preserve_known_zero_and_descriptor_length() {
    for block in 4..=7 {
        for option in 0..32 {
            let flags = 0x40 | option;
            if flags & 2 != 0 {
                continue;
            }
            let size = (flags & 8 != 0).then_some(0);
            let dict = (flags & 1 != 0).then_some(123);
            let bytes = frame(b"", flags, block << 4, size, dict);
            let header = parse_header(&bytes).unwrap();
            assert_eq!(header.content_size, size);
            assert_eq!(
                header.len,
                7 + usize::from(size.is_some()) * 8 + usize::from(dict.is_some()) * 4
            );
            let parsed = index(bytes, 0);
            assert!(parsed.complete, "{parsed:?}");
            assert_eq!(parsed.frames, 1);
        }
    }
}
#[test]
fn concatenated_skip_bounds_and_trailing_carrier() {
    let skip = [0x5f, 0x2a, 0x4d, 0x18, 3, 0, 0, 0, 0, 1, 2];
    let a = frame(b"hello", 0x7c, 0x40, Some(5), None);
    let mut bytes = vec![0x88; 31];
    bytes.extend_from_slice(&skip);
    bytes.extend_from_slice(&a);
    bytes.extend_from_slice(&skip);
    bytes.extend_from_slice(&a);
    let end = bytes.len();
    bytes.extend_from_slice(b"carrier-tail");
    let parsed = index(bytes, 31);
    assert!(parsed.complete);
    assert_eq!(parsed.end, end as u64);
    assert_eq!(parsed.frames, 2);
    assert_eq!(parsed.skips, 2);
    assert_eq!(parsed.decoded_size, Some(10));
    assert_eq!(parsed.content_checksums, 2);
    assert_eq!(parsed.block_checksums, 2);
}
#[test]
fn header_corruption_truncation_and_size_limits_fail_closed() {
    let original = frame(b"hello", 0x7c, 0x40, Some(5), None);
    for length in 4..original.len() {
        assert!(!index(original[..length].to_vec(), 0).complete);
    }
    let mut bytes = original.clone();
    bytes[14] ^= 1;
    assert_eq!(index(bytes, 0).error, "lz4_header_checksum_bad");
    let mut bytes = original;
    bytes[15..19].copy_from_slice(&0x80010001u32.to_le_bytes());
    assert_eq!(index(bytes, 0).error, "lz4_block_size_invalid");
    let mut header = frame(b"", 0x60, 0x40, None, None);
    header[5] = 0x80;
    assert_eq!(parse_header(&header).unwrap_err(), "lz4_reserved_bits_set");
}
#[test]
fn legacy_inputs_and_dictionary_descriptors_preserve_structure_identity() {
    let legacy = b"\x02\x21\x4c\x18\x06\0\0\0\x50hello";
    assert!(!leading(legacy));
    assert!(!identity(
        &ManagedReader::from_bytes(legacy.to_vec(), ReaderConfig::default()),
        0
    )
    .unwrap());
    assert_eq!(index(legacy.to_vec(), 0).error, "lz4_magic_not_found");
    for id in [0, 123, u32::MAX] {
        let bytes = frame(b"hello", 0x61, 0x40, None, Some(id));
        assert!(index(bytes, 0).complete);
    }
}
