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
