use super::*;
use crate::io::reader::ReaderConfig;
use std::io::{Read, Write};

fn reader(data: Vec<u8>) -> ManagedReader {
    ManagedReader::from_bytes(data, ReaderConfig::default())
}

// Codec fixtures do not place fixed fields at both cursor refill edges.
// Cover byte ownership, short fields and IO errors in one small matrix.
#[test]
fn fixed_fields_preserve_refill_edges_eof_and_io_errors() {
    let data = (0..INITIAL_PROBE_BYTES + BUFFER_SIZE + 32)
        .map(|index| (index * 73 + 19) as u8)
        .collect::<Vec<_>>();
    for start in [
        0,
        INITIAL_PROBE_BYTES - 2,
        INITIAL_PROBE_BYTES - 1,
        INITIAL_PROBE_BYTES,
        INITIAL_PROBE_BYTES + BUFFER_SIZE - 2,
        INITIAL_PROBE_BYTES + BUFFER_SIZE - 1,
    ] {
        let source = reader(data.clone());
        let mut read = |offset, count| source.read_cached_at(offset, count);
        let mut cursor = ByteCursor::new(&mut read, 0, source.len(), CachedBytes::default());
        cursor.read_chunks(start, |_| {}).unwrap();
        assert_eq!(cursor.read_array::<3>().unwrap(), data[start..start + 3]);
        assert_eq!(
            cursor.read_array::<8>().unwrap(),
            data[start + 3..start + 11]
        );
        assert_eq!(cursor.position(), (start + 11) as u64);
        assert_eq!(cursor.read_byte().unwrap(), data[start + 11]);
    }
    let source = reader(vec![1, 2]);
    let mut read = |offset, count| source.read_cached_at(offset, count);
    let mut cursor = ByteCursor::new(&mut read, 0, source.len(), CachedBytes::default());
    assert_eq!(
        cursor.read_array::<3>().unwrap_err().code(),
        "unexpected_end_of_stream"
    );
    assert_eq!(cursor.position(), 0);
    assert_eq!(
        cursor.read_chunks(usize::MAX, |_| {}).unwrap_err().code(),
        "unexpected_end_of_stream"
    );
}

// Encoders normally omit optional headers. Exercise CRC byte coverage,
// NUL ownership and both refill boundaries through the actual stream walk.
#[test]
fn gzip_optional_headers_keep_crc_terminators_and_concatenated_boundaries() {
    for flags in [0u8, 0x04, 0x08, 0x10, 0x1c] {
        for crc in [false, true] {
            for terminator in [255, 256, 65791, 65792] {
                if flags & 0x18 == 0 && terminator != 255 {
                    continue;
                }
                let mut header = vec![
                    0x1f,
                    0x8b,
                    8,
                    flags | if crc { 2 } else { 0 },
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ];
                if flags & 0x04 != 0 {
                    header.extend_from_slice(&[3, 0, 1, 0, 255]);
                }
                let mut string_end = None;
                for flag in [0x08, 0x10] {
                    if flags & flag != 0 {
                        if string_end.is_none() {
                            header.resize(terminator, b'n');
                            string_end = Some(header.len());
                        } else {
                            header.extend_from_slice(b"comment");
                        }
                        header.push(0);
                    }
                }
                if crc {
                    let checksum = crc32(&header) as u16;
                    header.extend_from_slice(&checksum.to_le_bytes());
                }
                let header_len = header.len();
                // Empty fixed DEFLATE block followed by CRC32/ISIZE.
                let mut member = header;
                member.extend_from_slice(&[3, 0]);
                member.extend_from_slice(&[0; 8]);
                let data = member.repeat(2);
                let source = reader(data.clone());
                let mut members = Vec::new();
                let end = validate_gzip_structure(&source, 0, source.len(), |start| {
                    members.push(start);
                    Ok(())
                })
                .unwrap();
                assert_eq!(end, data.len() as u64);
                assert_eq!(members, [0, member.len() as u64]);
                if crc {
                    let mut damaged = member.clone();
                    damaged[header_len - 1] ^= 1;
                    let source = reader(damaged);
                    assert_eq!(
                        validate_gzip_structure(&source, 0, source.len(), |_| Ok(()))
                            .unwrap_err()
                            .code(),
                        "gzip_header_crc_bad"
                    );
                }
                for end in [
                    string_end.unwrap_or(header_len),
                    header_len.saturating_sub(1),
                    member.len() - 1,
                ] {
                    let source = reader(member[..end].to_vec());
                    assert!(validate_gzip_structure(&source, 0, source.len(), |_| Ok(())).is_err());
                }
            }
        }
    }
}

// Independent of archive codecs: cover every fixed symbol, bit alignment,
// the short-code EOF fallback, and lookahead ownership across probe refill.
#[test]
fn fixed_deflate_constants_decode_all_rfc_codes_and_short_eof() {
    for prefix in 0..8 {
        for distance in [false, true] {
            let count = if distance { 32 } else { 288 };
            let mut logical = vec![0u8; prefix];
            for symbol in 0..count {
                let (code, length) = if distance {
                    (symbol, 5)
                } else {
                    match symbol {
                        0..=143 => (0x30 + symbol, 8),
                        144..=255 => (0x190 + symbol - 144, 9),
                        256..=279 => (symbol - 256, 7),
                        _ => (0xc0 + symbol - 280, 8),
                    }
                };
                for shift in (0..length).rev() {
                    logical.push(((code >> shift) & 1) as u8);
                }
            }
            let byte_count = logical.len().div_ceil(8);
            let mut data = vec![0u8; byte_count];
            for (index, bit) in logical.iter().enumerate() {
                data[index / 8] |= bit << (index % 8);
            }
            data.extend_from_slice(&[0xa5, 0x5a]);
            let source = reader(data.clone());
            let mut read = |offset, count| source.read_cached_at(offset, count);
            let mut cursor =
                ByteCursor::new(&mut read, 0, data.len() as u64, CachedBytes::default());
            let mut bits = LsbBits::new(&mut cursor);
            bits.read(prefix as u8).unwrap();
            let tree = if distance {
                FIXED_DISTANCE_TREE
            } else {
                FIXED_LITERAL_TREE
            };
            for symbol in 0..count {
                assert_eq!(tree.decode(&mut bits).unwrap(), symbol as u16);
            }
            bits.align_byte();
            assert_eq!(cursor.position(), byte_count as u64);
            assert_eq!(cursor.read_array::<2>().unwrap(), [0xa5, 0x5a]);
        }
    }
    let source = reader(vec![0]);
    let mut read = |offset, count| source.read_cached_at(offset, count);
    let mut cursor = ByteCursor::new(&mut read, 0, 1, CachedBytes::default());
    let mut bits = LsbBits::new(&mut cursor);
    assert_eq!(FIXED_LITERAL_TREE.decode(&mut bits).unwrap(), 256);
    assert_eq!(
        FIXED_LITERAL_TREE.decode(&mut bits).unwrap_err().code(),
        "unexpected_end_of_stream"
    );
}

// A short logical stream must fit its read budget even in a large carrier;
// existing whole-file fixtures do not detect reads of unrelated tail data.
#[test]
fn tiny_gzip_boundary_preserves_unrelated_carrier_read_budget() {
    let member = gzip_member(b"");
    let end = member.len() as u64;
    let mut data = member;
    data.extend_from_slice(b"carrier-tail");
    data.resize(2 * BUFFER_SIZE, 0);
    let source = ManagedReader::from_bytes(
        data,
        ReaderConfig {
            ..ReaderConfig::default()
        },
    );
    assert_eq!(
        validate_gzip_structure(&source, 0, source.len(), |_| Ok(())).unwrap(),
        end
    );
}

#[test]
fn deflate_rejects_back_reference_before_any_decoded_byte() {
    // Final fixed-Huffman block starts with a length-three, distance-one pair.
    let source = reader(vec![3, 2]);
    let mut read = |offset, count| source.read_cached_at(offset, count);
    let mut cursor = ByteCursor::new(&mut read, 0, source.len(), CachedBytes::default());
    assert_eq!(
        parse_deflate(&mut LsbBits::new(&mut cursor))
            .unwrap_err()
            .code(),
        "deflate_distance_out_of_range"
    );
}

// Independent coverage: lookahead byte ownership at all bit alignments,
// short codes at EOF, and 15/20-bit codes absent from the tiny real-stream
// fixtures. One bounded matrix catches boundary/truncation regressions.
#[test]
fn huffman_lookup_preserves_codes_eof_and_following_bytes() {
    for (max_len, order) in [(15, BitOrder::Lsb), (20, BitOrder::Msb)] {
        let mut lengths = (1..=max_len as u8).collect::<Vec<_>>();
        lengths.push(max_len as u8);
        let tree = Huffman::new(&lengths, max_len, order).unwrap();
        for prefix in 0..8 {
            let mut logical = vec![0u8; prefix];
            for (symbol, &length) in lengths.iter().enumerate() {
                // Complete canonical comb tree: 0, 10, 110, ... , 111... .
                let code = if symbol == max_len {
                    (1u32 << length) - 1
                } else {
                    (1u32 << length) - 2
                };
                for shift in (0..length).rev() {
                    logical.push(((code >> shift) & 1) as u8);
                }
            }
            logical.push(0); // shortest code, including insufficient lookup bits at EOF
            let byte_count = logical.len().div_ceil(8);
            let mut data = vec![0u8; byte_count];
            for (index, bit) in logical.iter().enumerate() {
                let shift = match order {
                    BitOrder::Lsb => index % 8,
                    BitOrder::Msb => 7 - index % 8,
                };
                data[index / 8] |= bit << shift;
            }
            for tail in [false, true] {
                let mut input = data.clone();
                if tail {
                    input.extend_from_slice(&[0xa5, 0x5a]);
                }
                let source = reader(input.clone());
                let mut read = |offset, count| source.read_cached_at(offset, count);
                let mut cursor =
                    ByteCursor::new(&mut read, 0, input.len() as u64, CachedBytes::default());
                match order {
                    BitOrder::Lsb => {
                        let mut bits = LsbBits::new(&mut cursor);
                        bits.read(prefix as u8).unwrap();
                        for symbol in 0..lengths.len() {
                            assert_eq!(tree.decode_lsb(&mut bits).unwrap(), symbol as u16);
                        }
                        assert_eq!(tree.decode_lsb(&mut bits).unwrap(), 0);
                        bits.align_byte();
                    }
                    BitOrder::Msb => {
                        let mut bits = MsbBits::new(&mut cursor);
                        bits.read(prefix as u8).unwrap();
                        for symbol in 0..lengths.len() {
                            assert_eq!(tree.decode_msb(&mut bits).unwrap(), symbol as u16);
                        }
                        assert_eq!(tree.decode_msb(&mut bits).unwrap(), 0);
                        bits.align_zero().unwrap();
                    }
                }
                assert_eq!(cursor.position(), byte_count as u64);
                if tail {
                    assert_eq!(cursor.read_array::<2>().unwrap(), [0xa5, 0x5a]);
                }
            }
        }
        let source = reader(vec![0xff]);
        let mut read = |offset, count| source.read_cached_at(offset, count);
        let mut cursor = ByteCursor::new(&mut read, 0, 1, CachedBytes::default());
        let error = match order {
            BitOrder::Lsb => tree.decode_lsb(&mut LsbBits::new(&mut cursor)),
            BitOrder::Msb => tree.decode_msb(&mut MsbBits::new(&mut cursor)),
        }
        .unwrap_err();
        assert_eq!(error.code(), "unexpected_end_of_stream");
    }
}

#[test]
fn gzip_token_walk_handles_dynamic_and_concatenated_members() {
    let mut first = Vec::new();
    {
        let mut encoder = flate2::write::GzEncoder::new(&mut first, flate2::Compression::default());
        encoder.write_all(&vec![b'A'; 2 * 1024 * 1024]).unwrap();
        encoder.finish().unwrap();
    }
    let mut data = first.clone();
    data.extend_from_slice(&first);
    let source = reader(data.clone());
    let mut members = Vec::new();
    let end = validate_gzip_structure(&source, 0, source.len(), |start| {
        members.push(start);
        Ok(())
    })
    .unwrap();
    assert_eq!(end, data.len() as u64);
    assert_eq!(members, [0, first.len() as u64]);
}

fn gzip_member(payload: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    let mut encoder = flate2::write::GzEncoder::new(&mut data, flate2::Compression::default());
    encoder.write_all(payload).unwrap();
    encoder.finish().unwrap();
    data
}

#[test]
fn gzip_boundary_walk_rejects_wrong_later_member_size() {
    let first = gzip_member(b"first");
    let second = gzip_member(b"second");
    let mut data = first;
    data.extend_from_slice(&second);
    let size_offset = data.len() - 4;
    data[size_offset] ^= 0x80;

    let source = reader(data);
    assert_eq!(
        validate_gzip_structure(&source, 0, source.len(), |_| Ok(()))
            .unwrap_err()
            .code(),
        "gzip_isize_mismatch"
    );
}

#[test]
fn gzip_boundary_walk_stops_before_multi_member_carrier_tail() {
    let first = gzip_member(b"first");
    let second = gzip_member(b"second");
    let mut data = first;
    data.extend_from_slice(&second);
    let archive_end = data.len();
    data.extend_from_slice(b"carrier-tail");

    let source = reader(data);
    assert_eq!(
        validate_gzip_structure(&source, 0, source.len(), |_| Ok(())).unwrap(),
        archive_end as u64
    );
}

#[test]
fn bzip2_huffman_walk_reaches_stream_end() {
    let data =
        bzip2::read::BzEncoder::new(&vec![b'B'; 2 * 1024 * 1024][..], bzip2::Compression::best())
            .bytes()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
    let source = reader(data.clone());
    assert_eq!(
        validate_bzip2_structure(&source, 0, source.len(), |_| Ok(())).unwrap(),
        data.len() as u64
    );
}

#[test]
fn bzip2_walk_skips_unused_selector_records() {
    let encoded = bzip2::read::BzEncoder::new(&b"B"[..], bzip2::Compression::best())
        .bytes()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let mut bits = encoded
        .iter()
        .flat_map(|byte| (0..8).rev().map(move |shift| (byte >> shift) & 1))
        .collect::<Vec<_>>();
    // The single-symbol map uses one group of 16 bits. This fixture has
    // exactly one table selector, followed by its table definitions.
    let count_start = 32 + 48 + 32 + 1 + 24 + 16 + 16 + 3;
    let selector_start = count_start + 15;
    assert_eq!(
        &bits[count_start..selector_start],
        &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
    );
    let selector_end = selector_start
        + bits[selector_start..]
            .iter()
            .position(|&bit| bit == 0)
            .unwrap()
        + 1;
    let extra = 18_008;
    for (position, bit) in bits[count_start..selector_start].iter_mut().enumerate() {
        *bit = (((extra + 1) >> (14 - position)) & 1) as u8;
    }
    bits.splice(selector_end..selector_end, std::iter::repeat_n(0, extra));
    let data = bits
        .chunks_exact(8)
        .map(|byte| byte.iter().fold(0, |value, bit| value * 2 + bit))
        .collect::<Vec<_>>();
    let mut decoded = Vec::new();
    bzip2::read::BzDecoder::new(data.as_slice())
        .read_to_end(&mut decoded)
        .unwrap();
    assert_eq!(decoded, b"B");
    let source = reader(data);
    assert_eq!(
        validate_bzip2_structure(&source, 0, source.len(), |_| Ok(())).unwrap(),
        source.len(),
    );
}

#[test]
fn zstd_block_walk_rejects_truncation() {
    let data = zstd::stream::encode_all(&vec![b'Z'; 1024 * 1024][..], 3).unwrap();
    let source = reader(data[..data.len() - 1].to_vec());
    assert!(validate_zstd_structure(&source, 0, (data.len() - 1) as u64, |_| Ok(())).is_err());
}

// One coarse regression covers the former million-block quotas and the
// XZ Index allocation path. Existing codec samples have only a few blocks.
#[test]
fn long_streams_validate_without_archive_wide_quotas() {
    const COUNT: usize = 1_000_064; // divisible by 64 for repeated BZip2 CRCs
    let mut zstd = vec![0x28, 0xb5, 0x2f, 0xfd, 0, 0];
    zstd.extend([0u8; 3].repeat(COUNT - 1));
    zstd.extend([1, 0, 0]);
    let end = zstd.len() as u64;
    zstd.extend(b"carrier tail");
    let source = reader(zstd);
    assert_eq!(
        validate_zstd_structure(&source, 0, source.len(), |_| Ok(())).unwrap(),
        end
    );
    assert!(validate_zstd_structure(&source, 0, end - 1, |_| Ok(())).is_err());

    // Repeat the actual encoder's block bits. Eight copies are byte
    // aligned; 64 identical CRCs fold to zero in the combined CRC.
    let encoded = bzip2::read::BzEncoder::new(&b"B"[..], bzip2::Compression::best())
        .bytes()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let bits: Vec<u8> = encoded
        .iter()
        .flat_map(|b| (0..8).rev().map(move |n| (b >> n) & 1))
        .collect();
    let end_magic: Vec<u8> = [0x17u8, 0x72, 0x45, 0x38, 0x50, 0x90]
        .iter()
        .flat_map(|b| (0..8).rev().map(move |n| (b >> n) & 1))
        .collect();
    let block_end = bits.windows(48).position(|w| w == end_magic).unwrap();
    let repeated_bits = bits[32..block_end].repeat(8);
    let group: Vec<u8> = repeated_bits
        .chunks_exact(8)
        .map(|b| b.iter().fold(0, |n, b| n * 2 + b))
        .collect();
    let mut bzip = b"BZh9".to_vec();
    bzip.extend(group.repeat(COUNT / 8));
    bzip.extend([0x17, 0x72, 0x45, 0x38, 0x50, 0x90, 0, 0, 0, 0]);
    let source = reader(bzip);
    assert_eq!(
        validate_bzip2_structure(&source, 0, source.len(), |_| Ok(())).unwrap(),
        source.len()
    );

    let mut xz = vec![0xfd, b'7', b'z', b'X', b'Z', 0, 0, 0];
    xz.extend(crc32(&xz[6..8]).to_le_bytes());
    let mut block = vec![2, 0, 0x21, 1, 0, 0, 0, 0];
    block.extend(crc32(&block).to_le_bytes());
    block.extend([0; 4]); // LZMA2 end marker followed by three padding bytes
    xz.extend(block.repeat(COUNT));
    let index_start = xz.len();
    xz.push(0);
    let mut count = COUNT as u64;
    while count >= 128 {
        xz.push(count as u8 | 0x80);
        count >>= 7;
    }
    xz.push(count as u8);
    xz.extend([13, 0].repeat(COUNT));
    while (xz.len() - index_start) % 4 != 0 {
        xz.push(0);
    }
    xz.extend(crc32(&xz[index_start..]).to_le_bytes());
    let backward = ((xz.len() - index_start) / 4 - 1) as u32;
    let mut footer = backward.to_le_bytes().to_vec();
    footer.extend([0, 0]);
    xz.extend(crc32(&footer).to_le_bytes());
    xz.extend(footer);
    xz.extend(b"YZ");
    let mut carrier = b"carrier prefix".to_vec();
    let offset = carrier.len() as u64;
    carrier.extend(xz);
    let end = carrier.len() as u64;
    carrier.extend(b"carrier suffix");
    let source = reader(carrier);
    assert_eq!(
        resolve_xz_stream_start(&source, offset, end).unwrap(),
        offset
    );
    assert!(resolve_xz_stream_start(&source, offset, end - 1).is_err());
}

#[test]
fn xz_reverse_index_walk_locates_stream_and_checks_index_crc() {
    let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 6);
    encoder.write_all(&vec![b'X'; 2 * 1024 * 1024]).unwrap();
    let mut data = encoder.finish().unwrap();
    let end = data.len();
    let source = reader(data.clone());
    assert_eq!(resolve_xz_stream_start(&source, 0, end as u64).unwrap(), 0);

    data[end - 16] ^= 1;
    let damaged = reader(data);
    assert_eq!(
        resolve_xz_stream_start(&damaged, 0, end as u64)
            .unwrap_err()
            .code(),
        "xz_index_crc_bad"
    );
}

#[test]
fn xz_prefix_bounds_declared_sizes_and_accepts_an_empty_first_stream() {
    let empty = xz2::write::XzEncoder::new(Vec::new(), 1).finish().unwrap();
    assert_eq!(check_xz_prefix(&empty[..13], Some(100), Some(9)).unwrap(), Some(32));
    // A subsequent stream may account for the ZIP member's nonzero unpacked size.
    assert_eq!(check_xz_prefix(&empty, Some(100), Some(9)).unwrap(), None);

    let mut prefix = empty[..12].to_vec();
    let block = [2, 0xc0, 4, 9, 0x21, 1, 0, 0];
    prefix.extend(block);
    prefix.extend(crc32(&block).to_le_bytes());
    assert_eq!(check_xz_prefix(&prefix[..13], None, None).unwrap(), Some(24));
    assert_eq!(check_xz_prefix(&prefix, Some(56), Some(9)).unwrap(), None);
    assert!(check_xz_prefix(&prefix, Some(55), Some(9)).is_err());
    assert!(check_xz_prefix(&prefix, Some(56), Some(8)).is_err());
}
