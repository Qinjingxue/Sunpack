// Necessary conditions at the beginning of a compressor stream, not a file or
// arbitrary solid-stream position. Compressor prefix checks never confirm a
// password; Confirmed is reserved for complete decoded-header/CRC evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SevenZipPrefixCheck {
    Reject,
    Weak,
    Strong,
    Confirmed,
}

// Keep selection separate from candidate checks: unsupported methods must not
// incur a KDF just to return an unconditional survivor.
pub(crate) fn seven_zip_prefix_is_supported(method: &[u8]) -> bool {
    matches!(
        method,
        [0x03, 0x01, 0x01]
            | [0x03, 0x04, 0x01]
            | [0x21]
            | [0x04, 0x02, 0x02]
            | [0x04, 0xf7, 0x11, 0x04]
            | [0x04, 0xf7, 0x11, 0x01]
            | [0x04, 0x01, 0x08]
            | [0x04, 0x01, 0x09]
    )
}

pub(crate) fn seven_zip_prefix_is_strong(method: &[u8]) -> bool {
    matches!(
        method,
        [0x04, 0x02, 0x02] | [0x04, 0xf7, 0x11, 0x04] | [0x04, 0xf7, 0x11, 0x01]
    )
}

pub(crate) fn seven_zip_prefix_check(
    method: &[u8],
    prefix: &[u8],
    packed_size: u64,
    unpack_size: u64,
) -> SevenZipPrefixCheck {
    use SevenZipPrefixCheck::{Reject, Strong, Weak};
    match method {
        // 7-Zip C/LzmaDec.c: initialization rejects a nonzero first byte and
        // the impossible initial repetition range (kBadRepCode).
        [0x03, 0x01, 0x01] => seven_zip_range_prefix(prefix, Some(0xbfff_fc00)),
        // 7-Zip C/Ppmd7Dec.c: Ppmd7z_RangeDec_Init, not ZIP's PPMd coder.
        [0x03, 0x04, 0x01] => seven_zip_range_prefix(prefix, Some(u32::MAX)),
        [0x21] => seven_zip_lzma2_prefix(prefix, packed_size, unpack_size),
        [0x04, 0x02, 0x02] => {
            // BZip2Decoder.cpp ReadStreamSignature2 / ReadBlockSignature2.
            // Both a data block and the empty stream's end marker are legal.
            if prefix.len() < 10 {
                return Weak;
            }
            if &prefix[..3] != b"BZh" || !(b'1'..=b'9').contains(&prefix[3]) {
                return Reject;
            }
            match &prefix[4..10] {
                [0x31, 0x41, 0x59, 0x26, 0x53, 0x59] | [0x17, 0x72, 0x45, 0x38, 0x50, 0x90] => {
                    Strong
                }
                _ => Reject,
            }
        }
        [0x04, 0xf7, 0x11, 0x04] => seven_zip_frame_prefix(prefix, packed_size, true),
        [0x04, 0xf7, 0x11, 0x01] => seven_zip_frame_prefix(prefix, packed_size, false),
        [0x04, 0x01, 0x08] | [0x04, 0x01, 0x09] => {
            // Only the common framing bits and optional uncompressed block
            // length are used here. The worker owns Huffman/payload decoding.
            match prefix.first().map(|first| (first >> 1) & 3) {
                Some(3) => Reject,
                Some(0) if prefix.len() >= 5 => {
                    let len = u16::from_le_bytes([prefix[1], prefix[2]]);
                    let complement = u16::from_le_bytes([prefix[3], prefix[4]]);
                    if len != !complement || u64::from(len) > unpack_size || u64::from(len) + 5 > packed_size {
                        Reject
                    } else {
                        Weak
                    }
                }
                _ => Weak,
            }
        }
        // Copy, filters and unknown codecs have no generic plaintext magic.
        _ => Weak,
    }
}

fn seven_zip_frame_prefix(
    mut prefix: &[u8],
    mut packed_size: u64,
    is_lz4: bool,
) -> SevenZipPrefixCheck {
    use crate::formats::{lz4, zstd};
    use SevenZipPrefixCheck::{Reject, Strong, Weak};

    let magic = loop {
        let Some(magic) = prefix.first_chunk::<4>().copied().map(u32::from_le_bytes) else {
            return Weak;
        };
        if !lz4::skippable(magic) {
            break magic;
        }
        if packed_size < 8 {
            return Reject;
        }
        let Some(size) = prefix.get(4..8) else {
            return Weak;
        };
        let span = 8 + u64::from(u32::from_le_bytes(size.try_into().unwrap()));
        if span > packed_size {
            return Reject;
        }
        packed_size -= span;
        let Ok(span) = usize::try_from(span) else {
            return Weak;
        };
        prefix = prefix.get(span..).unwrap_or_default();
    };
    let needed = if is_lz4 {
        if !prefix.starts_with(lz4::MAGIC) {
            return Reject;
        }
        let header = match lz4::parse_header(prefix) {
            Ok(header) => header,
            Err("lz4_header_truncated") => return Weak,
            Err(_) => return Reject,
        };
        let end = header.len + 4;
        if end as u64 > packed_size {
            return Reject;
        }
        let Some(block) = prefix.get(header.len..end) else {
            return Weak;
        };
        let word = u32::from_le_bytes(block.try_into().unwrap());
        header.block_span(word).ok().map(|span| {
            let end_marker = if word == 0 { 0 } else { 4 + u64::from(header.content_checksum) * 4 };
            end as u64 + span + end_marker
        })
    } else if magic == zstd::MAGIC {
        let Some(&descriptor) = prefix.get(4) else {
            return Weak;
        };
        if descriptor & 8 != 0 {
            return Reject;
        }
        let offset = 4 + zstd::frame_header_size(descriptor);
        let end = offset + zstd::BLOCK_HEADER_SIZE;
        if end as u64 > packed_size {
            return Reject;
        }
        let Some(block) = prefix.get(offset..end) else {
            return Weak;
        };
        zstd::FrameHeader::parse(&prefix[4..offset]).and_then(|frame| {
            let block = frame.block(block.try_into().unwrap())?;
            let next_header = if block.last { 0 } else { zstd::BLOCK_HEADER_SIZE as u64 };
            let checksum_size = if frame.has_checksum { 4 } else { 0 };
            Some(end as u64 + block.encoded_size + next_header + checksum_size)
        })
    } else {
        None
    };
    if needed.is_some_and(|size| size <= packed_size) { Strong } else { Reject }
}

fn seven_zip_lzma2_prefix(
    mut prefix: &[u8],
    mut packed: u64,
    mut unpacked: u64,
) -> SevenZipPrefixCheck {
    use SevenZipPrefixCheck::{Reject, Weak};

    // Same reset states as C/Lzma2Dec.c. Only walk to a following chunk
    // when its control byte is already in the decrypted prefix.
    let mut need_init = 0xe0;
    while let Some(&control) = prefix.first() {
        if control == 0 {
            return if unpacked == 0 { Weak } else { Reject };
        }
        let header_size = match control {
            1 => {
                need_init = 0xc0;
                3
            }
            2 if need_init != 0xe0 => 3,
            0x80..=0xff if control >= need_init => {
                need_init = 0;
                if control & 0x40 != 0 { 6 } else { 5 }
            }
            _ => return Reject,
        };
        if unpacked == 0 || header_size as u64 >= packed {
            return Reject;
        }
        let Some(unpack) = prefix.get(1..3) else {
            return Weak;
        };
        let mut size = u64::from(u16::from_be_bytes(unpack.try_into().unwrap())) + 1;
        let chunk_packed = if header_size == 3 {
            size
        } else {
            size += u64::from(control & 0x1f) << 16;
            let Some(pack) = prefix.get(3..5) else {
                return if size <= unpacked { Weak } else { Reject };
            };
            let pack = u64::from(u16::from_be_bytes(pack.try_into().unwrap())) + 1;
            // The range decoder needs its five initialization bytes.
            if pack < 5 {
                return Reject;
            }
            pack
        };
        let chunk_end = header_size + chunk_packed as usize;
        if size > unpacked || chunk_end as u64 > packed {
            return Reject;
        }
        if header_size == 6
            && prefix.get(5).is_some_and(|prop| *prop >= 225 || prop % 9 + (prop / 9) % 5 > 4)
        {
            return Reject;
        }
        if header_size != 3 {
            // The stricter bound only applies when the dictionary resets.
            let upper = (control >= 0xe0).then_some(0xbfff_fc00);
            if seven_zip_range_prefix(prefix.get(header_size..).unwrap_or_default(), upper) == Reject {
                return Reject;
            }
        }
        packed -= chunk_end as u64;
        unpacked -= size;
        prefix = prefix.get(chunk_end..).unwrap_or_default();
    }
    Weak
}

fn seven_zip_plain_header_prefix(prefix: &[u8], plaintext_size: u64) -> SevenZipPrefixCheck {
    use SevenZipPrefixCheck::{Reject, Weak};

    if prefix.first() != Some(&SZ_HEADER) {
        return Reject;
    }
    let mut pos = 1;
    let Some(section) = read_sz_vint(prefix, &mut pos) else {
        return if (prefix.len() as u64) < plaintext_size { Weak } else { Reject };
    };
    const ARCHIVE_PROPERTIES: u8 = 2;
    const ADDITIONAL_STREAMS_INFO: u8 = 3;
    match u8::try_from(section) {
        Ok(SZ_END | ARCHIVE_PROPERTIES | SZ_FILES_INFO) => Weak,
        // 7zFormat.txt lists the four optional Header sections. The first
        // property of either StreamsInfo must be one of its section tags.
        Ok(ADDITIONAL_STREAMS_INFO | SZ_MAIN_STREAMS_INFO) => {
            match read_sz_vint(prefix, &mut pos) {
                Some(id) if matches!(u8::try_from(id), Ok(SZ_END | SZ_PACK_INFO | SZ_UNPACK_INFO | SZ_SUB_STREAMS_INFO)) => Weak,
                None if (prefix.len() as u64) < plaintext_size => Weak,
                _ => Reject,
            }
        }
        _ => Reject,
    }
}

fn seven_zip_range_prefix(prefix: &[u8], upper: Option<u32>) -> SevenZipPrefixCheck {
    if prefix.first().is_some_and(|&first| first != 0) {
        return SevenZipPrefixCheck::Reject;
    }
    if let (Some(upper), Some(code)) = (upper, prefix.get(1..5)) {
        if u32::from_be_bytes(code.try_into().unwrap()) >= upper {
            return SevenZipPrefixCheck::Reject;
        }
    }
    SevenZipPrefixCheck::Weak
}

#[cfg(test)]
mod seven_zip_prefix_tests {
    use super::{seven_zip_plain_header_prefix, seven_zip_prefix_check, SevenZipPrefixCheck, SevenZipPrefixCheck::*};

    fn check(method: &[u8], _: &[u8], prefix: &[u8], unpack_size: u64) -> SevenZipPrefixCheck {
        seven_zip_prefix_check(method, prefix, u64::MAX, unpack_size)
    }

    #[test]
    fn compressor_prefixes_preserve_legal_variants_and_reject_impossible_starts() {
        let lzma = &[3, 1, 1];
        let ppmd = &[3, 4, 1];
        assert_eq!(check(lzma, &[], &[0, 0xbf, 0xff, 0xfb, 0xff], 1), Weak);
        assert_eq!(check(lzma, &[], &[0, 0xbf, 0xff, 0xfc, 0], 1), Reject);
        assert_eq!(check(ppmd, &[], &[0, 0xff, 0xff, 0xff, 0xfe], 1), Weak);
        assert_eq!(check(ppmd, &[], &[0, 0xff, 0xff, 0xff, 0xff], 1), Reject);
        assert_eq!(check(&[0x21], &[], &[0], 0), Weak);
        assert_eq!(check(&[0x21], &[], &[0], 1), Reject);
        assert_eq!(check(&[0x21], &[], &[1, 0, 1, 255, 255], 2), Weak);
        assert_eq!(check(&[0x21], &[], &[2], 1), Reject);
        let mut lzma2 = [0xe0, 0, 0, 0, 4, 0x5d, 0, 0, 0, 0, 0];
        assert_eq!(check(&[0x21], &[], &lzma2, 1), Weak);
        lzma2[5] = 224;
        assert_eq!(check(&[0x21], &[], &lzma2, 1), Reject);
        assert_eq!(check(&[4, 2, 2], &[], b"BZh91AY&SY", 1), Strong);
        assert_eq!(
            check(&[4, 2, 2], &[], b"BZh1\x17\x72\x45\x38\x50\x90", 0),
            Strong
        );
        assert_eq!(check(&[4, 2, 2], &[], &[0; 16], 1), Reject);
        for method in [&[4, 0xf7, 0x11, 1][..], &[4, 0xf7, 0x11, 4][..]] {
            for first in 0x50..=0x5f {
                assert_eq!(check(method, &[], &[first, 0x2a, 0x4d, 0x18, 0], 1), Weak);
            }
            assert_eq!(check(method, &[], &[0; 16], 1), Reject);
        }
        assert_eq!(
            check(&[4, 0xf7, 0x11, 1], &[], &[0x28, 0xb5, 0x2f, 0xfd, 0x10], 1),
            Weak
        );
        assert_eq!(
            check(&[4, 0xf7, 0x11, 1], &[], &[0x28, 0xb5, 0x2f, 0xfd, 8], 1),
            Reject
        );
        for method in [&[4, 1, 8][..], &[4, 1, 9][..]] {
            assert_eq!(check(method, &[], &[0, 1, 0, 0xfe, 0xff], 1), Weak);
            assert_eq!(check(method, &[], &[0, 1, 0, 0xff, 0xff], 1), Reject);
            assert_eq!(check(method, &[], &[6], 1), Reject);
            assert_eq!(check(method, &[], &[2], 1), Weak);
        }
        assert_eq!(check(&[0], &[], &[0xff; 16], 1), Weak);
        assert_eq!(check(lzma, &[], &[], 1), Weak);
    }

    #[test]
    fn framed_codecs_check_first_block_without_reading_its_body() {
        let zstd = [4, 0xf7, 0x11, 1];
        // Single-segment window of 8 and the decoder-ignored flag bit.
        let frame = [0x28, 0xb5, 0x2f, 0xfd, 0x30, 8, 0x43, 0, 0];
        assert_eq!(seven_zip_prefix_check(&zstd, &frame, 10, 8), Strong);
        assert_eq!(seven_zip_prefix_check(&zstd, &frame[..8], 10, 8), Weak);
        assert_eq!(seven_zip_prefix_check(&zstd, &frame, 9, 8), Reject);
        for word in [0x47, 0x49, 0x0d] { // reserved, raw over window, then too-short compressed
            let mut invalid = frame;
            invalid[6] = word;
            assert_eq!(seven_zip_prefix_check(&zstd, &invalid, 100, 8), Reject);
        }
        let mut skippable = vec![0x5f, 0x2a, 0x4d, 0x18, 1, 0, 0, 0, 0xff];
        skippable.extend(frame);
        assert_eq!(seven_zip_prefix_check(&zstd, &skippable, 19, 8), Strong);
        assert_eq!(seven_zip_prefix_check(&zstd, &skippable[..8], 19, 8), Weak);
        assert_eq!(seven_zip_prefix_check(&zstd, &skippable[..8], 8, 8), Reject);

        let lz4 = [4, 0xf7, 0x11, 4];
        let mut frame = [4, 0x22, 0x4d, 0x18, 0x54, 0x40, 0, 0, 0, 0, 0];
        frame[6] = (crate::formats::lz4::xxh32(&frame[4..6]) >> 8) as u8;
        // Zero is an end marker with a content checksum. A set high bit
        // denotes a valid empty raw block followed by a block checksum.
        for (word, required) in [(0u32, 15), (0x8000_0000, 23)] {
            frame[7..].copy_from_slice(&word.to_le_bytes());
            assert_eq!(seven_zip_prefix_check(&lz4, &frame[..10], required, 8), Weak);
            assert_eq!(seven_zip_prefix_check(&lz4, &frame, required - 1, 8), Reject);
            assert_eq!(seven_zip_prefix_check(&lz4, &frame, required, 8), Strong);
        }
        frame[7..].copy_from_slice(&65537u32.to_le_bytes());
        assert_eq!(seven_zip_prefix_check(&lz4, &frame, 70000, 8), Reject);
    }

    #[test]
    fn lzma2_prefix_uses_declared_lengths_and_checks_available_next_chunk() {
        let raw_then_end = [1, 0, 0, 0xff, 0];
        let lzma2 = [0x21];
        let check = |prefix, packed, unpacked| seven_zip_prefix_check(&lzma2, prefix, packed, unpacked);
        for len in 0..=raw_then_end.len() {
            assert_eq!(check(&raw_then_end[..len], 5, 1), Weak);
        }
        assert_eq!(check(&[1, 0, 8], 8, 9), Reject);
        assert_eq!(check(&[1, 0, 8], 16, 8), Reject);
        assert_eq!(check(&[1, 0, 0, 0xff, 0x80], 20, 2), Reject);
        assert_eq!(check(&[1, 0, 0, 0xff, 0xc0], 20, 2), Weak);
        assert_eq!(check(&[0xe0, 0, 0, 0, 3], 16, 1), Reject);
        assert_eq!(check(&[0xe0, 0, 0, 0, 4], 10, 1), Reject);
        assert_eq!(check(&[0xe0, 0, 0, 0, 4], 12, 1), Weak);
    }

    #[test]
    fn plain_header_prefix_preserves_varints_and_short_reads() {
        assert_eq!(seven_zip_plain_header_prefix(&[1, 0], 2), Weak);
        assert_eq!(seven_zip_plain_header_prefix(&[1, 2], 100), Weak);
        assert_eq!(seven_zip_plain_header_prefix(&[1, 3, 0x80, 6], 4), Weak);
        assert_eq!(seven_zip_plain_header_prefix(&[1, 4, 0x80], 100), Weak);
        assert_eq!(seven_zip_plain_header_prefix(&[1, 4, 0x80], 3), Reject);
        assert_eq!(seven_zip_plain_header_prefix(&[1, 4, 5], 100), Reject);
        assert_eq!(seven_zip_plain_header_prefix(&[1, 0x17], 100), Reject);
    }
}
