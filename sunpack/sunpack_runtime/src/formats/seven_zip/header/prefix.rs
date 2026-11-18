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
        [0x03, 0x01, 0x01] => {
            if unpack_size != 0 && packed_size < 5 {
                return Reject;
            }
            seven_zip_range_prefix(prefix, Some(0xbfff_fc00))
        }
        // Ppmd7.c initializes 256 literals of frequency one and a single
        // escape. At the root that escape ends the stream before any output.
        [0x03, 0x04, 0x01] => {
            if unpack_size != 0 && packed_size < 5 {
                return Reject;
            }
            let bound = if unpack_size == 0 { u32::MAX } else { (u32::MAX / 257) * 256 };
            seven_zip_range_prefix(prefix, Some(bound))
        }
        [0x21] => seven_zip_lzma2_prefix(prefix, packed_size, unpack_size),
        [0x04, 0x02, 0x02] => {
            // BZip2Decoder.cpp ReadStreamSignature2 / ReadBlockSignature2.
            // Both a data block and the empty stream's end marker are legal.
            if !b"BZh".starts_with(&prefix[..prefix.len().min(3)])
                || prefix.get(3).is_some_and(|level| !(b'1'..=b'9').contains(level))
            {
                return Reject;
            }
            if prefix.len() < 10 {
                return Weak;
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
            if crate::formats::deflate_prefix::matches_prefix(
                prefix, Some(packed_size), Some(unpack_size), method[2] == 0x09,
            ) {
                Weak
            } else {
                Reject
            }
        }
        // Copy, filters and unknown codecs have no generic plaintext magic.
        _ => Weak,
    }
}

enum SevenZipFrameStep {
    Skip(u64),
    Last(u64),
    Lz4(crate::formats::lz4::Header, u64),
    Zstd(crate::formats::zstd::FrameHeader, u64),
}

fn seven_zip_frame_prefix(
    mut prefix: &[u8],
    mut packed_size: u64,
    is_lz4: bool,
) -> SevenZipPrefixCheck {
    use SevenZipPrefixCheck::{Reject, Strong, Weak};
    loop {
        match seven_zip_frame_step(prefix, packed_size, is_lz4) {
            Ok(Some(SevenZipFrameStep::Skip(span))) => {
                packed_size -= span;
                prefix = prefix.get(usize::try_from(span).unwrap_or(usize::MAX)..).unwrap_or_default();
            }
            Ok(Some(_)) => return Strong,
            Ok(None) => return Weak,
            Err(()) => return Reject,
        }
    }
}

fn seven_zip_frame_step(
    prefix: &[u8], packed_size: u64, is_lz4: bool,
) -> Result<Option<SevenZipFrameStep>, ()> {
    use crate::formats::{lz4, zstd};
    let Some(magic) = prefix.first_chunk::<4>().copied().map(u32::from_le_bytes) else {
        return Ok(None);
    };
    if lz4::skippable(magic) {
        if packed_size < 8 {
            return Err(());
        }
        let Some(size) = prefix.get(4..8) else { return Ok(None) };
        let span = 8 + u64::from(u32::from_le_bytes(size.try_into().unwrap()));
        return (span <= packed_size).then_some(Some(SevenZipFrameStep::Skip(span))).ok_or(());
    }
    if is_lz4 {
        if !prefix.starts_with(lz4::MAGIC) {
            return Err(());
        }
        let header = match lz4::parse_header(prefix) {
            Ok(header) => header,
            Err("lz4_header_truncated") => return Ok(None),
            Err(_) => return Err(()),
        };
        let end = header.len + 4;
        if end as u64 > packed_size {
            return Err(());
        }
        let Some(block) = prefix.get(header.len..end) else { return Ok(None) };
        let word = u32::from_le_bytes(block.try_into().unwrap());
        seven_zip_lz4_block(&header, word, packed_size - end as u64).map(|(span, last)| {
            let next = end as u64 + span;
            Some(if last { SevenZipFrameStep::Last(next) } else { SevenZipFrameStep::Lz4(header, next) })
        })
    } else if magic == zstd::MAGIC {
        let Some(&descriptor) = prefix.get(4) else { return Ok(None) };
        if descriptor & 8 != 0 {
            return Err(());
        }
        let offset = 4 + zstd::frame_header_size(descriptor);
        let end = offset + zstd::BLOCK_HEADER_SIZE;
        if end as u64 > packed_size {
            return Err(());
        }
        let Some(block) = prefix.get(offset..end) else { return Ok(None) };
        let frame = zstd::FrameHeader::parse(&prefix[4..offset]).ok_or(())?;
        seven_zip_zstd_block(&frame, block.try_into().unwrap(), packed_size - end as u64).map(|(span, last)| {
            let next = end as u64 + span;
            Some(if last { SevenZipFrameStep::Last(next) } else { SevenZipFrameStep::Zstd(frame, next) })
        })
    } else {
        Err(())
    }
}

fn seven_zip_lz4_block(
    header: &crate::formats::lz4::Header, word: u32, remaining: u64,
) -> Result<(u64, bool), ()> {
    let span = header.block_span(word).map_err(|_| ())?;
    let next_header = if word == 0 { 0 } else { 4 + u64::from(header.content_checksum) * 4 };
    (span + next_header <= remaining).then_some((span, word == 0)).ok_or(())
}

fn seven_zip_zstd_block(
    frame: &crate::formats::zstd::FrameHeader, header: [u8; 3], remaining: u64,
) -> Result<(u64, bool), ()> {
    let block = frame.block(header).ok_or(())?;
    let next_header = if block.last { 0 } else { 3 };
    let checksum_size = if frame.has_checksum { 4 } else { 0 };
    (block.encoded_size + next_header + checksum_size <= remaining)
        .then_some((block.encoded_size + if block.last { checksum_size } else { 0 }, block.last))
        .ok_or(())
}

fn seven_zip_lzma2_prefix(
    mut prefix: &[u8],
    mut packed: u64,
    mut unpacked: u64,
) -> SevenZipPrefixCheck {
    use SevenZipPrefixCheck::{Reject, Weak};

    let mut need_init = 0xe0;
    loop {
        match seven_zip_lzma2_chunk(prefix, packed, unpacked, &mut need_init) {
            Ok(Some((size, span))) => {
                packed -= span;
                unpacked -= size;
                prefix = prefix.get(span as usize..).unwrap_or_default();
            }
            Ok(None) => return Weak,
            Err(()) => return Reject,
        }
    }
}

fn seven_zip_lzma2_chunk(
    prefix: &[u8], packed: u64, unpacked: u64, need_init: &mut u8,
) -> Result<Option<(u64, u64)>, ()> {
        let Some(&control) = prefix.first() else { return Ok(None) };
        if control == 0 {
            return (unpacked == 0).then_some(None).ok_or(());
        }
        // Same reset states as C/Lzma2Dec.c.
        let header_size = match control {
            1 => {
                *need_init = 0xc0;
                3
            }
            2 if *need_init != 0xe0 => 3,
            0x80..=0xff if control >= *need_init => {
                *need_init = 0;
                if control & 0x40 != 0 { 6 } else { 5 }
            }
            _ => return Err(()),
        };
        if unpacked == 0 || header_size as u64 >= packed {
            return Err(());
        }
        let Some(unpack) = prefix.get(1..3) else {
            return Ok(None);
        };
        let mut size = u64::from(u16::from_be_bytes(unpack.try_into().unwrap())) + 1;
        let chunk_packed = if header_size == 3 {
            size
        } else {
            size += u64::from(control & 0x1f) << 16;
            let Some(pack) = prefix.get(3..5) else {
                return (size <= unpacked).then_some(None).ok_or(());
            };
            let pack = u64::from(u16::from_be_bytes(pack.try_into().unwrap())) + 1;
            // The range decoder needs its five initialization bytes.
            if pack < 5 {
                return Err(());
            }
            pack
        };
        let chunk_end = header_size + chunk_packed as usize;
        if size > unpacked || chunk_end as u64 > packed {
            return Err(());
        }
        if header_size == 6
            && prefix.get(5).is_some_and(|prop| *prop >= 225 || prop % 9 + (prop / 9) % 5 > 4)
        {
            return Err(());
        }
        if header_size != 3 {
            // The stricter bound only applies when the dictionary resets.
            let upper = (control >= 0xe0).then_some(0xbfff_fc00);
            if seven_zip_range_prefix(prefix.get(header_size..).unwrap_or_default(), upper) == SevenZipPrefixCheck::Reject {
                return Err(());
            }
        }
        Ok(Some((size, chunk_end as u64)))
}

fn seven_zip_has_block_successor(method: &[u8]) -> bool {
    matches!(method, [0x21] | [0x04, 0xf7, 0x11, 0x04 | 0x01])
}

// Each extra read is derived from an already checked codec length. There is
// no magic scan, decompression, or dependence on the intervening block body.
pub(crate) fn seven_zip_successor_prefix<E>(
    method: &[u8], prefix: &[u8], packed: u64, unpacked: u64,
    mut read: impl FnMut(u64, &mut [u8]) -> Result<(), E>,
    mut still_ambiguous: impl FnMut(u64) -> bool,
) -> Result<SevenZipPrefixCheck, E> {
    use SevenZipPrefixCheck::{Reject, Strong, Weak};
    if method == [0x21] {
        let mut need_init = 0xe0;
        let mut chunk = seven_zip_lzma2_chunk(prefix, packed, unpacked, &mut need_init);
        let mut unpacked = unpacked;
        let mut next = 0;
        loop {
            match chunk {
                Ok(Some((size, span))) => {
                    let first = next == 0;
                    next += span;
                    if next == packed || (!first && !still_ambiguous(next)) {
                        // Do not require a separate end marker when the
                        // known-size stream is already exhausted.
                        return Ok(Weak);
                    }
                    unpacked -= size;
                }
                Ok(None) => return Ok(Weak),
                Err(()) => return Ok(Reject),
            }
            let mut header = [0; 11];
            let len = (packed - next).min(header.len() as u64) as usize;
            read(next, &mut header[..len])?;
            chunk = seven_zip_lzma2_chunk(&header[..len], packed - next, unpacked, &mut need_init);
        }
    }
    let is_lz4 = method == [0x04, 0xf7, 0x11, 0x04];
    let mut offset = 0;
    let mut step = seven_zip_frame_step(prefix, packed, is_lz4);
    if matches!(step, Ok(None)) && (prefix.len() as u64) < packed {
        let mut header = [0; 32];
        let size = packed.min(header.len() as u64) as usize;
        read(0, &mut header[..size])?;
        step = seven_zip_frame_step(&header[..size], packed, is_lz4);
    }
    let mut checked_successor = false;
    loop {
        step = match step {
            Ok(Some(SevenZipFrameStep::Last(span))) if
                packed - offset == span || !still_ambiguous(offset + span) => return Ok(Strong),
            Ok(Some(SevenZipFrameStep::Skip(span) | SevenZipFrameStep::Last(span))) => {
                offset += span;
                if packed - offset < 4 {
                    return Ok(Weak);
                }
                let mut header = [0; 32];
                let size = (packed - offset).min(header.len() as u64) as usize;
                read(offset, &mut header[..size])?;
                seven_zip_frame_step(&header[..size], packed - offset, is_lz4)
            }
            Ok(Some(SevenZipFrameStep::Lz4(frame, next))) => {
                if checked_successor && !still_ambiguous(offset + next) {
                    return Ok(Strong);
                }
                let mut header = [0; 4];
                read(offset + next, &mut header)?;
                checked_successor = true;
                seven_zip_lz4_block(&frame, u32::from_le_bytes(header), packed - offset - next - 4)
                    .map(|(span, last)| {
                        let next = next + 4 + span;
                        Some(if last { SevenZipFrameStep::Last(next) } else { SevenZipFrameStep::Lz4(frame, next) })
                    })
            }
            Ok(Some(SevenZipFrameStep::Zstd(frame, next))) => {
                if checked_successor && !still_ambiguous(offset + next) {
                    return Ok(Strong);
                }
                let mut header = [0; 3];
                read(offset + next, &mut header)?;
                checked_successor = true;
                seven_zip_zstd_block(&frame, header, packed - offset - next - 3)
                    .map(|(span, last)| {
                        let next = next + 3 + span;
                        Some(if last { SevenZipFrameStep::Last(next) } else { SevenZipFrameStep::Zstd(frame, next) })
                    })
            }
            Ok(None) => return Ok(Weak),
            Err(()) => return Ok(Reject),
        };
    }
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
    match u8::try_from(section) {
        Ok(SZ_END | SZ_ARCHIVE_PROPERTIES | SZ_FILES_INFO) => Weak,
        // 7zFormat.txt lists the four optional Header sections. The first
        // property of either StreamsInfo must be one of its section tags.
        Ok(SZ_ADDITIONAL_STREAMS_INFO | SZ_MAIN_STREAMS_INFO) => {
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

fn seven_zip_bcj2_range_prefix(prefix: &[u8], packed_size: u64) -> SevenZipPrefixCheck {
    // Bcj2Dec_Decode initializes only the RC input with five bytes.
    if packed_size < 5 {
        return SevenZipPrefixCheck::Reject;
    }
    seven_zip_range_prefix(prefix, Some(u32::MAX))
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
        let boundary = (u32::MAX / 257) * 256;
        let mut ppmd_code = [0; 5];
        ppmd_code[1..].copy_from_slice(&(boundary - 1).to_be_bytes());
        assert_eq!(check(ppmd, &[], &ppmd_code, 1), Weak);
        ppmd_code[1..].copy_from_slice(&boundary.to_be_bytes());
        assert_eq!(check(ppmd, &[], &ppmd_code, 1), Reject);
        assert_eq!(check(ppmd, &[], &ppmd_code, 0), Weak);
        assert_eq!(check(ppmd, &[], &[0, 0xff, 0xff, 0xff, 0xff], 1), Reject);
        assert_eq!(seven_zip_prefix_check(ppmd, &[0], 4, 1), Reject);
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
