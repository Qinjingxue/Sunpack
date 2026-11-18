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
        [0x04, 0xf7, 0x11, 0x04] => {
            // SunPack's 7z LZ4 codec uses standard frames, with optional
            // skippable frames. Reuse its parser and XXH32, not a second parser.
            if prefix.len() < 4 {
                return Weak;
            }
            let magic = u32::from_le_bytes(prefix[..4].try_into().unwrap());
            if crate::formats::lz4::skippable(magic) {
                return Strong;
            }
            if magic != 0x184d2204 {
                return Reject;
            }
            match crate::formats::lz4::parse_header(prefix) {
                Ok(_) => Strong,
                Err("lz4_header_truncated") => Weak,
                Err(_) => Reject,
            }
        }
        [0x04, 0xf7, 0x11, 0x01] => {
            // RFC 8878: skippable frames are part of the format, and the
            // unused descriptor bit is NOT a reserved bit that can be rejected.
            if prefix.len() < 5 {
                return Weak;
            }
            let magic = u32::from_le_bytes(prefix[..4].try_into().unwrap());
            if magic & 0xfffffff0 == 0x184d2a50 {
                return Strong;
            }
            if magic == 0xfd2fb528 && prefix[4] & 8 == 0 {
                Strong
            } else {
                Reject
            }
        }
        [0x04, 0x01, 0x08] | [0x04, 0x01, 0x09] => {
            if crate::scan::compression_stream::deflate_prefix_is_possible(
                prefix,
                method == [0x04, 0x01, 0x09],
                unpack_size,
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
    fn bounded_deflate_probe_keeps_stored_fixed_and_dynamic_prefixes() {
        // Raw zlib encodings of repeated "hello deflate ": Z_FIXED and
        // default dynamic Huffman. Exercise every available input prefix,
        // including incomplete trees and long matches with no output buffer.
        let fixed = [
            203, 72, 205, 201, 201, 87, 72, 73, 77, 203, 73, 44, 73, 85, 200, 24, 229, 141, 242,
            134, 12, 15, 0,
        ];
        let dynamic = [
            237, 199, 177, 9, 0, 32, 12, 0, 176, 87, 250, 154, 96, 165, 67, 161, 139, 255, 227, 15,
            206, 201, 150, 202, 238, 137, 157, 167, 215, 205, 40, 51,
        ];
        let stored = [1, 1, 0, 254, 255, 65];
        for (stream, size) in [(&fixed[..], 700), (&dynamic[..], 14000), (&stored[..], 1)] {
            for length in 0..=stream.len() {
                assert_eq!(check(&[4, 1, 8], &[], &stream[..length], size), Weak);
            }
        }
        // 7-Zip Deflate64 fixtures (fixed and dynamic), plus a fixed stream
        // checked by 7z t that emits 65545 bytes using length 285 and both
        // extended distance symbols. No output buffer is needed by the probe.
        let fixed64 = [
            203, 72, 205, 201, 201, 87, 72, 73, 77, 203, 73, 44, 73, 53, 51, 81, 24, 241, 124, 18,
            249, 0,
        ];
        let dynamic64 = [
            228, 193, 129, 0, 0, 0, 0, 128, 32, 182, 253, 165, 6, 169, 226, 241, 120, 60, 30, 143,
            199, 227, 241, 120, 60, 30, 143, 199, 227, 241, 120, 60,
        ];
        let wide64 = [115, 28, 253, 255, 7, 192, 7, 0, 0, 255, 255, 15, 0];
        for (stream, size) in [
            (&fixed64[..], 320),
            (&dynamic64[..], 70000),
            (&wide64[..], 65545),
            (&stored[..], 1),
        ] {
            for length in 0..=stream.len() {
                assert_eq!(check(&[4, 1, 9], &[], &stream[..length], size), Weak);
            }
        }
        // Legal literal-only dynamic block: no distance codes at all. Both
        // variants must accept it, but using an empty distance tree must fail.
        let empty_distance = [5, 192, 129, 8, 0, 0, 0, 0, 32, 182, 253, 165, 78];
        for method in [&[4, 1, 8][..], &[4, 1, 9][..]] {
            for length in 0..=empty_distance.len() {
                assert_eq!(check(method, &[], &empty_distance[..length], 1), Weak);
            }
            assert_eq!(check(method, &[], &[3, 2, 0], 1), Reject);
            assert_eq!(check(method, &[], &[3, 0], 0), Weak);
            assert_eq!(check(method, &[], &[3, 0], 1), Reject);
        }
        // HLIT=31 is reserved in Deflate32, unlike a merely incomplete tree.
        assert_eq!(check(&[4, 1, 8], &[], &[0xfd; 32], 1), Reject);
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
                assert_eq!(check(method, &[], &[first, 0x2a, 0x4d, 0x18, 0], 1), Strong);
            }
            assert_eq!(check(method, &[], &[0; 16], 1), Reject);
        }
        assert_eq!(
            check(&[4, 0xf7, 0x11, 1], &[], &[0x28, 0xb5, 0x2f, 0xfd, 0x10], 1),
            Strong
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
