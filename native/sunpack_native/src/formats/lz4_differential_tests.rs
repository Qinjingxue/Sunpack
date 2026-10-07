//! Bounded, reproducible mutation tests against the unmodified liblz4 API.
//! Payload checksums are deliberately deferred by the structural walker.
use super::tests::{frame, index};
use super::*;

#[repr(C)]
#[derive(Default)]
struct FrameInfo {
    block_size: i32,
    block_mode: i32,
    content_checksum: i32,
    frame_type: i32,
    content_size: u64,
    dictionary_id: u32,
    block_checksum: i32,
}
unsafe extern "C" {
    fn LZ4F_compressFrameBound(size: usize, preferences: *const c_void) -> usize;
    fn LZ4F_compressFrame(
        dst: *mut c_void,
        capacity: usize,
        src: *const c_void,
        size: usize,
        preferences: *const c_void,
    ) -> usize;
    fn LZ4F_createDecompressionContext(ctx: *mut *mut c_void, version: u32) -> usize;
    fn LZ4F_freeDecompressionContext(ctx: *mut c_void) -> usize;
    fn LZ4F_isError(code: usize) -> u32;
    fn LZ4F_getFrameInfo(
        ctx: *mut c_void,
        info: *mut FrameInfo,
        src: *const c_void,
        size: *mut usize,
    ) -> usize;
    fn LZ4F_decompress(
        ctx: *mut c_void,
        dst: *mut c_void,
        dst_size: *mut usize,
        src: *const c_void,
        src_size: *mut usize,
        options: *const c_void,
    ) -> usize;
}
struct Reference(*mut c_void);
impl Reference {
    fn encode(bytes: &[u8]) -> Vec<u8> {
        let mut output = vec![0; unsafe { LZ4F_compressFrameBound(bytes.len(), std::ptr::null()) }];
        let size = unsafe {
            LZ4F_compressFrame(
                output.as_mut_ptr().cast(),
                output.len(),
                bytes.as_ptr().cast(),
                bytes.len(),
                std::ptr::null(),
            )
        };
        assert_eq!(unsafe { LZ4F_isError(size) }, 0);
        output.truncate(size);
        output
    }
    fn new() -> Self {
        let mut ctx = std::ptr::null_mut();
        let status = unsafe { LZ4F_createDecompressionContext(&mut ctx, 100) };
        assert_eq!(unsafe { LZ4F_isError(status) }, 0);
        Self(ctx)
    }
    fn header(bytes: &[u8]) -> Option<(usize, FrameInfo)> {
        let ctx = Self::new();
        let mut info = FrameInfo::default();
        let mut size = bytes.len();
        let status =
            unsafe { LZ4F_getFrameInfo(ctx.0, &mut info, bytes.as_ptr().cast(), &mut size) };
        (unsafe { LZ4F_isError(status) } == 0).then_some((size, info))
    }
    fn decode(bytes: &[u8]) -> Option<Vec<u8>> {
        if bytes.is_empty() {
            return None;
        }
        let ctx = Self::new();
        let mut output = Vec::new();
        let mut offset = 0;
        loop {
            let mut buffer = [0u8; 257];
            let mut dst_size = buffer.len();
            let mut src_size = (bytes.len() - offset).min(31);
            let hint = unsafe {
                LZ4F_decompress(
                    ctx.0,
                    buffer.as_mut_ptr().cast(),
                    &mut dst_size,
                    bytes[offset..].as_ptr().cast(),
                    &mut src_size,
                    std::ptr::null(),
                )
            };
            if unsafe { LZ4F_isError(hint) } != 0 || output.len() + dst_size > 1024 * 1024 {
                return None;
            }
            output.extend_from_slice(&buffer[..dst_size]);
            offset += src_size;
            if hint == 0 && offset == bytes.len() {
                return Some(output);
            }
            if src_size == 0 && dst_size == 0 {
                return None;
            }
        }
    }
}
impl Drop for Reference {
    fn drop(&mut self) {
        unsafe {
            LZ4F_freeDecompressionContext(self.0);
        }
    }
}

fn compare_header(bytes: &[u8]) {
    let ours = parse_header(bytes);
    let reference = Reference::header(bytes);
    assert_eq!(ours.is_ok(), reference.is_some(), "header: {bytes:02x?}");
    if let (Ok(ours), Some((size, reference))) = (ours, reference) {
        assert_eq!(ours.len, size);
        assert_eq!(ours.block_max, 1 << (8 + 2 * reference.block_size));
        assert_eq!(
            ours.content_size,
            (bytes[4] & 8 != 0).then_some(reference.content_size)
        );
        assert_eq!(ours.content_checksum, reference.content_checksum != 0);
        assert_eq!(ours.block_checksum, reference.block_checksum != 0);
    }
}

#[test]
fn header_acceptance_matches_liblz4_for_all_flags_and_block_descriptors() {
    for flags in 0..=255u8 {
        for bd in 0..=255u8 {
            let bytes = frame(
                b"",
                flags,
                bd,
                (flags & 8 != 0).then_some(0),
                (flags & 1 != 0).then_some(0),
            );
            compare_header(&bytes);
        }
    }
    for flags in [0x40, 0x61, 0x7c, 0x7d] {
        let bytes = frame(
            b"",
            flags,
            0x70,
            (flags & 8 != 0).then_some(u64::MAX),
            (flags & 1 != 0).then_some(u32::MAX),
        );
        for length in 0..=parse_header(&bytes).unwrap().len {
            compare_header(&bytes[..length]);
        }
        for at in 4..parse_header(&bytes).unwrap().len {
            for bit in 0..8 {
                let mut mutated = bytes.clone();
                mutated[at] ^= 1 << bit;
                compare_header(&mutated);
            }
        }
    }
}

fn random(state: &mut u32) -> u32 {
    *state ^= *state << 13;
    *state ^= *state >> 17;
    *state ^= *state << 5;
    *state
}
fn compare_stream(bytes: &[u8], case: usize) {
    let reference = Reference::decode(bytes);
    let decoded = sample(std::io::Cursor::new(bytes), 1024 * 1024);
    assert_eq!(
        decoded.is_ok(),
        reference.is_some(),
        "decoder mutation {case}: {bytes:02x?}"
    );
    let parsed = index(bytes.to_vec(), 0);
    // A stream containing only skippable records is decodable, but deliberately
    // does not establish LZ4 archive identity without external format context.
    let structural_complete = parsed.error.is_empty()
        && parsed.end == bytes.len() as u64
        && (parsed.frames > 0 || parsed.skips > 0);
    if let Some(reference) = reference {
        assert_eq!(
            decoded.unwrap(),
            reference,
            "decoder output mutation {case}"
        );
        assert!(
            structural_complete,
            "walker rejected valid stream {case}: {parsed:?}"
        );
        if let Some(size) = parsed.decoded_size {
            assert_eq!(size, reference.len() as u64);
        }
    } else if !structural_complete {
        assert!(
            decoded.is_err(),
            "decoder accepted an incomplete structure {case}"
        );
    }
    // A structurally complete frame with a bad payload/checksum is expected to
    // be rejected only by the decoder. Do not turn analysis into a full decode.
}

#[test]
fn mutated_streams_match_liblz4_and_do_not_drift_from_structural_bounds() {
    let mut state = 0x5a17_c0de;
    let mut case = 0;
    for _ in 0..256 {
        let mut bytes = Vec::new();
        for _ in 0..1 + random(&mut state) % 3 {
            if random(&mut state) & 1 != 0 {
                let size = random(&mut state) % 16;
                bytes.extend_from_slice(&(0x184d2a50 | (random(&mut state) & 15)).to_le_bytes());
                bytes.extend_from_slice(&size.to_le_bytes());
                bytes.extend((0..size).map(|_| random(&mut state) as u8));
            }
            let flags = 0x40 | ((random(&mut state) as u8 & 15) << 2);
            let compressed = random(&mut state) & 1 != 0;
            let payload: Vec<u8> = (0..random(&mut state) % 2048)
                .map(|at| {
                    if compressed {
                        (at % 17) as u8
                    } else {
                        random(&mut state) as u8
                    }
                })
                .collect();
            bytes.extend(if compressed {
                Reference::encode(&payload)
            } else {
                frame(
                    &payload,
                    flags,
                    (4 + random(&mut state) as u8 % 4) << 4,
                    (flags & 8 != 0).then_some(payload.len() as u64),
                    None,
                )
            });
        }
        compare_stream(&bytes, case);
        case += 1;
        for mutation in 0..16 {
            let mut mutated = bytes.clone();
            let at = random(&mut state) as usize % mutated.len();
            match mutation % 4 {
                0 => mutated[at] ^= 1 << (random(&mut state) % 8),
                1 => mutated.truncate(at),
                2 => {
                    mutated.remove(at);
                }
                _ => mutated.insert(at, random(&mut state) as u8),
            }
            compare_stream(&mutated, case);
            case += 1;
        }
    }
}
