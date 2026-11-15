fn u16_le(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn u32_le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn u64_le(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

pub(super) fn tar_header_identity(header: &[u8], file_size: u64) -> bool {
    use crate::formats::tar::{header_size, number, padding};

    let Ok(size) = header_size(header) else { return false; };
    (TAR_BLOCK_SIZE as u64).saturating_add(size).saturating_add(padding(size)) <= file_size
        && header[..100].iter().any(|byte| *byte != 0)
        && (header[156] == 0 || (0x20..0x7f).contains(&header[156]))
        && [100..108, 108..116, 116..124, 136..148].into_iter()
            .all(|field| number(&header[field]).is_some())
}
