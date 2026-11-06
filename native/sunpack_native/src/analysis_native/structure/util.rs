fn parse_octal(field: &[u8]) -> Option<u64> {
    crate::formats::tar::number(field)
}
fn tar_checksum(header: &[u8]) -> u64 {
    crate::formats::tar::checksum(header)
}
fn padding_for_size(size: u64) -> u64 {
    crate::formats::tar::padding(size)
}

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
