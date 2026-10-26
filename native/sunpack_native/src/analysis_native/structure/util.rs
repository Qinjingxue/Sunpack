fn read_vint(data: &[u8], offset: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0;
    let end = data.len().min(offset.saturating_add(10));
    let last_valid_index = offset.checked_add(9);
    for index in offset..end {
        let byte = data[index];
        if Some(index) == last_valid_index && (byte & 0x7E) != 0 {
            return None;
        }
        value |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return index.checked_add(1).map(|next| (value, next));
        }
        shift += 7;
    }
    None
}

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
