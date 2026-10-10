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
    if field.is_empty() {
        return None;
    }
    if field[0] & 0x80 != 0 {
        let mut value = (field[0] & 0x7f) as u64;
        for byte in &field[1..] {
            value = value.checked_mul(256)?.checked_add(*byte as u64)?;
        }
        return Some(value);
    }
    let mut value = 0u64;
    let mut seen_digit = false;
    for byte in field {
        match *byte {
            b'0'..=b'7' => {
                seen_digit = true;
                value = value.checked_mul(8)?.checked_add((*byte - b'0') as u64)?;
            }
            b'\0' | b' ' => {}
            _ => return None,
        }
    }
    Some(if seen_digit { value } else { 0 })
}

fn tar_checksum(header: &[u8]) -> u64 {
    header[..148].iter().map(|b| *b as u64).sum::<u64>()
        + 32 * 8
        + header[156..].iter().map(|b| *b as u64).sum::<u64>()
}

fn padding_for_size(size: u64) -> u64 {
    let remainder = size % TAR_BLOCK_SIZE as u64;
    if remainder == 0 {
        0
    } else {
        TAR_BLOCK_SIZE as u64 - remainder
    }
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
