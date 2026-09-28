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

fn tar_header_plausible(header: &[u8]) -> (bool, &'static str, u64, bool) {
    if header.len() < TAR_BLOCK_SIZE {
        return (false, "short_tar_header", 0, false);
    }
    let Some(stored_checksum) = parse_octal(&header[148..156]) else {
        return (false, "invalid_checksum_field", 0, false);
    };
    let Some(member_size) = parse_octal(&header[124..136]) else {
        return (false, "invalid_size_field", 0, false);
    };
    if stored_checksum != tar_checksum(header) {
        return (false, "checksum_mismatch", 0, false);
    }
    (
        true,
        "",
        member_size,
        matches!(&header[257..263], b"ustar\x00" | b"ustar "),
    )
}

fn parse_octal(field: &[u8]) -> Option<u64> {
    if field.is_empty() {
        return None;
    }
    // GNU tar stores values outside the ustar range as positive base-256
    // numbers.  Size/checksum users require a non-negative u64 value.
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

#[derive(Clone, Copy)]
struct TarHeaderIdentity {
    stored_checksum: u64,
    computed_checksum: u64,
    member_size: u64,
    ustar_magic: bool,
    name_nonempty: bool,
    numeric_fields_valid: bool,
    typeflag_valid: bool,
    payload_in_range: bool,
    plausible: bool,
    error: &'static str,
}

fn tar_header_identity(header: &[u8], offset: u64, file_size: u64) -> TarHeaderIdentity {
    let stored_checksum = parse_octal(&header[148..156]);
    let member_size = parse_octal(&header[124..136]);
    let computed_checksum = tar_checksum(header);
    let (plausible, error, _, _) = tar_header_plausible(header);
    let ustar_magic = matches!(&header[257..263], b"ustar\x00" | b"ustar ");
    TarHeaderIdentity {
        stored_checksum: stored_checksum.unwrap_or(0),
        computed_checksum,
        member_size: member_size.unwrap_or(0),
        ustar_magic,
        name_nonempty: header[0..100].iter().any(|byte| *byte != 0),
        numeric_fields_valid: stored_checksum.is_some()
            && member_size.is_some()
            && parse_octal(&header[100..108]).is_some()
            && parse_octal(&header[108..116]).is_some()
            && parse_octal(&header[116..124]).is_some()
            && parse_octal(&header[136..148]).is_some(),
        typeflag_valid: header[156] == 0 || (0x20..0x7f).contains(&header[156]),
        payload_in_range: member_size.is_some_and(|size| {
            offset
                .saturating_add(TAR_BLOCK_SIZE as u64)
                .saturating_add(size)
                .saturating_add(tar_padding(size))
                <= file_size
        }),
        plausible,
        error,
    }
}

fn tar_checksum(header: &[u8]) -> u64 {
    header[..148].iter().map(|byte| *byte as u64).sum::<u64>()
        + 32 * 8
        + header[156..].iter().map(|byte| *byte as u64).sum::<u64>()
}

fn tar_padding(size: u64) -> u64 {
    let remainder = size % TAR_BLOCK_SIZE as u64;
    if remainder == 0 {
        0
    } else {
        TAR_BLOCK_SIZE as u64 - remainder
    }
}

fn tar_sparse_map_valid(
    block: &[u8],
    start: usize,
    count: usize,
    previous_end: &mut u64,
) -> bool {
    for index in 0..count {
        let base = start + index * 24;
        let Some(offset) = parse_octal(&block[base..base + 12]) else { return false; };
        let Some(length) = parse_octal(&block[base + 12..base + 24]) else { return false; };
        if offset == 0 && length == 0 {
            continue;
        }
        let Some(end) = offset.checked_add(length) else { return false; };
        if offset < *previous_end {
            return false;
        }
        *previous_end = end;
    }
    true
}
