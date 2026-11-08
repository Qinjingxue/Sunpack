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

fn parse_octal(field: &[u8]) -> Option<u64> {
    crate::formats::tar::number(field)
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
    validated_size: Result<u64, &'static str>,
}

fn tar_header_identity(header: &[u8], offset: u64, file_size: u64) -> TarHeaderIdentity {
    let stored_checksum = parse_octal(&header[148..156]);
    let member_size = parse_octal(&header[124..136]);
    let computed_checksum = tar_checksum(header);
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
        validated_size: crate::formats::tar::checked_header_size(
            stored_checksum,
            member_size,
            computed_checksum,
        ),
    }
}

fn tar_checksum(header: &[u8]) -> u64 {
    crate::formats::tar::checksum(header)
}
fn tar_padding(size: u64) -> u64 {
    crate::formats::tar::padding(size)
}
