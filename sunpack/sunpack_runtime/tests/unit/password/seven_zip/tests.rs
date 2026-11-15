use super::*;

#[test]
fn analysis_parser_confirms_predecoded_header() {
    assert!(predecoded_seven_zip_header_is_supported(&[0x01, 0x00]));
    assert!(!predecoded_seven_zip_header_is_supported(&[0x01, 0xff]));
}

#[test]
fn declared_next_header_beyond_input_requires_a_volume_or_has_damaged_offsets() {
    let mut bytes = [0u8; SEVEN_Z_HEADER_SIZE];
    bytes[..6].copy_from_slice(SEVEN_Z_MAGIC);
    bytes[12..20].copy_from_slice(&64u64.to_le_bytes());
    bytes[20..28].copy_from_slice(&16u64.to_le_bytes());
    assert_eq!(
        seven_zip_tail_requirement(&bytes, 64).unwrap_err().field,
        "7z.next_header"
    );
}
