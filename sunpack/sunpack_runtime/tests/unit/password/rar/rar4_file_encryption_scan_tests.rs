use super::*;

fn block(header_type: u8, flags: u16, body: &[u8]) -> Vec<u8> {
    let mut header = vec![0, 0, header_type];
    header.extend_from_slice(&flags.to_le_bytes());
    header.extend_from_slice(&((7 + body.len()) as u16).to_le_bytes());
    header.extend_from_slice(body);
    let crc = (crc32(&header[2..]) & 0xffff) as u16;
    header[..2].copy_from_slice(&crc.to_le_bytes());
    header
}

fn file_block(flags: u16, name: &[u8], payload: &[u8], unpacked: u32) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    body.extend_from_slice(&unpacked.to_le_bytes());
    body.push(2);
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.push(29);
    body.push(0x30);
    body.extend_from_slice(&(name.len() as u16).to_le_bytes());
    body.extend_from_slice(&0x20u32.to_le_bytes());
    body.extend_from_slice(name);
    let mut output = block(0x74, flags | RAR4_LONG_BLOCK, &body);
    output.extend_from_slice(payload);
    output
}

fn archive(members: &[Vec<u8>], end_flags: Option<u16>) -> Vec<u8> {
    let mut data = RAR4_SIGNATURE.to_vec();
    data.extend(block(0x73, 0, &[0; 6]));
    for member in members {
        data.extend_from_slice(member);
    }
    if let Some(flags) = end_flags {
        data.extend(block(0x7b, flags, &[]));
    }
    data
}

fn status_of(data: Vec<u8>) -> &'static str {
    let result = prepare_rar(|offset, len, _field| {
        let start = (offset as usize).min(data.len());
        Ok(data[start..(start + len).min(data.len())].to_vec())
    });
    match result {
        Ok(_) => "other_material",
        Err(PreparedStatus::Status(status, _)) => status,
        Err(PreparedStatus::ReadFault(_)) => "read_fault",
    }
}

#[test]
fn encrypted_member_after_plain_member_is_found() {
    let data = archive(
        &[
            file_block(0, b"plain.txt", b"plain", 5),
            file_block(RAR4_FILE_PASSWORD, b"secret.txt", &[0x55; 16], 7),
        ],
        Some(0),
    );
    assert_eq!(status_of(data), "unknown_needs_final_verifier");
}

#[test]
fn encrypted_member_beyond_prefix_is_found_by_seeking() {
    let large = vec![0xAA; RAR_INITIAL_PREFIX_SCAN * 4];
    let data = archive(
        &[
            file_block(0, b"large.bin", &large, large.len() as u32),
            file_block(RAR4_FILE_PASSWORD, b"secret.txt", &[0x55; 16], 7),
        ],
        Some(0),
    );
    assert_eq!(status_of(data), "unknown_needs_final_verifier");
}

#[test]
fn plain_archive_with_final_end_block_is_not_required() {
    let data = archive(&[file_block(0, b"plain.txt", b"plain", 5)], Some(0));
    assert_eq!(status_of(data), "not_required");
}

#[test]
fn plain_archive_without_end_block_is_undecided() {
    let data = archive(&[file_block(0, b"plain.txt", b"plain", 5)], None);
    assert_eq!(status_of(data), "unknown_needs_final_verifier");
}

#[test]
fn plain_first_volume_is_undecided() {
    let data = archive(
        &[file_block(0, b"plain.txt", b"plain", 5)],
        Some(RAR4_END_NEXT_VOLUME),
    );
    assert_eq!(status_of(data), "unknown_needs_final_verifier");
}

#[test]
fn encrypted_empty_member_alone_is_undecided() {
    let data = archive(
        &[file_block(RAR4_FILE_PASSWORD, b"empty.txt", &[], 0)],
        Some(0),
    );
    assert_eq!(status_of(data), "unknown_needs_final_verifier");
}

#[test]
fn local_header_password_evidence_does_not_require_contiguous_volumes() {
    use crate::password::input::VolumeSpec;
    let mut head = RAR4_SIGNATURE.to_vec();
    head.extend(block(0x73, RAR4_MAIN_HEADER_PASSWORD | 1, &[0; 6]));
    head.extend([0x44; 40]);
    // A RAR byte split inside its plaintext main header must assemble the
    // exact contiguous prefix before parsing the first password evidence.
    let split = VolumeSet::new([&head[..12], &head[12..]].into_iter().enumerate().map(|(i, data)| VolumeSpec {
        reader: ManagedReader::from_bytes(data.to_vec(), Default::default()),
        number: i as u32 + 1, start: 0, end: None,
    }).collect());
    assert!(matches!(prepare_rar_volumes(&split, false), Ok(RarPasswordContext { material: RarPasswordMaterial::Header(_) })));
    let volumes = VolumeSet::new(vec![
        VolumeSpec { reader: ManagedReader::from_bytes(head, Default::default()), number: 1, start: 0, end: None },
        VolumeSpec { reader: ManagedReader::from_bytes(vec![], Default::default()), number: 3, start: 0, end: None },
    ]);
    let result = prepare_rar_volumes(&volumes, true);
    assert!(matches!(result, Ok(RarPasswordContext { material: RarPasswordMaterial::Header(_) })));
}
