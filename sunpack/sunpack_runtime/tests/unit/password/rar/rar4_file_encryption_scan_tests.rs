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
    file_block_with_method(flags, name, payload, unpacked, 0x30, None)
}

fn file_block_with_method(flags: u16, name: &[u8], payload: &[u8], unpacked: u32,
    method: u8, salt: Option<&[u8; 8]>) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    body.extend_from_slice(&unpacked.to_le_bytes());
    body.push(2);
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.push(29);
    body.push(method);
    body.extend_from_slice(&(name.len() as u16).to_le_bytes());
    body.extend_from_slice(&0x20u32.to_le_bytes());
    body.extend_from_slice(name);
    if let Some(salt) = salt { body.extend_from_slice(salt); }
    let mut output = block(0x74, flags | RAR4_LONG_BLOCK, &body);
    output.extend_from_slice(payload);
    output
}

#[test]
fn rar4_aes_compressed_member_uses_its_table_only_at_an_independent_start() {
    use aes::cipher::{BlockModeEncrypt, KeyIvInit, block_padding::NoPadding};
    let salt = [0x68; 8];
    let (key, iv) = derive_rar3_key_iv("secret", Some(&salt)).unwrap();
    let candidates = [Arc::from("wrong"), Arc::from("secret")];
    let material = |flags, valid| {
        let mut prefix = [0; 16];
        if valid {
            // LZ mode and two one-bit level codes, then three zero runs
            // covering all four decoder trees.
            prefix[..6].copy_from_slice(&[0x07, 0xfc, 0x07, 0xff, 0xff, 0xfc]);
        }
        cbc::Encryptor::<Aes128>::new(&key.into(), &iv.into())
            .encrypt_padded::<NoPadding>(&mut prefix, 16).unwrap();
        archive(&[
            file_block(RAR4_FILE_PASSWORD, b"stored.bin", &[0; 16], 4),
            file_block_with_method(RAR4_FILE_PASSWORD | RAR4_FILE_SALT | flags,
                b"compressed.bin", &prefix, 4, 0x31, Some(&salt)),
        ], Some(0))
    };
    let verify = |bytes| {
        let reader = ManagedReader::from_bytes(bytes, Default::default());
        prepare_rar_ranges(&[RangeSpec::entire(&reader)]).unwrap_or_else(|_| panic!("readable compressed start"))
            .verify(&candidates, None).unwrap()
    };
    let result = verify(material(0, true));
    assert_eq!(result.matched_indices, [1]);
    assert_eq!(result.final_confirmation_required, Some(true));
    assert_eq!(result.match_evidence, Some("rar4_compressed_stream"));
    assert!(!verify(material(0, false)).matched_indices.contains(&1));
    for flags in [1, RAR4_FILE_SOLID] {
        assert_eq!(status_of(material(flags, true)), "unknown_needs_final_verifier");
    }
}

#[test]
fn rar3_level_table_cannot_repeat_an_undefined_first_length() {
    // Symbols zero and 16 each have one-bit codes. The four-tree descriptor
    // starts with symbol 16, which requires a previous length.
    let bytes = [0x07, 0xf4, 0x7c, 0x60];
    assert!(rar_level_table::<false>(&bytes, 2, 32) == LevelTable::Complete);
    assert!(rar3_lz_tables(&bytes) == LevelTable::Impossible);
}

#[test]
fn rar2_compressed_member_uses_the_legacy_cipher_and_raw_length_table() {
    // UnRAR 6.22 confirms legacy.txt contains 128 'A' bytes with "secret".
    let archive = [
        0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00, 0xcf, 0x90, 0x73, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x86, 0xd3, 0x74, 0x04, 0x80, 0x2a, 0x00, 0x50, 0x00, 0x00, 0x00, 0x80,
        0x00, 0x00, 0x00, 0x02, 0xde, 0x8a, 0x18, 0x04, 0x00, 0x00, 0x00, 0x00, 0x14, 0x31, 0x0a, 0x00,
        0x20, 0x00, 0x00, 0x00, 0x6c, 0x65, 0x67, 0x61, 0x63, 0x79, 0x2e, 0x74, 0x78, 0x74, 0xb1, 0x39,
        0xf7, 0x10, 0x2a, 0x31, 0x87, 0x8d, 0x35, 0x46, 0xae, 0xc8, 0x99, 0xc8, 0x8b, 0x9a, 0x02, 0x0c,
        0xe6, 0x89, 0xe7, 0x0d, 0x64, 0xff, 0x44, 0x3a, 0xf4, 0x4d, 0xc3, 0xea, 0xf0, 0xed, 0x55, 0x1c,
        0x48, 0xb1, 0x24, 0x49, 0x25, 0x0a, 0x70, 0x0d, 0x58, 0xe7, 0x2a, 0x93, 0x30, 0x14, 0x5f, 0x7c,
        0xad, 0xdb, 0x0c, 0x69, 0xfb, 0x99, 0x7b, 0xaa, 0xe2, 0xcf, 0x4f, 0x0e, 0x78, 0xa1, 0xfd, 0x49,
        0x46, 0x94, 0x1d, 0xe3, 0x52, 0x69, 0xef, 0x04, 0xad, 0x53, 0xa1, 0xe6, 0xae, 0xe6, 0x04, 0xb0,
        0x7b, 0x00, 0x00, 0x07, 0x00,
    ];
    let reader = ManagedReader::from_bytes(archive.to_vec(), Default::default());
    let context = prepare_rar_ranges(&[RangeSpec::entire(&reader)]).unwrap_or_else(|_| panic!("legacy stream start"));
    let result = context.verify(&[Arc::from("wrong"), Arc::from("secret")], None).unwrap();
    assert_eq!(result.matched_indices, [1]);
    assert_eq!(result.final_confirmation_required, Some(true));
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
