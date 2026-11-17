use super::*;
use crate::analysis_native::volume_anchor::{
    probe_volume_anchor_reader_at_offset, resolve_encrypted_relation_anchor,
};
use aes::cipher::BlockModeEncrypt;

fn vint(mut value: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    while value >= 128 {
        bytes.push((value as u8 & 127) | 128);
        value >>= 7;
    }
    bytes.push(value as u8);
    bytes
}
fn rar5_block(body: &[u8]) -> Vec<u8> {
    let mut bytes = vint(body.len() as u64);
    bytes.extend(body);
    let mut full = crc32(&bytes).to_le_bytes().to_vec();
    full.extend(bytes);
    full
}
fn rar4_block(kind: u8, flags: u16, body: &[u8]) -> Vec<u8> {
    let mut header = vec![0, 0, kind];
    header.extend(flags.to_le_bytes());
    header.extend(((7 + body.len()) as u16).to_le_bytes());
    header.extend(body);
    let crc = crc32(&header[2..]) as u16;
    header[..2].copy_from_slice(&crc.to_le_bytes());
    header
}

// Existing encrypted fixtures have small headers and no RAR4 ENDARC ID.
// This single lifecycle case covers both missing facts without extraction
// or payload-sized I/O, including a carrier and incomplete ciphertext.
#[test]
fn encrypted_relation_headers_keep_volume_identity_at_declared_extents() {
    let salt = [0x73u8; 8];
    let (key, iv) = derive_rar3_key_iv("secret", Some(&salt)).unwrap();
    let mut end = rar4_block(0x7b, 8, &2u16.to_le_bytes());
    end.resize(16, 0);
    let ciphertext = cbc::Encryptor::<Aes128>::new(&key.into(), &iv.into())
        .encrypt_padded::<NoPadding>(&mut end, 16)
        .unwrap();
    let mut data = vec![0x77; 37];
    data.extend(RAR4_SIGNATURE);
    data.extend(rar4_block(0x73, 0x91, &[0; 6]));
    data.extend(salt);
    data.extend(ciphertext);
    let passwords = [Arc::from("secret")];
    let reader = ManagedReader::from_bytes(data.clone(), Default::default());
    let anchor = probe_volume_anchor_reader_at_offset(&reader, "", 37, "rar").unwrap();
    let (anchor, matched) = resolve_encrypted_relation_anchor(&anchor, &reader, &passwords, true, None).unwrap();
    assert_eq!(matched, Some(0));
    assert_eq!(anchor.internal_volume_number, Some(3));
    assert_eq!(anchor.relation_has_next, Some(false));

    // The shared search retains ordered candidate semantics in its parallel
    // path, and its first-block proof transfers through the existing plan API.
    let parallel: Vec<Arc<str>> = ["wrong-a", "wrong-b", "secret", "secret", "wrong-c"]
        .into_iter().map(Arc::from).collect();
    assert!(matches!(probe_header_passwords(&reader, 37, &parallel, true, None).unwrap(),
        HeaderPassword::Matched(2, _)));
    assert!(matches!(probe_header_passwords(&reader, 37, &parallel[..2], true, None).unwrap(),
        HeaderPassword::Inconclusive));
    assert!(matches!(probe_header_passwords(&reader, 37, &[], true, None).unwrap(),
        HeaderPassword::Inconclusive));
    let offset = prepare_rar4_encrypted_headers(&reader, 37).unwrap().unwrap();
    let context = RarPasswordContext { material: RarPasswordMaterial::Header(
        reader.read_at(offset, 8 + 65536).unwrap()) };
    let mut proof = None;
    assert_eq!(context.verify(&passwords, Some(&mut proof)).unwrap().matched_index, Some(0));
    assert!(matches!(proof, Some(RarProvenKey::Rar4 { .. })));
    assert!(matches!(probe_header_passwords(&reader, 37, &passwords, true, proof.as_ref()).unwrap(),
        HeaderPassword::Matched(0, RarTerminalProof { terminal: Some(_), .. })));

    let unrelated = RarProvenKey::Rar4 { salt: [0; 8], key: [0; 16], iv: [0; 16] };
    assert!(matches!(probe_header_passwords(&reader, 37, &passwords, true, Some(&unrelated)).unwrap(),
        HeaderPassword::Matched(0, _)));
    let encrypted_fixture = |mut header: Vec<u8>| {
        let size = (header.len() + 15) & !15;
        header.resize(size, 0);
        cbc::Encryptor::<Aes128>::new(&key.into(), &iv.into())
            .encrypt_padded::<NoPadding>(&mut header, size).unwrap();
        let mut bytes = data[..offset as usize + 8].to_vec();
        bytes.extend(header);
        ManagedReader::from_bytes(bytes, Default::default())
    };
    let missing_tail = encrypted_fixture(rar4_block(0x75, 0, &[]));
    assert!(matches!(probe_header_passwords(&missing_tail, 37, &passwords, true, None).unwrap(),
        HeaderPassword::Matched(0, RarTerminalProof { password_matched: true, terminal: None, .. })));
    let large = encrypted_fixture(rar4_block(0x7b, 0, &vec![0; 65528]));
    assert!(matches!(probe_header_passwords(&large, 37, &passwords, true, None).unwrap(),
        HeaderPassword::Matched(0, RarTerminalProof { terminal: Some(_), .. })));

    // A CRC-valid first header is password evidence even when its data layout
    // is incomplete. Boundary discovery must not turn that into a rejection.
    let mut broken = rar4_block(0x74, 0, &[]);
    broken.resize(16, 0);
    cbc::Encryptor::<Aes128>::new(&key.into(), &iv.into())
        .encrypt_padded::<NoPadding>(&mut broken, 16).unwrap();
    data.truncate(offset as usize + 8);
    data.extend(broken);
    let incomplete = ManagedReader::from_bytes(data.clone(), Default::default());
    assert!(matches!(probe_header_passwords(&incomplete, 37, &passwords, true, None).unwrap(),
        HeaderPassword::Matched(0, RarTerminalProof { password_matched: true, terminal: None, .. })));
    data.truncate(data.len() - 1);
    let short = ManagedReader::from_bytes(data, Default::default());
    assert!(matches!(probe_header_passwords(&short, 37, &passwords, true, None).unwrap(),
        HeaderPassword::Inconclusive));

    let mut extra_body = vec![2, 1];
    extra_body.extend(vint(600));
    extra_body.extend(vec![b'a'; 600]);
    let mut extra = vint(extra_body.len() as u64);
    extra.extend(extra_body);
    let mut main = vec![1, 1];
    main.extend(vint(extra.len() as u64));
    main.extend([3, 2]);
    main.extend(extra);
    let mut plaintext = rar5_block(&main);
    let len = (plaintext.len() + 15) & !15;
    plaintext.resize(len, 0);
    let salt = [0x65u8; 16];
    let iv = [0x76u8; 16];
    let mut key = [0; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(b"secret", &salt, 16, &mut key);
    let ciphertext = cbc::Encryptor::<Aes256>::new(&key.into(), &iv.into())
        .encrypt_padded::<NoPadding>(&mut plaintext, len)
        .unwrap();
    let mut encryption = vec![4, 0, 0, 0, 4];
    encryption.extend(salt);
    let mut data = RAR5_SIGNATURE.to_vec();
    data.extend(rar5_block(&encryption));
    data.extend(iv);
    data.extend(ciphertext);
    let reader = ManagedReader::from_bytes(data.clone(), Default::default());
    let anchor = probe_volume_anchor_reader_at_offset(&reader, "", 0, "rar").unwrap();
    let (anchor, matched) = resolve_encrypted_relation_anchor(&anchor, &reader, &passwords, true, None).unwrap();
    assert_eq!(matched, Some(0));
    assert_eq!(anchor.internal_volume_number, Some(3), "{}", anchor.error);

    data.truncate(300);
    let reader = ManagedReader::from_bytes(data, Default::default());
    let anchor = probe_volume_anchor_reader_at_offset(&reader, "", 0, "rar").unwrap();
    let (anchor, matched) = resolve_encrypted_relation_anchor(&anchor, &reader, &passwords, true, None).unwrap();
    assert!(matched.is_none() && anchor.needs_password);
    assert!(!anchor.wrong_password);
}
