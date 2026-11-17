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
    let reader = ManagedReader::from_bytes(data, Default::default());
    let anchor = probe_volume_anchor_reader_at_offset(&reader, "", 37, "rar").unwrap();
    let (anchor, matched) = resolve_encrypted_relation_anchor(&anchor, &reader, &passwords, true, None).unwrap();
    assert_eq!(matched, Some(0));
    assert_eq!(anchor.internal_volume_number, Some(3));
    assert_eq!(anchor.relation_has_next, Some(false));

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
