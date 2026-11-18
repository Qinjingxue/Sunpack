use super::*;
use crate::io::reader::ReaderConfig;
use crate::password::input::VolumeSpec;

fn local_crypto_header() -> Vec<u8> {
    let mut bytes = vec![0u8; 43];
    bytes[..4].copy_from_slice(ZIP_LOCAL);
    bytes[6] = 1;
    bytes[17] = 0x5a;
    bytes[26] = 1;
    bytes[30] = b'a';
    bytes[31..].fill(0x9b);
    bytes
}

#[test]
fn local_anchor_never_reads_across_a_missing_disk_or_unknown_descriptor() {
    let material = local_crypto_header();
    let make = |first: Vec<u8>, tail: Vec<u8>| VolumeSet::new(vec![
        VolumeSpec { reader: ManagedReader::from_bytes(first, ReaderConfig::default()), number: 1, start: 0, end: None },
        VolumeSpec { reader: ManagedReader::from_bytes(tail, ReaderConfig::default()), number: 3, start: 0, end: None },
    ]);
    // Missing middle/tail does not invalidate proof already wholly in disk 1.
    let volumes = make(material.clone(), vec![0; 50]);
    assert!(matches!(prepare_zip_volumes(&volumes, None), Ok(ZipPasswordContext::ZipCrypto { header, check_byte: 0x5a }) if header == [0x9b; 12]));
    // But disk 3 must never be silently treated as disk 2 to complete a proof.
    let volumes = make(material[..35].to_vec(), material[35..].to_vec());
    assert!(prepare_zip_volumes(&volumes, None).is_err());
    let mut plain = vec![0u8; 31];
    plain[..4].copy_from_slice(ZIP_LOCAL);
    plain[6] = 8; // Descriptor: zero compressed size is not authoritative.
    plain[26] = 1;
    plain[30] = b'p';
    plain.extend_from_slice(&material);
    let result = prepare_zip_local_chain(|offset, size| {
        plain.get(offset as usize..offset as usize + size).map(<[u8]>::to_vec)
    });
    assert!(result.is_none(), "must not guess the next local header after a descriptor-sized entry");
}

// Covers all three verifier block positions, unsupported AE versions,
// and the strong-encryption flag on both local and directory-selected paths.
#[test]
fn aes_strength_drives_the_weak_screen_for_supported_versions() {
    for strength in 1..=3 {
        let (salt_len, key_len) = aes_lengths(strength).unwrap();
        let salt = vec![0x57; salt_len];
        let mut derived = vec![0; 2 * key_len + 2];
        pbkdf2::pbkdf2_hmac::<Sha1>(b"secret", &salt, 1000, &mut derived);
        for version in [1u16, 2, 3, u16::MAX] {
            let mut local = local_crypto_header()[..31].to_vec();
            local[8] = 99;
            local[28] = 11;
            local.extend([1, 0x99, 7, 0]);
            local.extend(version.to_le_bytes());
            local.extend([b'A', b'E', strength, 0, 0]);
            local.extend(&salt);
            local.extend(&derived[2 * key_len..]);
            if version > 2 {
                assert!(prepare_zip_local_chain(|offset, size| local.get(offset as usize..offset as usize + size).map(<[u8]>::to_vec)).is_none());
                continue;
            }
            let context = prepare_zip_stream(&mut std::io::Cursor::new(&local), local.len() as u64, None)
                .unwrap_or_else(|_| panic!("AE version {version}, strength {strength}"));
            let result = context.verify(&[Arc::from("wrong"), Arc::from("secret"), Arc::from("later")]).unwrap();
            assert_eq!(result.matched_indices, [1]);
            assert!(result.final_confirmation_required.unwrap_or(true));
            local[6] |= 0x40;
            assert!(prepare_zip_local_chain(|offset, size| local.get(offset as usize..offset as usize + size).map(<[u8]>::to_vec)).is_none());
            let volumes = VolumeSet::new(vec![VolumeSpec { reader: ManagedReader::from_bytes(local, ReaderConfig::default()), number: 1, start: 0, end: None }]);
            assert!(prepare_zip_volume_entry(&volumes, 0, 0).is_err());
        }
    }
}
