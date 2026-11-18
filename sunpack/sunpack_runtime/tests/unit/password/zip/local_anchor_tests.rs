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
    assert!(matches!(prepare_zip_volumes(&volumes, None), Ok(ZipPasswordContext::ZipCrypto { header, check_byte: 0x5a, .. }) if header == [0x9b; 12]));
    // But disk 3 must never be silently treated as disk 2 to complete a proof.
    let volumes = make(material[..35].to_vec(), material[35..].to_vec());
    assert!(prepare_zip_volumes(&volumes, None).is_err());
    let mut plain = vec![0u8; 31];
    plain[..4].copy_from_slice(ZIP_LOCAL);
    plain[6] = 8; // Descriptor: zero compressed size is not authoritative.
    plain[26] = 1;
    plain[30] = b'p';
    plain.extend_from_slice(&material);
    let result = prepare_zip_local_chain(|offset, size, _| {
        plain.get(offset as usize..offset as usize + size).map(<[u8]>::to_vec)
    });
    assert!(result.is_none(), "must not guess the next local header after a descriptor-sized entry");
}

#[test]
fn zipcrypto_deflate_eliminates_a_header_collision_only_with_member_bytes() {
    // A final stored Deflate block containing one byte, with the same stream
    // syntax for methods 8 and 9. The 12th ZipCrypto header byte is the CRC MSB.
    let plain_deflate = [1, 1, 0, 0xfe, 0xff, b'x'];
    let crc = crc32fast::hash(b"x");
    let mut archive = local_crypto_header();
    archive[14..18].copy_from_slice(&crc.to_le_bytes());
    archive[18..22].copy_from_slice(&18u32.to_le_bytes());
    archive[22..26].copy_from_slice(&1u32.to_le_bytes());
    let mut plain_header = [0x9b; ZIPCRYPTO_HEADER_LEN];
    let expected = (crc >> 24) as u8;
    plain_header[11] = expected;
    let mut cipher = ZipCryptoState::new();
    for &byte in b"secret" { cipher.update_keys(byte); }
    let ciphertext: Vec<_> = plain_header.into_iter().chain(plain_deflate).map(|plain| {
        let encrypted = plain ^ cipher.decrypt_byte();
        cipher.update_keys(plain);
        encrypted
    }).collect();
    archive.truncate(31);
    archive.extend_from_slice(&ciphertext);
    let header = ciphertext[..ZIPCRYPTO_HEADER_LEN].try_into().unwrap();
    let deflate = ZipDeflatePrefix { encrypted: ciphertext[ZIPCRYPTO_HEADER_LEN..].to_vec(), uncompressed_size: 1, deflate64: false };
    let collision = (0..4096).map(|i| format!("collision-{i}"))
        .find(|password| zipcrypto_checked_state(password.as_bytes(), &header, expected).is_some_and(|state| !deflate.matches(state)))
        .expect("a deterministic header collision rejected by the prefix");
    let passwords = [Arc::from(collision), Arc::from("secret")];

    for method in [8u8, 9] {
        archive[8] = method;
        let part = |range: std::ops::Range<usize>, number| VolumeSpec {
            reader: ManagedReader::from_bytes(archive[range].to_vec(), ReaderConfig::default()),
            number, start: 0, end: None,
        };
        // Same logical member, with the encrypted deflate prefix wholly or
        // partly in a continuation. A missing continuation keeps both matches.
        for (split, number, matches) in [(43, 2, &[1][..]), (45, 2, &[1][..]), (43, 3, &[0, 1][..])] {
            let volumes = VolumeSet::new(vec![part(0..split, 1), part(split..archive.len(), number)]);
            let context = prepare_zip_volumes(&volumes, None).unwrap_or_else(|_| panic!("method {method}, split {split}, disk {number}"));
            let verification = context.verify(&passwords).unwrap();
            assert_eq!(verification.matched_indices, matches, "method {method}, split {split}, disk {number}");
            assert_ne!(verification.final_confirmation_required, Some(false));
        }
    }

    archive[8] = 8;
    archive[6] |= 8;
    archive[11] = expected;
    archive[14..26].fill(0);
    archive.extend(b"PK\x07\x08");
    archive.extend(crc.to_le_bytes());
    archive.extend(18u32.to_le_bytes());
    archive.extend(1u32.to_le_bytes());
    let cd_start = archive.len();
    let mut central = [0; 47];
    central[..4].copy_from_slice(ZIP_CENTRAL);
    central[8] = 9;
    central[10] = 8;
    central[16..20].copy_from_slice(&crc.to_le_bytes());
    central[20..24].copy_from_slice(&18u32.to_le_bytes());
    central[24..28].copy_from_slice(&1u32.to_le_bytes());
    central[28] = 1;
    central[46] = b'a';
    archive.extend(central);
    let eocd = archive.len();
    let mut end = [0; 22];
    end[..4].copy_from_slice(ZIP_EOCD);
    end[8] = 1;
    end[10] = 1;
    end[12..16].copy_from_slice(&(central.len() as u32).to_le_bytes());
    end[16..20].copy_from_slice(&(cd_start as u32).to_le_bytes());
    archive.extend(end);
    let context = prepare_zip_stream(&mut std::io::Cursor::new(&archive), archive.len() as u64, Some(eocd as u64))
        .unwrap_or_else(|_| panic!("descriptor-sized member must use central-directory sizes"));
    assert_eq!(context.verify(&passwords).unwrap().matched_indices, [1]);
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
                assert!(prepare_zip_local_chain(|offset, size, _| local.get(offset as usize..offset as usize + size).map(<[u8]>::to_vec)).is_none());
                continue;
            }
            let context = prepare_zip_stream(&mut std::io::Cursor::new(&local), local.len() as u64, None)
                .unwrap_or_else(|_| panic!("AE version {version}, strength {strength}"));
            let result = context.verify(&[Arc::from("wrong"), Arc::from("secret"), Arc::from("later")]).unwrap();
            assert_eq!(result.matched_indices, [1]);
            assert!(result.final_confirmation_required.unwrap_or(true));
            local[6] |= 0x40;
            assert!(prepare_zip_local_chain(|offset, size, _| local.get(offset as usize..offset as usize + size).map(<[u8]>::to_vec)).is_none());
            let volumes = VolumeSet::new(vec![VolumeSpec { reader: ManagedReader::from_bytes(local, ReaderConfig::default()), number: 1, start: 0, end: None }]);
            assert!(prepare_zip_volume_entry(&volumes, 0, 0).is_err());
        }
    }
}
