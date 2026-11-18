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
fn rejected_zip_anchor_does_not_prepare_alternative_tails() {
    let local = local_crypto_header();
    let (paths, sources, plan) = volume_alternatives(&local, &[0; 25], &[0; 26]);
    let wrong = (0..).map(|i| format!("wrong-{i}")).find(|password|
        zipcrypto_header_state(password.as_bytes(), &[0x9b; 12], 0x5a).is_none()).unwrap();
    let mut preparation = Preparation::default();
    let result = zip_fast_verify_passwords_from_attempts(&mut preparation, &sources[0], &plan,
        &[Arc::from(wrong)], false, None, &[]).unwrap();
    assert_eq!(result.status, "no_match");
    assert!(preparation.verify_prepared(&[]).unwrap().is_none());
    drop(preparation);
    for path in paths { std::fs::remove_file(path).unwrap(); }
}

#[test]
fn local_anchor_never_reads_across_a_missing_disk_or_unknown_descriptor() {
    let material = local_crypto_header();
    let make = |first: Vec<u8>, tail: Vec<u8>| Arc::new(VolumeSet::new(vec![
        VolumeSpec { reader: ManagedReader::from_bytes(first, ReaderConfig::default()), number: 1, start: 0, end: None },
        VolumeSpec { reader: ManagedReader::from_bytes(tail, ReaderConfig::default()), number: 3, start: 0, end: None },
    ]));
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
        plain.get(offset as usize..offset as usize + size).map(<[u8]>::to_vec).ok_or_else(invalid_password_directory)
    });
    assert!(matches!(result, Ok(None)), "must not guess the next local header after a descriptor-sized entry");
}

#[test]
fn anchor_walk_can_skip_unsupported_encryption_with_an_authoritative_size() {
    let mut unsupported = local_crypto_header();
    unsupported[6] = 0x41;
    unsupported[8] = 99; // Contradictory encryption mode.
    unsupported[18..22].copy_from_slice(&12u32.to_le_bytes());
    let next_offset = unsupported.len();
    unsupported.extend(local_crypto_header());
    let prepare =
        |bytes: &[u8]| prepare_zip_anchor(&mut std::io::Cursor::new(bytes), bytes.len() as u64);
    let anchor = prepare(&unsupported)
        .ok()
        .flatten()
        .expect("next local header is readable");
    assert_eq!(anchor.local_offset, next_offset as u64);
    assert!(matches!(
        anchor.context,
        ZipPasswordContext::ZipCrypto { .. }
    ));

    unsupported[6] |= 8;
    assert!(matches!(
        prepare(&unsupported),
        Err(PreparedStatus::Status("unsupported_method", _))
    ));
}

#[test]
fn sized_local_walk_uses_later_proof_despite_unreadable_member_bytes() {
    let mut first = local_crypto_header();
    first[18..22].copy_from_slice(&12u32.to_le_bytes());
    let second = local_crypto_header();
    let next = first.len();
    first.extend(second);
    let result = prepare_zip_local_chain(|offset, size, _| {
        let offset = offset as usize;
        // Neither name is needed for a local proof. The first member's
        // encrypted header cannot be read, but its successor is located.
        if offset < next && offset + size > 30 || offset == next + 30 {
            return Err(invalid_password_directory());
        }
        Ok(first[offset..offset + size].to_vec())
    });
    let anchor = result.ok().flatten().expect("later encrypted header is readable");
    assert_eq!(anchor.local_offset, next as u64);
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
                assert!(matches!(prepare_zip_local_chain(|offset, size, _| local.get(offset as usize..offset as usize + size).map(<[u8]>::to_vec).ok_or_else(invalid_password_directory)), Err(PreparedStatus::Status("unsupported_method", _))));
                continue;
            }
            let context = prepare_zip_stream(&mut std::io::Cursor::new(&local), local.len() as u64, None)
                .unwrap_or_else(|_| panic!("AE version {version}, strength {strength}"));
            let result = context.verify(&[Arc::from("wrong"), Arc::from("secret"), Arc::from("later")]).unwrap();
            assert_eq!(result.matched_indices, [1]);
            assert!(result.final_confirmation_required.unwrap_or(true));
            local[6] |= 0x40;
            assert!(prepare_zip_local_chain(|offset, size, _| local.get(offset as usize..offset as usize + size).map(<[u8]>::to_vec).ok_or_else(invalid_password_directory)).is_err());
            let volumes = Arc::new(VolumeSet::new(vec![VolumeSpec { reader: ManagedReader::from_bytes(local, ReaderConfig::default()), number: 1, start: 0, end: None }]));
            assert!(prepare_zip_volume_entry(&volumes, 0, 0).is_err());
        }
    }
    let mut local = local_crypto_header();
    local[8] = 99;
    assert!(matches!(ZipEncryption::from_local(&local, &[], Some(&[])),
        Ok(ZipEncryption::Traditional { method: 99, .. })));
    assert!(ZipEncryption::from_local(&local, &[], None).is_err());
    assert!(ZipEncryption::from_local(&local, &[1, 0x99, 0, 0], Some(&[])).is_err());
}

#[test]
fn zipcrypto_deflate_uses_dynamic_tables_with_unknown_descriptor_sizes() {
    use std::io::Write;

    let plain = b"these symbols compress into a dynamic table ".repeat(256);
    let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&plain).unwrap();
    let mut body = encoder.finish().unwrap();
    assert_eq!((body[0] >> 1) & 3, 2);
    let mut local = local_crypto_header();
    local[8] = 8;
    local[6] |= 8;
    local[11] = 0x5a;
    let encrypt = |state: &mut ZipCryptoState, byte: &mut u8| {
        let plain = *byte;
        *byte ^= state.decrypt_byte();
        state.update_keys(plain);
    };
    let mut state = ZipCryptoState::new();
    for &byte in b"secret" {
        state.update_keys(byte);
    }
    local[42] = 0x5a;
    for byte in local[31..].iter_mut().chain(&mut body) {
        encrypt(&mut state, byte);
    }
    let header = local[31..].try_into().unwrap();
    let collision: Arc<str> = (0..20_000).find_map(|value| {
        let password = format!("candidate-{value}");
        let mut state = zipcrypto_header_state(password.as_bytes(), &header, 0x5a)?;
        let decoded: Vec<_> = body.iter().map(|&byte| state.decrypt(byte)).collect();
        ((decoded[0] >> 1) & 3 == 2 && !crate::formats::deflate_prefix::matches_prefix(
            &decoded, None, None, false,
        )).then(|| Arc::from(password))
    }).expect("a check-byte collision whose Deflate table is invalid");
    let mut bad = body.clone();
    bad[0] ^= 2; // BTYPE goes from dynamic to reserved under the correct key.

    let (paths, sources, plan) = volume_alternatives(&local, &bad, &body);
    let mut preparation = Preparation::default();
    let result = zip_fast_verify_passwords_from_attempts(&mut preparation, &sources[0], &plan,
        &[collision, Arc::from("secret")], false, None, &[]).unwrap();
    assert_eq!(result.matched_indices, [1]);
    preparation.fix_password();
    let verified = preparation.verify_prepared(&[Arc::from("secret")]).unwrap().unwrap();
    let reduced = verified.volume_attempts.expect("the bad body variant was eliminated");
    assert_eq!(reduced.sources.len(), 2);
    assert_eq!(reduced.sources[1].path, sources[2].path);
    drop(preparation);
    for path in paths { std::fs::remove_file(path).unwrap(); }
}

#[test]
fn winzip_aes_jumps_to_zstd_header_in_another_volume() {
    use aes::{cipher::{Block, BlockCipherEncrypt, KeyInit}, Aes128};

    let unpacked = b"frame after skippable bytes";
    let frame = zstd::stream::encode_all(&unpacked[..], 1).unwrap();
    let mut payload = Vec::from(b"\x50\x2a\x4d\x18\x1d\0\0\0");
    payload.extend([0; 29]);
    let split = payload.len();
    payload.extend(frame);
    let mut local = local_crypto_header()[..31].to_vec();
    local[8] = 99;
    local[18..22].copy_from_slice(&((20 + payload.len()) as u32).to_le_bytes());
    local[22..26].copy_from_slice(&(unpacked.len() as u32).to_le_bytes());
    local[28] = 11;
    local.extend([1, 0x99, 7, 0, 2, 0, b'A', b'E', 1, 93, 0]);
    let salt = [0x83; 8];
    let mut derived = [0; 34];
    pbkdf2::pbkdf2_hmac::<Sha1>(b"secret", &salt, 1000, &mut derived);
    local.extend(salt);
    local.extend(&derived[32..]);
    let cipher = Aes128::new_from_slice(&derived[..16]).unwrap();
    for (index, chunk) in payload.chunks_mut(16).enumerate() {
        let mut mask = Block::<Aes128>::from(((index + 1) as u128).to_le_bytes());
        cipher.encrypt_block(&mut mask);
        for (byte, mask) in chunk.iter_mut().zip(mask) { *byte ^= mask; }
    }
    local.extend(&payload[..split]);
    let mut good = payload[split..].to_vec();
    good.extend([0; 10]); // The Rust proof never opens the member MAC.
    let mut bad = good.clone();
    bad[0] ^= 1;
    let (paths, sources, plan) = volume_alternatives(&local, &bad, &good);
    let mut preparation = Preparation::default();
    let result = zip_fast_verify_passwords_from_attempts(&mut preparation, &sources[0], &plan,
        &[Arc::from("wrong"), Arc::from("secret")], false, Some(0), &[]).unwrap();
    assert_eq!(result.matched_indices, [1]);
    preparation.fix_password();
    let verified = preparation.verify_prepared(&[Arc::from("secret")]).unwrap().unwrap();
    let reduced = verified.volume_attempts.expect("Zstd frame ruled out the wrong volume");
    assert_eq!(reduced.sources.len(), 2);
    assert_eq!(reduced.sources[1].path, sources[2].path);
    drop(preparation);
    for path in paths { std::fs::remove_file(path).unwrap(); }
}

pub(super) fn volume_alternatives(head: &[u8], bad: &[u8], good: &[u8])
    -> ([std::path::PathBuf; 3], Vec<InputExtent>, VolumeAttemptPlan)
{
    use crate::io::archive_state::{VolumeDomain, VolumeLayout, VolumeSlot};
    let paths = [
        crate::test_support::temp_file("zip_framing_head", head),
        crate::test_support::temp_file("zip_framing_bad", bad),
        crate::test_support::temp_file("zip_framing_good", good),
    ];
    let sources: Vec<_> = paths.iter().zip([head.len(), bad.len(), good.len()]).map(|(path, len)| {
        InputExtent { path: path.to_string_lossy().into_owned(), start: 0, end: Some(len as u64) }
    }).collect();
    let plan = VolumeAttemptPlan {
        sources: sources.clone().into_boxed_slice(),
        layouts: vec![VolumeLayout {
            minimum_slots: 0,
            slots: vec![
                VolumeSlot { number: 1, canonical_name: "zip.001".into(), domain: 0 },
                VolumeSlot { number: 2, canonical_name: "zip.002".into(), domain: 1 },
            ].into_boxed_slice(),
        }].into_boxed_slice(),
        domains: vec![
            VolumeDomain { choices: Arc::new(vec![0]) },
            VolumeDomain { choices: Arc::new(vec![1, 2]) },
        ].into_boxed_slice(),
        minimum_size: Some((head.len() + good.len()) as u64),
        head_size_from_total: None,
        tail_totals: Box::new([]),
    };
    (paths, sources, plan)
}
