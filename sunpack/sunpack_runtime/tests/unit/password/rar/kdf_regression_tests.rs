use super::*;

// Real archives do not force every SHA1 checkpoint alignment or key length.
// One scalar byte-stream oracle checks all key/IV bytes for salt and UTF-16.
#[test]
fn rar4_batched_kdf_preserves_key_and_all_iv_checkpoints() {
    // Longer raw inputs use RAR3's mutating SHA1 variant, covered by the
    // real multi-head encrypted carrier lifecycle rather than this oracle.
    for password in ["", "secret", "密碼🔐", "abcdefghijklmnopqrstuvwxyz12"] {
        for salt in [None, Some(&[0x91u8; 8])] {
            let mut raw = password
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>();
            if let Some(salt) = salt {
                raw.extend_from_slice(salt);
            }
            let mut sha = Sha1::new();
            let mut iv = [0u8; 16];
            for counter in 0..RAR3_KDF_ITERATIONS {
                sha.update(&raw);
                sha.update(&counter.to_le_bytes()[..3]);
                if counter % 0x4000 == 0 {
                    iv[(counter / 0x4000) as usize] = sha.clone().finalize()[19];
                }
            }
            let digest = sha.finalize();
            let mut key = [0u8; 16];
            for (target, source) in key.chunks_exact_mut(4).zip(digest[..16].chunks_exact(4)) {
                target.copy_from_slice(source);
                target.reverse();
            }
            assert_eq!(derive_rar3_key_iv(password, salt), Some((key, iv)));
        }
    }
}

#[test]
fn rar5_checked_key_matches_standard_pbkdf2_checkpoints() {
    for password in ["", "secret", "密碼🔐", &"s".repeat(64), &"long-password".repeat(10)] {
        for lg2_count in [0, 4, 10] {
            let iterations = 1u32 << lg2_count;
            let mut header = Rar5EncryptionIdentity {
                iv: [0; 16],
                lg2_count,
                salt: [0x73; 16],
                password_check: None,
            };
            let mut key = [0u8; 32];
            let mut hash = [0u8; 32];
            let mut check = [0u8; 32];
            pbkdf2::pbkdf2_hmac::<Sha256>(
                password.as_bytes(),
                &header.salt,
                iterations + 16,
                &mut hash,
            );
            pbkdf2::pbkdf2_hmac::<Sha256>(
                password.as_bytes(),
                &header.salt,
                iterations,
                &mut key,
            );
            pbkdf2::pbkdf2_hmac::<Sha256>(
                password.as_bytes(),
                &header.salt,
                iterations + 32,
                &mut check,
            );
            let mut proof = [0; 8];
            for (index, byte) in check.iter().enumerate() { proof[index % 8] ^= byte; }
            let password: Arc<str> = Arc::from(password);
            let first = RarPasswordContext { material: RarPasswordMaterial::Rar5(header) };
            let other = RarPasswordContext {
                material: RarPasswordMaterial::Rar5(Rar5EncryptionIdentity { iv: [0xa5; 16], ..header }),
            };
            let cache = RarKeyCache::for_contexts([&first, &other].into_iter());
            assert_eq!(cache.rar5(&password, &header), Some(key));
            assert_eq!(cache.rar5_hash_key(&password, &header), Some(hash));
            assert!(cache.rar5[&(lg2_count, header.salt)].lock().unwrap().values().all(|slot|
                slot.get().unwrap().as_ref().unwrap().check.get().is_none()));
            header.password_check = Some(proof);
            assert_eq!(cache.rar5(&password, &header), Some(key));
            proof[0] ^= 1;
            header.password_check = Some(proof);
            assert_eq!(cache.rar5(&password, &header), None);
            header.password_check = None;
            header.iv = [0xa5; 16];
            assert_eq!(cache.rar5(&password, &header), Some(key));
            assert_eq!(cache.rar5_derivations.load(std::sync::atomic::Ordering::Relaxed), 1,
                "check and IV are not KDF inputs");
        }
    }
}

#[test]
fn distinct_rar5_salts_do_not_retain_candidate_checkpoints() {
    let contexts: Vec<_> = (0..64).map(|salt| RarPasswordContext {
        material: RarPasswordMaterial::Rar5(Rar5EncryptionIdentity {
            iv: [0; 16], lg2_count: 0, salt: [salt; 16], password_check: None,
        }),
    }).collect();
    let cache = RarKeyCache::for_contexts(contexts.iter());
    let candidates: Vec<Arc<str>> = (0..32).map(|index| Arc::from(index.to_string())).collect();
    for context in &contexts {
        let RarPasswordMaterial::Rar5(identity) = &context.material else { unreachable!() };
        for password in &candidates {
            assert!(cache.rar5(password, identity).is_some());
        }
    }
    assert_eq!(cache.rar5_derivations.load(std::sync::atomic::Ordering::Relaxed), 64 * 32);
    assert!(cache.rar5.is_empty(), "each unique salt needs no reusable candidate slots");
}
