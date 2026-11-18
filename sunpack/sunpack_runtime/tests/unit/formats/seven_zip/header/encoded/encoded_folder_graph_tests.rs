use super::*;

#[test]
fn lzma2_encoded_coder_requires_declared_size_and_end_marker() {
    // Raw LZMA2 encoding of "test" repeated 128 times. Existing folder
    // graph tests do not exercise size lies or truncated LZMA2 streams.
    let packed = [
        224, 1, 255, 0, 12, 93, 0, 58, 25, 74, 206, 43, 15, 35, 137, 235, 206, 128, 0, 0,
    ];
    let coder = SevenZipCoderAst {
        method_id: EncoderMethod::ID_LZMA2.to_vec(),
        properties: vec![0],
        num_in_streams: 1,
        num_out_streams: 1,
    };
    let decode = |data: &[u8], size| {
        decode_seven_zip_encoded_coder(CoderInput::Borrowed(data), &coder, size)
    };
    assert_eq!(decode(&packed, 512).unwrap(), b"test".repeat(128));
    for wrong_size in [0, 1, 511, 513] {
        assert!(decode(&packed, wrong_size).is_err());
    }
    assert!(decode(&packed[..packed.len() - 1], 512).is_err());
    // A large advertised dictionary does not imply a large history for a
    // known, complete 512-byte folder. This also covers the maximum prop.
    let mut large_dictionary = coder;
    large_dictionary.properties[0] = 40;
    assert_eq!(
        decode_seven_zip_encoded_coder(
            CoderInput::Borrowed(packed.as_slice()),
            &large_dictionary,
            512
        )
        .unwrap(),
        b"test".repeat(128)
    );
}

#[test]
fn lz4_encoded_coder_checks_size_properties_and_checksum() {
    let mut bytes = vec![0x04, 0x22, 0x4d, 0x18, 0x64, 0x40];
    bytes.push((crate::formats::lz4::xxh32(&bytes[4..]) >> 8) as u8);
    bytes.extend_from_slice(&0x80000004u32.to_le_bytes());
    bytes.extend_from_slice(b"test");
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&crate::formats::lz4::xxh32(b"test").to_le_bytes());
    let mut coder = SevenZipCoderAst {
        method_id: vec![0x04, 0xf7, 0x11, 0x04],
        properties: vec![1, 10, 1, 0, 0],
        num_in_streams: 1,
        num_out_streams: 1,
    };
    assert_eq!(
        decode_seven_zip_encoded_coder(CoderInput::Borrowed(bytes.as_slice()), &coder, 4)
            .unwrap(),
        b"test"
    );
    for wrong_size in [0, 3, 5, 64 * 1024 * 1024 + 1] {
        assert!(decode_seven_zip_encoded_coder(
            CoderInput::Borrowed(bytes.as_slice()),
            &coder,
            wrong_size
        )
        .is_err());
    }
    *bytes.last_mut().unwrap() ^= 1;
    assert!(decode_seven_zip_encoded_coder(
        CoderInput::Borrowed(bytes.as_slice()),
        &coder,
        4
    )
    .is_err());
    coder.properties.clear();
    assert!(decode_seven_zip_encoded_coder(
        CoderInput::Borrowed(bytes.as_slice()),
        &coder,
        4
    )
    .is_err());
}

fn reference_aes_key(properties: &[u8], password: &[u8]) -> [u8; 32] {
    let b0 = properties[0];
    let b1 = properties.get(1).copied().unwrap_or(0);
    let salt_size = usize::from(((b0 >> 7) & 1) + (b1 >> 4));
    let salt = properties.get(2..2 + salt_size).unwrap_or_default();
    reference_aes_key_bytes(1u64 << (b0 & 63), salt, password)
}

fn reference_aes_key_bytes(cycles: u64, salt: &[u8], password: &[u8]) -> [u8; 32] {
    let mut sha = sha2_11::Sha256::default();
    for counter in 0..cycles {
        sha2_11::Digest::update(&mut sha, salt);
        sha2_11::Digest::update(&mut sha, password);
        sha2_11::Digest::update(&mut sha, counter.to_le_bytes());
    }
    sha2_11::Digest::finalize(sha).into()
}

#[test]
fn specialized_7z_kdf_matches_record_by_record_oracle() {
    let password = b"p\0a\0s\0s\0";
    for cycles_power in [0u8, 1, 6, 10] {
        let no_salt = [cycles_power];
        assert_eq!(
            seven_zip_aes_key_iv(&no_salt, password).unwrap().0,
            reference_aes_key(&no_salt, password)
        );

        let with_salt_and_iv = [cycles_power | 0xc0, 0x12, 0x11, 0x22, 0x31, 0x32, 0x33];
        assert_eq!(
            seven_zip_aes_key_iv(&with_salt_and_iv, password).unwrap().0,
            reference_aes_key(&with_salt_and_iv, password)
        );
    }
    // Whole batches do not expose stale counters in a partial last batch,
    // nor accidental overlap between long passwords and the counter field.
    for password in [b"p\0a\0s\0s\0".to_vec(), vec![0xa5; 300]] {
        for salt in [&[][..], &[0x5a; 16][..]] {
            for cycles in [0, 3, 63, 65, 129] {
                assert_eq!(
                    derive_seven_zip_aes_key(cycles, salt, &password).unwrap(),
                    reference_aes_key_bytes(u64::from(cycles), salt, &password)
                );
            }
        }
    }
}

#[test]
fn password_probe_accepts_7z_aes_without_salt_or_iv() {
    let mut folder = SevenZipFolderAst {
        coders: vec![SevenZipCoderAst {
            method_id: EncoderMethod::ID_AES256_SHA256.to_vec(),
            properties: Vec::new(),
            num_in_streams: 1,
            num_out_streams: 1,
        }],
        bind_pairs: Vec::new(),
        packed_streams: vec![0],
        main_output_stream: 0,
        unpack_sizes: SevenZipUnpackSizes::Main(1),
        expected_crc: Some(crc32(b"a")),
    };
    let password = Password::from("pass");
    assert!(seven_zip_probe_folder_supported(&folder));
    assert_eq!(
        seven_zip_aes_key_iv(&[], password.as_slice()).unwrap().0,
        reference_aes_key_bytes(1, &[], password.as_slice()),
    );

    folder.coders[0].properties.push(SEVEN_Z_AES_DIRECT_KEY);
    assert!(seven_zip_probe_folder_supported(&folder));
    let mut direct_key = [0; 32];
    direct_key[..password.as_slice().len()].copy_from_slice(password.as_slice());
    assert_eq!(
        seven_zip_aes_key_iv(&folder.coders[0].properties, password.as_slice())
            .unwrap()
            .0,
        direct_key,
    );
    folder.coders[0].properties[0] = SEVEN_Z_AES_MAX_CYCLES_POWER + 1;
    assert!(!seven_zip_probe_folder_supported(&folder));
}

#[test]
fn header_prescreen_and_full_crc_share_one_candidate_scoped_key() {
    use aes::cipher::BlockModeEncrypt;
    for compressed in [false, true] {
        let properties = vec![0xc1, 0x10, 9, 10, 11];
        // LZMA2 uncompressed chunk containing the valid empty Header tree.
        let encoded: &[u8] = if compressed {
            &[1, 0, 1, SZ_HEADER, SZ_END, 0]
        } else {
            &[SZ_HEADER, SZ_END]
        };
        let mut encrypted = vec![0x99; 16];
        encrypted[..encoded.len()].copy_from_slice(encoded);
        let bytes = Password::from("secret");
        let (key, iv) = seven_zip_aes_key_iv(&properties, bytes.as_slice()).unwrap();
        cbc::Encryptor::<Aes256>::new(&key.into(), &iv.into())
            .encrypt_padded::<NoPadding>(&mut encrypted, 16)
            .unwrap();
        let mut folder = SevenZipFolderAst {
            coders: vec![SevenZipCoderAst {
                method_id: EncoderMethod::ID_AES256_SHA256.to_vec(),
                properties,
                num_in_streams: 1,
                num_out_streams: 1,
            }],
            bind_pairs: Vec::new(),
            packed_streams: vec![0],
            main_output_stream: 0,
            unpack_sizes: SevenZipUnpackSizes::Main(2),
            expected_crc: Some(crc32(&[SZ_HEADER, SZ_END])),
        };
        if compressed {
            folder.coders.push(SevenZipCoderAst {
                method_id: EncoderMethod::ID_LZMA2.to_vec(),
                properties: vec![0],
                num_in_streams: 1,
                num_out_streams: 1,
            });
            folder.bind_pairs.push((1, 0));
            folder.main_output_stream = 1;
            folder.unpack_sizes = SevenZipUnpackSizes::All(vec![encoded.len() as u64, 2]);
        }
        let mut probe = SevenZipPasswordProbe::from_parts(vec![encrypted.into()], folder, SevenZipMetadata::Header);
        for password in ["wrong", "secret", "secret"] {
            SEVEN_ZIP_KDF_DERIVATIONS.with(|count| count.set(0));
            assert_eq!(probe.check_header(|properties| SevenZipAesKey::derive(properties, password)).unwrap(), if password == "secret" {
                SevenZipPrefixCheck::Confirmed
            } else {
                SevenZipPrefixCheck::Reject
            });
            // The prefix survivor must not derive again in the full decoder;
            // repeated requests have no hidden global retained-key state.
            assert_eq!(SEVEN_ZIP_KDF_DERIVATIONS.with(|count| count.get()), 1);
        }
        probe.folder.expected_crc = Some(probe.folder.expected_crc.unwrap() ^ 1);
        assert_eq!(probe.check_header(|properties| SevenZipAesKey::derive(properties, "secret")).unwrap(), SevenZipPrefixCheck::Reject);
    }
}

#[test]
fn double_encrypted_header_uses_both_ivs_and_checks_the_header_crc() {
    use aes::cipher::BlockModeEncrypt;
    let coder = |iv| SevenZipCoderAst {
        method_id: EncoderMethod::ID_AES256_SHA256.to_vec(),
        properties: vec![0x41, 0, iv],
        num_in_streams: 1,
        num_out_streams: 1,
    };
    let folder = SevenZipFolderAst {
        coders: vec![coder(11), coder(12), SevenZipCoderAst {
            method_id: EncoderMethod::ID_LZMA2.to_vec(),
            properties: vec![0],
            num_in_streams: 1,
            num_out_streams: 1,
        }],
        bind_pairs: vec![(1, 0), (2, 1)],
        packed_streams: vec![0],
        main_output_stream: 2,
        unpack_sizes: SevenZipUnpackSizes::All(vec![16, 6, 2]),
        expected_crc: Some(crc32(&[SZ_HEADER, SZ_END])),
    };
    let mut packed = [0u8; 16];
    packed[..6].copy_from_slice(&[1, 0, 1, SZ_HEADER, SZ_END, 0]);
    for coder in folder.coders[..2].iter().rev() {
        let key = SevenZipAesKey::derive(&coder.properties, "secret").unwrap();
        cbc::Encryptor::<Aes256>::new(&key.key.into(), &key.iv.into())
            .encrypt_padded::<NoPadding>(&mut packed, 16).unwrap();
    }
    assert!(seven_zip_probe_folder_supported(&folder));
    let plan = seven_zip_payload_plan(&folder, 0, 0, 16, false).expect("stacked AES compressed prefix");
    let prefix = SevenZipPasswordContext::Prefix {
        probe: SevenZipPayloadProbes {
            first: SevenZipPayloadProbe {
                offset: 0,
                properties: plan.properties,
                inner_aes: plan.inner_aes,
                encrypted: packed,
                kind: plan.kind,
            },
            rest: Vec::new(),
            source: None,
        },
        header: false,
    };
    let passwords = [Arc::from("wrong"), Arc::from("secret")];
    assert_eq!(prefix.verify(&passwords).unwrap().matched_indices, [1]);
    let probe = SevenZipPasswordProbe::from_parts(vec![packed.to_vec().into()], folder, SevenZipMetadata::Header);
    let context = SevenZipPasswordContext::Header(probe);
    SEVEN_ZIP_KDF_DERIVATIONS.with(|count| count.set(0));
    let result = context.verify(&passwords).unwrap();
    assert_eq!(result.matched_indices, [1]);
    assert_eq!(result.final_confirmation_required, Some(false));
    assert_eq!(SEVEN_ZIP_KDF_DERIVATIONS.with(|count| count.get()), passwords.len());

    let keys = [11, 12].map(|iv| SevenZipAesKey::derive(&coder(iv).properties, "secret").unwrap());
    let structure = SevenZipPayloadEvidence {
        packed_size: 60,
        unchanged_prefix: u64::MAX,
        verifier: SevenZipPayloadVerifier::Compressed {
            method: EncoderMethod::ID_LZMA2.to_vec(),
            unpack_size: 56,
        },
    };
    for next in [0, 0x7f] {
        let mut packed = [0; 64];
        packed[..3].copy_from_slice(&[1, 0, 55]); // Raw chunk with 56 data bytes, then a marker.
        packed[59] = next;
        for key in keys.iter().rev() {
            cbc::Encryptor::<Aes256>::new(&key.key.into(), &key.iv.into())
                .encrypt_padded::<NoPadding>(&mut packed, 64).unwrap();
        }
        let first: &[u8; 16] = packed[..16].try_into().unwrap();
        let (prefix, len) = structure.decrypt_prefix_with_inner(first, &keys[0], &keys[1..]).unwrap();
        let mut read = |at: u64, output: &mut [u8]| -> Result<(), DeferredReadError> {
            let start = at as usize;
            output.copy_from_slice(&packed[start..start + output.len()]);
            Ok(())
        };
        let result = structure.check_successor(0, first, &prefix[..len], &keys[0], &keys[1..],
            &mut read, &SevenZipPayloadSource::Fixed(Arc::new([]))).unwrap();
        assert_eq!(result == SevenZipPrefixCheck::Reject, next != 0);
    }
}

#[test]
fn only_the_bound_bcj2_range_input_yields_password_evidence() {
    let mut folder = SevenZipFolderAst {
        coders: vec![
            SevenZipCoderAst {
                method_id: EncoderMethod::ID_BCJ2.to_vec(),
                properties: Vec::new(),
                num_in_streams: 4,
                num_out_streams: 1,
            },
            SevenZipCoderAst {
                method_id: EncoderMethod::ID_AES256_SHA256.to_vec(),
                properties: vec![0x3f],
                num_in_streams: 1,
                num_out_streams: 1,
            },
        ],
        bind_pairs: vec![(3, 1)],
        packed_streams: vec![0, 1, 2, 4],
        main_output_stream: 0,
        unpack_sizes: SevenZipUnpackSizes::All(vec![2, 5]),
        expected_crc: None,
    };
    let plan = seven_zip_payload_plan(&folder, 4, 0, 16, false).unwrap();
    let proof = plan.kind;
    assert_eq!(proof.plaintext_prefix_size(), 5);
    assert_eq!(proof.check_prefix(&[0, 0xff, 0xff, 0xff, 0xfe]), SevenZipPrefixCheck::Weak);
    assert_eq!(proof.check_prefix(&[0, 0xff, 0xff, 0xff, 0xff]), SevenZipPrefixCheck::Reject);
    assert_eq!(proof.check_prefix(&[1, 0, 0, 0, 0]), SevenZipPrefixCheck::Reject);
    for port in 0..3 {
        folder.bind_pairs[0].0 = port;
        assert!(seven_zip_payload_plan(&folder, 4, 0, 16, false).is_none());
    }
}

#[test]
fn delta_prefix_evidence_never_reads_beyond_its_unmodified_span() {
    use aes::cipher::BlockModeEncrypt;

    let coder = |method: &[u8], properties| SevenZipCoderAst {
        method_id: method.to_vec(), properties, num_in_streams: 1, num_out_streams: 1,
    };
    let folder = SevenZipFolderAst {
        coders: vec![
            coder(EncoderMethod::ID_AES256_SHA256, vec![0x3f]),
            coder(EncoderMethod::ID_DELTA, vec![2]),
            coder(EncoderMethod::ID_LZMA2, vec![0]),
        ],
        bind_pairs: vec![(1, 0), (2, 1)],
        packed_streams: vec![0],
        main_output_stream: 2,
        unpack_sizes: SevenZipUnpackSizes::All(vec![6, 6, 2]),
        expected_crc: Some(crc32(&[SZ_HEADER, SZ_END])),
    };
    let plan = seven_zip_payload_plan(&folder, 0, 0, 16, false).unwrap();
    let key = SevenZipAesKey::derive(&plan.properties, "secret").unwrap();
    // Distance-3 Delta encoding of [1, 0, 1, SZ_HEADER, SZ_END, 0].
    // The last byte is not a valid LZMA2 end marker before Delta decoding.
    let mut encrypted = [0; 16];
    encrypted[..6].copy_from_slice(&[1, 0, 1, SZ_HEADER - 1, SZ_END, 0xff]);
    cbc::Encryptor::<Aes256>::new(&key.key.into(), &key.iv.into())
        .encrypt_padded::<NoPadding>(&mut encrypted, 16).unwrap();
    assert_eq!(plan.kind.plaintext_prefix_size(), 3);
    assert!(!plan.kind.has_successor());
    assert_eq!(plan.kind.check_encrypted_prefix(&encrypted, &key).unwrap(), SevenZipPrefixCheck::Weak);
    let header = SevenZipPasswordProbe::from_parts(vec![encrypted.to_vec().into()], folder, SevenZipMetadata::Header);
    assert_eq!(header.check_header(|properties| SevenZipAesKey::derive(properties, "secret")).unwrap(),
        SevenZipPrefixCheck::Confirmed);
}

#[test]
fn delta_successor_uses_only_readable_headers_with_full_packed_bounds() {
    use aes::cipher::BlockModeEncrypt;
    use SevenZipPrefixCheck::{Reject, Weak};

    let key = SevenZipAesKey::derive(&[0x3f], "secret").unwrap();
    for (distance, chunk_len, expected) in [(20, 30, Weak), (22, 30, Weak), (23, 30, Reject), (23, 11, Weak)] {
        let structure = SevenZipPayloadEvidence {
            packed_size: 36,
            unchanged_prefix: distance,
            verifier: SevenZipPayloadVerifier::Compressed {
                method: EncoderMethod::ID_LZMA2.to_vec(),
                unpack_size: 29,
            },
        };
        let mut plaintext = [0x44u8; 36];
        plaintext[..3].copy_from_slice(&[1, 0, 16]); // 17 raw bytes.
        plaintext[20..23].copy_from_slice(&[2, 0, chunk_len]); // 12 raw bytes when valid.
        plaintext[35] = 0;
        let mut ciphertext = [0; 48];
        ciphertext[..plaintext.len()].copy_from_slice(&plaintext);
        for at in distance as usize..plaintext.len() {
            ciphertext[at] = plaintext[at].wrapping_sub(plaintext[at - distance as usize]);
        }
        cbc::Encryptor::<Aes256>::new(&key.key.into(), &key.iv.into())
            .encrypt_padded::<NoPadding>(&mut ciphertext, 48).unwrap();
        let first = ciphertext.first_chunk::<16>().unwrap();
        let (prefix, len) = structure.decrypt_prefix(first, &key).unwrap();
        assert_eq!(structure.check_prefix(&prefix[..len]), Weak);
        let mut did_read = false;
        let mut read = |offset, output: &mut [u8]| -> Result<(), DeferredReadError> {
            assert!(!did_read);
            assert_eq!((offset, output.len()), (16, 16));
            output.copy_from_slice(&ciphertext[16..32]);
            did_read = true;
            Ok(())
        };
        assert_eq!(
            structure.check_successor(0, first, &prefix[..len], &key, &[], &mut read,
                &SevenZipPayloadSource::Fixed(Arc::new([]))).unwrap(),
            expected
        );
        assert_eq!(did_read, distance > 20);
    }
}

#[test]
fn decoder_follows_bind_pairs_instead_of_coder_declaration_order() {
    let copy = || SevenZipCoderAst {
        method_id: EncoderMethod::ID_COPY.to_vec(),
        properties: Vec::new(),
        num_in_streams: 1,
        num_out_streams: 1,
    };
    // Packed input stream 1 -> coder 1/out 1 -> coder 2/in 2 ->
    // coder 2/out 2 -> coder 0/in 0 -> main output 0.
    let folder = SevenZipFolderAst {
        coders: vec![copy(), copy(), copy()],
        bind_pairs: vec![(2, 1), (0, 2)],
        packed_streams: vec![1],
        main_output_stream: 0,
        unpack_sizes: SevenZipUnpackSizes::All(vec![4; 3]),
        expected_crc: None,
    };
    let decoded =
        decode_seven_zip_encoded_folder(&[b"test".to_vec().into()], &folder).unwrap();
    assert_eq!(decoded, b"test");
}

#[test]
fn unavailable_second_aes_block_keeps_first_block_structure() {
    use aes::cipher::BlockModeEncrypt;

    let properties = vec![0x3f]; // Direct AES key for this fixture.
    let key = SevenZipAesKey::derive(&properties, "secret").unwrap();
    let mut encrypted = [0; 32];
    encrypted[..4].copy_from_slice(b"BZh9");
    encrypted[4..10].copy_from_slice(b"1AY&SY");
    cbc::Encryptor::<Aes256>::new(&key.key.into(), &key.iv.into())
        .encrypt_padded::<NoPadding>(&mut encrypted, 32)
        .unwrap();
    let mut reader = Cursor::new(&encrypted[..16]);
    let plan = SevenZipPayloadPlan {
        inner_aes: Box::default(),
        offset: 0,
        properties,
        kind: SevenZipPayloadEvidence {
            packed_size: 32,
            unchanged_prefix: u64::MAX,
            verifier: SevenZipPayloadVerifier::Compressed {
                method: vec![4, 2, 2],
                unpack_size: 1,
            },
        },
        cost: 0,
    };
    let probe = SevenZipPayloadProbe::load_plan(&mut reader, 32, plan, &()).unwrap();
    let check = |key: &SevenZipAesKey| {
        probe.kind.check_encrypted_prefix(&probe.encrypted, key).unwrap()
    };
    assert_eq!(check(&key), SevenZipPrefixCheck::Strong);
    let wrong = SevenZipAesKey::derive(&probe.properties, "wrong").unwrap();
    assert_eq!(check(&wrong), SevenZipPrefixCheck::Reject);
}

// Real password tests cover malformed plaintext, but cannot inject OOM or
// OS read failures. This tiny case preserves that independent distinction
// without large allocations or another archive-generation matrix.
#[test]
fn decoder_read_failures_keep_resource_errors_distinct_from_invalid_data() {
    struct FailedRead(Option<std::io::Error>);
    impl Read for FailedRead {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(self.0.take().unwrap())
        }
    }
    for (error, resource) in [
        (std::io::Error::other("invalid compressed distance"), false),
        (std::io::Error::from(std::io::ErrorKind::OutOfMemory), true),
        (std::io::Error::from_raw_os_error(8), true),
        (std::io::Error::from_raw_os_error(5), true),
    ] {
        let error = collect_decoded(FailedRead(Some(error)), 1).unwrap_err();
        assert_eq!(
            error.starts_with("resource_unavailable:"),
            resource,
            "{error}"
        );
    }
}

#[test]
fn decoder_rejects_bind_pair_cycles() {
    let copy = SevenZipCoderAst {
        method_id: EncoderMethod::ID_COPY.to_vec(),
        properties: Vec::new(),
        num_in_streams: 1,
        num_out_streams: 1,
    };
    let folder = SevenZipFolderAst {
        coders: vec![copy],
        bind_pairs: vec![(0, 0)],
        packed_streams: Vec::new(),
        main_output_stream: 0,
        unpack_sizes: SevenZipUnpackSizes::Main(1),
        expected_crc: None,
    };
    let error = decode_seven_zip_encoded_folder(&[], &folder).unwrap_err();
    assert_eq!(error, "encoded_header_bind_pair_cycle");
}
