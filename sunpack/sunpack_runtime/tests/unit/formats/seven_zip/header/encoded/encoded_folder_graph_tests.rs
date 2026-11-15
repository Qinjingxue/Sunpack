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
        decode_seven_zip_encoded_coder(CoderInput::Borrowed(data), &coder, None, size)
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
            None,
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
        decode_seven_zip_encoded_coder(CoderInput::Borrowed(bytes.as_slice()), &coder, None, 4)
            .unwrap(),
        b"test"
    );
    for wrong_size in [0, 3, 5, 64 * 1024 * 1024 + 1] {
        assert!(decode_seven_zip_encoded_coder(
            CoderInput::Borrowed(bytes.as_slice()),
            &coder,
            None,
            wrong_size
        )
        .is_err());
    }
    *bytes.last_mut().unwrap() ^= 1;
    assert!(decode_seven_zip_encoded_coder(
        CoderInput::Borrowed(bytes.as_slice()),
        &coder,
        None,
        4
    )
    .is_err());
    coder.properties.clear();
    assert!(decode_seven_zip_encoded_coder(
        CoderInput::Borrowed(bytes.as_slice()),
        &coder,
        None,
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
fn seven_zip_kdf_cache_is_bounded_and_preserves_keys() {
    seven_zip_kdf_cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clear();
    for index in 0..SEVEN_ZIP_KDF_CACHE_CAPACITY + 17 {
        let password = format!("cache-password-{index}").into_bytes();
        assert_eq!(
            cached_seven_zip_aes_key(4, b"salt", &password),
            derive_seven_zip_aes_key(4, b"salt", &password)
        );
    }
    assert_eq!(
        seven_zip_kdf_cache()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len(),
        SEVEN_ZIP_KDF_CACHE_CAPACITY
    );
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
        decode_seven_zip_encoded_folder(&[b"test".to_vec().into()], &folder, None).unwrap();
    assert_eq!(decoded, b"test");
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
    let error = decode_seven_zip_encoded_folder(&[], &folder, None).unwrap_err();
    assert_eq!(error, "encoded_header_bind_pair_cycle");
}
