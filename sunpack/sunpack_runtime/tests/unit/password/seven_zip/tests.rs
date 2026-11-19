use super::*;

#[test]
fn declared_next_header_beyond_input_requires_a_volume_or_has_damaged_offsets() {
    let mut bytes = [0u8; SEVEN_Z_HEADER_SIZE];
    bytes[..6].copy_from_slice(SEVEN_Z_MAGIC);
    bytes[12..20].copy_from_slice(&64u64.to_le_bytes());
    bytes[20..28].copy_from_slice(&16u64.to_le_bytes());
    assert_eq!(
        seven_zip_tail_requirement(&bytes, 64).unwrap_err().field,
        "7z.next_header"
    );
}

#[test]
fn payload_prefix_collisions_survive_until_complete_header_evidence() {
    let candidates: Vec<Arc<str>> = ["wrong", "collision", "wrong2", "correct", "later"]
        .into_iter()
        .map(Arc::from)
        .collect();
    let evidence = Some("7z_payload_prefix");
    let weak = collect_candidates(&candidates, false, |index, value| {
        Ok(if value == "collision" || value == "correct" {
            (SevenZipPrefixCheck::Weak, index + 1)
        } else {
            (SevenZipPrefixCheck::Reject, 0)
        })
    })
    .unwrap();
    assert_eq!(weak, [(1, Ok((SevenZipPrefixCheck::Weak, 2))), (3, Ok((SevenZipPrefixCheck::Weak, 4)))]);
    let weak = candidate_result(&weak, candidates.len(), evidence, true);
    assert_eq!(weak.matched_indices, [1, 3]);
    assert_eq!(weak.attempts, candidates.len());
    assert_eq!(weak.final_confirmation_required, Some(true));
    let confirmed = collect_candidates(&candidates, false, |_, value| {
        Ok((match value {
            "collision" => SevenZipPrefixCheck::Strong,
            "correct" => SevenZipPrefixCheck::Confirmed,
            _ => SevenZipPrefixCheck::Reject,
        }, ()))
    })
    .unwrap();
    let confirmed = candidate_result(&confirmed, candidates.len(), evidence, true);
    assert_eq!(confirmed.matched_index, Some(3));
    assert_eq!(confirmed.final_confirmation_required, Some(false));
    let absent = collect_candidates(&candidates, false, |_, _| Ok((SevenZipPrefixCheck::Reject, ()))).unwrap();
    let absent = candidate_result(&absent, candidates.len(), evidence, true);
    assert_eq!(absent.status, "no_match");
    assert_eq!(absent.attempts, candidates.len());
    let fault_or_reject = |index, _: &str| {
        if index == 2 {
            Err("resource_unavailable: test".into())
        } else {
            Ok((SevenZipPrefixCheck::Reject, ()))
        }
    };
    for proof in [Some("7z_payload_prefix"), None] {
        let fault = collect_candidates(&candidates, proof.is_none(), fault_or_reject).unwrap();
        let fault = candidate_result(&fault, candidates.len(), proof, true);
        assert_eq!(fault.matched_indices, [2]);
        assert_eq!(fault.attempts, candidates.len());
        assert_eq!(fault.final_confirmation_required, Some(true));
    }
    let confirmed = collect_candidates(&candidates, true, |index, password| {
        if password == "correct" { Ok((SevenZipPrefixCheck::Confirmed, ())) }
        else { fault_or_reject(index, password) }
    }).unwrap();
    assert_eq!(confirmed, [(3, Ok((SevenZipPrefixCheck::Confirmed, ())))]);
}

const AES_LZMA2_FOLDER: &[u8] = &[2, 0x24, 6, 0xf1, 7, 1, 1, 0x3f, 0x21, 0x21, 1, 0, 1, 0];

fn direct_key_ciphertext(plaintext: &[u8]) -> Vec<u8> {
    let mut key = [0; 32];
    key[..12].copy_from_slice(b"s\0e\0c\0r\0e\0t\0");
    encrypt_payload_fixture(plaintext, &key)
}

fn encrypt_payload_fixture(plaintext: &[u8], key: &[u8; 32]) -> Vec<u8> {
    use aes::cipher::{block_padding::NoPadding, BlockModeEncrypt, KeyIvInit};
    let mut encrypted = plaintext.to_vec();
    let length = plaintext.len().next_multiple_of(16);
    encrypted.resize(length, 0);
    cbc::Encryptor::<aes::Aes256>::new(key.into(), &[0; 16].into())
        .encrypt_padded::<NoPadding>(&mut encrypted, length)
        .unwrap();
    encrypted
}

fn archive_with_descriptor(body: &[u8], header: &[u8]) -> Vec<u8> {
    let mut archive = vec![0; SEVEN_Z_HEADER_SIZE];
    archive[..SEVEN_Z_MAGIC.len()].copy_from_slice(SEVEN_Z_MAGIC);
    archive[7] = 4;
    archive[12..20].copy_from_slice(&(body.len() as u64).to_le_bytes());
    archive.extend_from_slice(body);
    archive.extend_from_slice(header);
    update_descriptor_crc(&mut archive);
    archive
}

#[test]
fn encoded_header_reads_packed_remainder_only_for_prefix_survivors() {
    let mut plain = vec![1, 2, 0x19, 72];
    plain.extend([b'x'; 72]);
    plain.extend([0, 0]);
    let encrypted = direct_key_ciphertext(&plain);
    let mut descriptor = vec![
        0x17, 6, 0, 1, 9, encrypted.len() as u8, 0,
        7, 11, 1, 0, 1, 0x24, 6, 0xf1, 7, 1, 1, 0x3f,
        12, plain.len() as u8, 10, 1,
    ];
    descriptor.extend(crc32fast::hash(&plain).to_le_bytes());
    descriptor.extend([0, 0]);
    let archive = archive_with_descriptor(&encrypted, &descriptor);
    let reader = ManagedReader::from_bytes(archive.clone(), Default::default());
    let evidence = FixedSevenZipEvidence(Arc::new([RangeSpec::entire(&reader)]));
    let context = prepare_seven_zip(reader.stream_cursor(), reader.len(), &evidence).ok().unwrap();
    let before = reader.stats().direct_read_bytes;
    assert_eq!(context.verify(&[Arc::from("wrong")]).unwrap().status, "no_match");
    assert_eq!(reader.stats().direct_read_bytes, before);
    let correct = context.verify(&[Arc::from("secret")]).unwrap();
    assert_eq!(correct.final_confirmation_required, Some(false));
    assert_eq!(reader.stats().direct_read_bytes - before, encrypted.len() as u64 - 16);
    let (paths, sources, plan) = uncertain_tail_fixture_at(&archive, &[], 64);
    let context = prepare_seven_zip_attempts(&sources[0], &plan, &[], None).ok().unwrap();
    let result = context.verify(&[Arc::from("wrong"), Arc::from("secret")], None).unwrap();
    assert_eq!(result.matched_indices, [1]);
    assert_eq!(result.final_confirmation_required, Some(false));
    assert!(!result.volume_attempts.unwrap().sources.iter().any(|source| source.path == sources[1].path));
    drop(context);
    for path in paths { std::fs::remove_file(path).unwrap(); }
}

#[test]
fn alternate_short_prefix_rejects_without_reading_first_stream_successor() {
    let mut stream = vec![1, 0, 44];
    stream.extend([0xa9; 45]);
    stream.extend([2, 0, 44]);
    stream.extend([0x4a; 45]);
    stream.push(0);
    let first = direct_key_ciphertext(&stream);
    let mut header = vec![1, 4, 6, 0, 2, 9, first.len() as u8, 32, 0, 7, 11, 2, 0];
    header.extend(AES_LZMA2_FOLDER);
    let mut other_folder = AES_LZMA2_FOLDER.to_vec();
    other_folder[7] = 0;
    header.extend(other_folder);
    header.extend([12, stream.len() as u8, 90, 32, 28, 0, 0, 0]);
    // The first stream uses a direct key and truncates the password. The
    // other stream uses a one-round SHA-256 key and distinguishes the suffix.
    let equivalent = format!("secret{}second", "\0".repeat(10));
    let key = <sha2_11::Sha256 as sha2_11::Digest>::digest(b"s\0e\0c\0r\0e\0t\0\0\0\0\0\0\0\0\0").into();
    let mut valid = [0xa9; 32];
    valid[..3].copy_from_slice(&[1, 0, 27]);
    valid[31] = 0;
    for (plain, expected, expected_reads) in [([0xff; 32], [1], 16), (valid, [0], 32)] {
        let mut body = first.clone();
        body.extend(encrypt_payload_fixture(&plain, &key));
        let reader = ManagedReader::from_bytes(archive_with_descriptor(&body, &header), Default::default());
        let evidence = FixedSevenZipEvidence(Arc::new([RangeSpec::entire(&reader)]));
        let context = prepare_seven_zip(reader.stream_cursor(), reader.len(), &evidence).ok().unwrap();
        let before = reader.stats().read_bytes;
        let proof = context.verify(&[Arc::from("secret"), Arc::from(equivalent.as_str())]).unwrap();
        assert_eq!(proof.matched_indices, expected);
        assert_eq!(proof.final_confirmation_required, Some(true));
        assert_eq!(reader.stats().read_bytes - before, expected_reads);
    }
}

#[test]
fn fixed_layout_leaves_last_prefix_survivor_to_final_confirmation() {
    let mut stream = vec![1, 0, 44];
    stream.extend([0xa9; 45]);
    // A complete first chunk followed by an invalid control in the next CBC window.
    stream.extend([0x7f; 16]);
    let first = direct_key_ciphertext(&stream);
    let packed = first.len() as u8;
    let passwords: Vec<Arc<str>> = (0..4)
        .map(|index| Arc::from(format!("secret{}{index}", "\0".repeat(10))))
        .collect();
    let mut second = [0xa9; 32];
    second[..3].copy_from_slice(&[1, 0, 27]);
    second[31] = 0;
    // Cover successor-only reads, the parallel wave, and the tail after
    // staging two viable candidates with a separate stream.
    for (count, staged, expected_reads) in [(2, false, 32), (4, false, 96), (3, true, 96)] {
        let (body, header) = if staged {
            let mut body = first.clone();
            body.extend(direct_key_ciphertext(&second));
            let mut header = vec![1, 4, 6, 0, 2, 9, packed, 32, 0, 7, 11, 2, 0];
            header.extend(AES_LZMA2_FOLDER);
            header.extend(AES_LZMA2_FOLDER);
            header.extend([12, stream.len() as u8, 90, 32, 28, 0, 0, 0]);
            (body, header)
        } else {
            let mut header = vec![1, 4, 6, 0, 1, 9, packed, 0, 7, 11, 1, 0];
            header.extend(AES_LZMA2_FOLDER);
            header.extend([12, stream.len() as u8, 90, 0, 0, 0]);
            (first.clone(), header)
        };
        let reader = ManagedReader::from_bytes(archive_with_descriptor(&body, &header), Default::default());
        let evidence = FixedSevenZipEvidence(Arc::new([RangeSpec::entire(&reader)]));
        let context = prepare_seven_zip(reader.stream_cursor(), reader.len(), &evidence).ok().unwrap();
        let before = reader.stats().read_bytes;
        let proof = context.verify(&passwords[..count]).unwrap();
        assert_eq!(proof.matched_indices, [count - 1]);
        assert_eq!(proof.final_confirmation_required, Some(true));
        assert_eq!(reader.stats().read_bytes - before, expected_reads);
    }
}

#[test]
fn projected_packed_crc_prunes_before_password_screening() {
    let mut stream = vec![1, 0, 44];
    stream.extend([0xa9; 45]);
    stream.extend([2, 0, 44]);
    stream.extend([0x4a; 45]);
    stream.push(0);
    let encrypted = direct_key_ciphertext(&stream);
    let mut header = vec![1, 4, 6, 0, 1, 9, encrypted.len() as u8, 10, 1];
    header.extend(crc32fast::hash(&encrypted).to_le_bytes());
    header.extend([0, 7, 11, 1, 0]);
    header.extend(AES_LZMA2_FOLDER);
    header.extend([12, stream.len() as u8, 90, 0, 0, 0]);
    let archive = archive_with_descriptor(&encrypted, &header);
    let (paths, sources, plan) = uncertain_tail_fixture_at(&archive, &[], 48);
    let context = prepare_seven_zip_attempts(&sources[0], &plan, &[], None)
        .unwrap_or_else(|_| panic!("projected prefix and packed CRC"));
    let PasswordContext::Evidence(evidence) = context else { panic!("projection was lost"); };
    let public = evidence.public_plan().unwrap().unwrap();
    assert!(!public.sources.iter().any(|source| source.path == sources[1].path));
    let wrong = evidence.verify_batch(&[Arc::from("wrong")], false, true).unwrap();
    assert_eq!(wrong.status, "no_match");
    assert!(Arc::ptr_eq(&public, &wrong.volume_attempts.unwrap()));
    let correct = evidence.verify_batch(&[Arc::from("secret")], true, true).unwrap();
    assert_eq!(correct.matched_indices, [0]);
    let plan = correct.volume_attempts.unwrap();
    assert!(!plan.sources.iter().any(|source| source.path == sources[1].path));
    drop(evidence);
    for path in paths { std::fs::remove_file(path).unwrap(); }
}

#[test]
fn projected_lzma2_successor_removes_bad_cbc_source_after_prefix_survives() {
    use crate::io::archive_state::{VolumeDomain, VolumeSlot};

    // Two LZMA2 blocks have known controls and lengths, and their intervening
    // bodies need no scan. The end marker's CBC predecessor is on the disputed
    // volume, beyond the first successor already checked in the common head.
    let mut stream = vec![1, 0, 44];
    stream.extend([0xa9; 45]);
    stream.extend([2, 0, 44]);
    stream.extend([0x4a; 45]);
    stream.push(0);
    let mut encrypted = direct_key_ciphertext(&stream);
    let fixed_start = SEVEN_Z_HEADER_SIZE + encrypted.len();
    let packed = encrypted.len() as u8;
    let mut header = vec![1, 4, 6, 0, 2, 9, packed, packed, 0, 7, 11, 2, 0];
    header.extend(AES_LZMA2_FOLDER);
    header.extend(AES_LZMA2_FOLDER);
    header.extend([12, stream.len() as u8, 90, stream.len() as u8, 90, 0, 0, 0]);
    encrypted.extend(direct_key_ciphertext(&stream));
    let archive = archive_with_descriptor(&encrypted, &header);
    let (mut paths, mut sources, mut plan) = uncertain_tail_fixture_at(&archive[..fixed_start], &[], 112);
    let fixed_path = crate::test_support::temp_file("7z_fixed_tail", &archive[fixed_start..]);
    sources.push(InputExtent {
        path: fixed_path.to_string_lossy().into_owned(),
        start: 0,
        end: Some((archive.len() - fixed_start) as u64),
    });
    paths.push(fixed_path);
    let input = Arc::make_mut(&mut plan);
    input.sources = sources.clone().into_boxed_slice();
    input.minimum_size = Some(archive.len() as u64);
    let mut slots = input.layouts[0].slots.to_vec();
    slots.push(VolumeSlot { number: 3, canonical_name: "x.003".into(), domain: 2 });
    input.layouts[0].slots = slots.into_boxed_slice();
    let mut domains = input.domains.to_vec();
    domains.push(VolumeDomain { choices: Arc::new(vec![sources.len() - 1]) });
    input.domains = domains.into_boxed_slice();

    let session = NativeArchiveSession::new(sources.last().unwrap().path.clone()).unwrap();
    let (_, fixed_tail) = session.borrowed_reader();
    let context = prepare_seven_zip_attempts(&sources[0], &plan, std::slice::from_ref(&session), None)
        .unwrap_or_else(|_| panic!("LZMA2 projected header"));
    let PasswordContext::Evidence(evidence) = context else {
        panic!("the common prefix should retain separate successor sources");
    };
    let before = fixed_tail.stats().direct_read_bytes;
    let proof = evidence.verify_batch(&[Arc::from("secret")], true, true).unwrap();
    assert_eq!(proof.matched_indices, [0]);
    assert!(!proof.volume_attempts.unwrap().sources.iter().any(|source| source.path == sources[1].path));
    assert_eq!(fixed_tail.stats().direct_read_bytes, before);
    drop(evidence);
    drop(fixed_tail);
    drop(session);
    for path in paths { std::fs::remove_file(path).unwrap(); }
}

#[test]
fn projected_concatenated_frame_rejects_incompatible_next_volume() {
    let lz4_frame = |body: &[u8]| {
        let mut frame = vec![4, 0x22, 0x4d, 0x18, 0x60, 0x40];
        frame.push((crate::formats::lz4::xxh32(&frame[4..]) >> 8) as u8);
        frame.extend((0x8000_0000 | body.len() as u32).to_le_bytes());
        frame.extend(body);
        frame.extend([0; 4]);
        frame
    };
    let zstd_frame = |body: &[u8]| {
        let mut frame = vec![0x28, 0xb5, 0x2f, 0xfd, 0x20, body.len() as u8];
        frame.extend([((body.len() as u8) << 3) | 1, (body.len() >> 5) as u8, 0]);
        frame.extend(body);
        frame
    };
    let cases = [
        (lz4_frame(&[3; 33]), lz4_frame(&[42]), &[0x24, 4, 0xf7, 0x11, 4, 5, 1, 10, 1, 0, 0][..], 34),
        (zstd_frame(&[3; 39]), zstd_frame(&[42]), &[4, 4, 0xf7, 0x11, 1][..], 40),
    ];
    for (mut stream, next_frame, coder, unpack_size) in cases {
        let next = stream.len();
        assert_eq!(next % 16, 0);
        stream.extend(next_frame);
        let encrypted = direct_key_ciphertext(&stream);
        let mut header = vec![
            1, 4, 6, 0, 1, 9, encrypted.len() as u8, 0, 7, 11, 1, 0,
            2, 0x24, 6, 0xf1, 7, 1, 1, 0x3f,
        ];
        header.extend(coder);
        header.extend([1, 0, 12, stream.len() as u8, unpack_size, 0, 0, 0]);
        let archive = archive_with_descriptor(&encrypted, &header);
        let (paths, sources, plan) = uncertain_tail_fixture_at(&archive, &[], SEVEN_Z_HEADER_SIZE + next);
        let context = prepare_seven_zip_attempts(&sources[0], &plan, &[], None)
            .unwrap_or_else(|_| panic!("concatenated frame descriptor"));
        let PasswordContext::Evidence(evidence) = context else {
            panic!("the first frame is common to both candidate volumes");
        };
        let proof = evidence.verify_batch(&[Arc::from("secret")], true, true).unwrap();
        assert_eq!(proof.matched_indices, [0]);
        assert!(!proof.volume_attempts.unwrap().sources.iter().any(|source| source.path == sources[1].path));
        drop(evidence);
        for path in paths { std::fs::remove_file(path).unwrap(); }
    }
}

#[test]
fn external_folder_metadata_locates_encrypted_payload_stream() {
    let mut body = direct_key_ciphertext(&[1, 0, 0, 42, 0]);
    body.extend(AES_LZMA2_FOLDER);
    let size = AES_LZMA2_FOLDER.len() as u8;
    let header = [
        1, 3,                       // Header and AdditionalStreamsInfo
        6, 16, 1, 9, size, 0,       // PackInfo for the external Copy stream
        7, 11, 1, 0, 1, 1, 0,      // one inline Copy folder
        12, size, 0, 0,
        4, 6, 0, 1, 9, 16, 0,      // MainStreamsInfo and payload PackInfo
        7, 11, 1, 1, 0,            // one external folder in AdditionalStreams stream 0
        12, 5, 1, 0, 0, 0,
    ];
    let archive = archive_with_descriptor(&body, &header);
    let context = prepare_seven_zip(std::io::Cursor::new(&archive), archive.len() as u64, &())
        .unwrap_or_else(|_| panic!("external folder should expose its AES compressor prefix"));
    let proof = context.verify(&[Arc::from("wrong"), Arc::from("secret")]).unwrap();
    assert_eq!(proof.matched_indices, [1]);
    assert_eq!(proof.match_evidence, Some("7z_payload_prefix"));
    assert_eq!(proof.final_confirmation_required, Some(true));
}

#[test]
fn encrypted_external_names_supply_password_proof_for_clear_members() {
    for (name, crc) in [(&b"x\0\0\0"[..], true), (&b"x\0\0\0\0\0\xff"[..], false)] {
        let encrypted = direct_key_ciphertext(name);
        let mut header = vec![
            1, 3, 6, 0, 1, 9, 16, 0, // AdditionalStreamsInfo
            7, 11, 1, 0, 1, 0x24, 6, 0xf1, 7, 1, 1, 0x3f, // AES folder
            12, name.len() as u8,
        ];
        if crc {
            header.extend([10, 1]);
            header.extend(crc32fast::hash(name).to_le_bytes());
        }
        header.extend([
            0, 0, 5, 1, 14, 1, 0x80, 15, 1, 0x80, // one empty file
            17, 2, 1, 0, 0, 0,                   // its name is in external folder 0
        ]);
        let archive = archive_with_descriptor(&encrypted, &header);
        let context = prepare_seven_zip(std::io::Cursor::new(&archive), archive.len() as u64, &())
            .unwrap_or_else(|_| panic!("external names have CRC or name structure evidence"));
        let proof = context.verify(&[Arc::from("wrong"), Arc::from("secret")]).unwrap();
        assert_eq!(proof.matched_indices, [1]);
        assert_eq!(proof.final_confirmation_required, Some(!crc));
    }
}

#[test]
fn ppmd_encoded_header_confirms_password_from_decoder_output_crc() {
    // NanaZip PPMd order 6 with a 64 KiB model. The decoded header is
    // [Header, FilesInfo, number of files = 0, End, End].
    let packed = [0, 0x01, 0x07, 0xd0, 0xcd, 0x32, 0x9f, 0x4e];
    let encrypted = direct_key_ciphertext(&packed);
    let mut header = vec![
        0x17, 6, 0, 1, 9, 16, 0,
        7, 11, 1, 0, 2, 0x24, 6, 0xf1, 7, 1, 1, 0x3f,  // AES
        0x23, 3, 4, 1, 5, 6, 0, 0, 1, 0,             // PPMd
        1, 0, 12, packed.len() as u8, 5, 10, 1,
    ];
    header.extend(crc32fast::hash(&[1, 5, 0, 0, 0]).to_le_bytes());
    header.extend([0, 0]);
    let archive = archive_with_descriptor(&encrypted, &header);
    let context = prepare_seven_zip(std::io::Cursor::new(&archive), archive.len() as u64, &())
        .unwrap_or_else(|_| panic!("PPMd encoded header descriptor"));
    let proof = context.verify(&[Arc::from("wrong"), Arc::from("secret")]).unwrap();
    assert_eq!(proof.matched_indices, [1]);
    assert_eq!(proof.final_confirmation_required, Some(false));
}

#[test]
fn deflate64_encoded_header_confirms_password_with_extended_match_length() {
    // Fixed Huffman block with Deflate64 symbol 285 and a 16-bit length
    // extension. A Deflate32 decoder cannot read this 300-byte match.
    let packed = [0x63, 0x64, 0x92, 0x6c, 0xd4, 0x8d, 0x18, 0x4d, 9, 0, 0x0c, 0x0c, 0];
    let mut plaintext = vec![1, 2, 0x19, 0x81, 0x2d]; // 301 bytes of an archive property
    plaintext.extend([b'X'; 301]);
    plaintext.extend([0, 0]);
    let encrypted = direct_key_ciphertext(&packed);
    let mut header = vec![
        0x17, 6, 0, 1, 9, 16, 0,
        7, 11, 1, 0, 2, 0x24, 6, 0xf1, 7, 1, 1, 0x3f,
        3, 4, 1, 9, 1, 0,
        12, packed.len() as u8, 0x80 | (plaintext.len() >> 8) as u8, plaintext.len() as u8,
        10, 1,
    ];
    header.extend(crc32fast::hash(&plaintext).to_le_bytes());
    header.extend([0, 0]);
    let archive = archive_with_descriptor(&encrypted, &header);
    let context = prepare_seven_zip(std::io::Cursor::new(&archive), archive.len() as u64, &())
        .unwrap_or_else(|_| panic!("Deflate64 encoded header descriptor"));
    let proof = context.verify(&[Arc::from("wrong"), Arc::from("secret")]).unwrap();
    assert_eq!(proof.matched_indices, [1]);
    assert_eq!(proof.final_confirmation_required, Some(false));
}

#[test]
fn uncertain_7z_tails_use_crc_linked_evidence_but_preserve_unknown_paths() {
    let bytes: &[u8] = &[
        55, 122, 188, 175, 39, 28, 0, 4, 178, 190, 162, 6, 16, 0, 0, 0, 0, 0, 0, 0, 90, 0, 0, 0, 0,
        0, 0, 0, 137, 92, 122, 211, 37, 116, 224, 226, 140, 241, 42, 72, 179, 115, 25, 153, 186,
        152, 193, 102, 1, 4, 6, 0, 1, 9, 16, 0, 7, 11, 1, 0, 2, 36, 6, 241, 7, 1, 18, 83, 15, 90,
        12, 52, 178, 191, 180, 172, 56, 77, 7, 166, 158, 159, 175, 101, 31, 1, 0, 1, 0, 12, 16, 16,
        0, 8, 10, 1, 53, 59, 166, 46, 0, 0, 5, 1, 25, 3, 0, 0, 0, 17, 5, 0, 120, 0, 0, 0, 20, 10,
        1, 0, 100, 53, 227, 238, 121, 118, 221, 1, 21, 6, 1, 0, 32, 0, 0, 0, 0, 0,
    ];
    // The same Copy data, this time with the optional public PackInfo CRC.
    // Both tails have the right NextHeader. Only their packed bytes differ.
    let mut with_digest = bytes.to_vec();
    let digest = crc32fast::hash(&bytes[32..48]);
    with_digest.splice(55..55, [0x0a, 1].into_iter().chain(digest.to_le_bytes()));
    update_descriptor_crc(&mut with_digest);
    let (paths, sources, plan) = uncertain_tail_fixture_at(&with_digest, &[], 32);
    let context = prepare_seven_zip_attempts(&sources[0], &plan, &[], None).unwrap_or_else(|_| panic!("packed CRC"));
    let result = context.verify(&[Arc::from("secret")], None).unwrap();
    assert!(!result.volume_attempts.unwrap().sources.iter().any(|source| source.path == sources[1].path));
    drop(context);
    for path in paths { std::fs::remove_file(path).unwrap(); }
    let (paths, sources, mut plan) = uncertain_tail_fixture(bytes);
    {
        let context =
            prepare_seven_zip_attempts(&sources[0], &plan, &[], None).unwrap_or_else(
                |error| match error {
                    PreparedStatus::Status(status, message) => {
                        panic!("valid tail: {status}: {message}")
                    }
                    PreparedStatus::ReadFault(fault) => panic!("valid tail: {fault:?}"),
                },
            );
        let result = context
            .verify(&[Arc::from("wrong"), Arc::from("secret")], None)
            .unwrap();
        // AES + Copy has no compression-prefix proof. Only the public
        // NextHeader CRC can reject a tail; member CRC belongs to the worker.
        assert_eq!(result.status, "unknown_needs_final_verifier");
        let remaining = result.volume_attempts.unwrap();
        assert!(!remaining.sources.iter().any(|source| source.path == sources[1].path));
        assert_eq!(
            context.verify(&[Arc::from("wrong")], None).unwrap().status,
            "unknown_needs_final_verifier"
        );
    }
    // A completed combination shorter than the declared NextHeader cannot be
    // the archive. It must not hide the good tail as an unknown alternative.
    Arc::make_mut(&mut plan).domains[1].choices = Arc::new(vec![2, 3]);
    assert!(prepare_seven_zip_attempts(&sources[0], &plan, &[], None).is_ok());
    // A physical EOF inside the declared extent excludes this choice when
    // another tail supplies the range. An open failure retains its choice.
    Arc::make_mut(&mut plan).sources[3].end = Some((bytes.len() - 48) as u64);
    let unavailable = InputExtent { path: format!("{}.absent", sources[3].path), ..plan.sources[3].clone() };
    Arc::make_mut(&mut plan).sources = plan.sources.iter().cloned().chain([unavailable.clone()]).collect();
    Arc::make_mut(&mut plan).domains[1].choices = Arc::new(vec![2, 3, 4]);
    let uncertain = prepare_seven_zip_attempts(&sources[0], &plan, &[], None).unwrap_or_else(|_| panic!("retain unsupported paths"));
    let result = uncertain.verify(&[Arc::from("secret")], None).unwrap();
    assert_eq!(result.status, "unknown_needs_final_verifier");
    let remaining = result.volume_attempts.unwrap();
    assert!(!remaining.sources.iter().any(|source| source.path == sources[3].path));
    assert!(remaining.sources.iter().any(|source| source.path == unavailable.path));
    // A fixed-size tail proves the head trim, but does not prove a Copy key.
    Arc::make_mut(&mut plan).domains[1].choices = Arc::new(vec![2]);
    Arc::make_mut(&mut plan).head_size_from_total = Some(bytes.len() as u64);
    let context = prepare_seven_zip_attempts(&sources[0], &plan, &[], None)
        .unwrap_or_else(|_| panic!("exact tail geometry proves carrier trim"));
    assert_eq!(
        context
            .verify(&[Arc::from("secret")], None)
            .unwrap()
            .status,
        "unknown_needs_final_verifier"
    );
    drop(context);
    for path in paths {
        std::fs::remove_file(path).unwrap();
    }
}

// Both tests use the same real two-part layout; only the evidence kind differs.
fn uncertain_tail_fixture(
    bytes: &[u8],
) -> (Vec<std::path::PathBuf>, Vec<InputExtent>, Arc<VolumeAttemptPlan>) {
    uncertain_tail_fixture_at(bytes, &[], 48)
}

fn uncertain_tail_fixture_at(
    bytes: &[u8],
    suffix: &[u8],
    split: usize,
) -> (Vec<std::path::PathBuf>, Vec<InputExtent>, Arc<VolumeAttemptPlan>) {
    use crate::io::archive_state::{VolumeDomain, VolumeLayout, VolumeSlot};
    let mut bad = bytes[split..].to_vec();
    bad[0] ^= 1;
    let mut good = bytes[split..].to_vec();
    good.extend_from_slice(suffix);
    let paths = [
        crate::test_support::temp_file("attempt_head", &bytes[..split]),
        crate::test_support::temp_file("attempt_bad_tail", &bad),
        crate::test_support::temp_file("attempt_good_tail", &good),
        crate::test_support::temp_file("attempt_short_tail", &[0; 7]),
    ];
    let sources: Vec<_> = paths
        .iter()
        .map(|path| InputExtent {
            path: path.to_string_lossy().into_owned(),
            start: 0,
            end: Some(std::fs::metadata(path).unwrap().len()),
        })
        .collect();
    let plan = Arc::new(VolumeAttemptPlan {
        sources: sources.clone().into_boxed_slice(),
        layouts: vec![VolumeLayout {
            minimum_slots: 0,
            slots: vec![
                VolumeSlot {
                    number: 1,
                    canonical_name: "x.001".into(),
                    domain: 0,
                },
                VolumeSlot {
                    number: 2,
                    canonical_name: "x.002".into(),
                    domain: 1,
                },
            ]
            .into_boxed_slice(),
        }]
        .into_boxed_slice(),
        domains: vec![
            VolumeDomain {
                choices: Arc::new(vec![0]),
            },
            VolumeDomain {
                choices: Arc::new(vec![1, 2]),
            },
        ]
        .into_boxed_slice(),
        head_size_from_total: None,
        minimum_size: Some(bytes.len() as u64),
        tail_totals: Box::new([]),
    });
    (paths.into(), sources, plan)
}

#[test]
fn encrypted_header_alternative_ciphertexts_share_candidate_kdf_and_confirm() {
    // Real 7-Zip AES-encrypted Copy header. Both tails retain exactly the same
    // CRC-valid public descriptor, but the first tail has corrupted ciphertext.
    let bytes: &[u8] = &[
        55, 122, 188, 175, 39, 28, 0, 4, 150, 96, 215, 24, 112, 0, 0, 0, 0, 0, 0, 0, 46, 0, 0, 0,
        0, 0, 0, 0, 69, 149, 29, 212, 3, 225, 66, 163, 147, 140, 91, 232, 1, 22, 148, 68, 77, 132,
        149, 99, 31, 50, 205, 33, 183, 240, 152, 241, 51, 160, 215, 44, 87, 99, 236, 160, 143, 65,
        226, 141, 180, 33, 118, 251, 78, 242, 186, 228, 202, 40, 250, 35, 17, 116, 180, 107, 36,
        102, 94, 237, 143, 161, 155, 45, 69, 113, 130, 168, 147, 181, 132, 123, 233, 44, 115, 11,
        164, 24, 112, 255, 148, 185, 51, 41, 124, 122, 202, 128, 51, 92, 47, 177, 22, 183, 64, 249,
        25, 233, 250, 15, 19, 184, 222, 124, 90, 189, 177, 134, 238, 105, 241, 244, 182, 66, 30,
        132, 23, 6, 16, 1, 9, 96, 0, 7, 11, 1, 0, 1, 36, 6, 241, 7, 1, 18, 83, 15, 136, 73, 242,
        156, 134, 229, 231, 126, 225, 247, 29, 129, 125, 4, 71, 144, 12, 90, 10, 1, 216, 135, 198,
        224, 0, 0,
    ];
    // Remove the optional folder CRC from the same real encoded header.
    // The complete header can still reject invalid trees but cannot confirm the password.
    let mut crc_less = bytes.to_vec();
    let crc_field = crc_less.len() - 8;
    assert_eq!(&crc_less[crc_field..crc_field + 2], &[0x0a, 1]);
    crc_less.drain(crc_field..crc_field + 6);
    update_descriptor_crc(&mut crc_less);
    let context = prepare_seven_zip(std::io::Cursor::new(&crc_less), crc_less.len() as u64, &())
        .unwrap_or_else(|_| panic!("CRC-less header must use structural evidence"));
    let result = context.verify(&[Arc::from("wrong-first"), Arc::from("secret")]).unwrap();
    assert_eq!(result.matched_indices, [1]);
    assert_eq!(result.match_evidence, Some("7z_header_structure"));
    assert_eq!(result.final_confirmation_required, Some(true));
    // A single substream covers the whole encrypted metadata folder.
    // Move the original folder digest to SubStreamsInfo, then split the
    // StartHeader across two alternative second volumes.
    let mut substream_digest = crc_less;
    substream_digest.splice(crc_field + 1..crc_field + 1,
        [8, 10, 1].into_iter().chain(bytes[crc_field + 2..crc_field + 6].iter().copied()).chain([0]));
    update_descriptor_crc(&mut substream_digest);
    let (fragment_paths, fragment_sources, fragment_plan) =
        uncertain_tail_fixture_at(&substream_digest, &[], 20);
    let context = prepare_seven_zip_attempts(&fragment_sources[0], &fragment_plan, &[], None)
        .unwrap_or_else(|_| panic!("split StartHeader and encoded-header substream CRC"));
    let result = context.verify(&[Arc::from("wrong-first"), Arc::from("secret")], None).unwrap();
    assert_eq!(result.matched_indices, [1]);
    assert_eq!(result.final_confirmation_required, Some(false));
    assert!(!result
        .volume_attempts
        .unwrap()
        .sources
        .iter()
        .any(|source| source.path == fragment_sources[1].path));
    drop(context);
    for path in fragment_paths { std::fs::remove_file(path).unwrap(); }
    // The correct tail has trailing carrier junk, unlike the bad-cipher tail.
    // Right-aligning it at NextHeader.end would discard the correct password.
    let (mut paths, mut sources, mut plan) =
        uncertain_tail_fixture_at(bytes, b"trailing carrier junk", 48);
    // Production relation heads spell physical EOF as None, while the plan
    // records the exact same physical boundary as Some(file length).
    let mut fixed_head = sources[0].clone();
    fixed_head.end = None;
    let mut earlier_head = fixed_head.clone();
    earlier_head.end = Some(47);
    assert!(
        prepare_seven_zip_attempts(&earlier_head, &plan, &[], None).is_err(),
        "an earlier explicit boundary is a different logical head"
    );
    let context =
        prepare_seven_zip_attempts(&fixed_head, &plan, &[], None).unwrap_or_else(|error| match error {
            PreparedStatus::Status(status, message) => panic!("header tails: {status}: {message}"),
            PreparedStatus::ReadFault(fault) => panic!("header tails: {fault:?}"),
        });
    let PasswordContext::Evidence(evidence) = &context else {
        panic!("must prepare alternatives")
    };
    assert!(Arc::ptr_eq(&evidence.plan, &plan));
    assert_eq!(
        evidence.alternatives.len(),
        2,
        "ciphertext damage must not discard the valid public descriptor"
    );
    assert!(evidence.alternatives.iter().all(|(probe, _)| matches!(probe, PasswordContext::SevenZip(SevenZipPasswordContext::Header(_)))));
    let result = context
        .verify(&[
            Arc::from("wrong-first"),
            Arc::from("secret"),
            Arc::from("wrong-last"),
        ], None)
        .unwrap();
    assert_eq!(result.status, "match");
    assert_eq!(result.matched_indices, [1]);
    assert_eq!(result.attempts, 2);
    assert_eq!(result.final_confirmation_required, Some(false));

    let rejected = context
        .verify(&[Arc::from("wrong-first"), Arc::from("wrong-last")], None)
        .unwrap();
    assert_eq!(rejected.status, "no_match");
    assert_eq!(rejected.attempts, 2);

    drop(context);
    // Re-encrypt the same 90-byte decoded Header with "second-tail", using the
    // original descriptor's AES parameters and CBC padding. Both tail choices
    // now pass the Folder CRC but require different passwords.
    let mut second_tail = bytes[48..].to_vec();
    second_tail[..96].copy_from_slice(&[
        4, 6, 32, 112, 150, 66, 22, 66, 250, 215, 201, 115, 139, 95, 113, 56,
        203, 239, 43, 18, 140, 231, 142, 181, 251, 57, 58, 83, 24, 209, 119, 74,
        85, 91, 179, 210, 154, 187, 108, 144, 223, 1, 53, 216, 173, 135, 15, 42,
        243, 192, 203, 246, 173, 0, 247, 134, 123, 4, 146, 241, 108, 146, 109, 103,
        156, 83, 147, 93, 67, 172, 208, 216, 111, 17, 212, 51, 137, 201, 225, 35,
        160, 112, 147, 151, 76, 80, 117, 37, 103, 180, 233, 252, 59, 8, 199, 27,
    ]);
    std::fs::write(&paths[1], second_tail).unwrap();
    let two = prepare_seven_zip_attempts(&fixed_head, &plan, &[], None)
        .unwrap_or_else(|_| panic!("two valid encrypted tails"));
    let PasswordContext::Evidence(two) = two else { panic!("expected two tail choices") };
    let passwords = ["wrong", "secret", "second-tail"].map(Arc::from);
    let first_batch = two.verify_batch(&passwords[..2], false, false).unwrap();
    assert_eq!(first_batch.matched_indices, [1]);
    assert_eq!(first_batch.final_confirmation_required, Some(true));

    let result = two.verify(&passwords).unwrap();
    assert_eq!(result.matched_indices, [1, 2]);
    assert_eq!(result.final_confirmation_required, Some(true));
    let mut domains = crate::password::evidence::CandidateDomains::default();
    domains.append(result.password_domains, 0, 2);
    let (remaining, bound) = domains.finish(&two, 2).unwrap().unwrap();
    let bound = serde_json::to_value(bound).unwrap();
    assert_eq!(remaining.layouts.len(), 2);
    for (index, layout) in remaining.layouts.iter().enumerate() {
        let tail = &remaining.domains[layout.slots[1].domain].choices;
        assert_eq!(tail.len(), 1);
        let (source, expected) = [(1, 1), (2, 0)][index];
        assert_eq!(remaining.sources[tail[0]].path, sources[source].path);
        let group = bound["layout_password_domains"][index].as_u64().unwrap() as usize;
        assert_eq!(bound["password_domains"][group], serde_json::json!([expected]));
    }
    drop(two);
    // Now the encrypted header straddles a variable-length middle and tail.
    // Two physical ciphertexts share the same length; a third length moves the
    // public descriptor and is excluded by its CRC, without a Cartesian scan.
    let mut damaged_middle = bytes[48..80].to_vec();
    damaged_middle[0] ^= 1;
    let mut shifted_middle = bytes[48..80].to_vec();
    shifted_middle.push(0);
    let mut final_tail = bytes[80..].to_vec();
    final_tail.extend_from_slice(b"carrier suffix");
    for (name, data) in [
        ("middle_bad", damaged_middle.as_slice()),
        ("middle_good", &bytes[48..80]),
        ("middle_wrong_length", shifted_middle.as_slice()),
        ("final_tail", final_tail.as_slice()),
    ] {
        let path = crate::test_support::temp_file(name, data);
        sources.push(InputExtent {
            path: path.to_string_lossy().into_owned(),
            start: 0,
            end: Some(data.len() as u64),
        });
        paths.push(path);
    }
    use crate::io::archive_state::{VolumeDomain, VolumeLayout, VolumeSlot};
    Arc::make_mut(&mut plan).sources = sources.clone().into_boxed_slice();
    Arc::make_mut(&mut plan).domains = vec![
        VolumeDomain {
            choices: Arc::new(vec![0]),
        },
        VolumeDomain {
            choices: Arc::new(vec![4, 5, 6]),
        },
        VolumeDomain {
            choices: Arc::new(vec![7]),
        },
    ]
    .into_boxed_slice();
    Arc::make_mut(&mut plan).layouts = vec![VolumeLayout {
        minimum_slots: 2,
        slots: (0..3)
            .map(|index| VolumeSlot {
                number: index as u32 + 1,
                canonical_name: format!("x.{:03}", index + 1),
                domain: index,
            })
            .collect::<Vec<_>>()
            .into_boxed_slice(),
    }]
    .into_boxed_slice();
    let middle = prepare_seven_zip_attempts(&fixed_head, &plan, &[], None)
        .unwrap_or_else(|_| panic!("middle evidence projection"));
    let result = middle
        .verify(&[
            Arc::from("wrong-first"),
            Arc::from("secret"),
            Arc::from("wrong-last"),
        ], None)
        .unwrap();
    assert_eq!(result.matched_index, Some(1));

    drop(middle);
    for path in paths {
        std::fs::remove_file(path).unwrap();
    }
}

fn update_descriptor_crc(bytes: &mut [u8]) {
    let start = 32 + u64::from_le_bytes(bytes[12..20].try_into().unwrap()) as usize;
    let len = (bytes.len() - start) as u64;
    bytes[20..28].copy_from_slice(&len.to_le_bytes());
    let next_crc = crc32fast::hash(&bytes[start..]);
    bytes[28..32].copy_from_slice(&next_crc.to_le_bytes());
    let start_crc = crc32fast::hash(&bytes[12..32]);
    bytes[8..12].copy_from_slice(&start_crc.to_le_bytes());
}
