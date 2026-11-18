use aes::cipher::{block_padding::NoPadding, KeyIvInit};
use super::*;
use crate::analysis_native::volume_anchor::{
    probe_volume_anchor_reader_at_offset, resolve_encrypted_relation_anchor,
};
use crate::io::archive_state::{VolumeAttemptPlan, VolumeDomain, VolumeLayout, VolumeSlot};
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
    let path = crate::test_support::temp_file("rar4_hp_carrier", &data);
    let range = InputExtent {
        path: path.to_string_lossy().into_owned(), start: 37, end: Some(data.len() as u64),
    };
    let ranges = parse_ranges(std::iter::once(&range), &[]).unwrap();
    let context = prepare_rar_ranges(&ranges).unwrap_or_else(|_| panic!("encrypted RAR4 carrier"));
    let mut proof = None;
    assert_eq!(context.verify(&passwords, Some(&mut proof)).unwrap().matched_index, Some(0));
    assert!(matches!(proof, Some(RarProvenKey::Rar4 { .. })));
    assert!(matches!(probe_header_passwords(&reader, 37, &passwords, true, proof.as_ref()).unwrap(),
        HeaderPassword::Matched(0, RarTerminalProof { terminal: Some(_), .. })));
    drop(context);
    drop(ranges);
    std::fs::remove_file(path).unwrap();

    // A second genuine header has a separate salt and can confirm a weak
    // initial hit. A single ENDARC or corrupted successor stays weak.
    let next_salt = [0xb8; 8];
    let (key2, iv2) = derive_rar3_key_iv("secret", Some(&next_salt)).unwrap();
    let seal = |mut header: Vec<u8>, key: [u8; 16], iv: [u8; 16]| {
        let size = header.len().next_multiple_of(16);
        header.resize(size, 0);
        cbc::Encryptor::<Aes128>::new(&key.into(), &iv.into())
            .encrypt_padded::<NoPadding>(&mut header, size).unwrap();
        header
    };
    let mut two_headers = data[37..offset as usize].to_vec();
    two_headers.extend(salt);
    two_headers.extend(seal(rar4_block(0x75, 0, &[]), key, iv));
    two_headers.extend(next_salt);
    two_headers.extend(seal(rar4_block(0x7b, 0, &[]), key2, iv2));
    let verify = |bytes: Vec<u8>| {
        let reader = ManagedReader::from_bytes(bytes, Default::default());
        prepare_rar_ranges(&[RangeSpec::entire(&reader)]).unwrap_or_else(|_| panic!("RAR4 header proof"))
            .verify(&passwords, None).unwrap()
    };
    assert_eq!(verify(two_headers.clone()).final_confirmation_required, Some(false));
    *two_headers.last_mut().unwrap() ^= 1;
    assert_eq!(verify(two_headers).final_confirmation_required, Some(true));

    let mut comment = rar4_block(0x75, 0, &[0, 0, 0, 0, 0, 0]);
    let mut file_header = rar4_block(0x74, 0x8000 | RAR4_FILE_COMMENT, &[0; 25]);
    let header_size = (file_header.len() + comment.len()) as u16;
    file_header[5..7].copy_from_slice(&header_size.to_le_bytes());
    let header_crc = crc32(&file_header[2..]) as u16;
    file_header[..2].copy_from_slice(&header_crc.to_le_bytes());
    file_header.append(&mut comment);
    let mut commented = data[37..offset as usize].to_vec();
    commented.extend(salt);
    commented.extend(seal(file_header, key, iv));
    let result = verify(commented);
    assert_eq!((result.matched_index, result.final_confirmation_required), (Some(0), Some(true)));

    // A short encrypted header at the end of the first byte-split part is
    // useful even when every undecided tail is unavailable.
    let split_head = [RAR4_SIGNATURE, &rar4_block(0x73, RAR4_MAIN_HEADER_PASSWORD, &[0; 6]), &data[offset as usize..]].concat();
    let head = crate::test_support::temp_file("rar4_split_short_header", &split_head);
    let mut sources = vec![InputExtent {
        path: head.to_string_lossy().into_owned(), start: 0, end: Some(split_head.len() as u64),
    }];
    for length in [17, 71] {
        sources.push(InputExtent {
            path: head.with_extension(format!("missing-{length}")).to_string_lossy().into_owned(),
            start: 0, end: Some(length),
        });
    }
    let slot = |number, domain| VolumeSlot { number, canonical_name: format!("part.{number}"), domain };
    let plan = VolumeAttemptPlan {
        sources: sources.into_boxed_slice(),
        layouts: vec![VolumeLayout { minimum_slots: 0, slots: vec![slot(1, 0), slot(2, 1)].into_boxed_slice() }].into_boxed_slice(),
        domains: [vec![0], vec![1, 2]].into_iter().map(|choices| VolumeDomain { choices: Arc::new(choices) }).collect(),
        head_size_from_total: None, minimum_size: None, tail_totals: Box::default(),
    };
    let result = rar_fast_verify_passwords_from_attempts(&mut Preparation::default(), &plan.sources[0],
        &plan, &parallel, &[], false).unwrap();
    assert_eq!((result.matched_indices.as_slice(), result.final_confirmation_required), (&[2, 3][..], Some(true)), "{}", result.message);
    std::fs::remove_file(head).unwrap();

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

    // A large unrelated member after this encrypted header must not enter
    // preparation or be retained for the password batch.
    let mut large = data.clone();
    large.resize(4 * 1024 * 1024, 0x65);
    let bounded = ManagedReader::from_bytes(large, Default::default());
    let context = prepare_rar_ranges(&[RangeSpec::entire(&bounded)]).unwrap_or_else(|_| panic!("no-check header proof"));
    let match_result = context.verify(&parallel, None).unwrap();
    assert_eq!(match_result.matched_index, Some(2));
    assert_eq!(match_result.final_confirmation_required, Some(false));
    assert_eq!(match_result.match_evidence, Some("rar5_header_crc32"));
    assert!(bounded.stats().read_bytes < 4096, "{}", bounded.stats().read_bytes);

    // An uncertain raw split must not project the next disk merely to
    // prepare an encrypted header. Its first block can complete a short CRC.
    let start = data.len() - len;
    let projected = |archive: &[u8]| {
        prepare_rar(|offset, size, _| {
            let start = offset as usize;
            assert!(start + size <= archive.len());
            Ok(archive[start..start + size].to_vec())
        }).unwrap_or_else(|_| panic!("encrypted header prefix"))
            .verify(&parallel, None).unwrap()
    };
    let long = projected(&data[..start + 16]);
    assert_eq!((long.matched_index, long.final_confirmation_required), (Some(2), Some(true)));
    let mut short = rar5_block(&[1, 0, 0]);
    short.resize(16, 0);
    cbc::Encryptor::<Aes256>::new(&key.into(), &iv.into())
        .encrypt_padded::<NoPadding>(&mut short, 16).unwrap();
    let mut first_disk = data[..start].to_vec();
    first_disk.extend(short);
    let short = projected(&first_disk);
    assert_eq!((short.matched_index, short.final_confirmation_required), (Some(2), Some(false)));

    // The normal attempt dispatcher resolves a first cipher block split
    // between two disks, while both unrelated tail choices are absent.
    let split = first_disk.len() - 5;
    let paths = [crate::test_support::temp_file("rar5_split_head", &first_disk[..split]),
        crate::test_support::temp_file("rar5_split_ciphertext", &first_disk[split..])];
    let mut sources: Vec<_> = paths.iter().map(|path| InputExtent {
        path: path.to_string_lossy().into_owned(), start: 0, end: Some(path.metadata().unwrap().len()),
    }).collect();
    for len in [17, 431] {
        sources.push(InputExtent { path: paths[0].with_extension(format!("missing-{len}")).to_string_lossy().into_owned(),
            start: 0, end: Some(len) });
    }
    let plan = VolumeAttemptPlan {
        sources: sources.into_boxed_slice(),
        layouts: vec![VolumeLayout { minimum_slots: 0, slots: (0..3).map(|i| VolumeSlot {
            number: 1 + i as u32, canonical_name: format!("part.{i}"), domain: i,
        }).collect() }].into_boxed_slice(),
        domains: [vec![0], vec![1], vec![2, 3]].into_iter().map(|choices| VolumeDomain { choices: Arc::new(choices) }).collect(),
        head_size_from_total: None, minimum_size: None, tail_totals: Box::default(),
    };
    let result = rar_fast_verify_passwords_from_attempts(&mut Preparation::default(), &plan.sources[0],
        &plan, &parallel, &[], false).unwrap();
    assert_eq!((result.matched_index, result.final_confirmation_required), (Some(2), Some(false)), "{}", result.message);
    for path in paths { std::fs::remove_file(path).unwrap(); }

    // Only the active projection knows the remainder of this encrypted
    // main header. Both possible sources share those bytes and have
    // distinct outside padding, which must never enter the CRC proof.
    let paths = [
        crate::test_support::temp_file("rar5_active_prefix", &data[..start + 16]),
        crate::test_support::temp_file("rar5_active_body_a", &[&data[start + 16..], &[0x5a]].concat()),
        crate::test_support::temp_file("rar5_active_body_b", &[&data[start + 16..], &[0xa5]].concat()),
    ];
    let sources: Vec<_> = paths.iter().map(|path| InputExtent { path: path.to_string_lossy().into_owned(),
        start: 0, end: Some(path.metadata().unwrap().len()) }).collect();
    let cut = VolumeAttemptPlan {
        sources: sources.into_boxed_slice(),
        layouts: vec![VolumeLayout { minimum_slots: 0, slots: (0..2).map(|i| VolumeSlot {
            number: i as u32 + 1, canonical_name: format!("part.{}", i + 1), domain: i,
        }).collect() }].into_boxed_slice(),
        domains: [vec![0], vec![1, 2]].into_iter().map(|choices| VolumeDomain { choices: Arc::new(choices) }).collect(),
        head_size_from_total: None, minimum_size: None, tail_totals: Box::default(),
    };
    let result = rar_fast_verify_passwords_from_attempts(&mut Preparation::default(), &cut.sources[0],
        &cut, &parallel, &[], false).unwrap();
    assert_eq!((result.matched_index, result.final_confirmation_required), (Some(2), Some(false)), "{}", result.message);
    for path in paths { std::fs::remove_file(path).unwrap(); }

    data.truncate(300);
    let reader = ManagedReader::from_bytes(data, Default::default());
    let anchor = probe_volume_anchor_reader_at_offset(&reader, "", 0, "rar").unwrap();
    let (anchor, matched) = resolve_encrypted_relation_anchor(&anchor, &reader, &passwords, true, None).unwrap();
    assert!(matched.is_none() && anchor.needs_password);
    assert!(!anchor.wrong_password);
}

// Real fixtures normally carry the optional quick check. This exercises the
// no-check compressed stream path and the boundaries that prohibit using it.
#[test]
fn rar5_no_check_stream_prefix_is_weak_and_requires_a_real_start() {
    let salt = [0x41; 16];
    let iv = [0x62; 16];
    let mut key = [0; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(b"secret", &salt, 16, &mut key);
    let encrypt = |block: &mut [u8]| {
        let size = block.len();
        cbc::Encryptor::<Aes256>::new(&key.into(), &iv.into())
            .encrypt_padded::<NoPadding>(block, size).unwrap();
    };
    let mut block = [0u8; 16];
    block[0] = 0x40;
    block[1] = 0x1a; // Legal empty final block, reusing solid tables.
    encrypt(&mut block);
    let make = |split: bool, method: u64, version: u64, block: &[u8]| {
        let mut encryption = vec![1, 0, 0, 4]; // extra type, version, flags, KDF log
        encryption.extend(salt); encryption.extend(iv);
        let mut extra = vint(encryption.len() as u64); extra.extend(encryption);
        let mut file = vec![2, 3 | if split { 8 } else { 0 }];
        file.extend(vint(extra.len() as u64)); file.extend(vint(block.len() as u64));
        file.extend([0, 0, 0]); // file flags, unpack size, attributes
        file.extend(vint(method << 7 | 0x40 | version)); // solid
        file.extend([0, 1, b'x']); file.extend(extra);
        let mut bytes = RAR5_SIGNATURE.to_vec();
        bytes.extend(rar5_block(&[1,0,0])); bytes.extend(rar5_block(&file));
        bytes.extend(block); bytes.extend(rar5_block(&[5,0,0])); bytes
    };
    let prepare = |bytes: Vec<u8>| {
        let reader = ManagedReader::from_bytes(bytes, Default::default());
        prepare_rar(|offset, size, _| Ok(reader.read_at(offset, size).unwrap()))
    };
    let context = prepare(make(false, 1, 0, &block)).unwrap_or_else(|_| panic!("compressed first block"));
    let candidates = [Arc::from("wrong"), Arc::from("secret"), Arc::from("secret")];
    let result = context.verify(&candidates, None).unwrap();
    assert_eq!(result.matched_indices, [1, 2]);
    assert_eq!(result.final_confirmation_required, Some(true));
    assert_eq!(result.match_evidence, Some("rar5_compressed_block"));
    // A missing middle disk and a stored first member do not make a
    // later independent RAR7-compatible compressed member unreadable.
    let volumes = VolumeSet::new([make(false, 0, 0, &block), make(false, 1, 1, &block)].into_iter().enumerate().map(|(i, data)|
        crate::password::input::VolumeSpec { reader: ManagedReader::from_bytes(data, Default::default()),
            number: 1 + (2 * i) as u32, start: 0, end: None }).collect());
    let later = prepare_rar_volumes(&volumes, true).unwrap_or_else(|_| panic!("independent later member"));
    assert_eq!(later.verify(&candidates, None).unwrap().matched_indices, [1, 2]);
    let plain_first = [RAR5_SIGNATURE, &rar5_block(&[1, 0, 1]), &rar5_block(&[5, 0, 1])].concat();
    assert!(matches!(prepare(plain_first), Err(PreparedStatus::Status("unknown_needs_final_verifier", _))));
    for (split, method) in [(true, 1), (false, 0)] {
        assert!(matches!(prepare(make(split, method, 0, &block)), Err(PreparedStatus::Status("unknown_needs_final_verifier", _))));
    }

    let mut plaintext = [0u8; 64];
    plaintext[..3].copy_from_slice(&[0x07, 0x5a ^ 7 ^ 44, 44]);
    // The next header starts at byte 47, crossing two CBC blocks. It
    // requires the preceding ciphertext but no intervening decompression.
    plaintext[47..50].copy_from_slice(&[0x40, 0x1a, 0]);
    let mut valid = plaintext;
    encrypt(&mut valid);
    let reader = ManagedReader::from_bytes(make(false, 1, 0, &valid), Default::default());
    let context = prepare_rar_ranges(&[RangeSpec::entire(&reader)]).unwrap_or_else(|_| panic!("second block"));
    assert_eq!(context.verify(&candidates, None).unwrap().matched_indices, [1, 2]);

    plaintext[48] ^= 1;
    encrypt(&mut plaintext);
    let archive = make(false, 1, 0, &plaintext);
    let reader = ManagedReader::from_bytes(archive.clone(), Default::default());
    let context = prepare_rar_ranges(&[RangeSpec::entire(&reader)]).unwrap_or_else(|_| panic!("invalid second block"));
    assert_eq!(context.verify(&candidates, None).unwrap().status, "no_match");
    // Missing optional follow-up evidence preserves the first-block survivors.
    assert_eq!(prepare(archive).unwrap_or_else(|_| panic!("available first block"))
        .verify(&candidates, None).unwrap().matched_indices, [1, 2]);
}

#[test]
fn rar5_packed_blake2sp_prunes_only_complete_nonfinal_fragments() {
    // BLAKE2sp tree digest for this payload, independently generated with
    // eight BLAKE2s leaves and one root. The payload spans two read buffers.
    let mut packed: Vec<_> = (0..66000).map(|i| ((i ^ (i >> 8)) * 17) as u8).collect();
    let hash = [
        0xa3, 0xc4, 0x37, 0xe2, 0x7e, 0xc1, 0x59, 0x36, 0x99, 0x8c, 0x98, 0xf8, 0x6f, 0xe3, 0x43, 0x83,
        0x1e, 0x29, 0xa2, 0x40, 0x01, 0xe1, 0x5f, 0x16, 0x92, 0xb3, 0xf7, 0x36, 0x2d, 0xfe, 0x94, 0xa6,
    ];
    let volume = |number: u8, split: u8, bytes: &[u8]| {
        let mut extra = vec![34, 2, 0];
        extra.extend(hash);
        let mut member = vec![2, 3 | split];
        member.extend(vint(extra.len() as u64));
        member.extend(vint(66000));
        member.extend([0, 0, 0, 0, 0, 1, b'x']);
        member.extend(extra);
        let main = if number == 0 { rar5_block(&[1, 0, 1]) } else { rar5_block(&[1, 0, 3, number]) };
        [RAR5_SIGNATURE, &main, &rar5_block(&member), bytes,
            &rar5_block(&[5, 0, u8::from(split & 16 != 0)])].concat()
    };
    let good = volume(1, 24, &packed);
    packed[65999] ^= 1;
    let damaged = volume(1, 24, &packed);
    let tail = volume(2, 8, &packed);
    let head = volume(0, 16, &packed);
    let paths: Vec<_> = [head, damaged, good, tail].into_iter().enumerate().map(|(i, bytes)|
        crate::test_support::temp_file(&format!("rar5_blake_{i}"), &bytes)).collect();
    let plan = VolumeAttemptPlan {
        sources: paths.iter().map(|path| InputExtent { path: path.to_string_lossy().into_owned(),
            start: 0, end: Some(path.metadata().unwrap().len()) }).collect(),
        layouts: vec![VolumeLayout { minimum_slots: 0, slots: (0..3).map(|i| VolumeSlot {
            number: i as u32 + 1, canonical_name: format!("part.{}", i + 1), domain: i,
        }).collect() }].into_boxed_slice(),
        domains: [vec![0], vec![1, 2], vec![3]].into_iter().map(|choices| VolumeDomain { choices: Arc::new(choices) }).collect(),
        head_size_from_total: None, minimum_size: None, tail_totals: Box::default(),
    };
    let result = rar_fast_verify_passwords_from_attempts(&mut Preparation::default(), &plan.sources[0],
        &plan, &[Arc::from("secret")], &[], true).unwrap();
    let remaining = result.volume_attempts.unwrap();
    assert!(remaining.sources.contains(&plan.sources[2]));
    assert!(remaining.sources.contains(&plan.sources[3]));
    assert!(!remaining.sources.contains(&plan.sources[1]));
    for path in paths { std::fs::remove_file(path).unwrap(); }
}
