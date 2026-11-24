use super::*;
use crate::password::rar::rar5_header_decryption_tests::{hex_bytes, PART1_HP_HEX, PART2_HP_HEX, SINGLE_HP_HEX};

#[test]
fn standalone_gzip_reuses_sample_and_extends_long_headers() {
    use std::io::Write;

    for name_len in [8, 2048, 70_000] {
        let mut encoder = flate2::GzBuilder::new()
            .filename(vec![b'a'; name_len])
            .write(Vec::new(), flate2::Compression::fast());
        encoder.write_all(b"sample").unwrap();
        let gzip = encoder.finish().unwrap();
        let path = crate::test_support::temp_file("gzip_anchor_prefix", &gzip);
        let prefix = &gzip[..gzip.len().min(512)];
        if prefix.len() == gzip.len() {
            std::fs::remove_file(&path).unwrap();
        }
        let anchor = probe_volume_anchor_from_head(path.to_str().unwrap(), gzip.len() as u64, prefix);
        assert!(anchor.anchor().is_some_and(|anchor| anchor.standalone && anchor.format == "gzip"));
        if prefix.len() != gzip.len() {
            std::fs::remove_file(&path).unwrap();
        }
    }

    // Empty non-final stored blocks are valid DEFLATE. Delay the first
    // output past both the supplied sample and the old payload probe limit.
    let mut gzip = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];
    gzip.extend([0, 0, 0, 255, 255].repeat(400));
    gzip.extend([1, 1, 0, 254, 255, b'a']);
    gzip.extend(crc32(b"a").to_le_bytes());
    gzip.extend(1u32.to_le_bytes());
    let path = crate::test_support::temp_file("gzip_empty_blocks", &gzip);
    let anchor = probe_volume_anchor_from_head(path.to_str().unwrap(), gzip.len() as u64, &gzip[..512]);
    assert!(anchor.anchor().is_some_and(|anchor| anchor.standalone && anchor.format == "gzip"));
    std::fs::remove_file(path).unwrap();
}

#[test]
fn standalone_xz_and_zstd_detect_open_ends() {
    use std::io::Write;

    let classify = |data: &[u8], format, truncated| {
        let mut anchor = VolumeAnchor {
            size: data.len() as u64,
            ..VolumeAnchor::default()
        };
        probe_standalone_stream(&data[..data.len().min(512)], &mut anchor, |offset, count| {
            let offset = offset as usize;
            Ok(data[offset..offset + count].to_vec())
        });
        assert!(anchor.standalone);
        assert_eq!(anchor.format, format);
        assert_eq!(anchor.has_any(STANDALONE_TRUNCATED), truncated);
    };

    let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 1);
    encoder.write_all(&[b'X'; 4096]).unwrap();
    let xz = encoder.finish().unwrap();
    classify(&xz, "xz", false);
    let mut concatenated = xz.clone();
    concatenated.extend([0; 4]);
    concatenated.extend(&xz[..xz.len() - 4]);
    classify(&concatenated, "xz", true);
    concatenated.extend(&xz[xz.len() - 4..]);
    concatenated.resize(concatenated.len() + 70_000, 0);
    classify(&concatenated, "xz", false);

    let mut zstd = b"\x28\xb5\x2f\xfd\x00\x00".to_vec();
    for last in [0, 1] {
        let header = ((600u32 << 3) | last).to_le_bytes();
        zstd.extend(&header[..3]);
        zstd.extend([b'Z'; 600]);
    }
    classify(&zstd[..zstd.len() - 1], "zstd", true);
    classify(&zstd, "zstd", false);
    let mut concatenated = zstd.clone();
    concatenated.extend(b"\x5f\x2a\x4d\x18\x04\x00\x00\x00meta");
    classify(&concatenated, "zstd", false);
    concatenated.extend(&zstd[..3]);
    classify(&concatenated, "zstd", true);
    concatenated.extend(&zstd[3..]);
    classify(&concatenated, "zstd", false);
}

#[test]
fn bare_mz_does_not_expand_or_authorize_nonleading_archive_probes() {
    let mut seven_zip = SEVEN_ZIP.to_vec();
    seven_zip.extend([0, 4]);
    let mut start = 0u64.to_le_bytes().to_vec();
    start.extend(1u64.to_le_bytes());
    start.extend(crc32(&[1]).to_le_bytes());
    seven_zip.extend(crc32(&start).to_le_bytes());
    seven_zip.extend(start);
    seven_zip.push(1);
    let mut zip_local = ZIP_LOCAL.to_vec();
    zip_local.resize(30, 0);
    zip_local[4..6].copy_from_slice(&20u16.to_le_bytes());
    zip_local[26..28].copy_from_slice(&1u16.to_le_bytes());
    zip_local.push(b'a');
    for archive in [seven_zip, zip_local] {
        for offset in [64, 0x800] {
            let mut bytes = vec![0; 8192];
            bytes[..2].copy_from_slice(b"MZ");
            bytes[offset..offset + archive.len()].copy_from_slice(&archive);
            let path = crate::test_support::temp_file("mz_not_pe_deep_anchor", &bytes);
            let reader = ManagedReader::open(&path).unwrap();
            let anchor = probe_volume_anchor_reader_at_offset(
                &reader, path.to_str().unwrap(), 0, "",
            ).unwrap();
            assert_eq!(anchor.pe_state, PeState::None);
            assert!(anchor.bytes_read <= 512 + crate::formats::zip::EOCD_SEARCH_BYTES);
            assert!(anchor.format.is_empty());
            assert!(!anchor.sfx);
            std::fs::remove_file(path).unwrap();
        }
    }
}

fn rar4_block(kind: u8, flags: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0, 0, kind];
    bytes.extend(flags.to_le_bytes());
    bytes.extend(((7 + body.len()) as u16).to_le_bytes());
    bytes.extend(body);
    let crc = (crc32(&bytes[2..]) & 0xffff) as u16;
    bytes[..2].copy_from_slice(&crc.to_le_bytes());
    bytes
}

#[test]
fn rar4_roles_and_numbering_are_independent_from_exact_identity() {
    for (flags, slot, style) in [
        (0x111, Some(1), RAR_PART_NUMBERING),
        (0x11, None, RAR_PART_NUMBERING),
        (1, None, RAR_OLD_NUMBERING),
    ] {
        let mut bytes = RAR4.to_vec();
        bytes.extend(rar4_block(0x73, flags, &[0; 6]));
        bytes.extend(rar4_block(0x7b, 1, &[]));
        let path = crate::test_support::temp_file("rar4_relation_roles", &bytes);
        let anchor =
            probe_volume_anchor_path_cheap(path.to_str().unwrap());
        assert_eq!(anchor.internal_volume_number, slot);
        assert!(anchor.has_any(style));
        let end = upgrade_relation_rar_end(&anchor);
        assert_eq!(end.relation_has_next, Some(true));
        assert_eq!(end.internal_volume_number, slot);
        assert!(!end.has_any(TERMINAL));
        std::fs::remove_file(path).unwrap();
    }
}

#[test]
fn rar4_legacy_endarc_identity_is_a_bonus_and_cached_once() {
    let mut bytes = RAR4.to_vec();
    bytes.extend(rar4_block(0x73, 0x11, &[0; 6]));
    bytes.extend(rar4_block(0x7b, 8, &2u16.to_le_bytes()));
    let path = crate::test_support::temp_file("rar4_legacy_identity", &bytes);
    let anchor =
        probe_volume_anchor_path_cheap(path.to_str().unwrap());
    assert_eq!(anchor.internal_volume_number, None);
    let upgraded = upgrade_relation_rar_end(&anchor);
    assert_eq!(upgraded.internal_volume_number, Some(3));
    assert_eq!(upgraded.relation_has_next, Some(false));
    assert!(upgraded.has_any(TERMINAL));
    std::fs::remove_file(path).unwrap();
    assert_eq!(
        upgrade_relation_rar_end(&upgraded).bytes_read,
        upgraded.bytes_read
    );
}

#[test]
fn rar_endarc_inside_payload_does_not_create_a_terminal_fact() {
    let mut bytes = RAR4.to_vec();
    bytes.extend(rar4_block(0x73, 0x111, &[0; 6]));
    let fake_end = rar4_block(0x7b, 0, &[]);
    let mut file_body = vec![0; 25];
    file_body[..4].copy_from_slice(&(fake_end.len() as u32).to_le_bytes());
    bytes.extend(rar4_block(0x74, 0x8002, &file_body));
    bytes.extend(fake_end);
    bytes.extend(rar4_block(0x7b, 1, &[]));
    bytes.extend(vec![0; 2048]); // Carriers may have trailing junk.
    let path = crate::test_support::temp_file("rar_payload_fake_end", &bytes);
    let anchor =
        probe_volume_anchor_path_cheap(path.to_str().unwrap());
    let upgraded = upgrade_relation_rar_end(&anchor);
    assert_eq!(upgraded.relation_has_next, Some(true));
    assert!(!upgraded.has_any(TERMINAL));
    assert!(upgraded.bytes_read < 700);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn rar_terminal_walk_is_bounded_by_file_spans_not_entry_count() {
    let mut bytes = RAR4.to_vec();
    bytes.extend(rar4_block(0x73, 0x111, &[0; 6]));
    let mut file_body = vec![0; 25];
    file_body[8] = 2; // Windows host.
    file_body[17] = 20; // Unpack version.
    file_body[18] = 0x30; // Stored empty file.
    file_body[19..21].copy_from_slice(&1u16.to_le_bytes());
    file_body.push(b'a');
    let block = rar4_block(0x74, 0x8000, &file_body);
    for _ in 0..4100 {
        bytes.extend(&block);
    }
    bytes.extend(rar4_block(0x7b, 0, &[]));
    let path = crate::test_support::temp_file("rar_many_headers", &bytes);
    let anchor =
        probe_volume_anchor_path_cheap(path.to_str().unwrap());
    let upgraded = upgrade_relation_rar_end(&anchor);
    assert_eq!(upgraded.relation_has_next, Some(false));
    assert!(upgraded.has_any(TERMINAL));
    assert!(upgraded.error.is_empty());
    std::fs::remove_file(path).unwrap();
}

#[test]
fn zip64_disk_identity_upgrades_only_overflowed_classic_fields() {
    let mut tail = b"PK\x06\x06".to_vec();
    tail.extend(44u64.to_le_bytes());
    tail.extend([0; 4]);
    tail.extend(70000u32.to_le_bytes());
    tail.extend(69999u32.to_le_bytes());
    tail.extend([0; 32]);
    tail.extend(b"PK\x06\x07");
    tail.extend(70000u32.to_le_bytes());
    tail.extend(0u64.to_le_bytes());
    tail.extend(70001u32.to_le_bytes());
    tail.extend(b"PK\x05\x06");
    tail.extend(0xffffu16.to_le_bytes());
    tail.extend(0xffffu16.to_le_bytes());
    tail.extend([0; 14]);
    let path = crate::test_support::temp_file("zip64_terminal", &tail);
    let anchor =
        probe_volume_anchor_path_cheap(path.to_str().unwrap());
    let upgraded = upgrade_relation_zip_tail(&anchor);
    assert_eq!(upgraded.internal_volume_number, Some(70001));
    assert!(upgraded.has_any(ZIP_SPLIT_END));
    assert!(upgraded.bytes_read <= 512 + tail.len() as u64);
    std::fs::remove_file(path).unwrap();
    // Invalid ZIP64 bytes must not matter when classic identity is valid.
    let mut classic = b"PK\x05\x06".to_vec();
    classic.extend(4u16.to_le_bytes());
    classic.extend(3u16.to_le_bytes());
    classic.extend([0; 14]);
    let mut out = VolumeAnchor::default();
    assert!(probe_zip(&[], &classic, 0, &mut out));
    assert_eq!(out.internal_volume_number, Some(5));
}

#[test]
fn rar4_main_header_requires_its_stored_crc() {
    let mut header = vec![0u8; 13];
    header[2] = 0x73;
    header[3..5].copy_from_slice(&0x0101u16.to_le_bytes());
    let header_len = header.len() as u16;
    header[5..7].copy_from_slice(&header_len.to_le_bytes());
    let stored = (crc32(&header[2..]) & 0xffff) as u16;
    header[..2].copy_from_slice(&stored.to_le_bytes());

    assert_eq!(rar4_main_flags(&header, 0), Some(0x0101));

    header[8] ^= 0x01;
    assert_eq!(rar4_main_flags(&header, 0), None);
}


fn probe_encrypted_rar(prefix: &[u8], password: Option<&str>) -> VolumeAnchor {
    let reader = ManagedReader::from_bytes(prefix.to_vec(), Default::default());
    let anchor = probe_volume_anchor_reader_at_offset(&reader, "", 0, "rar").unwrap();
    if let Some(password) = password {
        resolve_encrypted_relation_anchor(&anchor, &reader, &[Arc::from(password)], false, None)
            .unwrap()
            .0
    } else {
        anchor
    }
}

#[test]
fn encrypted_single_rar_without_password_is_not_multivolume() {
    let prefix = hex_bytes(SINGLE_HP_HEX);
    let anchor = probe_encrypted_rar(&prefix, None);
    assert!(anchor.encrypted);
    assert!(anchor.needs_password);
    assert!(!anchor.wrong_password);
    assert!(
        !anchor.multivolume,
        "encrypted headers must not force multivolume"
    );
    assert!(!anchor.standalone);
    assert!(anchor.has_any(RAR_VERSION_5));
}

#[test]
fn encrypted_single_rar_with_correct_password_is_standalone() {
    let prefix = hex_bytes(SINGLE_HP_HEX);
    let anchor = probe_encrypted_rar(&prefix, Some("secret"));
    assert!(anchor.standalone);
    assert!(!anchor.multivolume);
    assert!(!anchor.needs_password);
}

#[test]
fn encrypted_single_rar_with_wrong_password_reports_wrong_password() {
    let prefix = hex_bytes(SINGLE_HP_HEX);
    let anchor = probe_encrypted_rar(&prefix, Some("wrong"));
    assert!(anchor.encrypted);
    assert!(anchor.needs_password);
    assert!(anchor.wrong_password);
    assert!(!anchor.multivolume);
    assert!(!anchor.standalone);
}

#[test]
fn encrypted_split_rar_uses_decrypted_volume_numbers() {
    let first = hex_bytes(PART1_HP_HEX);
    let second = hex_bytes(PART2_HP_HEX);
    let first_anchor = probe_encrypted_rar(&first, Some("secret"));
    assert!(first_anchor.multivolume);
    assert_eq!(first_anchor.internal_volume_number, Some(1));
    assert!(first_anchor.has_any(FIRST));

    let second_anchor = probe_encrypted_rar(&second, Some("secret"));
    assert!(second_anchor.multivolume);
    assert_eq!(second_anchor.internal_volume_number, Some(2));
    assert!(second_anchor.has_any(MEMBER));
}
