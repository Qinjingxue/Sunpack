use super::*;
use crate::test_support::temp_file;
use bzip2::write::BzEncoder;
use bzip2::Compression as BzCompression;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::fs;
use std::io::Write;
use xz2::write::XzEncoder;

// Ordinary complete ZIPs cannot expose a negative proof hiding a split
// EOCD rejected by standalone validation, especially at a read boundary.
#[test]
fn zip_terminal_absence_preserves_split_headers_and_chunk_edges() {
    for terminal in [false, true] {
        let mut data = vec![b'x'; 128 * 1024];
        let mut local = [0u8; 31];
        local[..4].copy_from_slice(ZIP_LOCAL);
        local[4] = 20;
        local[26] = 1;
        local[30] = b'a';
        data[37..68].copy_from_slice(&local);
        if terminal {
            let offset = 64 * 1024 - 2;
            data[offset..offset + 4].copy_from_slice(ZIP_EOCD);
            data[offset + 4..offset + 22].fill(0);
            data[offset + 4] = 1; // Multi-disk EOCD is not standalone.
        }
        let path = temp_file("zip_terminal_proof", &data);
        let scan = scan_embedded_archives_native_with_iocp(
            ManagedReader::open(&path).unwrap(),
            64 * 1024,
            2,
            2,
        )
        .unwrap();
        let anchors = scan.relation_anchors();
        assert!(!anchors.is_empty());
        assert_eq!(scan.zip_eocd_absent, !terminal);
        assert!(anchors
            .iter()
            .all(|a| a.has_any(ZIP_CARRIER_CHECKED) == !terminal));
        let _ = fs::remove_file(path);
    }
}

fn stored_hits(hits: &[RawHit]) -> hit_storage::HitStorage {
    hit_storage::HitStorage::from_hits(hits)
}

#[test]
fn packed_sample_keeps_tar_lookbehind_at_high_offsets() {
    let mut tar = vec![0u8; 32];
    tar[..TAR_USTAR.len()].copy_from_slice(TAR_USTAR);
    for base in [4096, 1 << 32, u64::MAX - 1024] {
        assert_eq!(scan_sample(&tar, 0, base), [RawHit::new(base - 257, 9)]);
    }
}

// Ordinary valid-stream fixtures do not cover tail facts shared by many
// earlier false headers, or unrelated footer reads after a conclusive match.
#[test]
fn xz_footer_evidence_preserves_false_headers_peers_and_lazy_io() {
    use crate::io::reader::ReaderConfig;
    let mut encoder = XzEncoder::new(Vec::new(), 1);
    encoder.write_all(b"xz payload").unwrap();
    let stream = encoder.finish().unwrap();
    let mut data = b"carrier-prefix".to_vec();
    for variant in 0..4 {
        data.extend_from_slice(&stream[..12]);
        data.extend_from_slice(b"broken stream contents");
        let mut footer = stream[stream.len() - 12..].to_vec();
        match variant {
            0 => footer[0] ^= 1,
            1 => footer[8] = 1,
            2 => footer[9] = 2,
            _ => footer[4..8].fill(0),
        }
        if variant != 0 {
            let checksum = crc32(&footer[4..10]);
            footer[..4].copy_from_slice(&checksum.to_le_bytes());
        }
        data.extend_from_slice(&footer);
        data.extend_from_slice(b"invalid gap");
    }
    let mut expected = Vec::new();
    for _ in 0..2 {
        expected.push(data.len() as u64);
        data.extend_from_slice(&stream);
        data.extend_from_slice(b"peer separator");
    }
    let mut hits = scan_sample(&data, 0, 0);
    let mut ends = hits
        .iter()
        .filter(|hit| hit.kind() == "xz_footer")
        .cloned()
        .collect::<Vec<_>>();
    ends.sort_unstable_by_key(|hit| hit.offset());
    hits.retain(|hit| hit.kind() != "xz_footer");
    hits.sort_unstable_by_key(|hit| hit.offset());
    let source = ManagedReader::from_bytes(data, ReaderConfig::default());
    let candidates = validate_raw_hits(
        &source,
        source.len(),
        stored_hits(&hits).view(0),
        stored_hits(&ends).view(0),
    )
    .unwrap();
    assert_eq!(
        candidates
            .iter()
            .map(|item| item.offset)
            .collect::<Vec<_>>(),
        expected
    );
    assert!(candidates.iter().all(|item| item.end_offset.is_some()));

    let mut data = stream.clone();
    data.extend_from_slice(b"unrelated tail");
    for _ in 0..100 {
        data.extend_from_slice(b"bad footerYZ");
    }
    let hits = scan_sample(&data, 0, 0);
    let mut ends = hits
        .iter()
        .filter(|hit| hit.kind() == "xz_footer")
        .cloned()
        .collect::<Vec<_>>();
    ends.sort_unstable_by_key(|hit| hit.offset());
    let source = ManagedReader::from_bytes(
        data,
        ReaderConfig {
            ..ReaderConfig::default()
        },
    );
    let ends = stored_hits(&ends);
    let mut facts = XzFooterEvidence {
        ends: ends.view(0),
        next_unchecked: 0,
        valid: BTreeMap::new(),
    };
    let matched = validate_xz(&source, source.len(), 0, &mut facts)
        .unwrap()
        .unwrap();
    assert_eq!(matched.end_offset, Some(stream.len() as u64));
}

// Ordinary LZ4 fixtures cannot catch failed-suffix ownership hiding a real
// archive in skipped payload, or carving a valid long concatenation twice.
#[test]
fn lz4_suffixes_keep_payload_roots_and_own_long_concatenations() {
    use crate::io::reader::ReaderConfig;
    let empty = b"\x04\x22\x4d\x18\x60\x40\x82\0\0\0\0";
    let mut data = b"carrier".to_vec();
    let root = data.len() as u64;
    data.extend_from_slice(&empty.repeat(1024));
    data.extend_from_slice(&empty[..7]);
    data.extend_from_slice(&(0x80000000 | empty.len() as u32).to_le_bytes());
    let inner = data.len() as u64;
    data.extend_from_slice(empty);
    data.extend_from_slice(&[0; 4]);
    data.extend_from_slice(b"\x04\x22");

    let budget_data = empty.repeat(65_537);
    let budget_end = budget_data.len() as u64;
    for (data, root, inner, inner_end) in [
        (data, root, inner, inner + empty.len() as u64),
        (budget_data, 0, empty.len() as u64, budget_end),
    ] {
        let mut hits = scan_sample(&data, 0, 0);
        hits.sort_unstable_by_key(|hit| hit.offset());
        let source = ManagedReader::from_bytes(
            data.clone(),
            ReaderConfig {
                ..Default::default()
            },
        );
        let candidates = validate_raw_hits(
            &source,
            source.len(),
            stored_hits(&hits).view(0),
            stored_hits(&[]).view(0),
        )
        .unwrap();
        assert_eq!(candidates.len(), 1);
        if root == 0 {
            assert_eq!(candidates[0].offset, root);
            assert_eq!(candidates[0].end_offset, Some(inner_end));
        } else {
            assert_eq!(candidates[0].offset, inner);
            assert_eq!(candidates[0].end_offset, Some(inner_end));
        }
        assert!(source.stats().read_bytes <= data.len() as u64 * 3);
    }
}

// Ordinary peers do not exercise future roots discovered by an earlier
// false header, or the finite reader budget consumed by corrupt indexes.
#[test]
fn xz_index_evidence_keeps_future_roots_under_read_budget_and_propagates_io() {
    use crate::io::reader::ReaderConfig;
    let mut encoder = XzEncoder::new(Vec::new(), 1);
    encoder.write_all(b"future xz root").unwrap();
    let stream = encoder.finish().unwrap();
    let mut data = b"carrier-prefix".to_vec();
    let mut footer = 1u32.to_le_bytes().to_vec();
    footer.extend_from_slice(&stream[6..8]);
    for _ in 0..64 {
        data.extend_from_slice(&stream[..12]);
        data.extend_from_slice(&[0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]);
        data.extend_from_slice(&crc32(&footer).to_le_bytes());
        data.extend_from_slice(&footer);
        data.extend_from_slice(b"YZ");
    }
    let mut expected = Vec::new();
    for gap in [&[0; 8][..], &b"independent peer"[..], &[][..]] {
        expected.push((data.len() as u64, (data.len() + stream.len()) as u64));
        data.extend_from_slice(&stream);
        data.extend_from_slice(gap);
    }
    // Aligned zero padding joins the first two streams. The nonzero gap
    // still leaves the third as an independent archive under the same budget.
    let expected = vec![(expected[0].0, expected[1].1), expected[2]];
    let mut hits = scan_sample(&data, 0, 0);
    let mut ends = hits
        .iter()
        .filter(|hit| hit.kind() == "xz_footer")
        .cloned()
        .collect::<Vec<_>>();
    ends.sort_unstable_by_key(|hit| hit.offset());
    hits.retain(|hit| hit.kind() != "xz_footer");
    hits.sort_unstable_by_key(|hit| hit.offset());
    let source = ManagedReader::from_bytes(
        data,
        ReaderConfig {
            ..ReaderConfig::default()
        },
    );
    let candidates = validate_raw_hits(
        &source,
        source.len(),
        stored_hits(&hits).view(0),
        stored_hits(&ends).view(0),
    )
    .unwrap();
    assert_eq!(
        candidates
            .iter()
            .map(|item| (item.offset, item.end_offset.unwrap()))
            .collect::<Vec<_>>(),
        expected
    );
}

// Equal starts, crossing/removed ranges, anchors and zero-width endpoints
// are independent of stream parsing. Check the strict interval semantics.
#[test]
fn linear_candidate_resolution_preserves_strict_interval_ownership() {
    for shift in 0..8 {
        let mut inputs = (0..192u64)
            .map(|i| {
                let offset = i / 3;
                let end = (i % 7 != 0).then_some(offset + (i * 17 + shift) % 21);
                let kind = if i % 5 == 0 || end.is_none() {
                    CandidateKind::Anchor
                } else {
                    CandidateKind::Archive
                };
                candidate("zip", offset, end, kind)
            })
            .collect::<Vec<_>>();
        let project =
            |item: &EmbeddedCandidate| (item.offset, item.end_offset, item.kind);
        let expected = inputs
            .iter()
            .filter(|item| {
                !inputs.iter().any(|owner| {
                    owner.is_logical_archive()
                        && owner
                            .end_offset
                            .is_some_and(|end| owner.offset < item.offset && item.offset < end)
                })
            })
            .map(project)
            .collect::<Vec<_>>();
        resolve_logical_candidates(&mut inputs);
        assert_eq!(inputs.iter().map(project).collect::<Vec<_>>(), expected);
    }
}
fn reference_raw_hits(data: &[u8]) -> Vec<RawHit> {
    // Compare matcher enumeration independently; both paths must apply the
    // same canonical fixed-header policy to each signature.
    let mut hits = new_hit_batch(0, 0, data.len());
    for matched in embedded_matcher().find_overlapping_iter(data) {
        record_raw_hit(
            &mut hits,
            data,
            0,
            0,
            matched.pattern().as_usize(),
            matched.start(),
            matched.end(),
        );
    }
    let mut results = hits.results.iter().collect::<Vec<_>>();
    results.sort_unstable_by_key(|hit| (hit.offset(), hit.hit_name()));
    results
}

fn optimized_raw_hits(data: &[u8]) -> Vec<RawHit> {
    let mut hits = scan_sample(data, 0, 0);
    hits.retain(|hit| hit.kind() != "xz_footer");
    hits.sort_unstable_by_key(|hit| (hit.offset(), hit.hit_name()));
    hits
}

#[test]
fn simd_scan_matches_reference_with_footers_and_carry_boundaries() {
    let mut data = vec![0x55; 64 + PATTERNS.len() * 19];
    for (index, (magic, _, _)) in PATTERNS.iter().enumerate() {
        let start = 41 + index * 19;
        data[start..start + magic.len()].copy_from_slice(magic);
    }
    let mut footer = [0u8; 12];
    footer[4..8].copy_from_slice(&1u32.to_le_bytes());
    footer[10..12].copy_from_slice(XZ_FOOTER_MAGIC);
    let checksum = crc32(&footer[4..10]);
    footer[..4].copy_from_slice(&checksum.to_le_bytes());
    data[21..33].copy_from_slice(&footer);
    data[213..225].copy_from_slice(&footer);

    for length in 0..=data.len() {
        for carry_len in [0, 31, 32, 33, 64] {
            let sample = &data[..length];
            let mut expected = new_hit_batch(4096, carry_len, sample.len());
            for matched in embedded_matcher().find_overlapping_iter(sample) {
                record_raw_hit(
                    &mut expected,
                    sample,
                    carry_len,
                    4096,
                    matched.pattern().as_usize(),
                    matched.start(),
                    matched.end(),
                );
            }
            for start in memmem::find_iter(sample, XZ_FOOTER_MAGIC) {
                if start >= 10
                    && start + 2 > carry_len
                    && parse_xz_footer(&sample[start - 10..start + 2], 4096 + start as u64 + 2)
                        .is_ok()
                {
                    expected
                        .results
                        .push(RawHit::new(4096 + start as u64, PATTERNS.len() as u8));
                }
            }
            let mut actual = scan_sample(sample, carry_len, 4096);
            let mut expected = expected.results.iter().collect::<Vec<_>>();
            expected.sort_unstable_by_key(|hit| (hit.offset(), hit.hit_name()));
            actual.sort_unstable_by_key(|hit| (hit.offset(), hit.hit_name()));
            assert_eq!(actual, expected, "length={length} carry={carry_len}");
        }
    }

    for prefix in [b"PK".as_slice(), b"Rar", b"7z", b"YZ"] {
        let dense = prefix.repeat(4096);
        let mut expected = new_hit_batch(0, 0, dense.len());
        for matched in embedded_matcher().find_overlapping_iter(&dense) {
            record_raw_hit(
                &mut expected,
                &dense,
                0,
                0,
                matched.pattern().as_usize(),
                matched.start(),
                matched.end(),
            );
        }
        for start in memmem::find_iter(&dense, XZ_FOOTER_MAGIC) {
            if start >= 10
                && parse_xz_footer(&dense[start - 10..start + 2], start as u64 + 2).is_ok()
            {
                expected
                    .results
                    .push(RawHit::new(start as u64, PATTERNS.len() as u8));
            }
        }
        let mut actual = scan_sample(&dense, 0, 0);
        let mut expected = expected.results.iter().collect::<Vec<_>>();
        expected.sort_unstable_by_key(|hit| (hit.offset(), hit.hit_name()));
        actual.sort_unstable_by_key(|hit| (hit.offset(), hit.hit_name()));
        assert_eq!(actual, expected, "dense prefix {prefix:?}");
    }
}

fn append_tar_member(data: &mut Vec<u8>, name: &str, payload: &[u8]) {
    let member_start = data.len();
    let mut header = [0u8; 512];
    header[..name.len()].copy_from_slice(name.as_bytes());
    header[100..108].copy_from_slice(b"0000644\0");
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");
    let size = format!("{:011o}\0", payload.len());
    header[124..136].copy_from_slice(size.as_bytes());
    header[136..148].copy_from_slice(b"00000000000\0");
    header[148..156].fill(b' ');
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let checksum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
    let checksum = format!("{:06o}\0 ", checksum);
    header[148..156].copy_from_slice(checksum.as_bytes());
    data.extend_from_slice(&header);
    data.extend_from_slice(payload);
    data.resize(member_start + 512 + payload.len().next_multiple_of(512), 0);
}

// Failed outer walks must share only their visited heads. Same-format
// archives inside skipped payload remain independent carrier candidates.
#[test]
fn failed_suffixes_keep_inner_archives_under_read_budget_and_propagate_io() {
    use crate::io::reader::ReaderConfig;
    let mut gz = GzEncoder::new(Vec::new(), Compression::none());
    gz.write_all(b"inner gzip").unwrap();
    let inner_gz = gz.finish().unwrap();
    let mut empty = GzEncoder::new(Vec::new(), Compression::fast());
    empty.write_all(b"").unwrap();
    let empty_gz = empty.finish().unwrap();
    let mut outer = GzEncoder::new(Vec::new(), Compression::none());
    outer.write_all(&inner_gz).unwrap();
    let mut bad_gz = outer.finish().unwrap();
    let last = bad_gz.len() - 1;
    bad_gz[last] ^= 1;
    let mut gz_data = empty_gz.repeat(32);
    gz_data.extend_from_slice(&bad_gz);

    let mut bz = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::fast());
    bz.write_all(b"").unwrap();
    let empty_bz = bz.finish().unwrap();
    let mut bz_data = empty_bz.repeat(32);
    bz_data.extend_from_slice(b"BZh9broken-block");
    bz_data.extend_from_slice(&empty_bz);

    let empty_zs = [0x28, 0xb5, 0x2f, 0xfd, 0x20, 0, 1, 0, 0];
    let mut zs_data = empty_zs.repeat(32);
    zs_data.extend_from_slice(&[0x28, 0xb5, 0x2f, 0xfd, 0x20, 9, 72, 0, 0]);
    zs_data.extend_from_slice(&empty_zs); // raw block containing a real frame
    zs_data.extend_from_slice(&[7, 0, 0]); // reserved next block type

    // The outer frame skips all inner heads, but visits the bad suffix.
    // The first inner walk must join that evidence and publish its own
    // heads, otherwise all later inner candidates rewalk the same tail.
    let payload = empty_zs.repeat(32);
    let mut zs_join = vec![0x28, 0xb5, 0x2f, 0xfd, 0x60];
    zs_join.extend_from_slice(&((payload.len() - 256) as u16).to_le_bytes());
    let block = ((payload.len() as u32) << 3) | 1;
    zs_join.extend_from_slice(&block.to_le_bytes()[..3]);
    zs_join.extend_from_slice(&payload);
    zs_join.extend_from_slice(&[0x28, 0xb5, 0x2f, 0xfd, 0x20, 0, 7, 0, 0]);

    let mut inner_tar = Vec::new();
    append_tar_member(&mut inner_tar, "inner", b"payload");
    inner_tar.extend_from_slice(&[0; 1024]);
    let mut tar_data = Vec::new();
    for _ in 0..32 {
        append_tar_member(&mut tar_data, "prefix", b"");
    }
    append_tar_member(&mut tar_data, "outer", &inner_tar);

    for (kind, data, expected_count) in [
        ("gzip", gz_data, 1),
        ("bzip2", bz_data, 1),
        ("zstd", zs_data, 1),
        ("tar", tar_data, 1),
        ("zstd", zs_join, 0),
    ] {
        let mut hits = scan_sample(&data, 0, 0);
        hits.retain(|hit| hit.kind() == kind);
        hits.sort_unstable_by_key(|hit| hit.offset());
        let reference = ManagedReader::from_bytes(data.clone(), ReaderConfig::default());
        let mut expected = Vec::new();
        for hit in &hits {
            if let Some(candidate) = validate_candidate(
                &reference,
                reference.len(),
                kind,
                hit.offset(),
                &mut Default::default(),
            )
            .unwrap()
            {
                expected.push(candidate);
            }
        }
        assert_eq!(expected.len(), expected_count, "{kind}");
        let source = ManagedReader::from_bytes(
            data.clone(),
            ReaderConfig {
                ..Default::default()
            },
        );
        assert_eq!(
            validate_raw_hits(
                &source,
                source.len(),
                stored_hits(&hits).view(0),
                stored_hits(&[]).view(0)
            )
            .unwrap_or_else(|error| panic!("{kind}: {error}")),
            expected,
            "{kind}"
        );
    }
}

#[test]
fn long_zstd_concatenations_keep_their_original_root() {
    use crate::io::reader::ReaderConfig;
    // Crossing the old aggregate quota must preserve the complete range
    // rooted at the first frame, rather than carving only its suffix.
    let mut frame = vec![0x28, 0xb5, 0x2f, 0xfd, 0x20, 0];
    frame.extend(std::iter::repeat([0, 0, 0]).take(500_000).flatten());
    frame.extend_from_slice(&[1, 0, 0]);
    let second = frame.len() as u64;
    let source = ManagedReader::from_bytes(frame.repeat(2), ReaderConfig::default());
    let hits = [0, second].map(|offset| RawHit::new(offset, 8));
    let candidates = validate_raw_hits(
        &source,
        source.len(),
        stored_hits(&hits).view(0),
        stored_hits(&[]).view(0),
    )
    .unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(
        (candidates[0].offset, candidates[0].end_offset),
        (0, Some(source.len()))
    );
}

fn append_zip64_archive(data: &mut Vec<u8>) -> (u64, u64) {
    let archive_start = data.len() as u64;
    let name = b"x";
    data.extend_from_slice(ZIP_LOCAL);
    data.extend_from_slice(&45u16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&crc32(b"x").to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&(name.len() as u16).to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(name);
    data.push(b'x');

    let cd_offset = data.len() as u64 - archive_start;
    let cd_start = data.len();
    data.extend_from_slice(b"PK\x01\x02");
    data.extend_from_slice(&45u16.to_le_bytes());
    data.extend_from_slice(&45u16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&crc32(b"x").to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&(name.len() as u16).to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(name);
    let cd_size = (data.len() - cd_start) as u64;

    let zip64_record_offset = data.len() as u64 - archive_start;
    data.extend_from_slice(b"PK\x06\x06");
    data.extend_from_slice(&44u64.to_le_bytes());
    data.extend_from_slice(&45u16.to_le_bytes());
    data.extend_from_slice(&45u16.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&1u64.to_le_bytes());
    data.extend_from_slice(&1u64.to_le_bytes());
    data.extend_from_slice(&cd_size.to_le_bytes());
    data.extend_from_slice(&cd_offset.to_le_bytes());
    data.extend_from_slice(b"PK\x06\x07");
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&zip64_record_offset.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(ZIP_EOCD);
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&u16::MAX.to_le_bytes());
    data.extend_from_slice(&u16::MAX.to_le_bytes());
    data.extend_from_slice(&u32::MAX.to_le_bytes());
    data.extend_from_slice(&u32::MAX.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    (archive_start, data.len() as u64)
}

#[test]
fn keeps_crc_valid_truncated_7z_unresolved_and_unextractable() {
    let mut start_header = Vec::new();
    start_header.extend_from_slice(&1024u64.to_le_bytes());
    start_header.extend_from_slice(&16u64.to_le_bytes());
    start_header.extend_from_slice(&0u32.to_le_bytes());

    let mut data = b"carrier-prefix".to_vec();
    let start = data.len() as u64;
    data.extend_from_slice(SEVEN_ZIP);
    data.extend_from_slice(&[0, 4]);
    data.extend_from_slice(&crc32(&start_header).to_le_bytes());
    data.extend_from_slice(&start_header);
    let path = temp_file("embedded_truncated_7z", &data);

    let result = scan_embedded_archives_native(ManagedReader::open(&path).unwrap()).unwrap();
    let seven = result
        .candidates
        .iter()
        .find(|candidate| candidate.format == "7z")
        .expect("CRC-valid truncated 7z must remain a logical candidate");

    assert_eq!(seven.offset, start);
    assert_eq!(seven.end_offset, None);
    assert!(seven.is_logical_archive());
    assert!(seven.volume_anchor.as_ref().is_some_and(|anchor| anchor.is_volume_entry()));
    let _ = fs::remove_file(path);
}

#[test]
fn exact_7z_range_suppresses_valid_inner_stream_before_validation() {
    let mut gzip = GzEncoder::new(Vec::new(), Compression::fast());
    gzip.write_all(b"inner payload").unwrap();
    let inner = gzip.finish().unwrap();
    let next_header = b"\x01";

    let mut start_header = Vec::new();
    start_header.extend_from_slice(&(inner.len() as u64).to_le_bytes());
    start_header.extend_from_slice(&(next_header.len() as u64).to_le_bytes());
    start_header.extend_from_slice(&crc32(next_header).to_le_bytes());

    let mut data = b"carrier-prefix".to_vec();
    let start = data.len() as u64;
    data.extend_from_slice(SEVEN_ZIP);
    data.extend_from_slice(&[0, 4]);
    data.extend_from_slice(&crc32(&start_header).to_le_bytes());
    data.extend_from_slice(&start_header);
    data.extend_from_slice(&inner);
    data.extend_from_slice(next_header);
    let end = data.len() as u64;
    let path = temp_file("embedded_7z_owns_inner_stream", &data);

    let result = scan_embedded_archives_native(ManagedReader::open(&path).unwrap()).unwrap();
    let logical = result
        .candidates
        .iter()
        .filter(|candidate| candidate.is_logical_archive())
        .collect::<Vec<_>>();

    assert_eq!(logical.len(), 1);
    assert_eq!(logical[0].format, "7z");
    assert_eq!(logical[0].offset, start);
    assert_eq!(logical[0].end_offset, Some(end));
    assert!(!result
        .candidates
        .iter()
        .any(|candidate| candidate.format == "gzip"));
    let _ = fs::remove_file(path);
}

#[test]
fn aggregates_embedded_zip64_from_locator_eocd_and_local_links() {
    let mut data = b"sfx-prefix".to_vec();
    let (start, end) = append_zip64_archive(&mut data);
    let path = temp_file("embedded_zip64", &data);

    let result = scan_embedded_archives_native(ManagedReader::open(&path).unwrap()).unwrap();
    let zip = result
        .candidates
        .iter()
        .find(|candidate| candidate.format == "zip")
        .expect("ZIP64 must become one logical candidate");

    assert_eq!(zip.offset, start);
    assert_eq!(zip.end_offset, Some(end));
    assert_eq!(zip.zip_eocd_offset, Some(end - 22));
    let _ = fs::remove_file(path);
}

#[test]
fn aggregates_many_tar_member_anchors_into_one_logical_archive() {
    let mut data = b"carrier-prefix".to_vec();
    let start = data.len() as u64;
    append_tar_member(&mut data, "one.txt", b"one");
    append_tar_member(&mut data, "two.txt", b"two");
    data.extend_from_slice(&[0u8; 1024]);
    let end = data.len() as u64;
    let path = temp_file("embedded_tar_members", &data);

    let result = scan_embedded_archives_native(ManagedReader::open(&path).unwrap()).unwrap();
    let tar = result
        .candidates
        .iter()
        .filter(|candidate| candidate.format == "tar")
        .collect::<Vec<_>>();

    assert_eq!(tar.len(), 1);
    assert_eq!(tar[0].offset, start);
    assert_eq!(tar[0].end_offset, Some(end));
    let _ = fs::remove_file(path);
}

#[test]
fn aggregates_concatenated_bzip2_streams_into_one_logical_archive() {
    let mut data = b"carrier-prefix".to_vec();
    let start = data.len() as u64;
    let mut first = BzEncoder::new(Vec::new(), BzCompression::fast());
    first.write_all(b"first payload").unwrap();
    data.extend_from_slice(&first.finish().unwrap());
    let mut second = BzEncoder::new(Vec::new(), BzCompression::fast());
    second.write_all(b"second payload").unwrap();
    data.extend_from_slice(&second.finish().unwrap());
    let end = data.len() as u64;
    let path = temp_file("embedded_concatenated_bzip2", &data);

    let result = scan_embedded_archives_native(ManagedReader::open(&path).unwrap()).unwrap();
    let bzip2 = result
        .candidates
        .iter()
        .filter(|candidate| candidate.format == "bzip2")
        .collect::<Vec<_>>();

    assert_eq!(bzip2.len(), 1);
    assert_eq!(bzip2[0].offset, start);
    assert_eq!(bzip2[0].end_offset, Some(end));
    let _ = fs::remove_file(path);
}

#[test]
fn keeps_bzip2_streams_separate_across_invalid_gap() {
    let mut first = BzEncoder::new(Vec::new(), BzCompression::fast());
    first.write_all(b"first payload").unwrap();
    let mut data = first.finish().unwrap();
    data.extend_from_slice(b"invalid gap");
    let second_start = data.len() as u64;
    let mut second = BzEncoder::new(Vec::new(), BzCompression::fast());
    second.write_all(b"second payload").unwrap();
    data.extend_from_slice(&second.finish().unwrap());
    let path = temp_file("embedded_gapped_bzip2", &data);

    let result = scan_embedded_archives_native(ManagedReader::open(&path).unwrap()).unwrap();
    let bzip2_offsets = result
        .candidates
        .iter()
        .filter(|candidate| candidate.format == "bzip2")
        .map(|candidate| candidate.offset)
        .collect::<Vec<_>>();

    assert_eq!(bzip2_offsets, [0, second_start]);
    let _ = fs::remove_file(path);
}

#[test]
fn packed_search_preserves_every_signature_overlap() {
    let mut data = vec![0x11; 512];
    for (left_index, (left, _, _)) in PATTERNS.iter().enumerate() {
        for (right_index, (right, _, _)) in PATTERNS.iter().enumerate() {
            for overlap in 1..left.len().min(right.len()) {
                if left[left.len() - overlap..] != right[..overlap] {
                    continue;
                }
                let start = data.len();
                data.extend_from_slice(left);
                data.extend_from_slice(&right[overlap..]);
                data.extend_from_slice(&[0x11; 32]);
                assert!(signature_overlaps()[left_index].contains(&(right_index, overlap)));
                assert!(start > 0);
            }
        }
    }
    assert_eq!(optimized_raw_hits(&data), reference_raw_hits(&data));
}

#[test]
fn packed_search_matches_overlapping_aho_on_randomized_layouts() {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut data = vec![0u8; 2 * 1024 * 1024];
    for byte in &mut data {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *byte = state as u8;
    }
    for round in 0..2048usize {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let pattern = round % PATTERNS.len();
        let magic = PATTERNS[pattern].0;
        let start = 300 + (state as usize % (data.len() - 600 - magic.len()));
        data[start..start + magic.len()].copy_from_slice(magic);
    }
    // Force the only overlap in the set in addition to any accidental
    // overlaps generated by the randomized corpus.
    let overlap = b"\x28\xb5\x2f\xfd7zXZ\x00";
    data[128..128 + overlap.len()].copy_from_slice(overlap);

    assert_eq!(optimized_raw_hits(&data), reference_raw_hits(&data));
}

#[test]
fn finds_multiple_structurally_valid_embedded_streams() {
    let mut data = b"carrier".to_vec();
    let zip_offset = data.len() as u64;
    data.extend_from_slice(ZIP_LOCAL);
    data.extend_from_slice(&20u16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&1u16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    data.push(b'x');
    data.extend_from_slice(b"gap");
    let gzip_offset = data.len() as u64;
    let mut gzip = GzEncoder::new(Vec::new(), Compression::fast());
    gzip.write_all(b"payload").unwrap();
    data.extend_from_slice(&gzip.finish().unwrap());
    let path = temp_file("embedded_multi", &data);
    let result = scan_embedded_archives(path.to_str().unwrap()).unwrap();
    let rows = result.candidates();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].offset, zip_offset);
    assert_eq!(rows[1].offset, gzip_offset);
    let _ = fs::remove_file(path);
}

#[test]
fn finds_primary_and_later_stream_across_invalid_gap() {
    let mut first = GzEncoder::new(Vec::new(), Compression::fast());
    first.write_all(b"first payload").unwrap();
    let first = first.finish().unwrap();
    let gap = b"invalid bytes between valid streams";
    let second_offset = (first.len() + gap.len()) as u64;
    let mut second = GzEncoder::new(Vec::new(), Compression::fast());
    second.write_all(b"second payload").unwrap();

    let mut data = first;
    data.extend_from_slice(gap);
    data.extend_from_slice(&second.finish().unwrap());
    let path = temp_file("embedded_primary_gap_stream", &data);
    let result = scan_embedded_archives_native(ManagedReader::open(&path).unwrap()).unwrap();
    let gzip_offsets = result
        .candidates
        .iter()
        .filter(|candidate| candidate.format == "gzip")
        .map(|candidate| candidate.offset)
        .collect::<Vec<_>>();

    assert_eq!(gzip_offsets, [0, second_offset]);
    let _ = fs::remove_file(path);
}

#[test]
fn validates_supported_stream_headers_in_one_pass() {
    // Filtering must keep real peers after dense rejected headers.
    let mut noise = Vec::new();
    for pattern in [2, 5, 6, 7, 10] {
        let magic = PATTERNS[pattern].0;
        let mut header = [0xff; 32];
        header[..magic.len()].copy_from_slice(magic);
        noise.extend_from_slice(&header);
    }
    // Also exercise a plausible fixed header rejected by the full walk.
    noise.extend_from_slice(b"BZh9broken-block");
    let mut data = noise.repeat(512);
    let mut bzip = BzEncoder::new(Vec::new(), BzCompression::fast());
    bzip.write_all(b"bzip payload").unwrap();
    data.extend_from_slice(&bzip.finish().unwrap());
    let mut xz = XzEncoder::new(Vec::new(), 1);
    xz.write_all(b"xz payload").unwrap();
    data.extend_from_slice(&xz.finish().unwrap());
    data.extend_from_slice(&zstd::stream::encode_all(&b"zstd payload"[..], 1).unwrap());
    let path = temp_file("embedded_streams", &data);
    let scan = scan_embedded_archives_native_with_iocp(
        ManagedReader::open(&path).unwrap(),
        TEST_IOCP_CHUNK_SIZE,
        4,
        4,
    )
    .unwrap();
    assert!(scan.raw_hit_count > 2000);
    let formats: Vec<_> = scan.candidates().iter().map(|row| row.format).collect();
    assert_eq!(formats, ["bzip2", "xz", "zstd"]);
    let _ = fs::remove_file(path);
}

#[test]
fn validates_zstd_maximum_frame_header_layout() {
    let mut data = ZSTD.to_vec();
    data.push(0xc3);
    data.push(0x00);
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&1u64.to_le_bytes());
    data.extend_from_slice(&[0x09, 0x00, 0x00]);
    data.push(b'x');
    assert_eq!(data.len(), 22);

    let path = temp_file("embedded_zstd_maximum_header", &data);
    let reader = ManagedReader::open(&path).unwrap();
    let candidate = validate_zstd(&reader, data.len() as u64, 0, &mut Default::default())
        .unwrap()
        .expect("the full 14-byte RFC frame header must be accepted");
    assert_eq!(candidate.end_offset, Some(data.len() as u64));
    let _ = fs::remove_file(path);
}

#[test]
fn zstd_last_block_requires_declared_checksum_bytes() {
    let data = [0x28, 0xb5, 0x2f, 0xfd, 0x24, 0x01, 0x09, 0x00, 0x00, b'x'];
    let path = temp_file("embedded_zstd_missing_checksum", &data);
    let reader = ManagedReader::open(&path).unwrap();
    assert!(
        validate_zstd(&reader, data.len() as u64, 0, &mut Default::default())
            .unwrap()
            .is_none()
    );
    let _ = fs::remove_file(path);
}

#[test]
fn zstd_zero_length_rle_still_requires_its_content_byte() {
    let data = [0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x00, 0x03, 0x00, 0x00];
    let path = temp_file("embedded_zstd_empty_rle", &data);
    let reader = ManagedReader::open(&path).unwrap();
    assert!(
        validate_zstd(&reader, data.len() as u64, 0, &mut Default::default())
            .unwrap()
            .is_none()
    );
    let _ = fs::remove_file(path);
}

#[test]
fn finds_signature_split_across_reused_buffer_boundary() {
    let mut gzip = GzEncoder::new(Vec::new(), Compression::fast());
    gzip.write_all(b"cross-boundary payload").unwrap();
    let gzip_bytes = gzip.finish().unwrap();
    let gzip_offset = TEST_IOCP_CHUNK_SIZE - 2;
    let mut data = vec![b'x'; gzip_offset];
    data.extend_from_slice(&gzip_bytes);
    let path = temp_file("embedded_cross_boundary", &data);
    let result = scan_embedded_archives(path.to_str().unwrap()).unwrap();
    assert_eq!(result.candidates().len(), 1);
    assert_eq!(result.candidates()[0].offset, gzip_offset as u64);
    let _ = fs::remove_file(path);
}

#[cfg(windows)]
#[test]
fn iocp_matches_reference_scan_across_chunk_boundaries() {
    let mut data = vec![0x11; TEST_IOCP_CHUNK_SIZE * 3 + 123];
    let first = TEST_IOCP_CHUNK_SIZE - 2;
    data[first..first + GZIP.len()].copy_from_slice(GZIP);
    let second = TEST_IOCP_CHUNK_SIZE * 2 + 7;
    data[second..second + SEVEN_ZIP.len()].copy_from_slice(SEVEN_ZIP);
    let path = temp_file("embedded_iocp", &data);
    let mut expected = reference_raw_hits(&data);
    expected.sort_unstable_by_key(|hit| (hit.offset(), hit.hit_name()));
    let mut results = Vec::new();
    iocp::scan_file(
        &path,
        data.len() as u64,
        TEST_IOCP_CHUNK_SIZE,
        4,
        4,
        embedded_overlap(),
        scan_sample_batch,
        |batch| {
            results.extend(batch.iter());
            Ok(())
        },
    )
    .unwrap();
    results.sort_unstable_by_key(|hit| (hit.offset(), hit.hit_name()));
    assert_eq!(results, expected);
    let _ = fs::remove_file(path);
}
