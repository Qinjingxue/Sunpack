use super::*;

use crate::analysis_native::volume_anchor::probe_volume_anchor_path_cheap;

#[test]
fn retired_regex_generation_lives_only_until_concurrent_parse_finishes() {
    // Filename outcome tests miss retained pools and concurrent retirement.
    // Without this test, old-generation ownership remains unverified.
    // One synchronized worker covers retirement/reuse without corpus I/O.
    let cache = RelationRegexCache::default();
    let first = cache.acquire();
    let weak = Arc::downgrade(&first);
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    let parsing = std::thread::spawn(move || {
        assert_eq!(
            parse_volume_candidates_with_regexes("中文.part2.rar.jpg", &first)[0].number,
            2
        );
        ready_tx.send(()).unwrap();
        resume_rx.recv().unwrap();
        assert_eq!(
            parse_volume_candidates_with_regexes("中文.7z.003", &first)[0].number,
            3
        );
    });
    ready_rx.recv().unwrap();
    cache.clear();
    assert!(cache.0.read().unwrap().is_none());
    let second = cache.acquire();
    assert!(!Arc::ptr_eq(&weak.upgrade().unwrap(), &second));
    assert_eq!(
        parse_volume_candidates_with_regexes("中文.z02.jpg", &second)[0].number,
        2
    );
    resume_tx.send(()).unwrap();
    parsing.join().unwrap();
    assert!(weak.upgrade().is_none());
    let second_weak = Arc::downgrade(&second);
    drop(second);
    cache.clear();
    assert!(second_weak.upgrade().is_none());
}

#[test]
fn ordinary_words_and_invalid_part_numbers_are_not_volumes() {
    for name in [
        "Counterpart2.zip",
        "Rampart1.rar",
        "apart10.bin",
        "report_part3_final.docx",
        "release.Counterpart2.rar",
        "release.report_part3_final.rar",
        "a.part0.rar",
        "a.part0.rar.hidden",
        "a.rar.part0.hidden",
        "a.part4294967296.rar",
        "a.rar.part4294967296.hidden",
    ] {
        assert!(parse_relation_numbered_volume(name).is_none(), "{name}");
    }
    for (name, family) in [("photo.part2.7z", "7z"), ("a.part1.zip", "zip")] {
        let parsed = parse_relation_numbered_volume(name).unwrap();
        assert_eq!(parsed.family, family);
        assert_eq!(parsed.style, "part_numbered");
    }
    for name in ["a.part4294967295.rar.hidden", "a.rar.part4294967295.hidden"] {
        assert_eq!(
            parse_relation_numbered_volume(name).unwrap().number,
            u32::MAX
        );
    }
    assert_eq!(get_logical_name("Counterpart2.zip", true), "Counterpart2");
    assert_eq!(get_logical_name("Rampart1.rar", true), "Rampart1");
    assert!(!relations_size_filter_split_family_keys("Counterpart2.zip")
        .iter()
        .any(|key| key.starts_with("rar:part")));
}

#[test]
fn size_filter_family_keys_join_numbered_7z_parts_and_exclude_other_prefixes() {
    let first = relations_size_filter_split_family_keys(r"C:\downloads\payload.7z.001");
    let tail = relations_size_filter_split_family_keys(r"C:\downloads\payload.7z.003");
    let other = relations_size_filter_split_family_keys(r"C:\downloads\other.7z.003");

    assert!(first.iter().any(|key| tail.contains(key)));
    assert!(!first.iter().any(|key| other.contains(key)));
}

#[test]
fn zipx_aliases_share_only_the_standard_zip_spanned_size_family() {
    // Family keys span directories within the active discovery scope.
    let expected = vec![split_size_family_key("zip:spanned", "payload")];
    for name in [
        "payload.zx01",
        "payload.ZX12",
        "payload.zipx",
        "payload.ZIPX",
    ] {
        assert_eq!(
            relations_size_filter_split_family_keys(&format!(r"C:\downloads\{name}")),
            expected,
            "{name}"
        );
    }
    assert_eq!(archive_family("ZIPX"), Some("zip"));
    for name in ["payload.zipx.part02.zipx", "payload.part02.zipx"] {
        let parsed = parse_relation_numbered_volume(name).unwrap();
        assert_eq!(parsed.family, "zip");
        assert_eq!(parsed.prefix, "payload");
    }
    assert_eq!(get_logical_name("payload.zipx", false), "payload");
    for name in [
        "payload.zx0",
        "payload.zx00",
        "payload.zxAA",
        "payload.zx4294967296",
    ] {
        assert!(parse_relation_numbered_volume(name).is_none(), "{name}");
    }
}

#[test]
fn decorated_rar_sfx_head_keeps_exe_token_before_part_marker() {
    let first = parse_numbered_volume_name("shared.bundle.exe.part1.useless.fake").unwrap();
    let second = parse_numbered_volume_name("shared.bundle.rar.part2.useless.fake").unwrap();

    assert_eq!(first.family, "rar");
    assert_eq!(first.style, "rar_sfx_part");
    assert_eq!(first.prefix, "shared.bundle");
    assert_eq!(first.number, 1);
    assert_eq!(second.family, "rar");
    assert_eq!(second.style, "rar_part");
    assert_eq!(second.prefix, "shared.bundle");
    assert_eq!(second.number, 2);
}

#[test]
fn filename_features_preserve_loose_channels_and_case_folded_contexts() {
    let plain = filename::NameFeatures::parse("Backup2");
    assert_eq!(plain.numbers[0].value, 2);
    assert_eq!(plain.numbers[0].left, "backup");
    assert!(plain.canonical.is_empty());

    let ordinary = filename::NameFeatures::parse("Backup2.照片");
    assert!(ordinary.numbers.is_empty() && ordinary.canonical.is_empty());

    let repeated = filename::NameFeatures::parse("照片.PART02.RAR.part3.JPG");
    assert_eq!(repeated.numbers.len(), 2);
    assert_eq!(repeated.numbers[0].ordinal, 0);
    assert_eq!(repeated.numbers[1].ordinal, 1);
    assert_eq!(repeated.canonical[0].number, 3);
}

#[test]
fn structural_part_marker_outranks_numeric_camouflage_suffix() {
    let candidates = filename::NameFeatures::parse("payload.part2.photo.456").canonical;
    assert_eq!(candidates[0].prefix, "payload");
    assert_eq!(candidates[0].number, 2);
    assert_eq!(candidates[0].style, "part_numbered");
    assert_eq!(candidates[0].family, "generic");
    assert!(candidates[0].decorated);
    assert!(candidates.iter().any(|candidate| {
        candidate.style == "plain_numeric_suffix" && candidate.number == 456
    }));
}

#[test]
fn marker_parser_keeps_apparent_format_before_or_after_marker() {
    let before = parse_numbered_volume_name("payload.7z.part0002.photo").unwrap();
    let after = parse_numbered_volume_name("payload.part0002.7z.photo").unwrap();
    for parsed in [before, after] {
        assert_eq!(parsed.prefix, "payload");
        assert_eq!(parsed.number, 2);
        assert_eq!(parsed.style, "part_numbered");
        assert_eq!(parsed.family, "7z");
        assert_eq!(parsed.width, 4);
    }
}

#[test]
fn marker_parser_does_not_treat_partition_words_as_volumes() {
    let parsed = parse_numbered_volume_name("report.partition1.2024").unwrap();
    assert_eq!(parsed.style, "plain_numeric_suffix");
    assert_eq!(parsed.number, 2024);
}

fn validation_with_owned_paths(status: ProposalStatus, paths: &[&str]) -> ProposalValidation {
    ProposalValidation {
        attempts: None,
        status,
        reason: None,
        unresolved: Vec::new(),
        proposal: RelationProposal {
            format: "rar",
            logical_name: "test".to_string(),
            style: "rar_part",
            width: 2,
            volumes: paths
                .iter()
                .enumerate()
                .map(|(index, path)| ((*path).to_string(), index as u32 + 1))
                .collect(),
            companions: Vec::new(),
        },
        facts: Arc::default(),
        head_override: None,
    }
}

// A real parsed ENDARC before carrier EOF reaches NativeVolumes with a
// finite head extent. That physical bound must not invent a scan range.
#[test]
fn parsed_rar_head_extent_keeps_native_volume_scan_layout() {
    use crate::analysis_native::volume_anchor::upgrade_relation_rar_end;
    let mut bytes = b"Rar!\x1a\x07\x00".to_vec();
    for (kind, flags, body) in [(0x73, 0x111u16, vec![0; 6]), (0x7b, 1, vec![])] {
        let mut header = vec![0, 0, kind];
        header.extend(flags.to_le_bytes());
        header.extend(((7 + body.len()) as u16).to_le_bytes());
        header.extend(body);
        let crc = crc32fast::hash(&header[2..]) as u16;
        header[..2].copy_from_slice(&crc.to_le_bytes());
        bytes.extend(header);
    }
    let end = bytes.len() as u64;
    bytes.extend([0; 128]);
    let path = crate::test_support::temp_file("scan_native_head", &bytes);
    let path_string = path.to_string_lossy().into_owned();
    let anchor = probe_volume_anchor_path_cheap(&path_string);
    let anchor = upgrade_relation_rar_end(&anchor);
    assert_eq!(anchor.proven_extent_end(), Some(end));
    let mut validation = validation_with_owned_paths(ProposalStatus::Valid, &[&path_string]);
    Arc::make_mut(&mut validation.facts).anchors.insert(path_key(&path_string), Arc::new(anchor));
    let mut input = ArchiveInput::file(path_string, "rar".into(), "test".into());
    input.analysis.origin = AnalysisOrigin::Relations;
    project_proposal(&validation, &mut input);
    assert_eq!(input.mode, OpenMode::NativeVolumes);
    assert_eq!(input.parts[0].extent.start, 0);
    assert_eq!(input.parts[0].extent.end, Some(end));
    let layout = crate::pipeline::ScanLayout::from_input(&input, crate::pipeline::Mode::Scan);
    assert!(!layout.range);
    assert!(layout.volumes);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn encrypted_relations_require_readable_anchors_even_with_existing_failure() {
    for reason in [None, Some(RelationFailureReason::MissingVolume)] {
        let path = "archive.part1.rar";
        let mut validation = validation_with_owned_paths(ProposalStatus::Inconclusive, &[path]);
        validation.reason = reason;
        Arc::make_mut(&mut validation.facts).anchors.insert(
            path.into(),
            Arc::new(VolumeAnchor {
                format: "rar",
                needs_password: true,
                ..Default::default()
            }),
        );
        validate::validate(&mut validation);
        assert_eq!(validation.status, ProposalStatus::NeedsPassword);
        assert_eq!(
            validate::assignment_status(
                "rar",
                false,
                [(1, validation.facts.anchors.get(path).map(Arc::as_ref))].into_iter()
            ),
            ProposalStatus::NeedsPassword,
        );

        validation.reason = reason;
        let anchor = Arc::make_mut(&mut validation.facts).anchors.get_mut(path).unwrap();
        Arc::make_mut(anchor).error = "input could not be read".into();
        validate::validate(&mut validation);
        assert_eq!(validation.status, ProposalStatus::Reject);
        assert_eq!(
            validation.reason,
            Some(RelationFailureReason::CorruptArchive)
        );
        assert_eq!(
            validate::assignment_status(
                "rar",
                false,
                [(1, validation.facts.anchors.get(path).map(Arc::as_ref))].into_iter()
            ),
            ProposalStatus::Reject,
        );
    }
}

#[test]
fn conflict_index_marks_all_shared_owners_in_the_selected_status() {
    let validations = vec![
        validation_with_owned_paths(
            ProposalStatus::NeedsPassword,
            &[r"C:\case.part1.rar", r"C:\case.part2.rar"],
        ),
        validation_with_owned_paths(
            ProposalStatus::NeedsPassword,
            &[r"C:\case.part2.rar", r"C:\case.part3.rar"],
        ),
        validation_with_owned_paths(ProposalStatus::NeedsPassword, &[r"C:\case.part2.rar"]),
        validation_with_owned_paths(ProposalStatus::NeedsPassword, &[r"C:\other.part1.rar"]),
        validation_with_owned_paths(ProposalStatus::Valid, &[r"C:\case.part2.rar"]),
    ];
    let owned_paths: Vec<HashSet<String>> =
        validations.iter().map(validation_owned_paths).collect();
    let password_indexes = validations.iter().enumerate().filter_map(|(index, validation)| {
        (validation.status == ProposalStatus::NeedsPassword).then_some(index)
    });
    assert_eq!(
        conflicting_indexes_among(&owned_paths, password_indexes),
        HashSet::from([0, 1, 2])
    );
}
