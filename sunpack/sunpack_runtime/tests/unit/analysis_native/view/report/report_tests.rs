use super::*;

fn plan(evidences: impl IntoIterator<Item = Evidence>, size: u64) -> AnalysisReport {
    let mut plan = SegmentPlan::default();
    for evidence in evidences {
        plan.consider(evidence, size);
    }
    plan.finish()
}

#[test]
fn strict_subranges_require_exact_valid_bounds() {
    for (start, end, expected) in [
        (0, Some(100), false),
        (0, Some(50), true),
        (20, Some(100), true),
        (20, Some(50), true),
        (0, None, false),
        (20, None, false),
        (0, Some(0), false),
        (50, Some(50), false),
        (50, Some(20), false),
        (0, Some(101), false),
    ] {
        assert_eq!(
            strict_subrange(start, end, 100),
            expected,
            "{start} {end:?}"
        );
    }
}

#[test]
fn plan_orders_outer_carved_segments_including_prefix() {
    let report = plan(
        [
            Evidence::new("rar", Extractable, 40, Some(60), vec![]),
            Evidence::new("7z", Extractable, 4, Some(32), vec![]),
            Evidence::new("7z", Extractable, 0, Some(14), vec![]),
            Evidence::new("tar", Extractable, 90, None, vec![]),
        ],
        100,
    );
    let planned: Vec<_> = report
        .segments
        .iter()
        .map(|segment| (segment.format_hint, segment.start))
        .collect();
    assert_eq!(planned, [("7z", 0), ("rar", 40)]);
    assert_eq!(report.format_hint, "7z");
}

#[test]
fn complete_ranges_suppress_only_later_starts() {
    let report = plan(
        [
            Evidence::new("rar", Extractable, 40, Some(60), vec![]),
            Evidence::new("tar", Extractable, 0, Some(80), vec![]),
            Evidence::new("7z", Extractable, 0, Some(100), vec![]),
        ],
        100,
    );
    assert_eq!(report.format_hint, "7z");
    assert_eq!(report.segments.len(), 1);
    assert_eq!(report.segments[0].format_hint, "tar");
}

#[test]
fn plan_picks_first_carved_password_segment() {
    let evidences =
        [("7z", 0), ("rar", 90), ("rar", 64), ("zip", 10)].map(|(format, start)| {
            let mut evidence = Evidence::new(format, Damaged, start, None, vec![]);
            evidence.segment.password_required = true;
            evidence
        });
    let report = plan(evidences, 200);
    assert_eq!(report.segments.len(), 1);
    assert_eq!(report.segments[0].start, 10);
}

#[test]
fn plan_proves_missing_volume_from_seven_zip_declared_end() {
    for (size, valid, missing) in [(50, true, true), (142, true, false), (50, false, false)] {
        let mut bytes = vec![0u8; size];
        bytes[..6].copy_from_slice(SEVEN_ZIP);
        bytes[12..20].copy_from_slice(&100u64.to_le_bytes());
        bytes[20..28].copy_from_slice(&10u64.to_le_bytes());
        let checksum = crc32(&bytes[12..32]);
        bytes[8..12].copy_from_slice(&(checksum ^ u32::from(!valid)).to_le_bytes());
        let view = AnalysisBinaryView {
            reader: ManagedReader::from_bytes(bytes, ReaderConfig::default()),
        };
        let config = NativeAnalysisConfig::new([("seven_zip", true)]);
        let report = view.analyze_report(&config, None).unwrap();
        assert_eq!(
            report.facts.missing_volume_evidence.as_deref(),
            missing.then_some("seven_zip_start_header_length"),
        );
    }
}

#[test]
fn typed_zip_and_tar_facts_retain_planning_boundaries() {
    // Exercise real probes and the final facts together: dictionary-field
    // conversion errors otherwise silently default password/boundary facts.
    let mut zip = vec![0u8; 30 + 46 + 22];
    zip[..4].copy_from_slice(ZIP_LOCAL);
    zip[30..34].copy_from_slice(ZIP_CENTRAL);
    zip[38..40].copy_from_slice(&1u16.to_le_bytes()); // encrypted central member
    zip[76..80].copy_from_slice(ZIP_EOCD);
    zip[84..86].copy_from_slice(&1u16.to_le_bytes());
    zip[86..88].copy_from_slice(&1u16.to_le_bytes());
    zip[88..92].copy_from_slice(&46u32.to_le_bytes());
    zip[92..96].copy_from_slice(&30u32.to_le_bytes());
    let zip_path = crate::test_support::temp_file("typed_zip_facts", &zip);
    {
        let view = AnalysisBinaryView::new(&zip_path.to_string_lossy(), 0).unwrap();
        let signatures = LeadingSignatures::read(&view.reader).unwrap();
        let (offset, record) = signatures.zip_eocd.unwrap();
        let observed = view
            .probe_zip_with_disk_starts(offset, &record, None)
            .unwrap();
        assert!(observed.walk_ok && observed.password_required);
        let evidence = zip_from_native(observed, signatures.zip_local, zip.len() as u64);
        assert_eq!(evidence.segment.status, Extractable);
        assert_eq!(evidence.segment.end, Some(zip.len() as u64));
        let facts = evidence.analysis_facts();
        assert!(facts.structure_complete && facts.password_required);
        assert_eq!(facts.zip_eocd_offset, Some(76));
    }
    let mut tar = vec![0u8; 3 * TAR_BLOCK_SIZE];
    tar[0] = b'x';
    for range in [100..108, 108..116, 116..124, 124..136, 136..148] {
        tar[range.start..range.end - 1].fill(b'0');
    }
    tar[148..156].fill(b' ');
    tar[156] = b'0';
    tar[257..263].copy_from_slice(b"ustar\0");
    let checksum = format!("{:06o}\0 ", crate::formats::tar::checksum(&tar[..TAR_BLOCK_SIZE]));
    tar[148..156].copy_from_slice(checksum.as_bytes());
    let tar_path = crate::test_support::temp_file("typed_tar_facts", &tar);
    {
        let view = AnalysisBinaryView::new(&tar_path.to_string_lossy(), 0).unwrap();
        let mut context = ReportContext {
            view: &view,
            disk_starts: None,
            signatures: LeadingSignatures::read(&view.reader).unwrap(),
            stream_structure: None,
        };
        let evidence = context.tar_module().unwrap().unwrap();
        assert_eq!(evidence.segment.status, Extractable);
        assert_eq!(evidence.segment.end, Some(tar.len() as u64));
        assert!(evidence.analysis_facts().structure_complete);
    }
    crate::io::reader::release_reader_resources_under_roots(vec![
        zip_path.to_string_lossy().into_owned(),
        tar_path.to_string_lossy().into_owned(),
    ])
    .unwrap();
    std::fs::remove_file(zip_path).unwrap();
    std::fs::remove_file(tar_path).unwrap();
}
