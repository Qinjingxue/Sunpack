#[test]
fn recovery_descriptor_uses_main_contract_without_worker_projection_fields() {
    let mut input = ArchiveInput::file("archive.zip".into(), "zip".into(), "archive".into());
    assert_eq!(serde_json::to_string(&input.report()).unwrap(),
        r#"{"kind":"archive_input","entry_path":"archive.zip","open_mode":"file","format_hint":"zip","parts":[{"path":"archive.zip","role":"main","volume_number":1}],"logical_name":"archive"}"#);
    input.analysis.origin = AnalysisOrigin::Embedded;
    input.analysis.volume_completeness = Some(VolumeCompleteness::Complete);
    input.analysis.password_required = true;
    // Embedded's execution-only ZIP offset does not occur in main's
    // descriptor until planning installs it into the existing analysis.
    input.analysis.zip_eocd_offset = Some(8);
    assert_eq!(serde_json::to_value(input.report()).unwrap()["analysis"],
        serde_json::json!({"volume_completeness":"complete", "password_required":true}));
    input.analysis.planning_applied = true;
    assert_eq!(serde_json::to_value(input.report()).unwrap()["analysis"]["zip_eocd_offset"], 8);
    input.analysis.origin = AnalysisOrigin::Planned;
    input.analysis.status = Some(AnalysisStatus::Damaged);
    assert!(serde_json::to_string(&input.report()).unwrap().ends_with(
        r#""analysis":{"status":"damaged","damage_flags":[],"zip_eocd_offset":8,"password_required":true}}"#));
    let persisted = serde_json::to_vec(&input).unwrap();
    let restored: ArchiveInput = serde_json::from_slice(&persisted).unwrap();
    assert_eq!(serde_json::to_string(&input.report()).unwrap(), serde_json::to_string(&restored.report()).unwrap());
}

#[test]
fn recovery_descriptor_does_not_export_single_file_planning_hints() {
    let mut input = ArchiveInput::file("truncated.7z".into(), "7z".into(), "truncated".into());
    input.analysis.planning_applied = true;
    input.analysis.missing_volume_evidence = Some("seven_zip_start_header_length".into());
    assert!(serde_json::to_value(input.report()).unwrap().get("analysis").is_none());
    assert!(serde_json::to_value(input.worker_input()).unwrap().get("analysis").is_none());
    input.mode = OpenMode::NativeVolumes;
    input.parts = Box::new([InputPart::range(InputExtent { path: input.entry_path.clone(), start: 0, end: None })]);
    assert!(serde_json::to_value(input.report()).unwrap().get("analysis").is_none());
    assert!(serde_json::to_value(input.worker_input()).unwrap().get("analysis").is_none());
    input.parts = vec![input.parts[0].clone(), InputPart::range(InputExtent {
        path: "truncated.7z.002".into(), start: 0, end: None,
    })].into_boxed_slice();
    assert_eq!(serde_json::to_value(input.report()).unwrap()["analysis"]["execution"]["missing_volume_evidence"],
        "seven_zip_start_header_length");
    assert_eq!(serde_json::to_value(input.worker_input()).unwrap()["analysis"]["execution"]["missing_volume_evidence"],
        "seven_zip_start_header_length");
    // A relation conclusion is a different producer: main exports this
    // fact before planning even when only the first known volume exists.
    input.parts = Box::new([input.parts[0].clone()]);
    input.analysis.origin = AnalysisOrigin::Relations;
    input.analysis.planning_applied = false;
    input.analysis.missing_volume_evidence = Some("relation_missing_volume".into());
    assert_eq!(serde_json::to_value(input.report()).unwrap()["analysis"]["execution"]["missing_volume_evidence"],
        "relation_missing_volume");
    assert_eq!(serde_json::to_value(input.worker_input()).unwrap()["analysis"]["execution"]["missing_volume_evidence"],
        "relation_missing_volume");
}

#[test]
fn recovery_volume_descriptor_preserves_style_roles_and_plan_order() {
    let mut input = ArchiveInput::file("first.zip".into(), "zip".into(), "archive".into());
    input.mode = OpenMode::NativeVolumes;
    input.volume_style = "zip_spanned".into();
    input.parts = Box::new([InputPart { role: InputRole::Terminal,
        extent: InputExtent { path: "first.zip".into(), start: 0, end: Some(12) },
        volume_number: Some(1), canonical_name: "archive.zip".into() }]);
    input.analysis.origin = AnalysisOrigin::Relations;
    input.analysis.volume_completeness = Some(VolumeCompleteness::Unknown);
    input.volume_attempts = Some(Box::new(VolumeAttemptPlan {
        sources: Box::new([input.parts[0].extent.clone()]),
        domains: Box::new([VolumeDomain { choices: Arc::new(vec![0]) }]),
        layouts: Box::new([VolumeLayout { slots: Box::new([VolumeSlot {
            number: 1, canonical_name: "archive.zip".into(), domain: 0,
        }]), minimum_slots: 0 }]),
        head_size_from_total: None, minimum_size: None, tail_totals: Box::new([]),
    }));
    let text = serde_json::to_string(&input.report()).unwrap();
    assert!(text.contains(r#""domains":[{"choices":[0]}],"layouts":[{"slots":[{"number":1,"canonical_name":"archive.zip","domain":0}]}]"#));
    assert!(!text.contains("minimum_slots"));
    assert!(text.contains(r#""role":"terminal","volume_number":1,"canonical_name":"archive.zip","end":12"#));
    let decoded: ArchiveInput = serde_json::from_slice(&serde_json::to_vec(&input).unwrap()).unwrap();
    assert_eq!(text, serde_json::to_string(&decoded.report()).unwrap());
    input.select_volumes(&VolumeSelection { layout: 0, sources: vec![0] }).unwrap();
    assert_eq!(input.parts[0].role, InputRole::First);
    assert!(input.volume_attempts.is_none());
    assert_eq!(input.volume_style, "zip_spanned");
}
use super::*;

#[test]
fn trimmed_head_admission_keeps_first_sufficient_duplicate_extent() {
    // A shorter duplicate must not hide a later sufficient carrier. Keep
    // first-match order too: a later match cannot bypass source uniqueness.
    let mut plan = VolumeAttemptPlan {
        sources: [None, Some(4), Some(12), Some(8), Some(20), Some(10)]
            .into_iter().enumerate().map(|(i, end)| InputExtent {
                path: if i == 5 { "tail" } else { "carrier" }.into(),
                start: 0, end,
            }).collect(),
        layouts: Box::new([VolumeLayout {
            slots: Box::new([
                VolumeSlot { number: 1, canonical_name: String::new(), domain: 0 },
                VolumeSlot { number: 2, canonical_name: String::new(), domain: 1 },
            ]),
            minimum_slots: 0,
        }]),
        domains: Box::new([
            VolumeDomain { choices: Arc::new(vec![0, 1, 2, 3, 4]) },
            VolumeDomain { choices: Arc::new(vec![5]) },
        ]),
        head_size_from_total: Some(20), minimum_size: None, tail_totals: Box::new([]),
    };
    let mut parts = plan.selected_parts(&VolumeSelection {
        layout: 0, sources: vec![4, 5],
    }).unwrap();
    for end in [1, 4, 5, 8, 12, 13, 20, 21] {
        plan.head_size_from_total = Some(end + 10);
        parts[0].extent.end = Some(end);
        assert_eq!(plan.admits_parts(&parts), end <= 20, "head end {end}");
    }
    parts[0].extent.end = None;
    assert!(!plan.admits_parts(&parts));

    // Source 2 is the first sufficient head, but is already the tail.
    // Source 4 also fits; choosing it instead would change old behavior.
    plan.domains[1].choices = Arc::new(vec![2]);
    plan.head_size_from_total = Some(22);
    parts[0].extent.end = Some(10);
    parts[1].extent = plan.sources[2].clone();
    assert!(!plan.admits_parts(&parts));
}

#[test]
fn shared_volume_domains_are_indexed_once_and_validate_checkpoint_geometry() {
    // Same shared-pool shape used by attempts.rs for unnumbered interior
    // gaps. Both worker selection and checkpoint admission must stay valid
    // without re-scanning the pool for every slot.
    let count = 256;
    let choices = Arc::new((0..count).collect::<Vec<_>>());
    let mut plan = VolumeAttemptPlan {
        sources: (0..count).map(|i| InputExtent {
            path: format!("part-{i}"), start: 0, end: Some(10),
        }).collect(),
        layouts: Box::new([VolumeLayout {
            slots: (0..count).map(|i| VolumeSlot {
                number: i as u32 + 1, canonical_name: String::new(), domain: i,
            }).collect(),
            minimum_slots: 0,
        }]),
        // Distinct domain records can still share the same choices Arc.
        domains: (0..count).map(|_| VolumeDomain { choices: Arc::clone(&choices) }).collect(),
        head_size_from_total: None, minimum_size: None, tail_totals: Box::new([]),
    };
    let mut indexes = DomainMembers::new();
    let mut selection = VolumeSelection { layout: 0, sources: (0..count).rev().collect() };
    let parts = plan.selected_parts_indexed(&selection, &mut indexes).unwrap();
    assert_eq!(indexes.len(), 1);
    assert_eq!(indexes.values().map(HashSet::len).sum::<usize>(), count);
    assert!(plan.admits_parts(&parts));
    selection.sources[1] = selection.sources[0];
    assert!(plan.selected_parts(&selection).is_err());
    selection.sources[1] = count;
    assert!(plan.selected_parts(&selection).is_err());
    let mut wrong = parts.clone();
    wrong[1].extent.start = 1;
    assert!(!plan.admits_parts(&wrong));
    wrong = parts.clone();
    wrong[1].canonical_name = "unplanned".into();
    assert!(!plan.admits_parts(&wrong));

    // Variable counts use the final slot's domain, and a trimmed head is
    // matched by physical start before the exact total-size formula runs.
    plan.layouts[0].minimum_slots = 2;
    plan.head_size_from_total = Some(15);
    let trimmed = plan.selected_parts(&VolumeSelection {
        layout: 0, sources: vec![0, count - 1],
    }).unwrap();
    assert_eq!(trimmed[0].extent.end, Some(5));
    assert!(plan.admits_parts(&trimmed));
    let mut wrong = trimmed;
    wrong[0].extent.end = Some(6);
    assert!(!plan.admits_parts(&wrong));
}
