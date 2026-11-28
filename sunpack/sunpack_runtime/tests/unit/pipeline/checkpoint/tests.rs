use super::*;
use crate::io::reader::capture_file_generation;
use crate::io::archive_state::{InputExtent, InputPart, VolumeAttemptPlan, VolumeDomain, VolumeLayout, VolumeSlot};
use std::{fs, sync::Arc};

#[test]
fn recovery_receipts_preserve_pre_cleanup_facts_and_relocate_only_outputs() {
    let source = crate::test_support::temp_file("recovery_report", b"archive");
    let output = source.with_extension("out");
    let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "original".into());
    let generations = HashMap::from([(path_key(&input.entry_path), capture_file_generation(&source).unwrap())]);
    let mut result = ArchiveResult {
        path: source.clone(), format: "zip".into(), output: None, failure: None,
        files: 0, bytes: 0, encrypted: None, depth: 1, offset: 0, end_offset: None,
        volume_completeness: None, volume_attempts: None, source_paths: vec![source.clone()],
        password: None, discovery_source: DiscoverySource::Embedded,         partial: false, retained: false, recovered_complete_files: 0,
         scan_layout: Default::default(),
    };
    result.failure = Some(Failure::new(FailureKind::Damaged, "damaged").with_context(super::super::FailureContext::Extraction));
    result.output = Some(output.clone()); result.files = 3; result.bytes = 17;
    result.recovered_complete_files = 2;
    let state = InputCheckpoint::report_state(&input, &result, Some(&output), None, 4, 7);
    let shared_input = Arc::new(input.clone());
    let mut checkpoint = InputCheckpoint::create(&source, Arc::clone(&shared_input), &result, &generations, None).unwrap();
    assert!(Arc::ptr_eq(&shared_input, &checkpoint.shared_input()));
    checkpoint.install_report(state.clone());
    let checkpoint: InputCheckpoint = serde_json::from_slice(&serde_json::to_vec(&checkpoint).unwrap()).unwrap();
    let mut resumed = input.clone(); resumed.logical_name = "changed display".into();
    let state = InputCheckpoint::report_state(&resumed, &result, Some(&output), Some(&checkpoint), 1, 7).unwrap();
    assert_eq!(state.position, 4);
    assert_eq!(state.input_id, checkpoint.report.as_ref().unwrap().input_id);
    let recovery = InputRecovery::capture(&[checkpoint.clone()], &source, None, None, 7, true, true).unwrap();
    assert!(Arc::ptr_eq(&checkpoint.input, &recovery.inputs[0].input));
    assert!(Arc::ptr_eq(&checkpoint.sources, &recovery.inputs[0].sources));
    assert!(Arc::ptr_eq(checkpoint.failure.as_ref().unwrap(), recovery.inputs[0].failure.as_ref().unwrap()));
    let mut output_only = checkpoint.clone();
    output_only.relocate_flatten(output.parent().unwrap(), &output, output.parent().unwrap());
    assert!(Arc::ptr_eq(&checkpoint.input, &output_only.input));
    assert!(Arc::ptr_eq(&checkpoint.sources, &output_only.sources));
    let render = |failure: &Failure| serde_json::json!({"kind": format!("{:?}", failure.kind)});
    // Construction must not visit the potentially large recovery tree.
    // The existing output assertions below cover its full public schema.
    let visits = std::cell::Cell::new(0);
    let view = recovery.report_view(|failure| {
        visits.set(visits.get() + 1);
        render(failure)
    });
    assert_eq!(visits.get(), 0);
    let mut bytes = Vec::new();
    serde_json::to_writer(&mut bytes, &view).unwrap();
    assert_eq!(visits.get(), 1);
    let streamed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let report = recovery.report(render);
    assert_eq!(streamed, report);
    assert_eq!(report["inputs"][0]["position"], 4);
    assert_eq!(report["inputs"][0]["files_written"], 3);
    assert_eq!(report["inputs"][0]["bytes_written"], 17);
    assert_eq!(report["inputs"][0]["recovered_complete_files"], 2);
    assert_eq!(report["inputs"][0]["complete"], false);
    assert_eq!(report["inputs"][0]["archive_input"]["logical_name"], "original");
    assert_eq!(report["inputs"][0]["generation"], serde_json::to_value(&checkpoint.sources).unwrap());
    assert!(recovery.aggregated());
    let mut hinted = checkpoint.clone();
    let facts = &mut Arc::make_mut(&mut hinted.input).analysis;
    facts.missing_volume_evidence = Some("seven_zip_start_header_length".into());
    let hinted_report = InputRecovery::capture(&[hinted.clone()], &source, None, None, 1, false, true)
        .unwrap().report(render);
    assert_eq!(hinted_report["inputs"][0]["blockers"], serde_json::json!([]));
    let facts = &mut Arc::make_mut(&mut hinted.input).analysis;
    facts.origin = crate::io::archive_state::AnalysisOrigin::Relations;
    let confirmed_report = InputRecovery::capture(&[hinted], &source, None, None, 1, false, true)
        .unwrap().report(render);
    assert_eq!(confirmed_report["inputs"][0]["blockers"], serde_json::json!(["missing_volume"]));
    // Same-request replacement keeps the first checkpoint until a result
    // with the same logical ID overwrites it. Name/mode changes alone do
    // not invent another logical input; a different format does.
    assert!(checkpoint.same_report_input(&resumed));
    let mut replacement = resumed.clone();
    replacement.format_hint = "7z".into();
    assert!(!checkpoint.same_report_input(&replacement));
    let success = ArchiveResult {
        failure: None,
        format: "7z".into(),
        recovered_complete_files: 0,
        ..result
    };
    let mut replaced = InputCheckpoint::create(&source, Arc::new(replacement.clone()), &success, &generations, None).unwrap();
    replaced.install_report(InputCheckpoint::report_state(&replacement, &success,
        Some(&output), None, 1, 1));
    let retained = checkpoint.result(1);
    assert_eq!(super::super::TaskCompletion::from_group(&[success, retained]).status,
        super::super::TaskStatus::Failed);
    let changed_id = InputRecovery::capture(&[checkpoint.clone(), replaced],
        &source, None, None, 1, true, true).unwrap();
    let changed_report = changed_id.report(render);
    assert_eq!(changed_report["input_count"], 1);
    assert_eq!(changed_report["inputs"].as_array().unwrap().len(), 2);
    assert_eq!(changed_report["inputs"][0]["complete"], false);
    assert_eq!(changed_report["inputs"][1]["complete"], true);
    assert_ne!(changed_report["inputs"][0]["input_id"], changed_report["inputs"][1]["input_id"]);
    let mut relocated = recovery.as_ref().clone();
    let parent = output.parent().unwrap();
    relocated.relocate_flatten(parent, &output, parent);
    let relocated_report = relocated.report(render);
    let relocated_output = relocated_report["inputs"][0]["output_dir"].as_str().unwrap();
    assert_eq!(Path::new(relocated_output), parent);
    assert_eq!(relocated_report["inputs"][0]["archive_input"]["entry_path"], input.entry_path);
    // Content rejection must not revive an old partial continuation path.
    let mut cleared = checkpoint;
    InputCheckpoint::clear_report_output(&mut cleared.report);
    cleared.output.clear();
    let cleared = InputRecovery::capture(&[cleared], &source, None, Some(&output), 7, true, true).unwrap();
    assert!(cleared.retry_output().is_none());
    assert_eq!(cleared.report(render)["output_dir"], "");
    assert_eq!(cleared.report(render)["inputs"][0]["files_written"], 3);
    assert_eq!(cleared.report(render)["inputs"][0]["recovered_complete_files"], 0);
    fs::remove_file(source).unwrap();
}

#[test]
fn partial_retry_requires_fixed_mapping_and_facts_but_complete_admits_alternatives() {
    let source = crate::test_support::temp_file("checkpoint_retry", b"archive");
    let output = source.with_extension("output");
    fs::create_dir(&output).unwrap();
    let mut input = ArchiveInput::file(
        source.to_string_lossy().into_owned(), "7z".into(), "archive".into(),
    );
    input.mode = OpenMode::NativeVolumes;
    input.parts = vec![InputPart {
        role: crate::io::archive_state::InputRole::First,
        extent: InputExtent { view: None, path: input.entry_path.clone(), start: 0, end: Some(7) },
        volume_number: Some(1),
        canonical_name: "archive.7z.001".into(),
    }].into_boxed_slice();
    input.parts[0].extent.view = Some(Arc::new(crate::io::view::ReadView {
        generation: None,
        method: crate::io::view::ViewMethod::Apate, depth: 1, physical_size: 7,
        spans: vec![crate::io::view::Span { start: 0, end: 7, reverse: true }],
    }));
    let key = path_key(&input.entry_path);
    let mut generations = HashMap::from([
        (key.clone(), capture_file_generation(&source).unwrap()),
    ]);
    let complete = InputCheckpoint {
        schema_version: SCHEMA_VERSION,
        carrier: source.clone(),
        input: Arc::new(input.clone()), report: None,
        sources: vec![SourceGeneration {
            path: source.clone(), generation: generations[&key].clone(),
        }].into(),
        output: output.clone(),
        planned_output: None,
        container: None, files: 1, bytes: 7, encrypted: None,
        discovery_source: DiscoverySource::Embedded, failure: None,
    };
    let mut result = complete.result(1);
    result.failure = Some(Failure::new(FailureKind::MissingVolume, "missing volume"));
    result.partial = true;
    result.recovered_complete_files = 1;
    let partial = InputCheckpoint::create(&source, Arc::new(input.clone()), &result, &generations, None).unwrap();
    // Exercise the persisted representation, not just in-memory equality.
    let partial: InputCheckpoint = serde_json::from_slice(
        &serde_json::to_vec(&partial).unwrap(),
    ).unwrap();
    assert!(partial.valid_for(&input, &generations));
    // An ordinary growing input keeps its key. Coexisting validated siblings
    // with the same head must each recover their own output after restart.
    let mut sibling = input.clone();
    sibling.parts[0].extent.end = Some(5);
    assert_eq!(CheckpointKey::for_input(&sibling).0, CheckpointKey::for_input(&input).0);
    sibling.analysis.distinguish_end = true;
    let saved = serde_json::to_vec(&sibling).unwrap();
    sibling.parts[0].extent.end = Some(6);
    assert_ne!(CheckpointKey::for_input(&sibling).0, CheckpointKey::for_input(&serde_json::from_slice(&saved).unwrap()).0);
    let mut plain = input.clone();
    plain.parts[0].extent.view = None;
    assert!(!partial.valid_for(&plain, &generations));
    assert!(!complete.valid_for(&plain, &generations));
    let mut interrupted = serde_json::to_value(&partial).unwrap();
    interrupted["failure"]["failure"] = serde_json::json!({
        "kind":"process_error", "message":"worker exited", "evidence":{"native_kind":"worker_lost"}
    });
    let interrupted: InputCheckpoint = serde_json::from_value(interrupted).unwrap();
    assert!(!interrupted.valid_for(&input, &generations));
    let mut metadata_only = serde_json::to_value(&partial).unwrap();
    metadata_only["sources"][0]["generation"]["created"] = serde_json::json!([false, 1, 0]);
    #[cfg(windows)]
    { metadata_only["sources"][0]["generation"]["windows"]["change_time"] = serde_json::json!(1); }
    let metadata_only: InputCheckpoint = serde_json::from_value(metadata_only).unwrap();
    assert!(metadata_only.valid_for(&input, &generations));
    let mut changed = input.clone();
    changed.analysis.password_required = true;
    assert!(!partial.valid_for(&changed, &generations));
    changed = input.clone();
    changed.logical_name.push_str("-new");
    assert!(!partial.valid_for(&changed, &generations));

    let mut alternatives = input.clone();
    let alternative_path = source.with_extension("alternative");
    alternatives.volume_attempts = Some(Arc::new(VolumeAttemptPlan {
        sources: vec![input.parts[0].extent.clone(), InputExtent {
            view: None,
            path: alternative_path.to_string_lossy().into_owned(),
            start: 0, end: Some(7),
        }].into_boxed_slice(),
        layouts: vec![VolumeLayout {
            slots: vec![VolumeSlot {
                number: 1, canonical_name: input.parts[0].canonical_name.clone(), domain: 0,
            }].into_boxed_slice(), minimum_slots: 0,
        }].into_boxed_slice(),
        domains: vec![VolumeDomain { choices: Arc::new(vec![0, 1]) }].into_boxed_slice(),
        head_size_from_total: None, minimum_size: None, tail_totals: Box::new([]),
    }));
    assert!(complete.valid_for(&alternatives, &generations));
    assert!(!partial.valid_for(&alternatives, &generations));
    let mut checkpoint = InputCheckpoint::create(&source, Arc::new(alternatives.clone()), &result, &generations, None).unwrap();
    let moved_alternative = alternative_path.with_extension("moved");
    assert!(checkpoint.relocate(&alternative_path, &moved_alternative));
    let source_path = |input: &ArchiveInput| input.volume_attempts.as_ref().unwrap().sources[1].path.clone();
    assert_eq!(source_path(checkpoint.input()), moved_alternative.to_string_lossy());
    assert_eq!(source_path(&alternatives), alternative_path.to_string_lossy());

    // A failed input reserves its name without advertising recoverable
    // content. Persist and relocate that namespace independently of output.
    let mut failed = partial.clone();
    failed.output = PathBuf::new();
    let container = output.with_extension("carrier");
    let slot = container.join("segment");
    failed.container = Some(container.clone());
    failed.set_planned_output(Some(&slot));
    let mut failed: InputCheckpoint = serde_json::from_slice(
        &serde_json::to_vec(&failed).unwrap(),
    ).unwrap();
    assert!(!failed.has_output());
    assert!(failed.result(1).output.is_none());
    assert!(failed.output_slot_for(&input, &container));
    assert_eq!(failed.output_slot(), Some(slot.as_path()));
    let moved = container.with_extension("moved");
    assert!(failed.relocate(&container, &moved));
    assert_eq!(failed.output_slot(), Some(moved.join("segment").as_path()));
    assert!(!failed.has_output());
    // Length changes make this deterministic even on coarse file clocks.
    fs::write(&source, b"changed archive generation").unwrap();
    generations.insert(key, capture_file_generation(&source).unwrap());
    assert!(!partial.valid_for(&input, &generations));
    assert!(!complete.valid_for(&alternatives, &generations));
    fs::remove_dir(output).unwrap();
    fs::remove_file(source).unwrap();
}
