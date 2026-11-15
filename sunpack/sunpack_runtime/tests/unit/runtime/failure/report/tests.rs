use super::*;
use crate::pipeline::FailureEvidence;

fn collect(archives: &[ArchiveResult], language: Language) -> Vec<Report<'_>> {
    archive_groups(archives).into_iter()
        .filter_map(|entries| archive_report(&entries, language)).collect()
}

#[test]
fn missing_volume_wrapper_borrows_recovery_and_streams_both_receipts() {
    let recovery: crate::pipeline::InputRecovery = serde_json::from_value(json!({
        "inputs": [], "output": "restored", "input_count": 1,
        "had_checkpoints": false, "retry_output": true,
    })).unwrap();
    let mut failure = Failure::new(FailureKind::Damaged, "damaged")
        .with_context(FailureContext::Extraction);
    failure.evidence = Some(Box::new(FailureEvidence {
        possible_missing_volume: true, ..Default::default()
    }));
    failure.recovery = Some(std::sync::Arc::new(recovery));
    let archives = [ArchiveResult {
        path: "carrier.bin".into(), format: "zip".into(), output: None,
        failure: Some(failure), files: 0, bytes: 0, encrypted: None, depth: 0,
        offset: 0, end_offset: None, volume_completeness: None,
        volume_attempts: None, source_paths: vec![], password: None,
        discovery_source: DiscoverySource::Embedded,         partial: false, retained: false, recovered_complete_files: 0,
          scan_layout: Default::default(),
    }];
    let report = archive_report(&[&archives[0]], Language::En).unwrap();
    let original = &report.causes[0];
    assert!(std::ptr::eq(report.recovery.unwrap().0, original.recovery.unwrap().0));
    assert!(report.details.get("input_recovery").is_none());
    assert!(original.details.get("input_recovery").is_none());
    let mut bytes = Vec::new();
    serde_json::to_writer(&mut bytes, &report).unwrap();
    let streamed: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(streamed, serde_json::to_value(&report).unwrap());
    let expected = json!({"inputs": [], "output_dir": "restored", "input_count": 1});
    assert_eq!(streamed["details"]["input_recovery"], expected);
    assert_eq!(streamed["causes"][0]["details"]["input_recovery"], expected);
    assert_eq!(streamed["details"]["retry_output_dir"], "restored");
    assert_eq!(streamed["causes"][0]["details"]["retry_output_dir"], "restored");
}

#[test]
fn scan_failure_preserves_main_receipt_and_count() {
    let error = InputError { path: "folder".into(), message: "3".into(),
        kind: crate::pipeline::InputErrorKind::FilesystemScan,
        scan_operation: Some("output_scan".into()), scan_count: Some(3), failure: None };
    let report = serde_json::to_value(Report::filesystem_scan(&error, Language::En)).unwrap();
    assert_eq!(report, json!({"kind": "filesystem_error", "stage": "filesystem_scan",
        "message": "Output scan incomplete: folder (3 unreadable entries)",
        "message_key": "filesystem_scan.output_scan", "message_params": {"path": "folder", "error": "3"},
        "user_action": "", "causes": [], "details": {"path": "folder", "operation": "output_scan", "count": 3}}));
}

#[test]
fn read_error_projection_does_not_change_native_evidence() {
    let fault = crate::pipeline::ArchiveReadFault {
        code: "unexpected_eof".into(), operation: "read".into(), field: "header".into(),
        location: "tail".into(), offset: 4, requested: 8, actual: 2, source_len: 6,
        volume_number: None, possible_missing_volume: true, missing_volume_hint: true,
        io_kind: "UnexpectedEof".into(), os_error: None, detail: "short".into(),
    };
    let report = read_error(&fault);
    assert_eq!(report["io_kind"], "unexpectedeof");
    assert!(report.get("missing_volume_hint").is_none());
    assert_eq!(report["possible_missing_volume"], true);
    assert!(fault.missing_volume_hint);
    assert_eq!(fault.io_kind, "UnexpectedEof");
}

#[test]
fn failure_receipts_use_creation_context_and_keep_native_evidence_separate() {
    let mut failure = Failure::new(FailureKind::WrongPassword, "raw worker text")
        .with_context(FailureContext::Extraction);
    failure.evidence = Some(Box::new(FailureEvidence {
        stage: Some("item_extract".into()), stderr_tail: Some("worker detail".into()),
        ..Default::default()
    }));
    let report = serde_json::to_value(Report::from_failure(&failure, Language::Zh)).unwrap();
    assert_eq!(report["stage"], "extraction");
    assert_eq!(report["message"], Language::En.text("failure.password_not_in_list"));
    assert_eq!(report["message_key"], "failure.password_not_in_list");
    assert_eq!(report["user_action"], "request_password");
    assert_eq!(report["causes"], json!([]));
    assert_eq!(report["details"], json!({}));
    assert_eq!(report["message_params"], json!({}));
    let restored: Failure = serde_json::from_value(serde_json::to_value(&failure).unwrap()).unwrap();
    assert_eq!(restored.evidence.unwrap().stderr_tail.as_deref(), Some("worker detail"));
    assert_eq!(failure.message, "raw worker text");

    let warning = Failure::new(FailureKind::Unknown, "raw worker warning")
        .with_context(FailureContext::WorkerWarning);
    let report = serde_json::to_value(Report::from_failure(&warning, Language::Zh)).unwrap();
    assert_eq!(report["stage"], "extraction");
    assert_eq!(report["message_key"], "failure.warning_busy_or_partial");
    assert_eq!(report["message"], Language::En.text("failure.warning_busy_or_partial"));
    assert_eq!(super::super::message(&warning, Language::Zh), Language::Zh.text("failure.warning_busy_or_partial"));
    assert_eq!(warning.message, "raw worker warning");


}

#[test]
fn input_admission_receipt_preserves_missing_paths_without_guessing() {
    let failure = Failure::new(FailureKind::MissingVolume, "internal")
        .with_context(FailureContext::InputAdmission { missing_paths: vec!["part02.rar".into()] });
    let report = serde_json::to_value(Report::from_failure(&failure, Language::Zh)).unwrap();
    assert_eq!(report["stage"], "input_admission");
    assert_eq!(report["message"], Language::En.text("failure.missing_volume"));
    assert_eq!(report["message_key"], "failure.missing_volume");
    assert_eq!(report["user_action"], "");
    assert_eq!(report["details"], json!({"missing_volume_confirmed": true, "missing_paths": ["part02.rar"]}));
}

#[test]
fn single_discovery_failure_remains_a_leaf() {
    let failure = Failure::new(FailureKind::MissingVolume, "internal discovery text")
        .with_context(FailureContext::Discovery { discovery: DiscoverySource::Embedded,
            reason: "missing_volume".into(), path: "carrier.bin".into(), error: String::new() });
    let mut failure = failure;
    failure.evidence = Some(Box::new(FailureEvidence {
        stage: Some("discovery".into()), native_kind: Some("missing_volume".into()), ..Default::default()
    }));
    let leaf = Report::from_failure(&failure, Language::En);
    assert_eq!(leaf.stage, "embedded_boundary");
    assert_eq!(leaf.message, Language::En.text("failure.possible_missing_volume"));
    let archives = [ArchiveResult {
        path: "carrier.bin".into(), format: "zip".into(), output: None,
        failure: Some(failure), files: 0, bytes: 0, encrypted: None, depth: 0,
        offset: 0, end_offset: None, volume_completeness: None,
        volume_attempts: None, source_paths: vec![], password: None,
        discovery_source: DiscoverySource::Embedded,         partial: false, retained: false, recovered_complete_files: 0,
          scan_layout: Default::default(),
    }];
    let reports = serde_json::to_value(collect(&archives, Language::En)).unwrap();
    assert_eq!(reports[0]["kind"], "missing_volume");
    assert_eq!(reports[0]["stage"], "embedded_boundary");
    assert_eq!(reports[0]["message"], Language::En.text("failure.possible_missing_volume"));
    assert_eq!(reports[0]["causes"], json!([]));
    assert_eq!(reports[0]["details"]["reason"], "missing_volume");
}
