use super::*;
use crate::pipeline::{ArchiveReadFault, FailureEvidence};

#[test]
fn output_create_text_and_report_share_operation_context() {
    let failure = Failure::new(FailureKind::FilesystemError, "Access denied")
        .with_context(FailureContext::OutputCreate { error: "Access denied".into(), path: None });
    for language in [Language::En, Language::Zh] {
        let expected = language.translate("extract.dir_create_failed", &[("error", "Access denied")]);
        assert_eq!(message(&failure, language), expected);
        assert_eq!(original_message_spec(&failure, language).render(language), expected);
        let report = serde_json::to_value(report::Report::from_failure(&failure, language)).unwrap();
        assert_eq!(report["message"], expected);
        assert_eq!(report["message_key"], "extract.dir_create_failed");
        assert_eq!(report["stage"], "preflight");
    }
}

#[test]
fn split_recovery_warning_preserves_failure_kind_and_diagnostics() {
    let mut failure = Failure::new(FailureKind::Damaged, "raw backend damage");
    failure.evidence = Some(Box::new(FailureEvidence {
        possible_missing_volume: true,
        ..FailureEvidence::default()
    }));
    assert_eq!(message(&failure, Language::En), Language::En.text("failure.possible_missing_volume"));
    assert_eq!(failure.kind, FailureKind::Damaged);
    assert_eq!(failure.message, "raw backend damage");
}

#[test]
fn human_projection_keeps_distinct_causes_and_raw_diagnostics() {
    for (reason, kind, zh, en) in [
        ("corrupt_archive", FailureKind::Damaged, "压缩包损坏", "Archive is damaged"),
        ("ambiguous_volume_mapping", FailureKind::MissingVolume, "压缩包内容不完整，可能缺少分卷", "Archive is incomplete and may be missing volumes"),
        ("needs_volume_or_tail_damaged", FailureKind::Damaged, "分卷缺失，或尾部偏移/结构字段已损坏", "Missing split volume or damaged tail offset/structure"),
    ] {
        let mut failure = Failure::new(kind, "raw native diagnosis");
        failure.evidence = Some(Box::new(FailureEvidence {
            native_kind: Some(reason.into()), ..Default::default()
        }));
        assert_eq!(message(&failure, Language::Zh), zh);
        assert_eq!(message(&failure, Language::En), en);
        assert_eq!(serde_json::to_value(&failure).unwrap()["message"], "raw native diagnosis");
    }
    for retry in [false, true] {
        let mut failure = Failure::new(FailureKind::PasswordInconclusive, "password_or_volume_inconclusive");
        failure.password_retry = retry;
        assert_eq!(message(&failure, Language::Zh), "无法确认压缩包密码状态");
        assert_eq!(failure.is_password_retry(), retry);
    }
    let failure = Failure::new(FailureKind::ResourceUnavailable, "HRESULT 0x8007000E");
    assert_eq!(message(&failure, Language::Zh), "内存不足，无法完成压缩包处理");
    assert_eq!(message(&failure, Language::En), "Insufficient memory to process the archive");
    assert_eq!(failure.message, "HRESULT 0x8007000E");
    let mut process = Failure::new(FailureKind::ProcessError, "worker pipe closed");
    process.evidence = Some(Box::new(FailureEvidence {
        native_kind: Some("process_exit".into()), ..Default::default()
    }));
    assert_eq!(message(&process, Language::Zh), "7z 工作进程故障（process_exit）：worker pipe closed");
    assert_eq!(message(&process, Language::En), "7z worker failure (process_exit): worker pipe closed");
    assert_eq!(serde_json::to_value(&process).unwrap()["message"], "worker pipe closed");
    let empty_process = Failure::new(FailureKind::ProcessError, "");
    assert_eq!(message(&empty_process, Language::Zh), "7z 工作进程故障（process_error）：worker failed without a result");
    let mut fault = crate::io::read_fault::ReadFault::short_read("read", 42, 16, 3, 45);
    fault.field = "7z.next_header";
    fault.location = crate::io::read_fault::FieldLocation::Tail;
    fault.volume_number = Some(2);
    let mut failure = Failure::new(FailureKind::Damaged, fault.to_string());
    failure.evidence = Some(Box::new(FailureEvidence {
        archive_read_fault: Some(ArchiveReadFault::from(&fault)), ..Default::default()
    }));
    assert_eq!(message(&failure, Language::Zh), "无法读取压缩包字段“7z 尾部 Next Header”（偏移 42，应读取 16 字节，实际读取 3 字节）；可能缺少分卷");
    let json = serde_json::to_value(&failure).unwrap();
    let read = &json["evidence"]["archive_read_fault"];
    assert_eq!(read["field"], "7z.next_header");
    assert_eq!(read["offset"], 42);
    assert_eq!(read["requested"], 16);
    assert_eq!(read["actual"], 3);
    assert_eq!(read["volume_number"], 2);
    assert_eq!(read["possible_missing_volume"], true);
    let restored: Failure = serde_json::from_value(json).unwrap();
    assert_eq!(message(&restored, Language::Zh), message(&failure, Language::Zh));
    assert_eq!(restored.message, fault.to_string());
}
