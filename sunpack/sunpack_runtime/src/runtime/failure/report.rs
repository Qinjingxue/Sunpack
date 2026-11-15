//! Public failure reports for CLI and Watch. Execution keeps native evidence; this projection
//! uses the recorded creation boundary, never a guessed native worker phase.
use crate::core::i18n::Language;
use crate::pipeline::{ArchiveResult, DiscoverySource, Failure, FailureContext, FailureKind, InputError};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;

pub(in crate::runtime) struct Report<'a> {
    kind: &'static str,
    stage: &'static str,
    message: String,
    message_key: std::borrow::Cow<'static, str>,
    message_params: Value,
    user_action: &'static str,
    causes: Vec<Report<'a>>,
    details: Value,
    recovery: Option<(&'a crate::pipeline::InputRecovery, Language)>,
}

impl Serialize for Report<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut report = serializer.serialize_struct("Report", 8)?;
        report.serialize_field("kind", &self.kind)?;
        report.serialize_field("stage", &self.stage)?;
        report.serialize_field("message", &self.message)?;
        report.serialize_field("message_key", &self.message_key)?;
        report.serialize_field("message_params", &self.message_params)?;
        report.serialize_field("user_action", &self.user_action)?;
        report.serialize_field("causes", &self.causes)?;
        report.serialize_field("details", &ReportDetails(self))?;
        report.end()
    }
}

struct ReportDetails<'r, 'a>(&'r Report<'a>);
impl Serialize for ReportDetails<'_, '_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let details = self.0.details.as_object().expect("report details object");
        let recovery = self.0.recovery;
        let retry_output = recovery.and_then(|(recovery, _)| recovery.retry_output());
        let mut map = serializer.serialize_map(Some(details.len() + usize::from(recovery.is_some()) + usize::from(retry_output.is_some())))?;
        let mut fields = details.iter().peekable();
        for special in ["input_recovery", "retry_output_dir"] {
            while fields.peek().is_some_and(|(key, _)| key.as_str() < special) {
                let (key, value) = fields.next().unwrap();
                map.serialize_entry(key, value)?;
            }
            if special == "input_recovery" {
                if let Some((recovery, language)) = recovery {
                    map.serialize_entry(special, &recovery.report_view(|failure| Report::from_failure(failure, language)))?;
                }
            } else if let Some(output) = retry_output {
                map.serialize_entry(special, output)?;
            }
        }
        for (key, value) in fields { map.serialize_entry(key, value)?; }
        map.end()
    }
}

fn read_error(fault: &crate::pipeline::ArchiveReadFault) -> Value {
    json!({
        "code": fault.code, "operation": fault.operation, "field": fault.field,
        "location": fault.location, "offset": fault.offset, "requested": fault.requested,
        "actual": fault.actual, "source_len": fault.source_len, "volume_number": fault.volume_number,
        "io_kind": fault.io_kind.to_lowercase(), "os_error": fault.os_error, "detail": fault.detail,
        "possible_missing_volume": fault.possible_missing_volume,
    })
}

pub(in crate::runtime) fn recovery(failure: &Failure) -> Option<&crate::pipeline::InputRecovery> {
    failure.recovery.as_deref()
}

fn kind_name(kind: FailureKind) -> &'static str {
    match kind {
        FailureKind::Cancelled => "cancelled",
        FailureKind::InvalidInput => "invalid_input",
        FailureKind::FilesystemError => "filesystem_error",
        FailureKind::ProcessError => "process_error",
        FailureKind::BackendUnavailable => "backend_unavailable",
        FailureKind::Unsupported => "unsupported",
        FailureKind::MissingVolume => "missing_volume",
        FailureKind::PasswordRequired => "password_required",
        FailureKind::WrongPassword => "wrong_password",
        FailureKind::PasswordInconclusive => "password_inconclusive",
        FailureKind::Damaged => "damaged",
        FailureKind::ResourceUnavailable => "resource_unavailable",
        FailureKind::Unknown => "unknown",
    }
}

impl<'a> Report<'a> {
    fn attach_recovery(&mut self, recovery: &'a crate::pipeline::InputRecovery, language: Language) {
        self.recovery = Some((recovery, language));
    }

    pub(in crate::runtime) fn from_failure(failure: &'a Failure, language: Language) -> Self {
        let context = failure.context.as_deref();
        let mut spec = super::original_message_spec(failure, language);
        let mut stage = "";
        let mut details = json!({});
        let mut user_action = if failure.is_password_retry() { "request_password" } else { "" };
        let mut raw_message = None;
        let mut message_language = language;
        match context {
            Some(FailureContext::Discovery { discovery, path, reason, error }) => {
                stage = match discovery {
                    DiscoverySource::Embedded => "embedded_boundary",
                    DiscoverySource::Relations => "relations",
                    DiscoverySource::Detection => "detection",
                    DiscoverySource::Direct => "direct",
                };
                details = json!({"path": path, "reason": reason});
                // Preflight uses the localized discovery reason when it has a
                // message key. Native I/O diagnostics have no translation key.
                if spec.key.is_empty() {
                    raw_message = Some(error.clone());
                }
            }
            Some(FailureContext::InputAdmission { missing_paths }) => {
                stage = "input_admission";
                message_language = Language::En;
                spec = super::Message::key("failure.missing_volume");
                user_action = "";
                details = json!({"missing_volume_confirmed": true, "missing_paths": missing_paths});
            }
            Some(FailureContext::PasswordResolution) => {
                stage = "password_resolution";
                if failure.kind == FailureKind::MissingVolume { user_action = "wait_for_volume"; }
                if failure.kind == FailureKind::BackendUnavailable {
                    spec = super::Message::key("failure.password_verifier_unavailable");
                }
                let evidence = failure.evidence.as_deref()
                    .filter(|e| e.stage.as_deref() == Some("password_preflight"));
                let diagnostic = if evidence.is_some() {
                    failure.message.as_str()
                } else if failure.kind == FailureKind::PasswordRequired {
                    "archive requires a password but no candidates were provided"
                } else {
                    ""
                };
                let read_error = evidence
                    .and_then(|evidence| evidence.archive_read_fault.as_ref())
                    .map(read_error);
                details = json!({"diagnostic": diagnostic, "read_error": read_error});
            }
            Some(FailureContext::WorkerWarning) => {
                stage = "extraction";
                message_language = Language::En;
            }
            Some(FailureContext::Extraction) => {
                stage = "extraction";
                // main's worker classifier stores English text; its consumers
                // use message_key/params to render the requested language.
                message_language = Language::En;
                let evidence = failure.evidence.as_deref();
                if failure.kind == FailureKind::ResourceUnavailable {
                    details = json!({
                        "failure_kind": "resource_unavailable",
                        "failure_stage": evidence.and_then(|e| e.stage.as_deref()).unwrap_or(""),
                        "hresult": evidence.and_then(|e| e.hresult),
                        "message": failure.message,
                    });
                } else if failure.kind == FailureKind::ProcessError {
                    let kind = evidence.and_then(|e| e.native_kind.as_deref()).unwrap_or("process_error");
                    let phase = evidence.and_then(|e| e.stage.as_deref()).unwrap_or("worker_process");
                    details = json!({"failure_kind": kind, "failure_stage": phase,
                        "message": if failure.message.trim().is_empty() { "worker failed without a result" } else { failure.message.trim() }});
                } else if failure.kind == FailureKind::MissingVolume
                    || evidence.is_some_and(|e| e.missing_volume_suspected)
                {
                    details = json!({"missing_volume_confirmed": failure.kind == FailureKind::MissingVolume,
                        "evidence": evidence.and_then(|e| e.missing_volume_evidence.as_deref()).unwrap_or("structured_worker_result")});
                    if let Some(name) = evidence.and_then(|e| e.missing_volume_name.as_deref()).filter(|name| !name.is_empty()) {
                        details["missing_volume_name"] = json!(name);
                    }
                } else if failure.kind == FailureKind::PasswordInconclusive && failure.password_retry {
                    details["evidence"] = json!("password_or_volume_inconclusive");
                } else if let Some(evidence) = evidence {
                    if let Some(value) = &evidence.classification_evidence { details["evidence"] = json!(value); }
                    if let Some(value) = evidence.password_crc_proven_items { details["password_crc_proven_items"] = json!(value); }
                    if let Some(value) = &evidence.backend_operation_result { details["backend_operation_result"] = json!(value); }
                }
            }
            Some(FailureContext::OutputCreate { .. }) => {
                stage = "preflight";
            }
            None => {
                // Older persisted failures lack the creation boundary. Preserve
                // their original facts rather than inventing a stage or key.
                spec = super::Message::key("");
                raw_message = Some(failure.message.clone());
            }
        }
        let params = serde_json::to_value(&spec.params).expect("failure parameters serialize");
        Self {
            kind: kind_name(failure.kind), stage,
            message: raw_message.unwrap_or_else(|| spec.render(message_language).into_owned()),
            message_key: spec.key.into(), message_params: params, user_action,
            causes: Vec::new(),
            details, recovery: None,
        }
    }

    pub(in crate::runtime) fn input_error(error: &'a InputError, language: Language) -> Self {
        if let Some(failure) = error.failure.as_deref() {
            Self::from_failure(failure, language)
        } else {
            Self::invalid(error, language)
        }
    }

    pub(in crate::runtime) fn filesystem_scan(error: &InputError, language: Language) -> Self {
        let operation = error.scan_operation.as_deref().unwrap_or("");
        let key = format!("filesystem_scan.{operation}");
        let message = language.translate(&key, &[("path", &error.path.to_string_lossy()), ("error", &error.message)]);
        Self {
            kind: "filesystem_error", stage: "filesystem_scan", message,
            message_key: key.into(), message_params: json!({"path": error.path, "error": error.message}),
            user_action: "", causes: vec![],
            details: json!({"path": error.path, "operation": operation, "count": error.count()}), recovery: None,
        }
    }

    fn invalid(error: &InputError, language: Language) -> Self {
        let key = "failure.direct_file_required";
        let message = invalid_input_message(error, language);
        Self {
            kind: "invalid_input", stage: "input", message,
            message_key: key.into(), message_params: json!({"path": error.path}), user_action: "", causes: vec![],
            details: json!({"path": error.path}), recovery: None,
        }
    }
}

pub(in crate::runtime) fn invalid_input_message(error: &InputError, language: Language) -> String {
    language.translate("failure.direct_file_required", &[("path", &error.path.to_string_lossy())])
}

fn aggregate_key(all_password: bool) -> &'static str {
    if all_password { "failure.password_not_in_list" } else { "failure.embedded_extract_failed" }
}

/// Summary text uses the same carrier decision without allocating JSON reports.
pub(in crate::runtime) fn carrier_message<'a>(entries: &[&'a ArchiveResult], language: Language) -> std::borrow::Cow<'a, str> {
    let failures = || entries.iter().filter_map(|entry| entry.failure.as_ref());
    if failures().any(|failure| failure.evidence.as_deref().is_some_and(|e| e.possible_missing_volume)) {
        return language.text("failure.possible_missing_volume").into();
    }
    scan_message(entries.iter().copied(), language)
}

pub(in crate::runtime) fn scan_message<'a>(entries: impl Iterator<Item = &'a ArchiveResult> + ExactSizeIterator, language: Language) -> std::borrow::Cow<'a, str> {
    let count = entries.len();
    let mut failures = entries.filter_map(|entry| entry.failure.as_ref());
    if count > 1 {
        let key = aggregate_key(failures.all(|failure| matches!(failure.kind, FailureKind::PasswordRequired | FailureKind::WrongPassword)));
        return language.text(key).into();
    }
    failures.next().map_or_else(|| "".into(), |failure| super::original_message_spec(failure, language).render(language))
}

fn aggregate<'a>(causes: Vec<Report<'a>>, count: usize, language: Language) -> Report<'a> {
    let (key, params, message, action) = if count == 1 && causes.len() == 1 {
        let child = &causes[0];
        let params: Vec<_> = child.message_params.as_object().into_iter().flatten()
            .map(|(key, value)| (key.as_str(), value.as_str().map(str::to_owned).unwrap_or_else(|| value.to_string())))
            .collect();
        let rendered = if child.message_key.is_empty() { child.message.clone() } else {
            language.translate(&child.message_key, &params.iter().map(|(key, value)| (*key, value.as_str())).collect::<Vec<_>>())
        };
        (child.message_key.clone(), child.message_params.clone(), rendered, child.user_action)
    } else {
        let key = aggregate_key(causes.iter().all(|cause| matches!(cause.kind, "password_required" | "wrong_password")));
        let action = if causes.iter().any(|cause| cause.user_action == "request_password") { "request_password" } else { "" };
        (key.into(), json!({}), language.text(key).to_owned(), action)
    };
    Report { kind: "inputs_failed", stage: "inputs", message, message_key: key.into(),
        message_params: params, user_action: action,
        details: json!({"segment_count": count, "failed_segment_count": causes.len()}), causes, recovery: None }
}

pub(in crate::runtime) fn archive_groups<'a>(archives: impl IntoIterator<Item = &'a ArchiveResult>) -> Vec<Vec<&'a ArchiveResult>> {
    let mut positions = HashMap::new();
    let mut groups: Vec<Vec<&ArchiveResult>> = Vec::new();
    for archive in archives {
        let key = (crate::watch_store::watch_path_key(&archive.path.to_string_lossy()), archive.depth);
        let position = *positions.entry(key).or_insert_with(|| { groups.push(Vec::new()); groups.len() - 1 });
        groups[position].push(archive);
    }
    groups
}

pub(in crate::runtime) fn archive_report<'a>(entries: &[&'a ArchiveResult], language: Language) -> Option<Report<'a>> {
    archive_projection(entries, language, has_recovery_warning(entries))
}

pub(in crate::runtime) fn recovery_warning<'a>(entries: &[&'a ArchiveResult], language: Language) -> Option<Report<'a>> {
    if !has_recovery_warning(entries) { return None; }
    archive_projection(entries, language, true)
}

pub(in crate::runtime) fn has_recovery_warning(entries: &[&ArchiveResult]) -> bool {
    let failures = || entries.iter().filter_map(|entry| entry.failure.as_ref());
    !failures().any(|failure| failure.kind == FailureKind::MissingVolume)
        && failures().any(|failure| failure.evidence.as_deref().is_some_and(|e| e.possible_missing_volume))
}

fn archive_projection<'a>(entries: &[&'a ArchiveResult], language: Language, warning: bool) -> Option<Report<'a>> {
    let mut causes: Vec<_> = entries.iter().filter_map(|entry| entry.failure.as_ref())
        .map(|failure| Report::from_failure(failure, language)).collect();
    if causes.is_empty() { return None; }
    let recovery = entries.iter().filter_map(|entry| entry.failure.as_ref()).find_map(recovery);
    let report_count = recovery.map_or(entries.len(), |recovery| recovery.input_count());
    let aggregated = entries.len() > 1 || recovery.is_some_and(|recovery| recovery.aggregated());
    // Admission inspects the physical task before per-input execution.
    // Its repeated receipts are one task failure, not failed segments.
    let admission = entries.iter().all(|entry| entry.failure.as_ref().is_some_and(|failure|
        matches!(failure.context.as_deref(), Some(FailureContext::InputAdmission { .. }))));
    let mut report = if admission { causes.remove(0) } else if aggregated {
        aggregate(causes, report_count, language)
    } else { causes.remove(0) };
    if let Some(recovery) = recovery { report.attach_recovery(recovery, language); }
    if warning {
        let partial = entries.iter().any(|entry| entry.partial)
            && entries.iter().all(|entry| entry.failure.is_none() || entry.partial);
        let key = "failure.possible_missing_volume";
        let details = json!({"missing_volume_confirmed": false,
            "evidence": if partial { "partial_recovery_on_split_input" } else { "backend_possible_missing_volume" },
            "partial_recovery": partial, "original_failure_kind": report.kind});
        let shared_recovery = report.recovery;
        report = Report { kind: "damaged", stage: "extraction_report",
            message: language.text(key).to_owned(), message_key: key.into(),
            message_params: json!({}), user_action: "", causes: vec![report], details, recovery: shared_recovery };
    }
    if let Some(scope) = entries.iter().filter_map(|entry| entry.failure.as_ref())
        .find_map(|failure| failure.discovery_scope.as_deref())
    {
        report.details["discovery_scope"] = json!(scope);
    }
    if entries.iter().any(|entry| entry.depth > 1) {
        report.details["path"] = json!(entries[0].path);
        report.details["nested_input"] = json!(true);
    }
    Some(report)
}

#[cfg(test)]
#[path = "../../../tests/unit/runtime/failure/report/tests.rs"]
mod tests;
