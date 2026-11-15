//! Human-facing projection shared by CLI and Watch. The serialized Failure
//! retains its original message and structured evidence for diagnosis.
use crate::core::i18n::Language;
use crate::pipeline::{Failure, FailureContext, FailureKind};
use std::borrow::Cow;

pub(super) mod report;

pub(super) enum MessageParams<'a> {
    None,
    Read { field: Cow<'static, str>, offset: u64, requested: usize, actual: usize },
    Process { kind: &'a str, message: &'a str },
    Error(&'a str),
}

impl serde::Serialize for MessageParams<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let count = match self { Self::None => 0, Self::Read { .. } => 4, Self::Process { .. } => 2, Self::Error(_) => 1 };
        let mut map = serializer.serialize_map(Some(count))?;
        match self {
            Self::None => {},
            Self::Read { field, offset, requested, actual } => {
                map.serialize_entry("field", field)?;
                map.serialize_entry("offset", offset)?;
                map.serialize_entry("requested", requested)?;
                map.serialize_entry("actual", actual)?;
            }
            Self::Process { kind, message } => {
                map.serialize_entry("kind", kind)?;
                map.serialize_entry("message", message)?;
            }
            Self::Error(error) => map.serialize_entry("error", error)?,
        }
        map.end()
    }
}

pub(super) struct Message<'a> {
    pub key: &'static str,
    pub params: MessageParams<'a>,
    raw: Option<&'a str>,
}

impl<'a> Message<'a> {
    pub(super) fn key(key: &'static str) -> Self { Self { key, params: MessageParams::None, raw: None } }
    pub(super) fn error(key: &'static str, error: &'a str) -> Self {
        Self { key, params: MessageParams::Error(error), raw: None }
    }
    pub fn render(&self, language: Language) -> Cow<'a, str> {
        if let Some(raw) = self.raw { return raw.into(); }
        match &self.params {
            MessageParams::None => language.text(self.key).into(),
            MessageParams::Read { field, offset, requested, actual } => language.translate(self.key, &[
                ("field", field), ("offset", &offset.to_string()),
                ("requested", &requested.to_string()), ("actual", &actual.to_string()),
            ]).into(),
            MessageParams::Process { kind, message } => language.translate(self.key, &[
                ("kind", kind), ("message", message),
            ]).into(),
            MessageParams::Error(error) => language.translate(self.key, &[("error", error)]).into(),
        }
    }
}

pub(super) fn message(failure: &Failure, language: Language) -> Cow<'_, str> {
    message_spec(failure, language).render(language)
}

// One key/parameter projection feeds human text and structured CLI reports.
pub(super) fn message_spec(failure: &Failure, language: Language) -> Message<'_> {
    describe(failure, language, true)
}

pub(super) fn original_message_spec(failure: &Failure, language: Language) -> Message<'_> {
    describe(failure, language, false)
}

fn describe(failure: &Failure, language: Language, warning: bool) -> Message<'_> {
    if let Some(FailureContext::OutputCreate { error, .. }) = failure.context.as_deref() {
        return Message::error("extract.dir_create_failed", error);
    }
    if warning && failure.evidence.as_deref().is_some_and(|e| e.possible_missing_volume) {
        return Message::key("failure.possible_missing_volume");
    }
    if matches!(failure.context.as_deref(), Some(FailureContext::WorkerWarning)) {
        return Message::key("failure.warning_busy_or_partial");
    }
    if failure.kind == FailureKind::PasswordInconclusive {
        return Message::key("failure.password_state_unknown");
    }
    if failure.kind != FailureKind::FilesystemError && failure.is_password_retry() {
        return Message::key("failure.password_not_in_list");
    }
    let evidence = failure.evidence.as_deref();
    if let Some(fault) = evidence.and_then(|evidence| evidence.archive_read_fault.as_ref()) {
        let key = if fault.possible_missing_volume {
            "failure.archive_field_read_failed_possible_missing_volume"
        } else {
            "failure.archive_field_read_failed"
        };
        let field_key = format!("archive.field.{}", fault.field);
        let field = language.lookup(&field_key).map_or(Cow::Owned(field_key), Cow::Borrowed);
        return Message { key, raw: None, params: MessageParams::Read {
            field, offset: fault.offset, requested: fault.requested, actual: fault.actual,
        } };
    }
    let reason = evidence.and_then(|evidence| evidence.native_kind.as_deref());
    if failure.kind == FailureKind::ProcessError {
        return Message { key: "failure.worker_process_failed", raw: None, params: MessageParams::Process {
            kind: reason.filter(|kind| !kind.is_empty()).unwrap_or("process_error"),
            message: if failure.message.trim().is_empty() {
                "worker failed without a result"
            } else { failure.message.trim() },
        } };
    }
    let key = match reason {
        Some("missing_volume") if evidence.and_then(|e| e.stage.as_deref()) == Some("discovery") => "failure.possible_missing_volume",
        Some("ambiguous_volume_mapping" | "structural_conflict") => "failure.possible_missing_volume",
        Some("needs_volume_or_tail_damaged") => "failure.missing_volume_or_tail_damaged",
        _ => match failure.kind {
            FailureKind::Damaged => "failure.damaged",
            FailureKind::MissingVolume => "failure.missing_volume",
            FailureKind::Unsupported => "failure.unsupported",
            FailureKind::BackendUnavailable => "failure.backend_unavailable",
            FailureKind::ResourceUnavailable => "failure.out_of_memory",
            FailureKind::Cancelled => "failure.user_interrupted",
            FailureKind::PasswordInconclusive => "failure.password_state_unknown",
            _ => return Message { key: "", params: MessageParams::None, raw: Some(&failure.message) },
        },
    };
    Message::key(key)
}

#[cfg(test)]
#[path = "../../tests/unit/runtime/failure/tests.rs"]
mod tests;
