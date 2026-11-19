//! Stable CLI report envelope; nested objects use their native JSON representation.
use super::{ArchiveResult, CommandResult, Language, failure_message, password_failure};
use serde::{Serialize, Serializer};
use serde::ser::{SerializeMap, SerializeSeq, SerializeStruct};

impl Serialize for CommandResult {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut result = serializer.serialize_struct("CliCommandResult", 7)?;
        result.serialize_field("command", &self.command)?;
        result.serialize_field("inputs", &self.inputs)?;
        result.serialize_field("summary", &self.summary)?;
        result.serialize_field("errors", &self.errors)?;
        if let Some(sources) = &self.password_sources {
            result.serialize_field("items", &[sources.item()])?;
        } else if let Some(report) = &self.scan_report {
            result.serialize_field("items", report)?;
        } else {
            result.serialize_field("items", &self.items)?;
        }
        result.serialize_field("tasks", &self.tasks)?;
        result.serialize_field("logs", &self.logs)?;
        result.end()
    }
}

pub(super) struct ScanReport {
    pub(super) archives: Vec<ArchiveResult>,
    pub(super) rows: Vec<(String, usize)>,
    pub(super) language: Language,
    pub(super) verbose: bool,
}

impl Serialize for ScanReport {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.rows.len()))?;
        for (key, index) in &self.rows {
            sequence.serialize_element(&ScanItem {
                entry: &self.archives[*index], key, language: self.language, verbose: self.verbose,
            })?;
        }
        sequence.end()
    }
}

struct ScanItem<'a> {
    entry: &'a ArchiveResult,
    key: &'a str,
    language: Language,
    verbose: bool,
}

impl Serialize for ScanItem<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let entry = self.entry;
        let (show_parts, completeness) = entry.scan_layout.volumes(entry);
        let mut item = serializer.serialize_map(None)?;
        if show_parts {
            item.serialize_entry("all_parts", &entry.source_paths)?;
        }
        if self.verbose {
            item.serialize_entry("discovery_source", &entry.discovery_source)?;
        }
        if entry.scan_layout.range {
            item.serialize_entry("end_offset", &entry.end_offset)?;
        }
        if let Some(failure) = &entry.failure {
            item.serialize_entry("error", &failure_message(failure, self.language))?;
            item.serialize_entry("error_kind", &failure.kind)?;
        }
        if !entry.format.is_empty() {
            item.serialize_entry("format", &entry.format)?;
        }
        item.serialize_entry("input_id", &format_args!("{}|{}|{}", self.key, entry.format, entry.offset))?;
        item.serialize_entry("main_path", &entry.path)?;
        if entry.scan_layout.range {
            item.serialize_entry("offset", &entry.offset)?;
        }
        if entry.encrypted == Some(true) || entry.password.is_some() || password_failure(entry) {
            item.serialize_entry("password_used", &entry.password)?;
        }
        if let Some(plan) = entry.volume_attempts.as_deref() {
            item.serialize_entry("volume_attempts", plan)?;
        }
        if let Some(value) = completeness {
            item.serialize_entry("volume_completeness", value)?;
        }
        item.end()
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/runtime/cli/json/tests.rs"]
mod tests;
