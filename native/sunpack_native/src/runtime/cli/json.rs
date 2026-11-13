//! CLI presentation order follows main's report dictionaries, without changing
//! serde_json's maps globally or copying the report into a second JSON tree.
use super::{CommandResult, Value};
use crate::core::config::order::{Order, Ordered};
use serde::{Serialize, Serializer};
use serde::ser::{SerializeMap, SerializeSeq, SerializeStruct};

const PASSWORDS: &[&str] = &["user_passwords", "clipboard_passwords", "recent_passwords", "builtin_passwords", "use_builtin_passwords", "combined_passwords"];
const COUNTS: &[&str] = &["success_count", "failed_count", "scan_error_count", "scan_failures", "input_error_count", "processed_count", "partial_success_count", "recovered_outputs", "use_builtin_passwords", "password_retry_count", "cleanup_results"];
const FAILURE: &[&str] = &["kind", "stage", "message", "message_key", "message_params", "user_action", "causes", "details"];
const WATCH: &[&str] = &["roots_path", "added", "updated", "removed", "rejected", "apply", "start", "start_requested", "started", "stopped", "reloaded", "running", "generation", "pending", "last_error", "count", "state_dir", "exit_code", "enabled", "command", "changed", "rebuilt"];

fn child_order(key: &str, value: &Value) -> &'static [&'static str] {
    match key {
        "config_overrides" => &["recursive_extract", "archive_cleanup_mode", "output_dir", "flatten_single_directory"],
        "cleanup_results" => &["path", "mode", "status", "error_code", "message"],
        "recovered_outputs" => &["archive", "out_dir", "complete_files", "warning"],
        "warning" => FAILURE,
        "failure" | "failures" | "causes" | "scan_failures" => FAILURE,
        "message_params" if value.get("field").is_some() => &["field", "offset", "requested", "actual"],
        "message_params" if value.get("kind").is_some() => &["kind", "message"],
        "message_params" => &["path", "error", "code"],
        "details" => details_order(value),
        "read_error" => &["code", "operation", "field", "location", "offset", "requested", "actual", "source_len", "volume_number", "io_kind", "os_error", "detail", "possible_missing_volume"],
        "discovery_scope" => &["root", "max_depth", "excluded_subtrees"],
        "input_recovery" => &["inputs", "output_dir", "input_count"],
        "inputs" => &["input_id", "position", "archive_input", "generation", "output_dir", "complete", "blockers", "failure", "files_written", "bytes_written", "recovered_complete_files"],
        "archive_input" => &["kind", "entry_path", "open_mode", "format_hint", "volume_attempts", "parts", "ranges", "logical_name", "volume_style", "analysis"],
        "parts" => &["path", "role", "volume_number", "canonical_name", "start", "end"],
        "ranges" => &["path", "start", "end"],
        "volume_attempts" => &["sources", "domains", "layouts", "head_size_from_total", "minimum_size", "tail_totals"],
        "sources" => &["path", "start", "end"],
        "domains" => &["choices"],
        "layouts" => &["slots", "minimum_slots"],
        "slots" => &["number", "canonical_name", "domain"],
        "tail_totals" => &["source", "total"],
        "start" => WATCH,
        "apply" => &["roots_path", "added", "updated", "removed", "rejected", "applied", "running", "generation"],
        _ => &[],
    }
}

// FailureInfo.details is a collection of creation-boundary projections, not
// one uniform object. In particular, discovery starts with a path whereas a
// promoted extraction appends its path after the already recorded scope.
fn details_order(value: &Value) -> &'static [&'static str] {
    if value.get("reason").is_some() {
        &["path", "reason", "input_recovery", "retry_output_dir", "discovery_scope", "promoted_nested_input"]
    } else if value.get("operation").is_some() && value.get("count").is_some() {
        &["path", "operation", "count", "discovery_scope", "promoted_nested_input"]
    } else if value.get("partial_recovery").is_some() {
        // archive_job copies recovery facts before constructing the warning.
        &["input_recovery", "retry_output_dir", "missing_volume_confirmed", "evidence", "partial_recovery", "original_failure_kind", "discovery_scope", "path", "promoted_nested_input"]
    } else {
        &["segment_count", "failed_segment_count", "diagnostic", "read_error",
          "failure_kind", "failure_stage", "hresult", "message", "exit_code", "exit_code_hex",
          "missing_volume_confirmed", "missing_paths", "evidence", "missing_volume_name",
          "password_crc_proven_items", "backend_operation_result", "destination",
          "input_recovery", "retry_output_dir", "discovery_scope", "path", "promoted_nested_input"]
    }
}

struct Projection<'a>(&'a Value, &'static [&'static str]);
impl Serialize for Projection<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            Value::Object(values) => {
                let mut map = serializer.serialize_map(Some(values.len()))?;
                for key in self.1 {
                    if let Some(value) = values.get(*key) {
                        map.serialize_entry(key, &Projection(value, child_order(key, value)))?;
                    }
                }
                // Preserve additional diagnostics instead of silently dropping
                // data not part of a fixed public projection.
                for (key, value) in values {
                    if !self.1.contains(&key.as_str()) {
                        map.serialize_entry(key, &Projection(value, child_order(key, value)))?;
                    }
                }
                map.end()
            }
            Value::Array(values) => {
                let mut seq = serializer.serialize_seq(Some(values.len()))?;
                for value in values { seq.serialize_element(&Projection(value, self.1))?; }
                seq.end()
            }
            value => value.serialize(serializer),
        }
    }
}

struct Items<'a>(&'a [Value], &'static [&'static str], Option<&'a Order>);
impl Serialize for Items<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for value in self.0 {
            if let Some(order) = self.2 { seq.serialize_element(&Ordered(value, order))?; }
            else { seq.serialize_element(&Projection(value, self.1))?; }
        }
        seq.end()
    }
}

impl Serialize for CommandResult {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let inputs = match self.command {
            "extract" => &["paths", "common_root", "json", "verbose", "config_overrides", "direct_file", "deep_detect"][..],
            "scan" => &["paths", "deep_detect"],
            "passwords" => &["json", "use_builtin_passwords"],
            "watch" => &["action", "paths", "output_dir", "deep_detect", "once", "startup_action"],
            "config" => &["action"],
            _ => &[],
        };
        let summary = if self.summary.get("status").is_some() { &["status", "conflicts"][..] }
            else if self.summary.get("interrupted").is_some() { &["interrupted", "cleanup_complete"] }
            else { match self.command {
                "extract" => COUNTS,
                "scan" => &["archive_count", "failed_count", "scan_error_count", "input_error_count"],
                "passwords" => &["user_password_count", "recent_password_count", "clipboard_password_count", "builtin_password_count", "combined_password_count"],
                "doctor" => &["checks", "ok", "warnings", "skipped", "failed"],
                "config" => &["config_path", "changed", "valid"],
                "watch" => WATCH,
                _ => &[],
            }};
        let items = match self.command {
            "extract" | "passwords" => PASSWORDS,
            "scan" => &["main_path", "input_id", "format", "offset", "end_offset", "password_used", "volume_attempts", "all_parts", "volume_completeness", "error_kind", "error", "discovery_source", "damage_flags"],
            "doctor" => &["name", "status", "detail", "config_path", "errors", "path"],
            "config" => &["ok", "errors", "warnings"],
            _ => &[],
        };
        let mut result = serializer.serialize_struct("CliCommandResult", 7)?;
        result.serialize_field("command", &self.command)?;
        result.serialize_field("inputs", &Projection(&self.inputs, inputs))?;
        result.serialize_field("summary", &Projection(&self.summary, summary))?;
        result.serialize_field("errors", &self.errors)?;
        result.serialize_field("items", &Items(&self.items, items, self.config_order.as_ref()))?;
        result.serialize_field("tasks", &Items(&self.tasks, &["success_count", "failed_count", "scan_error_count", "input_error_count", "processed_count", "partial_success_count", "recovered_outputs", "wrong_password_failure", "failures"], None))?;
        result.serialize_field("logs", &self.logs)?;
        result.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn cli_reports_follow_main_field_order_without_changing_values() {
        let mut result = CommandResult::new("passwords");
        result.inputs = json!({"json":true,"use_builtin_passwords":false});
        result.summary = json!({"user_password_count":1,"recent_password_count":2,"clipboard_password_count":3,"builtin_password_count":4,"combined_password_count":5});
        result.items.push(json!({"user_passwords":[],"clipboard_passwords":[],"recent_passwords":[],"builtin_passwords":[],"use_builtin_passwords":false,"combined_passwords":[]}));
        let text = serde_json::to_string(&result).unwrap();
        assert!(text.contains(r#""summary":{"user_password_count":1,"recent_password_count":2,"clipboard_password_count":3,"builtin_password_count":4,"combined_password_count":5}"#));
        assert!(text.contains(r#""items":[{"user_passwords":[],"clipboard_passwords":[],"recent_passwords":[],"builtin_passwords":[],"use_builtin_passwords":false,"combined_passwords":[]}]"#));
        let plan = json!({"volume_attempts":{"sources":[{"path":"x","start":0,"end":10}],"domains":[{"choices":[0]}],"layouts":[{"slots":[{"number":1,"canonical_name":"x","domain":0}],"minimum_slots":2}]}});
        let text = serde_json::to_string(&Projection(&plan, &[])).unwrap();
        assert!(text.contains(r#""sources":[{"path":"x","start":0,"end":10}],"domains""#));
        assert!(text.contains(r#""number":1,"canonical_name":"x","domain":0"#));
        assert_eq!(serde_json::from_str::<Value>(&text).unwrap(), plan);
    }

    #[test]
    fn nested_failure_fields_keep_main_creation_and_annotation_order() {
        // Parsing each expected receipt first intentionally loses insertion
        // order. The final CLI projection must reconstruct it, including
        // nested causes and the scope-before-path promotion boundary.
        for expected in [
            r#"{"message_params":{"field":"header","offset":8,"requested":16,"actual":2}}"#,
            r#"{"message_params":{"kind":"pipe_closed","message":"worker exited"}}"#,
            r#"{"message_params":{"path":"x","error":"denied"}}"#,
            r#"{"details":{"segment_count":2,"failed_segment_count":1,"discovery_scope":{"root":"in","max_depth":null,"excluded_subtrees":[]},"path":"out/x","promoted_nested_input":true}}"#,
            r#"{"details":{"path":"x","reason":"missing_volume","discovery_scope":{"root":"in","max_depth":1,"excluded_subtrees":[]},"promoted_nested_input":true}}"#,
            r#"{"details":{"path":"x","operation":"open","count":1}}"#,
            r#"{"details":{"missing_volume_confirmed":true,"evidence":"structured_worker_result","missing_volume_name":"part02.rar"}}"#,
            r#"{"details":{"missing_volume_confirmed":true,"missing_paths":["part02.rar"]}}"#,
            r#"{"details":{"failure_kind":"resource_unavailable","failure_stage":"item_extract","hresult":-1,"message":"memory"}}"#,
            r#"{"details":{"failure_kind":"process_exit","failure_stage":"worker_process","message":"exited"}}"#,
            r#"{"details":{"failure_stage":"worker_process","exit_code":-1,"exit_code_hex":"0xFFFFFFFF"}}"#,
            r#"{"details":{"evidence":"entry_crc_proven_before_failure","password_crc_proven_items":1}}"#,
            r#"{"details":{"evidence":"zipcrypto_failure_without_password_proof","backend_operation_result":"crc_error"}}"#,
            r#"{"details":{"input_recovery":{"inputs":[],"output_dir":"out","input_count":1},"retry_output_dir":"out","missing_volume_confirmed":false,"evidence":"partial_recovery_on_split_input","partial_recovery":true,"original_failure_kind":"damaged","discovery_scope":{"root":"in","max_depth":1,"excluded_subtrees":[]}}}"#,
            r#"{"details":{"diagnostic":"short","read_error":{"code":"unexpected_eof","operation":"read_exact","field":"header","location":"tail","offset":8,"requested":16,"actual":2,"source_len":10,"volume_number":null,"io_kind":"unexpectedeof","os_error":null,"detail":"short","possible_missing_volume":true}}}"#,
            r#"{"causes":[{"kind":"damaged","stage":"extraction","message":"bad","message_key":"failure.damaged","message_params":{},"user_action":"","causes":[],"details":{"missing_volume_confirmed":false,"evidence":"structured_worker_result"}}]}"#,
        ] {
            let value: Value = serde_json::from_str(expected).unwrap();
            assert_eq!(serde_json::to_string(&Projection(&value, &[])).unwrap(), expected);
        }
    }

}
