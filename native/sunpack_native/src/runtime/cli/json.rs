//! Stable CLI report envelopes without changing serde_json maps globally or
//! copying reports. Open diagnostic payloads retain their native map order.
use super::{CommandResult, Value};
use serde::{Serialize, Serializer};
use serde::ser::{SerializeMap, SerializeSeq, SerializeStruct};

const PASSWORDS: &[&str] = &["user_passwords", "clipboard_passwords", "recent_passwords", "builtin_passwords", "use_builtin_passwords", "combined_passwords"];
const COUNTS: &[&str] = &["success_count", "failed_count", "scan_error_count", "scan_failures", "input_error_count", "processed_count", "partial_success_count", "recovered_outputs", "use_builtin_passwords", "password_retry_count", "cleanup_results"];
const FAILURE: &[&str] = &["kind", "stage", "message", "message_key", "message_params", "user_action", "causes", "details"];
const WATCH: &[&str] = &["roots_path", "added", "updated", "removed", "rejected", "apply", "start", "start_requested", "started", "stopped", "reloaded", "running", "generation", "pending", "last_error", "count", "state_dir", "exit_code", "enabled", "command", "changed", "rebuilt"];

fn child_order(key: &str) -> &'static [&'static str] {
    match key {
        "config_overrides" => &["recursive_extract", "archive_cleanup_mode", "output_dir", "flatten_single_directory"],
        "cleanup_results" => &["path", "mode", "status", "error_code", "message"],
        "recovered_outputs" => &["archive", "out_dir", "complete_files", "warning"],
        "warning" => FAILURE,
        "failure" | "failures" | "causes" | "scan_failures" => FAILURE,
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

// Diagnostics are deliberately opaque here: field names such as `reason` or
// `partial_recovery` do not identify a schema or a historical insertion order.
// Serialize them directly, including unknown nested fields, without traversing
// them through the presentation projection.
struct Child<'a>(&'a str, &'a Value);
impl Serialize for Child<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            "details" | "message_params" => self.1.serialize(serializer),
            key => Projection(self.1, child_order(key)).serialize(serializer),
        }
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
                        map.serialize_entry(key, &Child(key, value))?;
                    }
                }
                // Preserve additional diagnostics instead of silently dropping
                // data not part of a fixed public projection.
                for (key, value) in values {
                    if !self.1.contains(&key.as_str()) {
                        map.serialize_entry(key, &Child(key, value))?;
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

struct Items<'a>(&'a [Value], &'static [&'static str]);
impl Serialize for Items<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for value in self.0 {
            seq.serialize_element(&Projection(value, self.1))?;
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
        if self.command == "config" && self.inputs.get("action").and_then(Value::as_str) == Some("show") {
            result.serialize_field("items", &self.items)?;
        } else {
            result.serialize_field("items", &Items(&self.items, items))?;
        }
        result.serialize_field("tasks", &Items(&self.tasks, &["success_count", "failed_count", "scan_error_count", "input_error_count", "processed_count", "partial_success_count", "recovered_outputs", "wrong_password_failure", "failures"]))?;
        result.serialize_field("logs", &self.logs)?;
        result.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn config_items_preserve_all_values_without_parallel_order_metadata() {
        let mut result = CommandResult::new("config");
        result.inputs = json!({"action":"show"});
        let document = json!({"z": {"details": {"unfamiliar": 1, "reason": "opaque"}},
            "filesystem": {"scan_filters": [{"name":"b"}, {"name":"a"}]},
            "user_passwords": ["second", "first"]});
        result.items.push(document.clone());
        let encoded = serde_json::to_value(result).unwrap();
        assert_eq!(encoded["items"], json!([document]));
    }

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
    fn open_diagnostics_preserve_values_without_shape_based_ordering() {
        let details = json!({
            "reason": "missing_volume", "operation": "read", "count": 1,
            "partial_recovery": true, "path": "x", "future_field": [null, true, 7],
            "input_recovery": {"inputs": [{"new_member": "kept"}]},
            "warning": {"stage": "opaque", "kind": "not_a_report"},
            "nested": {"details": {"z": 0, "reason": "opaque", "a": 1}}
        });
        let params = json!({"field": "header", "kind": "pipe_closed", "path": "x", "extra": {"start": {"z": 1, "running": true}}});
        let failure = json!({
            "kind": "damaged", "stage": "extraction", "message": "bad",
            "message_key": "failure.damaged", "message_params": params,
            "user_action": "", "causes": [], "details": details,
            "new_report_field": {"value": 42}
        });
        let value = json!({"failures": [failure]});
        let text = serde_json::to_string(&Projection(&value, &[])).unwrap();
        assert!(text.starts_with(r#"{"failures":[{"kind":"damaged","stage":"extraction","message":"bad","message_key":"failure.damaged","message_params":"#));
        assert!(text.contains(&format!("\"details\":{}", serde_json::to_string(&details).unwrap())));
        assert!(text.contains(&format!("\"message_params\":{}", serde_json::to_string(&params).unwrap())));
        assert_eq!(serde_json::from_str::<Value>(&text).unwrap(), value);
    }

}
