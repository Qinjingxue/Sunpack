//! Stable CLI report envelope; nested objects use their native JSON representation.
use super::CommandResult;
use serde::{Serialize, Serializer};
use serde::ser::SerializeStruct;

impl Serialize for CommandResult {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut result = serializer.serialize_struct("CliCommandResult", 7)?;
        result.serialize_field("command", &self.command)?;
        result.serialize_field("inputs", &self.inputs)?;
        result.serialize_field("summary", &self.summary)?;
        result.serialize_field("errors", &self.errors)?;
        if let Some(sources) = &self.password_sources {
            result.serialize_field("items", &[sources.item()])?;
        } else {
            result.serialize_field("items", &self.items)?;
        }
        result.serialize_field("tasks", &self.tasks)?;
        result.serialize_field("logs", &self.logs)?;
        result.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
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
    fn cli_reports_preserve_values_and_array_order() {
        let mut result = CommandResult::new("passwords");
        result.inputs = json!({"json":true,"use_builtin_passwords":false});
        result.summary = json!({"user_password_count":1,"recent_password_count":2});
        let item = json!({"user_passwords":["second", "first"], "new_field":{"extra":42}});
        result.items.push(item.clone());
        let encoded = serde_json::to_value(result).unwrap();
        assert_eq!(encoded["items"], json!([item]));
        assert_eq!(encoded["summary"]["recent_password_count"], 2);
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
        let mut result = CommandResult::new("extract");
        let value = json!({"failures": [failure]});
        result.tasks.push(value.clone());
        let text = serde_json::to_string(&result).unwrap();
        let parsed = serde_json::from_str::<Value>(&text).unwrap();
        assert_eq!(parsed["tasks"], json!([value]));
    }

}
