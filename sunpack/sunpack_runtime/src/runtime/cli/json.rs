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
#[path = "../../../tests/unit/runtime/cli/json/tests.rs"]
mod tests;
