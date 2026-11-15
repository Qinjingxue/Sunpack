use std::collections::HashSet;
use std::io;
use std::path::Path;

pub(crate) type DirectoryReadError = (String, String, String);

#[derive(Default)]
pub(crate) struct DirectoryReadErrors {
    messages: Vec<DirectoryReadError>,
    keys: Option<HashSet<DirectoryReadError>>,
}

impl DirectoryReadErrors {
    pub(crate) fn report() -> Self {
        Self {
            keys: Some(HashSet::new()),
            ..Self::default()
        }
    }

    pub(crate) fn extend(&mut self, errors: Vec<DirectoryReadError>) {
        if self.keys.is_none() {
            self.messages.extend(errors);
        } else {
            for error in errors {
                self.record(error);
            }
        }
    }

    pub(crate) fn merge_report(&mut self, other: Self) {
        self.extend(other.messages);
    }

    fn record(&mut self, error: DirectoryReadError) {
        if let Some(keys) = &mut self.keys {
            let key = (
                error.0.clone(),
                crate::path_keys::path_key(&error.1),
                error.2.clone(),
            );
            if !keys.insert(key) {
                return;
            }
        }
        self.messages.push(error);
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    pub(crate) fn push(&mut self, path: &Path, operation: &str, error: io::Error) {
        self.record((
            operation.to_owned(),
            path.to_string_lossy().into_owned(),
            error.to_string(),
        ));
    }

    pub(crate) fn into_messages(self) -> Vec<DirectoryReadError> {
        self.messages
    }
}

#[cfg(test)]
#[path = "../../tests/unit/io/directory_errors/tests.rs"]
mod tests;
