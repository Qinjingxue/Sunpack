use std::collections::HashSet;
use std::io;
use std::path::Path;

pub(crate) type DirectoryReadError = (String, String, String);
pub(crate) const DIRECTORY_ERROR_REPORT_LIMIT: usize = 100;

/// Diagnostics only: keep successful rows and bound memory on unreadable trees.
pub(crate) struct DirectoryReadErrors {
    scope: String,
    messages: Vec<DirectoryReadError>,
    omitted: usize,
    limit: usize,
    summary_operation: &'static str,
    keys: Option<HashSet<DirectoryReadError>>,
}

impl Default for DirectoryReadErrors {
    fn default() -> Self {
        Self {
            scope: String::new(),
            messages: Vec::new(),
            omitted: 0,
            limit: 20,
            summary_operation: "omitted",
            keys: None,
        }
    }
}

impl DirectoryReadErrors {
    pub(crate) fn report() -> Self {
        Self {
            limit: DIRECTORY_ERROR_REPORT_LIMIT,
            summary_operation: "report_omitted",
            keys: Some(HashSet::new()),
            ..Self::default()
        }
    }

    pub(crate) fn extend(&mut self, errors: Vec<DirectoryReadError>) {
        for error in errors {
            self.record(error);
        }
    }

    pub(crate) fn merge_report(&mut self, other: Self) {
        debug_assert_eq!(other.summary_operation, "report_omitted");
        self.extend(other.messages);
        self.omitted += other.omitted;
    }

    fn record(&mut self, error: DirectoryReadError) {
        if error.0 == "report_omitted" {
            self.omitted += directory_error_count(&error);
            return;
        }
        if let Some(keys) = &mut self.keys {
            let key = (
                error.0.clone(),
                crate::path_keys::path_key(&error.1),
                error.2.clone(),
            );
            if keys.contains(&key) {
                return;
            }
            if self.messages.len() < self.limit {
                keys.insert(key);
            }
        }
        if self.messages.len() < self.limit {
            self.messages.push(error);
        } else {
            self.omitted += directory_error_count(&error);
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.messages.is_empty() && self.omitted == 0
    }
    pub(crate) fn new(scope: &Path) -> Self {
        Self {
            scope: scope.to_string_lossy().into_owned(),
            ..Self::default()
        }
    }

    pub(crate) fn push(&mut self, path: &Path, operation: &str, error: io::Error) {
        self.push_detail(path, operation, error.to_string());
    }

    pub(crate) fn push_detail(&mut self, path: &Path, operation: &str, detail: String) {
        if self.keys.is_none() && self.messages.len() >= self.limit {
            self.omitted += 1;
        } else {
            self.record((
                operation.to_owned(),
                path.to_string_lossy().into_owned(),
                detail,
            ));
        }
    }

    pub(crate) fn into_messages(mut self) -> Vec<DirectoryReadError> {
        if self.omitted != 0 {
            self.messages.push((
                self.summary_operation.to_string(),
                self.scope,
                self.omitted.to_string(),
            ));
        }
        self.messages
    }
}

pub(crate) fn directory_error_count(error: &DirectoryReadError) -> usize {
    match error.0.as_str() {
        "omitted" | "report_omitted" | "output_scan" => error.2.parse().unwrap_or(1),
        _ => 1,
    }
}
