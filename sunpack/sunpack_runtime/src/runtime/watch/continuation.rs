//! Durable completion of a Watch task whose recursive inputs are blocked.
use super::*;
use crate::watch_store::{continuation_output_key, NativeWatchOperations, CONTINUATION_PREFIX};
use serde::Serialize;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct Parent {
    pub id: String,
    pub depth: usize,
}

#[derive(Default, Deserialize, Serialize)]
pub(super) struct Continuation {
    remaining: usize,
    abandoned: bool,
    root: String,
    event: Value,
    #[serde(skip)]
    new_blockers: Vec<String>,
}

#[derive(Deserialize, Serialize)]
struct Directory {
    path: PathBuf,
    identity: String,
}

impl Continuation {
    pub(super) fn id(batch: &str, owner: &str) -> String {
        format!("{CONTINUATION_PREFIX}{batch}|{owner}")
    }

    pub(super) fn load(journal: &journal::Journal, id: &str) -> io::Result<Option<Self>> {
        journal
            .state()
            .runtime_record(id)
            .map(|value| Self::deserialize(value.as_ref()).map_err(io::Error::other))
            .transpose()
    }

    pub(super) fn begin(&mut self, root: &str, event: Value) {
        self.root = root.to_owned();
        self.event = event;
    }

    pub(super) fn block(&mut self, path: String) {
        self.remaining += 1;
        self.new_blockers.push(path);
    }

    pub(super) fn ready(&self) -> bool {
        self.remaining == 0
    }

    pub(super) fn defer(
        &self,
        journal: &journal::Journal,
        id: &str,
        paths: &std::collections::LinkedList<PathBuf>,
        operations: &mut NativeWatchOperations,
    ) {
        if paths.is_empty() || self.new_blockers.is_empty() {
            return;
        }
        let blockers: HashSet<_> = self
            .new_blockers
            .iter()
            .flat_map(|path| crate::path_keys::path_ancestors(path).skip(1))
            .collect();
        for path in paths {
            let normalized = key(path);
            if !blockers.contains(normalized.as_str()) {
                continue;
            }
            let key = continuation_output_key(id, &normalized);
            if journal.state().runtime_record(&key).is_some() {
                continue;
            }
            if let Ok(identity) = output_identity(&path.to_string_lossy()) {
                operations.set_runtime(
                    key,
                    Some(json!(Directory {
                        path: path.clone(),
                        identity
                    })),
                );
            }
        }
    }

    pub(super) fn settle(&mut self, event: &Value, counts: CompletionSuccessCounts) {
        self.remaining -= 1;
        if event["path"] == self.event["path"] {
            if let Some(segments) = event.get("segments") {
                self.event["segments"] = segments.clone();
            }
        } else if matches!(event["event"].as_str(), Some("failed_terminal" | "partial_rejected")) {
            if let (Some(path), Some(segments)) =
                (event["path"].as_str(), self.event.get_mut("segments").and_then(Value::as_array_mut))
            {
                let path = watch_path_key(path);
                for segment in segments.iter_mut().filter(|segment| segment["event"] == "done") {
                    let inside = segment["output_dirs"].as_array().into_iter().flatten().filter_map(Value::as_str)
                        .any(|output| crate::watch_store::is_path_under(&path, &watch_path_key(output)));
                    if inside {
                        segment["event"] = json!("failed_terminal");
                        segment["error"] = event["error"].clone();
                        segment["error_kind"] = event["error_kind"].clone();
                        break;
                    }
                }
            }
        }
        if event["event"] == "done" {
            for (field, value) in [
                ("success_count", counts.success_count),
                ("partial_success_count", counts.partial_success_count),
            ] {
                self.event[field] =
                    json!(self.event[field].as_u64().unwrap_or_default() + value as u64);
            }
        } else if event["event"] != "watch_deduplicated" && self.event["event"] != "failed_terminal"
        {
            self.event["event"] = json!("failed_terminal");
            self.event["error"] = event["error"].clone();
            self.event["error_kind"] = event["error_kind"].clone();
            if let Some(failures) = event.get("failures") {
                self.event["failures"] = failures.clone();
            }
        }
    }

    pub(super) fn store(&self, id: String, operations: &mut NativeWatchOperations) {
        operations.set_runtime(
            id,
            Some(serde_json::to_value(self).expect("serializable continuation")),
        );
    }

    fn relocate(&mut self, from: &Path, to: Option<&Path>) {
        let relocate = |event: &mut Value| {
            if let Some(outputs) = event.get_mut("output_dirs").and_then(Value::as_array_mut) {
                outputs.retain_mut(|output| {
                    if output.as_str().is_some_and(|path| Path::new(path) == from) {
                        let Some(to) = to else { return false; };
                        *output = json!(to);
                    }
                    true
                });
            }
        };
        relocate(&mut self.event);
        if let Some(segments) = self.event.get_mut("segments").and_then(Value::as_array_mut) {
            segments.iter_mut().for_each(relocate);
        }
    }
}

impl Scheduler {
    pub(super) fn finish_continuation(
        &mut self,
        id: &str,
        mut continuation: Continuation,
    ) -> io::Result<()> {
        debug_assert!(continuation.ready());
        self.journal.wait_before_mutation()?;
        let publish = !continuation.abandoned && self.roots.contains_key(&continuation.root);
        if publish
            && continuation.event["event"] == "done"
            && continuation.event["partial_success_count"]
                .as_u64()
                .unwrap_or_default()
                == 0
            && self.settings.post_extract.flatten_single_directory
        {
            let mut directories = self
                .journal
                .state()
                .project_runtime(&continuation_output_key(id, ""), |_, value| Some(Arc::clone(value)))
                .into_iter()
                .map(|value| Directory::deserialize(value.as_ref()).map_err(io::Error::other))
                .collect::<io::Result<Vec<_>>>()?;
            directories.sort_unstable_by_key(|directory| {
                std::cmp::Reverse(directory.path.components().count())
            });
            let publication = FlattenPublication {
                journal: &self.journal,
                continuation: id,
            };
            for Directory { path, identity } in directories {
                let current = identity_if_present(&path.to_string_lossy())?;
                if current.as_deref() != Some(&identity) {
                    continuation.relocate(&path, None);
                    continue;
                }
                let source = Path::new(continuation.event["path"].as_str().unwrap());
                let (output, cleanup) = self.engine.finalize_directory(
                    &publication,
                    source,
                    path.clone(),
                    self.settings.post_extract.flatten_directory_name,
                )?;
                for failure in cleanup {
                    self.journal.log(
                        json!({"event":"pipeline_cleanup_failed","path":failure.path,
                        "owner":continuation.event["owner"],"cleanup":failure}),
                    );
                }
                continuation.relocate(&path, output.as_deref());
            }
        }
        let paths = continuation.event["output_dirs"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(watch_path_key)
            .collect::<Vec<_>>();
        if publish && !paths.is_empty() {
            let scopes: Vec<_> = self
                .roots
                .values()
                .map(|(_, scope)| scope.clone())
                .collect();
            let published = self.catalog.publish_outputs(
                &paths,
                &scopes,
                &self.deep_options,
                Some(&continuation.root),
            )?;
            self.hub
                .update(|signals| signals.published_outputs.extend(published));
        }
        if publish {
            self.journal.log(continuation.event);
        }
        self.journal.commit(true, |_| {
            let mut operations = NativeWatchOperations::empty();
            operations.set_runtime(id.to_owned(), None);
            Ok(operations)
        })
    }

    pub(super) fn recover_continuations(
        &mut self,
        roots: Option<&HashSet<String>>,
    ) -> io::Result<()> {
        for id in self.journal.state().runtime_keys(CONTINUATION_PREFIX) {
            if let Some(continuation) = Continuation::load(&self.journal, &id)? {
                if continuation.ready()
                    && roots.is_none_or(|roots| roots.contains(&continuation.root))
                {
                    self.finish_continuation(&id, continuation)?;
                }
            }
        }
        Ok(())
    }
}

struct FlattenPublication<'a> {
    journal: &'a journal::Journal,
    continuation: &'a str,
}

impl Observer for FlattenPublication<'_> {
    fn notify(&self, _: Event) {}

    fn before_flatten(
        &self,
        root: &Path,
        work: &Path,
        leaf: &Path,
        destination: &Path,
        _: Option<CleanupReceipt<'_>>,
    ) -> io::Result<()> {
        prepare_flatten(
            self.journal,
            "",
            root,
            work,
            leaf,
            destination,
            Some(self.continuation),
            None,
        )
    }

    fn after_flatten(
        &self,
        _: crate::pipeline::TaskId,
        root: &Path,
        old: &Path,
        _: &Path,
    ) -> io::Result<()> {
        if root != old {
            finish_flatten(self.journal, &root.to_string_lossy())?;
        }
        Ok(())
    }
}

pub(super) fn relocate_output(
    state: &crate::watch_store::NativeWatchState,
    id: &str,
    from: &Path,
    to: &Path,
    operations: &mut NativeWatchOperations,
) -> io::Result<()> {
    if let Some(value) = state.runtime_record(id) {
        let mut continuation =
            Continuation::deserialize(value.as_ref()).map_err(io::Error::other)?;
        operations.set_runtime(continuation_output_key(id, &key(from)), None);
        continuation.relocate(from, Some(to));
        continuation.store(id.to_owned(), operations);
    }
    Ok(())
}
