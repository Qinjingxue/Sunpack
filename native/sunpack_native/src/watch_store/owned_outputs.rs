//! Owned-directory lifecycle. Reuse the runtime path index and the journal's
//! publication gate; no watcher-local ownership cache can outlive a reservation.

use super::{is_path_under, path_key, NativeWatchOperations, NativeWatchState, Operation, Operations, PathSet, StateData};
use crate::scan::scope::NativeDiscoveryScope;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

impl StateData {
    fn recovery_output_roots(&self) -> PathSet {
        let mut roots = PathSet::default();
        for record in self.pending.values() {
            for path in std::iter::once(&record.path)
                .chain(record.active_outputs.values())
                .chain(record.committed_roots.iter())
                .chain(record.promoted_destinations.iter())
            {
                roots.retain_root(path);
            }
        }
        for (_, record) in self.runtime.range("flatten|".to_owned()..)
            .take_while(|(key, _)| key.starts_with("flatten|"))
        {
            for field in ["root", "work"] {
                if let Some(path) = record[field].as_str() {
                    roots.retain_root(path);
                }
                for path in record[format!("{field}_paths")].as_array().into_iter().flatten()
                    .filter_map(Value::as_str)
                {
                    roots.retain_root(path);
                }
            }
        }
        // Only failed inputs retain logical recovery after pending work ends.
        for entry in self.entries.values() {
            for record in entry.failure_payload.get("input_checkpoints")
                .and_then(Value::as_array).into_iter().flatten()
            {
                for path in crate::pipeline::InputCheckpoint::serialized_output_roots(record) {
                    roots.retain_root(path);
                }
            }
        }
        roots
    }

    fn owned_records(&self, paths: Option<&[String]>) -> BTreeMap<String, Arc<Value>> {
        let Some(paths) = paths else {
            return self.runtime.range("owned|".to_owned()..)
                .take_while(|(key, _)| key.starts_with("owned|"))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
        };
        let keys: Vec<_> = paths.iter().map(|path| path_key(path)).collect();
        let mut records = self.owned_ancestors(&keys);
        for path in &keys {
            let prefix = format!("owned|{}\\", path.trim_end_matches('\\'));
            records.extend(self.runtime.range(prefix.clone()..)
                .take_while(|(key, _)| key.starts_with(&prefix))
                .map(|(key, value)| (key.clone(), value.clone())));
        }
        // An event in either namespace reconciles the original pair, even
        // after the junction disappeared or was redirected. A reused key
        // belonging to a newer registration is never part of this pair.
        let aliases = records.values().flat_map(|record| {
            record_paths(record).filter_map(move |path| {
                let key = format!("owned|{}", path_key(path));
                self.runtime.get(&key)
                    .filter(|other| same_registration(record, other))
                    .map(|other| (key, other.clone()))
            })
        }).collect::<Vec<_>>();
        records.extend(aliases);
        records
    }

    fn owned_ancestors(&self, keys: impl IntoIterator<Item = impl AsRef<str>>) -> BTreeMap<String, Arc<Value>> {
        let mut records = BTreeMap::new();
        if self.runtime.range::<str, _>((std::ops::Bound::Included("owned|"), std::ops::Bound::Unbounded)).next()
            .is_none_or(|(key, _)| !key.starts_with("owned|"))
        {
            return records;
        }
        let mut key = String::from("owned|");
        for path in keys {
            for ancestor in crate::path_keys::path_ancestors(path.as_ref()) {
                key.truncate("owned|".len());
                key.push_str(ancestor);
                if let Some(value) = self.runtime.get(&key) {
                    records.entry(key.clone()).or_insert_with(|| value.clone());
                }
            }
        }
        records
    }
}

pub(crate) fn find_owned_root(state: &Mutex<StateData>, path: &str) -> Option<String> {
    let key = path_key(path);
    let records = state.lock().unwrap_or_else(|e| e.into_inner()).owned_ancestors([key]);
    records.into_iter().rev().find_map(|(key, record)| {
        if !identity_matches(&record) {
            return None;
        }
        let current = state.lock().unwrap_or_else(|e| e.into_inner());
        current.runtime.get(&key)
            .is_some_and(|value| same_registration(&record, value))
            .then(|| key["owned|".len()..].to_owned())
    })
}

pub(crate) fn owned_roots(state: &Mutex<StateData>, under: &str) -> Vec<String> {
    let path = path_key(under);
    let prefix = format!("owned|{}\\", path.trim_end_matches('\\'));
    let (ancestors, descendants) = {
        let data = state.lock().unwrap_or_else(|e| e.into_inner());
        let ancestors = data.owned_ancestors([path]);
        let descendants = data.runtime.range(prefix.clone()..)
            .take_while(|(key, _)| key.starts_with(&prefix))
            .map(|(key, value)| (key.clone(), Arc::clone(value)))
            .collect::<Vec<_>>();
        (ancestors, descendants)
    };
    ancestors.into_iter().rev().chain(descendants)
        .filter(|(_, record)| identity_matches(record))
        .map(|(key, _)| key["owned|".len()..].to_owned())
        .collect()
}

impl PathSet {
    fn intersects(&self, path: &str) -> bool {
        if self.covers(path) {
            return true;
        }
        let prefix = format!("{}\\", path_key(path).trim_end_matches('\\'));
        self.0.range(prefix.clone()..).next()
            .is_some_and(|(key, _)| key.starts_with(&prefix))
    }
}

/// Filesystem observations are prepared without the journal publication lock.
/// Publication below compares the same indexed registrations and rechecks live
/// recovery ownership, so a newer mkdir/flatten reservation cannot be retired.
pub(crate) struct OwnedRetirement(Vec<(String, Arc<Value>, bool)>);

impl OwnedRetirement {
    pub(crate) fn operations(self, state: &NativeWatchState) -> NativeWatchOperations {
        if self.0.is_empty() {
            return NativeWatchOperations::empty();
        }
        let data = state.lock();
        let mut recovery = None;
        let operations = self.0.into_iter().filter_map(|(key, record, replaced)| {
            if !data.runtime.get(&key).is_some_and(|current| Arc::ptr_eq(&record, current)) {
                return None;
            }
            if !replaced {
                let roots = recovery.get_or_insert_with(|| data.recovery_output_roots());
                if record_paths(&record).filter(|path| {
                    data.runtime.get(&format!("owned|{}", path_key(path)))
                        .is_some_and(|current| same_registration(&record, current))
                }).any(|path| roots.intersects(path)) {
                    return None;
                }
            }
            Some(Operation::Runtime(key, None))
        }).collect();
        NativeWatchOperations { operations: Arc::new(Operations(operations)) }
    }
}

impl NativeWatchState {
    /// None is startup/configuration reconciliation; ordinary checkpoints visit
    /// only ancestor records and indexed descendants of actual changed paths.
    pub(crate) fn prepare_owned_retirement(
        &self,
        scopes: &[NativeDiscoveryScope],
        paths: Option<&[String]>,
    ) -> OwnedRetirement {
        let records = self.lock().owned_records(paths);
        // Filesystem I/O runs outside the state lock. Reuse identity probes
        // across paired namespace checks and build recovery roots only on demand.
        let mut recovery = None;
        let mut identities = HashMap::new();
        let mut availability = HashMap::new();
        let candidates = records.iter().filter_map(|(key, record)| {
            let Some(path) = record["path"].as_str() else {
                return Some((key.clone(), Arc::clone(record), false));
            };
            let aliases = record_paths(record).filter(|alias| {
                records.get(&format!("owned|{}", path_key(alias)))
                    .is_some_and(|other| same_registration(record, other))
            });
            let mut recovery_in_use = || {
                let roots = recovery.get_or_insert_with(|| self.lock().recovery_output_roots());
                aliases.clone().any(|alias| roots.intersects(alias))
            };
            let relevant = aliases.clone().any(|alias| {
                scopes.iter().any(|scope| scope.intersects_output(alias))
                    && !identities.entry(alias).or_insert_with(|| output_identity(alias))
                        .as_ref().is_ok_and(|id| id.as_ref().is_some_and(|id| !record_matches(record, id)))
            });
            let (retire, replaced) = if !relevant && !recovery_in_use() {
                let replaced = identities.get(path).is_some_and(|identity| identity.as_ref()
                    .is_ok_and(|id| id.as_ref().is_some_and(|id| !record_matches(record, id))));
                (true, replaced)
            } else {
                match identities.entry(path).or_insert_with(|| output_identity(path)) {
                    Ok(Some(identity)) => {
                        let replaced = !record_matches(record, identity);
                        (replaced, replaced)
                    }
                    Ok(None) => (!recovery_in_use() && aliases
                        .clone().all(|alias| path_available(alias, scopes, &mut availability)), false),
                    Err(_) => (false, false), // Offline/locked is not proof of deletion.
                }
            };
            retire.then(|| (key.clone(), Arc::clone(record), replaced))
        }).collect();
        OwnedRetirement(candidates)
    }

    #[cfg(test)]
    pub(crate) fn owned_retirement_operations(
        &self, scopes: &[NativeDiscoveryScope], paths: Option<&[String]>,
    ) -> NativeWatchOperations {
        self.prepare_owned_retirement(scopes, paths).operations(self)
    }

    /// Disposal may finish after its delete notification was already handled
    /// while the output was still active. Retire that now-invalid exclusion in
    /// the existing finish delta instead of waiting for another filesystem event.
    pub(super) fn discarded_owned_operations(&self, output: &str) -> Vec<Operation> {
        let root = format!("owned|{}", path_key(output).trim_end_matches('\\'));
        let records = self.lock().owned_records(Some(&[output.to_owned()]));
        let mut identities = HashMap::new();
        records.into_iter().filter_map(|(key, record)| {
            if !record_paths(&record).any(|path| {
                let key = format!("owned|{}", path_key(path));
                key == root || is_path_under(&key, &root)
            }) {
                return None; // A nested discard never retires its owning parent.
            }
            let path = record["path"].as_str()?;
            let stale = identities.entry(path.to_owned()).or_insert_with(|| output_identity(path))
                .as_ref().is_ok_and(|identity| identity.as_ref()
                    .is_none_or(|identity| !record_matches(&record, identity)));
            stale.then_some(Operation::Runtime(key, None))
        }).collect()
    }

    /// Remove only the matching generation from a completed flatten's saved
    /// work aliases; a newly registered directory at a reused key survives.
    pub(crate) fn remove_owned_output(&self, paths: &[String], identity: &str) -> NativeWatchOperations {
        let data = self.lock();
        let mut keys = std::collections::BTreeSet::new();
        for path in paths {
            let key = format!("owned|{}", path_key(path).trim_end_matches('\\'));
            let Some(record) = data.runtime.get(&key).filter(|record| record_matches(record, identity)) else {
                continue;
            };
            keys.extend(record_paths(record).filter_map(|alias| {
                let key = format!("owned|{}", path_key(alias));
                data.runtime.get(&key).filter(|other| same_registration(record, other)).map(|_| key)
            }));
        }
        let operations = keys.into_iter().map(|key| Operation::Runtime(key, None)).collect();
        NativeWatchOperations { operations: Arc::new(Operations(operations)) }
    }

    /// Capture registrations at the mkdir/publication boundary. Identity I/O
    /// must happen after releasing the journal's global publication gate.
    pub(crate) fn owned_event_records<'a>(
        &self, paths: impl Iterator<Item = &'a Path>,
    ) -> BTreeMap<String, Arc<Value>> {
        self.lock().owned_ancestors(paths.map(|path| path_key(&path.to_string_lossy())))
    }

    #[cfg(test)]
    pub(crate) fn retain_unowned_events(&self, paths: &mut Vec<PathBuf>, boundary: &Path) {
        let records = self.owned_event_records(paths.iter().map(PathBuf::as_path));
        if let Some(filter) = self.owned_event_filter(boundary, records) {
            paths.retain(|path| !filter.contains(path));
        }
    }

    pub(crate) fn owned_event_filter(
        &self, boundary: &Path, records: BTreeMap<String, Arc<Value>>,
    ) -> Option<OwnedEventFilter> {
        if records.is_empty() { return None; }
        let mut identities = HashMap::new();
        let verified: Vec<_> = records.into_iter().filter(|(_, record)| {
            let Some(path) = record["path"].as_str() else { return false; };
            identities.entry(path.to_owned()).or_insert_with(|| output_identity(path))
                .as_ref().is_ok_and(|identity| identity.as_ref()
                    .is_some_and(|identity| record_matches(record, identity)))
        }).collect();
        // A concurrent rollback or replacement must not inherit the snapshot's
        // exclusion. Only registrations that survived the probe still filter.
        let data = self.lock();
        let owned: HashSet<_> = verified.into_iter().filter_map(|(key, record)| {
            data.runtime.get(&key).filter(|current| same_registration(&record, current))
                .map(|_| key["owned|".len()..].to_owned())
        }).collect();
        if owned.is_empty() { return None; }
        let boundary = path_key(&boundary.to_string_lossy());
        Some(OwnedEventFilter { boundary, owned })
    }

}

pub(crate) struct OwnedEventFilter {
    boundary: String,
    owned: HashSet<String>,
}

impl OwnedEventFilter {
    pub(crate) fn contains(&self, path: &Path) -> bool {
        let key = path_key(&path.to_string_lossy());
        key != self.boundary && crate::path_keys::path_ancestors(&key)
            .any(|parent| self.owned.contains(parent))
    }
}

fn record_paths(record: &Value) -> impl Iterator<Item = &str> + Clone {
    record["path"].as_str().into_iter().chain(
        record["aliases"].as_array().into_iter().flatten().filter_map(Value::as_str)
            .filter(move |alias| record["path"].as_str() != Some(*alias)),
    )
}

fn same_registration(left: &Value, right: &Value) -> bool {
    left["identities"] == right["identities"] && left["aliases"] == right["aliases"]
}

pub(super) fn owned_operations<'a>(
    paths: &'a [String],
    identities: &'a [&'a str],
) -> impl Iterator<Item = Operation> + 'a {
    paths.iter().map(move |path| {
        let record = serde_json::json!({"path":path,"identities":identities,"aliases":paths});
        Operation::Runtime(format!("owned|{}", path_key(path)), Some(Arc::new(record)))
    })
}

impl NativeWatchOperations {
    pub(crate) fn owned_outputs(paths: &[String], identities: &[&str]) -> Self {
        Self { operations: Arc::new(Operations(owned_operations(paths, identities).collect())) }
    }
}

fn path_available(
    path: &str,
    scopes: &[NativeDiscoveryScope],
    availability: &mut HashMap<String, bool>,
) -> bool {
    let path = path_key(path);
    scopes.iter().all(|scope| {
        let root = path_key(&scope.root);
        (path != root && !is_path_under(&path, &root) && !is_path_under(&root, &path))
            || *availability.entry(root).or_insert_with(|| Path::new(&scope.root).is_dir())
    })
}

/// Missing is distinct from a replacement or an inconclusive access failure.
fn output_identity(path: &str) -> io::Result<Option<String>> {
    match crate::filesystem::watch_path_identity(path) {
        Ok((volume, id, _)) => Ok(Some(format!("{volume}|{id}"))),
        Err(error) if matches!(error.kind(), io::ErrorKind::NotFound | io::ErrorKind::NotADirectory) => Ok(None),
        Err(error) => Err(error),
    }
}

fn record_matches(record: &Value, identity: &str) -> bool {
    record["identities"].as_array().is_some_and(|ids| {
        ids.iter().any(|value| value.as_str() == Some(identity))
    })
}

pub(super) fn identity_matches(record: &Value) -> bool {
    record["path"].as_str().is_some_and(|path| {
        output_identity(path).is_ok_and(|identity| {
            identity.is_some_and(|identity| record_matches(record, &identity))
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::watch_store::PendingRecord;
    use serde_json::json;

    fn put_owned(state: &NativeWatchState, path: &Path, identity: &str) {
        state.apply(&NativeWatchOperations::owned_outputs(
            &[path.to_string_lossy().into_owned()],
            &[identity],
        ));
    }

    fn has_owned(state: &NativeWatchState, path: &Path) -> bool {
        state.runtime_record(&format!("owned|{}", path_key(&path.to_string_lossy()))).is_some()
    }

    #[test]
    fn indexed_retirement_keeps_recovery_and_does_not_scan_prefix_siblings() {
        let marker = crate::test_support::temp_file("owned_index", b"");
        let base = marker.with_extension("outputs");
        let affected = base.join("old");
        let stale = affected.join("stale");
        let sibling = base.join("old-sibling");
        let active = affected.join("active");
        let committed = affected.join("committed");
        let container = affected.join("container");
        let checkpoint = container.join("segment");
        let flatten = affected.join("flatten");
        let state = NativeWatchState::new();
        for path in [&stale, &sibling, &active, &committed, &container, &checkpoint, &flatten] {
            put_owned(&state, path, "missing-directory");
        }
        let mut pending = PendingRecord {
            path: base.join("source.zip").to_string_lossy().into_owned(),
            ..Default::default()
        };
        pending.active_outputs.insert(pending.path.clone(), active.to_string_lossy().into_owned());
        pending.committed_roots.insert(committed.to_string_lossy().into_owned());
        {
            let mut data = state.lock();
            data.pending.insert(path_key(&pending.path), Arc::new(pending));
            let receipt: crate::pipeline::InputCheckpoint = serde_json::from_value(json!({
                "schema_version":1,"carrier":base.join("source.zip"),
                "input":crate::io::archive_state::ArchiveInput::file(
                    base.join("source.zip").to_string_lossy().into_owned(), "zip".into(), "source".into(),
                ),
                "sources":[],"output":checkpoint,"container":container,
                "files":1,"bytes":1,"encrypted":false,"discovery_source":"embedded",
            })).unwrap();
            let entry = super::super::EntryRecord {
                path: "test".into(), status: "failed_password".into(),
                failure_payload: json!({"input_checkpoints":[receipt]}).as_object().unwrap().clone(),
                size: 0, mtime: 0.0, file_id: String::new(), change_usn: 0,
                last_error: String::new(), attempt_count: 1, failure_kind: String::new(),
                failure_stage: String::new(), last_attempt_at: 0.0,
            };
            data.entries.insert("test".into(), Arc::new(entry));
            data.runtime.insert("flatten|test".into(), Arc::new(json!({"root":flatten})));
        }
        state.apply(&state.owned_retirement_operations(&[], Some(&[affected.to_string_lossy().into_owned()])));
        assert!(!has_owned(&state, &stale));
        assert!(has_owned(&state, &sibling)); // "old" must not match "old-sibling".
        for path in [&active, &committed, &container, &checkpoint, &flatten] {
            assert!(has_owned(&state, path));
        }
        state.apply(&state.owned_retirement_operations(&[], None));
        assert!(!has_owned(&state, &sibling));
        for path in [&active, &committed, &container, &checkpoint, &flatten] {
            assert!(has_owned(&state, path));
        }
        // Completion has removed Pending but the entry/checkpoint remains.
        state.lock().pending.clear();
        state.apply(&state.owned_retirement_operations(&[], None));
        assert!(has_owned(&state, &checkpoint));
        assert!(has_owned(&state, &container));
        state.lock().entries.remove("test");
        state.apply(&state.owned_retirement_operations(&[], None));
        assert!(!has_owned(&state, &checkpoint));
        assert!(!has_owned(&state, &container));
        std::fs::remove_file(marker).unwrap();
    }

    #[test]
    fn prepared_retirement_is_sparse_and_preserves_concurrent_registration_and_recovery() {
        let marker = crate::test_support::temp_file("owned_retirement_publication", b"");
        let base = marker.with_extension("outputs");
        let state = NativeWatchState::new();
        for index in 0..1000 {
            put_owned(&state, &base.join(format!("output-{index}")), "old-generation");
        }
        let unrelated = base.join("new.zip").to_string_lossy().into_owned();
        let prepared = state.prepare_owned_retirement(&[], Some(&[unrelated]));
        assert!(prepared.0.is_empty());
        let target = base.join("output-7");
        let paths = [target.to_string_lossy().into_owned()];
        let prepared = state.prepare_owned_retirement(&[], Some(&paths));
        assert_eq!(prepared.0.len(), 1);
        // A concurrent output registration at the same key wins over stale IO.
        put_owned(&state, &target, "new-generation");
        state.apply(&prepared.operations(&state));
        assert!(has_owned(&state, &target));
        let prepared = state.prepare_owned_retirement(&[], Some(&paths));
        let owner = base.join("source.zip").to_string_lossy().into_owned();
        let mut pending = PendingRecord { path: owner.clone(), ..Default::default() };
        pending.active_outputs.insert(owner.clone(), paths[0].clone());
        state.lock().pending.insert(path_key(&owner), Arc::new(pending));
        state.apply(&prepared.operations(&state));
        assert!(has_owned(&state, &target));
        // Once recovery releases this absent output, ordinary retirement works.
        state.lock().pending.clear();
        state.apply(&state.prepare_owned_retirement(&[], Some(&paths)).operations(&state));
        assert!(!has_owned(&state, &target));
        assert_eq!(state.runtime_keys("owned|").len(), 999);
        std::fs::remove_file(marker).unwrap();
    }

    #[cfg(windows)]
    fn junction(link: &Path, target: &Path) {
        let result = std::process::Command::new("cmd.exe")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(link).arg(target).output().unwrap();
        assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    }

    #[cfg(windows)]
    #[test]
    fn junction_aliases_preserve_namespace_identity_across_reuse_and_discard() {
        // One lifecycle covers both catalog reads and early event filtering:
        // checking record.path only at the original name misses retargeting.
        let marker = crate::test_support::temp_file("owned_aliases", b"");
        let base = marker.with_extension("outputs");
        let real = base.join("real");
        let other = base.join("other");
        let alias = base.join("junction");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::create_dir_all(&other).unwrap();
        junction(&alias, &real);
        let output = alias.join("absent").join("parent").join("output");
        let physical = real.join("absent").join("parent").join("output");
        let replacement = other.join("absent").join("parent").join("output");
        let paths = crate::path_keys::output_path_aliases(&output).unwrap();
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[1], path_key(physical.to_str().unwrap()));
        let state = NativeWatchState::new();
        let owner = base.join("source.zip").to_string_lossy().into_owned();
        state.lock().pending.insert(path_key(&owner), Arc::new(PendingRecord {
            path: owner.clone(), ..Default::default()
        }));
        let scopes = [NativeDiscoveryScope::new(real.to_string_lossy().into_owned(), None, Vec::new()),
            NativeDiscoveryScope::new(other.to_string_lossy().into_owned(), None, Vec::new())];
        let start = || state.output_operation(&owner, owner.clone(), output.to_string_lossy().into_owned(),
            None, Some(&scopes)).unwrap().unwrap();
        state.apply(&start());
        let catalog = crate::scan::directory::NativeWatchCatalog::new(&state, None);
        for path in [&output, &physical] {
            assert!(has_owned(&state, path));
            assert!(catalog.is_owned(path.join("nested.blob").to_str().unwrap()));
        }
        assert_eq!(catalog.output_roots(real.to_str().unwrap()), vec![path_key(physical.to_str().unwrap())]);
        let mut events = vec![real.clone(), output.clone(), physical.clone(), physical.join("nested.blob")];
        state.retain_unowned_events(&mut events, &real);
        assert_eq!(events, [real.clone()]);
        state.apply(&state.output_operation(&owner, owner.clone(), output.to_string_lossy().into_owned(),
            Some(true), None).unwrap().unwrap());

        std::fs::rename(&physical, real.join("old-directory")).unwrap();
        std::fs::create_dir(&physical).unwrap();
        for path in [&output, &physical] {
            assert!(!catalog.is_owned(path.join("external.zip").to_str().unwrap()));
        }
        assert!(state.output_operation(&owner, owner.clone(), output.to_string_lossy().into_owned(),
            None, Some(&scopes)).is_err());
        state.apply(&state.owned_retirement_operations(&scopes, Some(&[physical.to_string_lossy().into_owned()])));
        assert!(state.runtime_keys("owned|").is_empty());
        std::fs::remove_dir(&physical).unwrap();
        state.apply(&start());

        // Detaching the literal name must neither suppress replacement input
        // there nor expose the still-owned physical output as a fresh archive.
        std::fs::remove_dir(&alias).unwrap();
        junction(&alias, &other);
        std::fs::create_dir_all(&replacement).unwrap();
        assert!(!catalog.is_owned(output.to_str().unwrap()));
        assert!(catalog.is_owned(physical.to_str().unwrap()));
        let mut events = vec![output.join("external.zip"), physical.join("generated.zip")];
        state.retain_unowned_events(&mut events, &real);
        assert_eq!(events, [output.join("external.zip")]);
        state.apply(&state.owned_retirement_operations(&scopes, Some(&[alias.to_string_lossy().into_owned()])));
        assert!(!has_owned(&state, &output));
        assert!(has_owned(&state, &physical));

        // Reusing the alias key for a later registration cannot let retirement
        // of the first physical output erase the newer output's exclusion.
        std::fs::remove_dir(&replacement).unwrap();
        state.apply(&start());
        std::fs::remove_dir(&physical).unwrap();
        state.apply(&state.owned_retirement_operations(&scopes, Some(&[physical.to_string_lossy().into_owned()])));
        assert!(!has_owned(&state, &physical));
        assert!(has_owned(&state, &output));
        assert!(has_owned(&state, &replacement));
        std::fs::remove_dir(&replacement).unwrap();
        state.apply(&state.output_operation(&owner, owner.clone(), output.to_string_lossy().into_owned(),
            Some(false), None).unwrap().unwrap());
        assert!(state.runtime_keys("owned|").is_empty());
        std::fs::remove_dir(&alias).unwrap();
        std::fs::remove_dir_all(base).unwrap();
        std::fs::remove_file(marker).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn event_snapshot_does_not_hide_revoked_output_after_identity_probe() {
        let marker = crate::test_support::temp_file("owned_event_snapshot", b"");
        let output = marker.with_extension("output");
        std::fs::create_dir(&output).unwrap();
        let state = NativeWatchState::new();
        let identity = output_identity(output.to_str().unwrap()).unwrap().unwrap();
        put_owned(&state, &output, &identity);
        let mut paths = vec![output.join("generated.zip")];
        let records = state.owned_event_records(paths.iter().map(PathBuf::as_path));
        state.apply(&state.remove_owned_output(&[output.to_string_lossy().into_owned()], &identity));
        if let Some(filter) = state.owned_event_filter(marker.parent().unwrap(), records) {
            paths.retain(|path| !filter.contains(path));
        }
        assert_eq!(paths, vec![output.join("generated.zip")]);
        std::fs::remove_dir(output).unwrap();
        std::fs::remove_file(marker).unwrap();
    }

    #[test]
    fn owned_lifecycle_filters_bursts_but_keeps_reuse_offline_and_flatten_safe() {
        let marker = crate::test_support::temp_file("owned_lifecycle", b"");
        let base = marker.with_extension("outputs");
        let watched = base.join("watched");
        let output = watched.join("output");
        let replaced = watched.join("replaced");
        let deleted = watched.join("deleted");
        let committed_deleted = watched.join("committed-deleted");
        let offline = base.join("offline");
        let offline_output = offline.join("output");
        let irrelevant = base.join("irrelevant");
        let work = watched.join("flatten-work");
        let leaf = output.join("leaf");
        let state = NativeWatchState::new();
        for path in [&output, &leaf, &replaced, &deleted, &committed_deleted, &offline_output, &irrelevant] {
            std::fs::create_dir_all(path).unwrap();
        }
        for path in [&output, &replaced, &deleted, &committed_deleted, &offline_output, &irrelevant] {
            put_owned(&state, path, &output_identity(path.to_str().unwrap()).unwrap().unwrap());
        }
        let scopes = [NativeDiscoveryScope::new(watched.to_string_lossy().into_owned(), None, Vec::new()),
            NativeDiscoveryScope::new(offline.to_string_lossy().into_owned(), None, Vec::new())];
        let ordinary = watched.join("ordinary.zip");
        let similar = watched.join("output-other").join("ordinary.zip");
        let mut paths = vec![watched.clone(), output.clone(), output.clone(), output.join("generated.zip"),
            leaf.join("nested.zip"), ordinary.clone(), similar.clone()];
        state.retain_unowned_events(&mut paths, &watched);
        assert_eq!(paths, vec![watched.clone(), ordinary, similar]);
        // An explicitly watched boundary inside another output still wakes.
        let mut paths = vec![leaf.clone(), leaf.join("generated.zip")];
        state.retain_unowned_events(&mut paths, &leaf);
        assert_eq!(paths, vec![leaf.clone()]);

        std::fs::rename(&replaced, base.join("old-identity")).unwrap();
        std::fs::create_dir(&replaced).unwrap();
        std::fs::remove_dir(&deleted).unwrap();
        std::fs::remove_dir_all(&offline).unwrap();
        let mut paths = vec![replaced.clone(), replaced.join("new-input.zip"), deleted.clone()];
        state.retain_unowned_events(&mut paths, &watched);
        assert_eq!(paths, vec![replaced.clone(), replaced.join("new-input.zip"), deleted.clone()]);
        // A delete notification can precede the owner's discard callback.
        // Reconciliation keeps the reservation, then discard must retire the
        // stale exclusion without depending on another event or a restart.
        let owner = watched.join("source.zip").to_string_lossy().into_owned();
        let mut pending = PendingRecord { path: owner.clone(), ..Default::default() };
        pending.active_outputs.insert(owner.clone(), deleted.to_string_lossy().into_owned());
        pending.active_outputs.insert(owner.clone(), replaced.to_string_lossy().into_owned());
        state.lock().pending.insert(path_key(&owner), Arc::new(pending));
        // Cancellation also rolls back committed outputs after start/finish
        // already removed their active reservation. Both ownership forms must
        // be retired by discard without relying on another notification.
        for keep in [None, Some(true)] {
            state.apply(&state.output_operation(&owner, owner.clone(),
                committed_deleted.to_string_lossy().into_owned(), keep, None).unwrap().unwrap());
        }
        std::fs::remove_dir(&committed_deleted).unwrap();
        state.apply(&state.owned_retirement_operations(&scopes, Some(&[committed_deleted.to_string_lossy().into_owned()])));
        assert!(has_owned(&state, &committed_deleted));
        state.apply(&state.output_operation(&owner, owner.clone(),
            committed_deleted.to_string_lossy().into_owned(), Some(false), None).unwrap().unwrap());
        assert!(!has_owned(&state, &committed_deleted));
        assert!(!state.pending(&owner).unwrap().committed_roots.contains(committed_deleted.to_str().unwrap()));
        state.apply(&state.owned_retirement_operations(&scopes, Some(&[deleted.to_string_lossy().into_owned()])));
        assert!(has_owned(&state, &deleted));
        let discard = state.output_operation(&owner, owner.clone(),
            deleted.to_string_lossy().into_owned(), Some(false), None).unwrap().unwrap();
        state.apply(&discard);
        assert!(!has_owned(&state, &deleted));
        assert!(state.discarded_owned_operations(output.join("unregistered").to_str().unwrap()).is_empty());
        assert!(has_owned(&state, &output));
        // A reservation does not protect a different directory reusing its path.
        state.apply(&state.owned_retirement_operations(&scopes, Some(&[replaced.to_string_lossy().into_owned()])));
        assert!(!has_owned(&state, &replaced));
        state.apply(&state.owned_retirement_operations(&scopes, None));
        for path in [&replaced, &deleted, &irrelevant] {
            assert!(!has_owned(&state, path));
        }
        assert!(has_owned(&state, &offline_output));
        assert!(has_owned(&state, &output));

        // Keep both identities through flatten's rename gap, then accept the
        // new directory at the published root rather than retiring its owner.
        let old = output_identity(output.to_str().unwrap()).unwrap().unwrap();
        let new = output_identity(leaf.to_str().unwrap()).unwrap().unwrap();
        state.apply(&NativeWatchOperations::owned_outputs(
            &[output.to_string_lossy().into_owned()],
            &[&old, &new],
        ));
        state.lock().runtime.insert("flatten|test".into(), Arc::new(json!({"root":output,"work":work})));
        put_owned(&state, &work, &old);
        std::fs::rename(&output, &work).unwrap();
        let mut paths = vec![output.clone(), work.clone()];
        state.retain_unowned_events(&mut paths, &watched);
        assert_eq!(paths, vec![output.clone()]);
        state.apply(&state.owned_retirement_operations(&scopes, Some(&[output.to_string_lossy().into_owned()])));
        assert!(has_owned(&state, &output));
        std::fs::rename(work.join("leaf"), &output).unwrap();
        state.apply(&state.owned_retirement_operations(&scopes, None));
        assert!(has_owned(&state, &output));
        assert!(has_owned(&state, &work));
        let mut paths = vec![output.clone(), output.join("generated.zip"), work.clone(), work.join("wrapper.tmp")];
        state.retain_unowned_events(&mut paths, &watched);
        assert!(paths.is_empty());
        std::fs::remove_dir_all(base).unwrap();
        std::fs::remove_file(marker).unwrap();
    }
}
