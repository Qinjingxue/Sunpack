//! Owned-directory lifecycle. Reuse the runtime path index and the journal's
//! publication gate; no watcher-local ownership cache can outlive a reservation.

use super::{is_path_under, path_key, NativeWatchOperations, NativeWatchState, Operation, Operations, PathSet, StateData};
use crate::scan::scope::NativeDiscoveryScope;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

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
        // A suspended nested input can retain a verified checkpoint after its
        // pending work was retired. Its output is still recovery-owned.
        for (_, record) in self.runtime.range("checkpoint|".to_owned()..)
            .take_while(|(key, _)| key.starts_with("checkpoint|"))
        {
            for path in crate::pipeline::InputCheckpoint::serialized_output_roots(record) {
                roots.retain_root(path);
            }
        }
        roots
    }

    fn owned_records(&self, paths: Option<&[String]>, descendants: bool) -> BTreeMap<String, Value> {
        let Some(paths) = paths else {
            return self.runtime.range("owned|".to_owned()..)
                .take_while(|(key, _)| key.starts_with("owned|"))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
        };
        let mut records = BTreeMap::new();
        for path in paths {
            let path = path_key(path);
            for ancestor in crate::path_keys::path_ancestors(&path) {
                let key = format!("owned|{ancestor}");
                if let Some(value) = self.runtime.get(&key) {
                    records.entry(key).or_insert_with(|| value.clone());
                }
            }
            if descendants {
                let prefix = format!("owned|{}\\", path.trim_end_matches('\\'));
                records.extend(self.runtime.range(prefix.clone()..)
                    .take_while(|(key, _)| key.starts_with(&prefix))
                    .map(|(key, value)| (key.clone(), value.clone())));
            }
        }
        if descendants {
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
        }
        records
    }
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
pub(crate) struct OwnedRetirement {
    observed: BTreeMap<String, Option<Value>>,
    operations: Vec<Operation>,
    replaced: HashSet<String>,
}

impl OwnedRetirement {
    pub(crate) fn operations(self, state: &NativeWatchState) -> NativeWatchOperations {
        let data = state.lock();
        let unchanged = |key: &str| self.observed.get(key)
            .is_some_and(|before| before.as_ref() == data.runtime.get(key));
        // Legacy alias normalization is one publication, not independent edits.
        if self.operations.iter().any(|op| matches!(op, Operation::Runtime(_, Some(_))))
            && !self.observed.keys().all(|key| unchanged(key))
        {
            return NativeWatchOperations::empty();
        }
        let mut recovery = None;
        let operations = self.operations.into_iter().filter(|op| {
            let Operation::Runtime(key, value) = op else { unreachable!() };
            if !unchanged(key) { return false; }
            if value.is_none() && !self.replaced.contains(key) {
                if let Some(Some(record)) = self.observed.get(key) {
                    let roots = recovery.get_or_insert_with(|| data.recovery_output_roots());
                    if record_paths(record).filter(|path| {
                        data.runtime.get(&format!("owned|{}", path_key(path)))
                            .is_some_and(|current| same_registration(record, current))
                    }).any(|path| roots.intersects(path)) { return false; }
                }
            }
            true
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
        let mut records = self.lock().owned_records(paths, true);
        let mut observed = records.iter().map(|(key, record)| (key.clone(), Some(record.clone())))
            .collect::<BTreeMap<_, _>>();
        if records.is_empty() {
            return OwnedRetirement { observed, operations: Vec::new(), replaced: HashSet::new() };
        }
        // The common in-scope, unchanged output needs only its identity probe.
        // Build recovery ownership once, only for missing or out-of-scope roots.
        let mut recovery = None;
        // Identity and root availability I/O must not hold the shared state map.
        // Reuse one probe per namespace across paired relevance/identity checks.
        let mut identities = HashMap::new();
        let mut availability = HashMap::new();
        let mut operations = Vec::new();
        if paths.is_none() {
            normalize_legacy_aliases(&mut records, &mut operations);
            for key in records.keys() {
                observed.entry(key.clone()).or_insert_with(|| self.runtime_record(key));
            }
        }
        // Upgrade old single-path snapshots before building the no-history
        // baseline. Never discover an alias from a replaced directory.
        let legacy = records.iter().filter(|(_, record)| !record["aliases"].is_array())
            .map(|(key, record)| (key.clone(), record.clone())).collect::<Vec<_>>();
        for (key, record) in legacy {
            let Some(path) = record["path"].as_str() else { continue; };
            let valid = identities.entry(path.to_owned()).or_insert_with(|| output_identity(path))
                .as_ref().is_ok_and(|id| id.as_ref().is_some_and(|id| record_matches(&record, id)));
            let indexed = &key["owned|".len()..];
            if !valid && indexed == path_key(path) {
                // Keep unresolved legacy records eligible for a later event
                // after an offline root returns. Do not seal a literal-only
                // alias list before its original identity can be verified.
                continue;
            }
            let mut aliases = if valid {
                crate::path_keys::output_path_aliases(Path::new(path))
                    .unwrap_or_else(|_| vec![path.to_owned()])
            } else {
                vec![path.to_owned()]
            };
            if !aliases.iter().any(|alias| path_key(alias) == indexed) {
                aliases.push(indexed.to_owned());
            }
            for (key, next) in owned_records(&aliases, &record["identities"]) {
                // Event reconciliation snapshots only an affected subtree.
                // Its newly discovered real alias can already belong to a
                // different registration outside that snapshot.
                let before = observed.entry(key.clone()).or_insert_with(|| self.runtime_record(&key));
                let existing = records.get(&key).cloned().or_else(|| before.clone());
                if existing.as_ref().is_some_and(|other| {
                    other["identities"] != record["identities"] || other["path"] != record["path"]
                }) {
                    continue;
                }
                records.insert(key.clone(), next.clone());
                operations.push(Operation::Runtime(key, Some(next)));
            }
        }
        // Canonical-key moves are protected by the all-record comparison above,
        // not by output recovery: the same registration is being re-indexed.
        let mut replaced = operations.iter().filter_map(|operation| match operation {
            Operation::Runtime(key, None) => Some(key.clone()),
            _ => None,
        }).collect::<HashSet<_>>();
        for (key, record) in &records {
            let retire = if let Some(path) = record["path"].as_str() {
                let aliases = record_paths(record).filter(|alias| {
                    records.get(&format!("owned|{}", path_key(alias)))
                        .is_some_and(|other| same_registration(record, other))
                }).collect::<Vec<_>>();
                let mut recovery_in_use = || {
                    let roots = recovery.get_or_insert_with(|| self.lock().recovery_output_roots());
                    aliases.iter().any(|alias| roots.intersects(alias))
                };
                let relevant = aliases.iter().any(|alias| {
                    scopes.iter().any(|scope| scope.intersects_output(alias))
                        && !identities.entry((*alias).to_owned()).or_insert_with(|| output_identity(alias))
                            .as_ref().is_ok_and(|id| id.as_ref().is_some_and(|id| !record_matches(record, id)))
                });
                if !relevant && !recovery_in_use() {
                    // A legacy literal name outside the watched tree may
                    // resolve into an offline watched volume. Until its
                    // identity can be checked we cannot prove irrelevance.
                    record["aliases"].is_array()
                        || identities.entry(path.to_owned()).or_insert_with(|| output_identity(path))
                            .as_ref().is_ok_and(|id| id.is_some())
                        || scopes.iter().all(|scope| *availability.entry(path_key(&scope.root))
                            .or_insert_with(|| Path::new(&scope.root).is_dir()))
                } else {
                    match identities.entry(path.to_owned()).or_insert_with(|| output_identity(path)) {
                        Ok(Some(identity)) => !record_matches(record, identity),
                        Ok(None) => !recovery_in_use() && aliases.iter()
                            .all(|alias| path_available(alias, scopes, &mut availability)),
                        Err(_) => false, // Offline/locked is not proof of deletion.
                    }
                }
            } else {
                true
            };
            if retire {
                if record["path"].as_str().and_then(|path| identities.get(path))
                    .is_some_and(|identity| identity.as_ref().is_ok_and(|identity|
                        identity.as_ref().is_some_and(|identity| !record_matches(record, identity))))
                {
                    replaced.insert(key.clone());
                }
                operations.push(Operation::Runtime(key.clone(), None));
            }
        }
        OwnedRetirement { observed, operations, replaced }
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
        let records = self.lock().owned_records(Some(&[output.to_owned()]), true);
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

    /// Read a legacy flatten's saved alias membership without following a
    /// junction that may now identify another physical directory.
    pub(crate) fn owned_output_paths(&self, path: &str, identity: &str) -> Vec<String> {
        let key = path_key(path);
        let data = self.lock();
        let direct = data.runtime.get(&format!("owned|{key}"))
            .filter(|record| record_matches(record, identity));
        // Only legacy flatten intents need this fallback. Their literal entry
        // may already be retired, but the physical record still remembers it.
        let record = direct.or_else(|| data.runtime.range("owned|".to_owned()..)
            .take_while(|(key, _)| key.starts_with("owned|"))
            .map(|(_, record)| record)
            .find(|record| record_matches(record, identity)
                && record_paths(record).any(|alias| path_key(alias) == key)));
        record.map(|record| record_paths(record).map(str::to_owned).collect())
            .unwrap_or_else(|| vec![path.to_owned()])
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

    /// Called under the same journal gate as mkdir + output publication. A
    /// verified root's own LastWrite events are generated output too. Missing or
    /// replaced roots fail verification and reach lifecycle reconciliation;
    /// the watched-directory boundary always remains visible for rearming.
    pub(crate) fn retain_unowned_events(&self, paths: &mut Vec<PathBuf>, boundary: &Path) {
        let boundary = path_key(&boundary.to_string_lossy());
        let keys: Vec<_> = paths.iter().map(|path| path_key(&path.to_string_lossy())).collect();
        let records = self.lock().owned_records(Some(&keys), false);
        let mut identities = HashMap::new();
        let mut owned = HashSet::new();
        for (key, record) in records {
            let Some(path) = record["path"].as_str() else { continue; };
            if identities.entry(path.to_owned()).or_insert_with(|| output_identity(path))
                .as_ref().is_ok_and(|identity| identity.as_ref()
                    .is_some_and(|identity| record_matches(&record, identity)))
            {
                owned.insert(key["owned|".len()..].to_owned());
            }
        }
        let mut keys = keys.into_iter();
        paths.retain(|_| {
            let key = keys.next().unwrap();
            key == boundary || !crate::path_keys::path_ancestors(&key)
                    .any(|parent| owned.contains(parent))
        });
    }
}

fn record_paths(record: &Value) -> impl Iterator<Item = &str> {
    record["path"].as_str().into_iter().chain(
        record["aliases"].as_array().into_iter().flatten().filter_map(Value::as_str)
            .filter(move |alias| record["path"].as_str() != Some(*alias)),
    )
}

fn same_registration(left: &Value, right: &Value) -> bool {
    left["identities"] == right["identities"]
        && if left["aliases"].is_array() {
            left["aliases"] == right["aliases"]
        } else {
            left["path"] == right["path"]
        }
}

fn normalize_legacy_aliases(records: &mut BTreeMap<String, Value>, operations: &mut Vec<Operation>) {
    // An earlier resolver appended a separator to the canonical name of an
    // existing directory. Event ancestor keys never contain that separator.
    let old = records.iter().filter(|(key, record)| {
        key.ends_with('\\') || record_paths(record).any(|path| path.ends_with(['\\', '/']))
    }).map(|(key, record)| (key.clone(), record.clone())).collect::<Vec<_>>();
    for (key, mut record) in old {
        let normalized = key.trim_end_matches('\\');
        if normalized != key {
            records.remove(&key);
            operations.push(Operation::Runtime(key.clone(), None));
            if records.contains_key(normalized) {
                continue; // A newer registration already owns the canonical key.
            }
        }
        if let Some(path) = record["path"].as_str() {
            record["path"] = Value::from(path.trim_end_matches(['\\', '/']));
        }
        if let Some(aliases) = record.get_mut("aliases").and_then(Value::as_array_mut) {
            for alias in aliases {
                if let Some(path) = alias.as_str() {
                    *alias = Value::from(path.trim_end_matches(['\\', '/']));
                }
            }
        }
        records.insert(normalized.to_owned(), record.clone());
        operations.push(Operation::Runtime(normalized.to_owned(), Some(record)));
    }
}

fn owned_records(paths: &[String], identities: &Value) -> Vec<(String, Value)> {
    paths.iter().map(|path| (format!("owned|{}", path_key(path)),
        serde_json::json!({"path":path,"identities":identities,"aliases":paths}))).collect()
}

impl NativeWatchOperations {
    pub(crate) fn owned_outputs(paths: &[String], identities: &[&str]) -> Self {
        Self { operations: Arc::new(Operations(owned_records(paths, &serde_json::json!(identities))
            .into_iter().map(|(key, value)| Operation::Runtime(key, Some(value))).collect())) }
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
        let text = path.to_string_lossy();
        state.lock().runtime.insert(format!("owned|{}", path_key(&text)),
            json!({"path":text,"identities":[identity]}));
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
                "input":{"entry":base.join("source.zip"),"mode":"file","format":"zip","parts":[],"ranges":[]},
                "sources":[],"output":checkpoint,"container":container,
                "files":1,"bytes":1,"encrypted":false,"discovery_source":"embedded",
                "children_complete":true,"remaining_depth":0
            })).unwrap();
            data.runtime.insert("checkpoint|test".into(), serde_json::to_value(receipt).unwrap());
            data.runtime.insert("flatten|test".into(), json!({"root":flatten}));
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
        state.lock().runtime.remove("checkpoint|test");
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
        assert!(prepared.observed.is_empty()); // no unrelated identity IO or JSON snapshot
        let target = base.join("output-7");
        let paths = [target.to_string_lossy().into_owned()];
        let prepared = state.prepare_owned_retirement(&[], Some(&paths));
        assert_eq!(prepared.observed.len(), 1);
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
    fn legacy_junction_records_gain_both_aliases_before_catalog_admission() {
        let marker = crate::test_support::temp_file("owned_alias_upgrade", b"");
        let base = marker.with_extension("outputs");
        let real = base.join("real");
        let alias = base.join("junction");
        let physical = real.join("output");
        std::fs::create_dir_all(&physical).unwrap();
        junction(&alias, &real);
        let output = alias.join("output");
        let identity = output_identity(output.to_str().unwrap()).unwrap().unwrap();
        let scopes = [NativeDiscoveryScope::new(real.to_string_lossy().into_owned(), None, Vec::new())];
        for layout in ["literal-only", "python-aliases", "legacy-resolver"] {
            let state = NativeWatchState::new();
            if layout == "legacy-resolver" {
                let names = [output.to_string_lossy().into_owned(), format!("{}\\", physical.display())];
                state.apply(&NativeWatchOperations::owned_outputs(&names, &[&identity]));
                assert!(state.owned_root(physical.to_str().unwrap()).is_none());
            } else {
                put_owned(&state, &output, &identity);
            }
            if layout == "python-aliases" {
                let record = state.runtime_record(&format!("owned|{}", path_key(output.to_str().unwrap()))).unwrap();
                state.lock().runtime.insert(format!("owned|{}", path_key(physical.to_str().unwrap())), record);
            }
            state.apply(&state.owned_retirement_operations(&scopes, None));
            let catalog = crate::scan::directory::NativeWatchCatalog::new(&state, None);
            assert_eq!(state.runtime_keys("owned|").len(), 2);
            for path in [&output, &physical] {
                let record = state.runtime_record(&format!("owned|{}", path_key(path.to_str().unwrap()))).unwrap();
                assert_eq!(path_key(record["path"].as_str().unwrap()), path_key(path.to_str().unwrap()));
                assert!(catalog.is_owned(path.join("nested.zip").to_str().unwrap()));
            }
            // An already upgraded restart produces no redundant WAL delta.
            assert_eq!(state.owned_retirement_operations(&scopes, None).__len__(), 0);
        }
        let state = NativeWatchState::new();
        put_owned(&state, &output, &identity);
        let offline = base.join("offline");
        std::fs::rename(&real, &offline).unwrap();
        state.apply(&state.owned_retirement_operations(&scopes, None));
        assert!(has_owned(&state, &output));
        let record = state.runtime_record(&format!("owned|{}", path_key(output.to_str().unwrap()))).unwrap();
        assert!(!record["aliases"].is_array());
        std::fs::rename(&offline, &real).unwrap();
        // The scheduler performs this full pass once when an unavailable root
        // returns; an event under real cannot find an outside legacy name.
        state.apply(&state.owned_retirement_operations(&scopes, None));
        assert_eq!(state.runtime_keys("owned|").len(), 2);
        assert!(state.owned_root(physical.to_str().unwrap()).is_some());
        std::fs::remove_dir(&alias).unwrap();
        std::fs::remove_dir_all(base).unwrap();
        std::fs::remove_file(marker).unwrap();
    }

    #[cfg(windows)]
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
        {
            let mut data = state.lock();
            data.runtime.insert(format!("owned|{}", path_key(output.to_str().unwrap())),
                json!({"path":output,"identities":[old,new]}));
            data.runtime.insert("flatten|test".into(), json!({"root":output,"work":work}));
        }
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
