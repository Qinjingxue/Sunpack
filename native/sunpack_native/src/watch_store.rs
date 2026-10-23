//! Resident Watch state records owned by Rust.
//!
//! `WatchStateStore` (Python) keeps sequencing, WAL submission and checkpoint
//! orchestration. The record maps, their snapshot/journal decoding, operation
//! application and snapshot encoding live here, so the long-running Watch
//! process never keeps every pending item and retry entry as Python objects.

use crate::io::resource_lifecycle::TrackedFile;
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyFloat, PyInt, PyList, PyString, PyTuple};
use serde::{Deserialize, Serialize, Serializer};
use serde::ser::SerializeMap;
use serde_json::{Map, Value};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

const SNAPSHOT_BUFFER_BYTES: usize = 1024 * 1024;

fn recorded_file_presence(path: &str) -> Option<bool> {
    match std::fs::metadata(path) {
        Ok(metadata) => Some(metadata.is_file()),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            Some(false)
        }
        Err(_) => None,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingRecord {
    path: String,
    size: i64,
    mtime: f64,
    file_id: String,
    change_usn: i64,
    force: bool,
    password_scope_dir: String,
    source_input_root: String,
    internal_recovery: bool,
    #[serde(default)]
    discovery_scope: Map<String,Value>,
    durable_owner: bool,
    active_outputs: BTreeMap<String, String>,
    committed_roots: Vec<String>,
    completed_sources: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryRecord {
    path: String,
    size: i64,
    mtime: f64,
    file_id: String,
    change_usn: i64,
    status: String,
    last_error: String,
    attempt_count: i64,
    failure_kind: String,
    failure_stage: String,
    failure_payload: Map<String, Value>,
    last_attempt_at: f64,
    password_generation: i64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    journal_id: i128,
    next_usn: i128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Collection {
    Pending,
    Entries,
}

#[derive(Debug, Clone)]
enum Operation {
    PutPending(String, Arc<PendingRecord>),
    PutEntry(String, Arc<EntryRecord>),
    Delete(Collection, String),
    SetMetadata(i64, String),
    SetCursors(BTreeMap<String, Cursor>),
    Runtime(String, Option<Arc<RuntimeRecord>>),
}

// Catalog rows dominate resident state. Keep metadata as a fixed Rust struct,
// rather than allocating a JSON object and field-name strings for every file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum RuntimeRecord {
    File(crate::scan::directory::DirectoryEntryRecord),
    Other(Value),
}
impl RuntimeRecord {
    pub(crate) fn file(&self) -> Option<&crate::scan::directory::DirectoryEntryRecord> {
        match self {Self::File(row)=>Some(row),_=>None}
    }
    pub(crate) fn path(&self) -> Option<&str> {
        match self {Self::File(row)=>Some(&row.path), Self::Other(value)=>value["path"].as_str()}
    }
    fn owner(&self) -> Option<&str> {
        match self {Self::Other(value)=>value["owner"].as_str(),_=>None}
    }
}

#[derive(Debug, Clone, Default)]
struct ScopeCatalog {
    // The bucket index shares each normalized path allocation with the path
    // index. Scope and stem occur once per scope/bucket, not in every row key.
    rows: BTreeMap<Arc<str>, Arc<RuntimeRecord>>,
    buckets: BTreeMap<String, BTreeSet<Arc<str>>>,
}

fn catalog_stem(path: &str) -> String {
    crate::path_keys::case_key(crate::relations::first_dot_stem(
        Path::new(path).file_name().and_then(|name| name.to_str()).unwrap_or_default(),
    ))
}

fn catalog_key(scope: &str, path: &str) -> String {
    format!("file|{scope}|{}|{}", catalog_stem(path), path_key(path))
}

#[derive(Debug, Clone, Default)]
pub(crate) struct StateData {
    pending: HashMap<String, Arc<PendingRecord>>,
    entries: HashMap<String, Arc<EntryRecord>>,
    password_generation: i64,
    password_source_signature: String,
    cursors: BTreeMap<String, Cursor>,
    pub(crate) runtime: BTreeMap<String, Arc<RuntimeRecord>>,
    catalogs: BTreeMap<String, ScopeCatalog>,
    owners: HashMap<String, std::collections::HashSet<String>>,
}

impl StateData {
    pub(crate) fn is_owned(&self, path: &str) -> bool {
        let key=path_key(path);
        let mut current=key.trim_end_matches('\\');
        loop {
            if self.runtime.contains_key(&format!("owned|{current}")) { return true; }
            let Some((parent,_))=current.rsplit_once('\\') else { return false; };
            current=parent;
        }
    }

    pub(crate) fn catalog_records(&self, scope: &str, target: &str) -> Vec<(String, Arc<RuntimeRecord>)> {
        let scope = path_key(scope);
        let target_key = path_key(target);
        let Some(catalog) = self.catalogs.get(&scope) else { return Vec::new(); };
        catalog.rows.range::<str, _>((std::ops::Bound::Included(target_key.as_str()), std::ops::Bound::Unbounded))
            .take_while(|(key, _)| key.starts_with(&target_key))
            .filter(|(key, _)| key.as_ref() == target_key || key[target_key.len()..].starts_with('\\') || target_key.ends_with('\\'))
            .map(|(_, value)| (catalog_key(&scope, value.path().unwrap()), Arc::clone(value))).collect()
    }

    pub(crate) fn catalog_file(&self, scope: &str, path: &str) -> Option<&crate::scan::directory::DirectoryEntryRecord> {
        self.catalogs.get(&path_key(scope))?.rows.get(path_key(path).as_str())?.file()
    }

    pub(crate) fn catalog_bucket(&self, scope: &str, seed: &str) -> Vec<Arc<RuntimeRecord>> {
        let Some(catalog) = self.catalogs.get(&path_key(scope)) else { return Vec::new(); };
        catalog.buckets.get(&catalog_stem(seed)).into_iter().flatten()
            .filter_map(|path| catalog.rows.get(path).cloned()).collect()
    }

    fn runtime_records(&self) -> impl Iterator<Item=(Cow<'_, str>, &Arc<RuntimeRecord>)> {
        self.runtime.iter().map(|(key, value)| (Cow::Borrowed(key.as_str()), value)).chain(
            self.catalogs.iter().flat_map(|(scope, catalog)| catalog.rows.values()
                .map(move |value| (Cow::Owned(catalog_key(scope, value.path().unwrap())), value)))
        )
    }

    fn apply_catalog(&mut self, key: &str, value: &Option<Arc<RuntimeRecord>>) {
        let Some((scope, rest)) = key.strip_prefix("file|").and_then(|rest| rest.split_once('|')) else { return; };
        let Some((stem, path)) = rest.split_once('|') else { return; };
        if let Some(catalog) = self.catalogs.get_mut(scope) {
            if catalog.rows.remove(path).is_some() {
                if let Some(bucket) = catalog.buckets.get_mut(stem) {
                    bucket.remove(path);
                    if bucket.is_empty() { catalog.buckets.remove(stem); }
                }
            }
            if catalog.rows.is_empty() { self.catalogs.remove(scope); }
        }
        if let Some(value) = value {
            let catalog = self.catalogs.entry(scope.to_owned()).or_default();
            let path: Arc<str> = Arc::from(path);
            catalog.buckets.entry(stem.to_owned()).or_default().insert(Arc::clone(&path));
            catalog.rows.insert(path, Arc::clone(value));
        }
    }

    fn apply(&mut self, operation: &Operation) {
        match operation {
            Operation::Runtime(key, value) => {
                if key.starts_with("file|") {
                    self.apply_catalog(key, value);
                    return;
                }
                if let Some(old) = self.runtime.remove(key) {
                    if key.starts_with("owned|") {
                        if let Some(owner) = old.owner() {
                            if let Some(keys) = self.owners.get_mut(owner) { keys.remove(key); if keys.is_empty() { self.owners.remove(owner); } }
                        }
                    }
                }
                if let Some(value) = value {
                    if key.starts_with("owned|") {
                        if let Some(owner) = value.owner().filter(|v| !v.is_empty()) {
                            self.owners.entry(owner.to_owned()).or_default().insert(key.clone());
                        }
                    }
                    self.runtime.insert(key.clone(),Arc::clone(value));
                }
            }
            Operation::PutPending(key, record) => {
                self.pending.insert(key.clone(), Arc::clone(record));
            }
            Operation::PutEntry(key, record) => {
                self.entries.insert(key.clone(), Arc::clone(record));
            }
            Operation::Delete(Collection::Pending, key) => {
                self.pending.remove(key);
            }
            Operation::Delete(Collection::Entries, key) => {
                self.entries.remove(key);
            }
            Operation::SetMetadata(generation, signature) => {
                self.password_generation = *generation;
                self.password_source_signature = signature.clone();
            }
            Operation::SetCursors(cursors) => self.cursors = cursors.clone(),
        }
    }
}

fn trim_map<K: Eq + std::hash::Hash, V>(map: &mut HashMap<K, V>) {
    if map.is_empty() {
        *map = HashMap::new();
    } else if map.capacity() > 256.max(map.len().saturating_mul(4)) {
        map.shrink_to(map.len().saturating_mul(2));
    }
}

/// Decoded journal operations, validated before their WAL record is submitted.
#[pyclass(module = "sunpack_native", frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct NativeWatchOperations {
    operations: Arc<Vec<Operation>>,
    payload: Arc<Vec<u8>>,
}

impl NativeWatchOperations {
    pub(crate) fn from_values(values: Vec<Value>) -> PyResult<Self> {
        let operations = values.iter().map(decode_operation).collect::<PyResult<Vec<_>>>()?;
        let payload = serde_json::to_vec(&values).map_err(|e| invalid(e.to_string()))?;
        Ok(Self { operations: Arc::new(operations), payload: Arc::new(payload) })
    }
    pub(crate) fn journal_value(&self) -> crate::watch_state::JsonValue {
        crate::watch_state::JsonValue::Encoded(Arc::clone(&self.payload))
    }
}
#[pymethods]
impl NativeWatchOperations {
    fn __len__(&self) -> usize { self.operations.len() }
}

/// Frozen checkpoint view; writing it never touches the live maps.
#[pyclass(module = "sunpack_native", frozen)]
pub(crate) struct NativeWatchSnapshot {
    checkpoint_seq: u64,
    data: StateData,
}

#[derive(Serialize)]
struct SnapshotDocument<'a> {
    checkpoint_seq: u64,
    password_generation: i64,
    password_source_signature: &'a str,
    watch_cursors: &'a BTreeMap<String, Cursor>,
    pending_work: BTreeMap<&'a str, &'a PendingRecord>,
    entries: BTreeMap<&'a str, &'a EntryRecord>,
    runtime: RuntimeRecords<'a>,
}

struct RuntimeRecords<'a>(&'a StateData);

impl Serialize for RuntimeRecords<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        for (key, value) in self.0.runtime_records() {
            map.serialize_entry(key.as_ref(), value.as_ref())?;
        }
        map.end()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotInput {
    checkpoint_seq: u64,
    password_generation: i64,
    password_source_signature: String,
    watch_cursors: BTreeMap<String, Cursor>,
    pending_work: BTreeMap<String, PendingRecord>,
    entries: BTreeMap<String, EntryRecord>,
    #[serde(default)]
    runtime: BTreeMap<String, RuntimeRecord>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalTransaction {
    seq: u64,
    operations: Vec<Value>,
}

#[pymethods]
impl NativeWatchSnapshot {
    #[getter]
    fn checkpoint_seq(&self) -> u64 {
        self.checkpoint_seq
    }

    /// Encode, write and fsync the snapshot to an existing temporary file.
    fn write(&self, py: Python<'_>, path: String) -> PyResult<u64> {
        py.detach(|| -> PyResult<u64> {
            let document = SnapshotDocument {
                checkpoint_seq: self.checkpoint_seq,
                password_generation: self.data.password_generation,
                password_source_signature: &self.data.password_source_signature,
                watch_cursors: &self.data.cursors,
                pending_work: self
                    .data
                    .pending
                    .iter()
                    .map(|(key, value)| (key.as_str(), value.as_ref()))
                    .collect(),
                runtime: RuntimeRecords(&self.data),
                entries: self
                    .data
                    .entries
                    .iter()
                    .map(|(key, value)| (key.as_str(), value.as_ref()))
                    .collect(),
            };
            let file = TrackedFile::open_with(&path, "watch_state_snapshot", |options| {
                options.write(true).truncate(true);
                #[cfg(windows)]
                {
                    use std::os::windows::fs::OpenOptionsExt;
                    const FILE_FLAG_SEQUENTIAL_SCAN: u32 = 0x0800_0000;
                    options.custom_flags(FILE_FLAG_SEQUENTIAL_SCAN);
                }
            })?;
            let mut writer = BufWriter::with_capacity(SNAPSHOT_BUFFER_BYTES, file);
            serde_json::to_writer(&mut writer, &document).map_err(|error| {
                PyValueError::new_err(format!("Watch snapshot encoding failed: {error}"))
            })?;
            writer.flush()?;
            writer.get_ref().sync_all()?;
            Ok(writer.get_ref().metadata()?.len())
        })
    }
}

/// Records applied from one journal segment.
#[pyclass(module = "sunpack_native", frozen)]
pub(crate) struct NativeWatchReplay {
    #[pyo3(get)]
    applied_seq: u64,
    #[pyo3(get)]
    expected_seq: u64,
    #[pyo3(get)]
    records: u64,
    #[pyo3(get)]
    bytes: u64,
}

#[pyclass(module = "sunpack_native", frozen)]
pub(crate) struct NativeWatchState {
    data: Mutex<StateData>,
}

impl NativeWatchState {
    pub(crate) fn lock(&self) -> MutexGuard<'_, StateData> {
        self.data
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[pymethods]
impl NativeWatchState {
    #[new]
    fn new() -> Self {
        Self {
            data: Mutex::new(StateData::default()),
        }
    }

    fn runtime_record(&self, py: Python<'_>, key: &str) -> PyResult<Option<Py<PyDict>>> {
        let data = self.lock();
        let record = if let Some((scope, rest)) = key.strip_prefix("file|").and_then(|rest| rest.split_once('|')) {
            rest.split_once('|').and_then(|(_, path)| data.catalogs.get(scope)?.rows.get(path))
        } else { data.runtime.get(key) };
        record.map(|v| to_py_dict(py, v.as_ref())).transpose()
    }

    fn runtime_owner_keys(&self, owner: &str) -> Vec<String> {
        self.lock().owners.get(owner).map(|keys| keys.iter().cloned().collect()).unwrap_or_default()
    }

    fn runtime_keys(&self, prefix: &str) -> Vec<String> {
        let data = self.lock();
        let mut keys: Vec<_> = data.runtime.range(prefix.to_owned()..).take_while(|(k,_)| k.starts_with(prefix)).map(|(k,_)| k.clone()).collect();
        if prefix.starts_with("file|") || "file|".starts_with(prefix) {
            keys.extend(data.catalogs.iter().flat_map(|(scope, catalog)| catalog.rows.values()
                .map(move |value| catalog_key(scope, value.path().unwrap()))).filter(|key| key.starts_with(prefix)));
            keys.sort();
        }
        keys
    }

    fn prune_runtime_scopes(&self, scopes: Vec<PyRef<'_, crate::scan::scope::NativeDiscoveryScope>>) -> PyResult<NativeWatchOperations> {
        let data=self.lock();
        let roots: std::collections::HashSet<_>=scopes.iter().map(|s|path_key(&s.root)).collect();
        let mut operations=Vec::new();
        for (key,value) in data.runtime_records() {
            let keep=if let Some(rest)=key.strip_prefix("file|") {
                rest.split_once('|').is_some_and(|(root,_)| roots.contains(root)
                    && value.path().is_some_and(|p|scopes.iter().any(|s|path_key(&s.root)==root && s.contains(p))))
            } else if let Some(root)=key.strip_prefix("catalog|") { roots.contains(root) }
            else if key.starts_with("done|") {value.path().is_some_and(|p|scopes.iter().any(|s|s.contains(p)))}
            else if key.starts_with("owned|") {
                value.owner().is_some_and(|owner|!owner.is_empty())
                    || value.path().is_some_and(|p|scopes.iter().any(|scope|scope.intersects_output(p)))
            } else {true};
            if !keep { operations.push(serde_json::json!({"op":"runtime","key":key})); }
        }
        NativeWatchOperations::from_values(operations)
    }

    fn owned_root(&self, path: &str) -> Option<String> {
        let normalized = path_key(path);
        let mut current = normalized.trim_end_matches('\\');
        let data = self.lock();
        loop {
            if data.runtime.contains_key(&format!("owned|{current}")) { return Some(current.to_owned()); }
            let Some((parent,_)) = current.rsplit_once('\\') else { return None; };
            current = parent;
        }
    }

    fn reset(&self) {
        *self.lock() = StateData::default();
    }

    /// Capacity-only maintenance: never changes records or checkpoint views.
    fn trim_idle_storage(&self) {
        let mut data = self.lock();
        trim_map(&mut data.pending);
        trim_map(&mut data.entries);
    }

    fn storage_capacities(&self) -> (usize, usize) {
        let data = self.lock();
        (data.pending.capacity(), data.entries.capacity())
    }

    #[getter]
    fn password_generation(&self) -> i64 {
        self.lock().password_generation
    }

    #[getter]
    fn password_source_signature(&self) -> String {
        self.lock().password_source_signature.clone()
    }

    #[getter]
    fn pending_count(&self) -> usize {
        self.lock().pending.len()
    }

    #[getter]
    fn entry_count(&self) -> usize {
        self.lock().entries.len()
    }

    fn pending(&self, py: Python<'_>, path: &str) -> PyResult<Option<Py<PyDict>>> {
        let record = self.lock().pending.get(&path_key(path)).cloned();
        record
            .map(|value| to_py_dict(py, value.as_ref()))
            .transpose()
    }

    fn entry(&self, py: Python<'_>, path: &str) -> PyResult<Option<Py<PyDict>>> {
        let record = self.lock().entries.get(&path_key(path)).cloned();
        record
            .map(|value| to_py_dict(py, value.as_ref()))
            .transpose()
    }

    fn pending_items(&self, py: Python<'_>) -> PyResult<Vec<Py<PyDict>>> {
        let records: Vec<_> = self.lock().pending.values().cloned().collect();
        records
            .iter()
            .map(|value| to_py_dict(py, value.as_ref()))
            .collect()
    }

    /// Entries, optionally only those with one ``status``.
    #[pyo3(signature = (status=None))]
    fn entry_items(&self, py: Python<'_>, status: Option<&str>) -> PyResult<Vec<Py<PyDict>>> {
        let records: Vec<_> = self
            .lock()
            .entries
            .values()
            .filter(|value| status.is_none_or(|status| value.status == status))
            .cloned()
            .collect();
        records
            .iter()
            .map(|value| to_py_dict(py, value.as_ref()))
            .collect()
    }

    fn has_entry_status(&self, status: &str) -> bool {
        self.lock()
            .entries
            .values()
            .any(|value| value.status == status)
    }

    fn has_pending(&self, path: &str) -> bool {
        self.lock().pending.contains_key(&path_key(path))
    }

    fn has_entry(&self, path: &str) -> bool {
        self.lock().entries.contains_key(&path_key(path))
    }

    /// Missing-only retirement keeps durable output recovery, even under a removed directory.
    #[pyo3(signature = (path, recursive, *, missing_only=false))]
    fn keys_matching(
        &self,
        py: Python<'_>,
        path: &str,
        recursive: bool,
        missing_only: bool,
    ) -> (Vec<String>, Vec<String>) {
        let expected = path_key(path);
        let matches =
            |key: &String| key == &expected || (recursive && is_path_under(key, &expected));
        let (pending, entries): (Vec<_>, Vec<_>) = {
            let data = self.lock();
            if recursive {
                (
                    data.pending
                        .iter()
                        .filter(|(key, _)| matches(key))
                        .map(|(key, record)| (key.clone(), Arc::clone(record)))
                        .collect(),
                    data.entries
                        .iter()
                        .filter(|(key, _)| matches(key))
                        .map(|(key, record)| (key.clone(), Arc::clone(record)))
                        .collect(),
                )
            } else {
                (
                    data.pending
                        .get(&expected)
                        .map(|record| (expected.clone(), Arc::clone(record)))
                        .into_iter()
                        .collect(),
                    data.entries
                        .get(&expected)
                        .map(|record| (expected.clone(), Arc::clone(record)))
                        .into_iter()
                        .collect(),
                )
            }
        };
        py.detach(move || {
            let mut pending: Vec<_> = pending
                .into_iter()
                .filter(|(_, record)| {
                    !missing_only
                        || (record.active_outputs.is_empty()
                            && record.committed_roots.is_empty()
                            && recorded_file_presence(&record.path) == Some(false))
                })
                .map(|(key, _)| key)
                .collect();
            let mut entries: Vec<_> = entries
                .into_iter()
                .filter(|(_, record)| {
                    !missing_only || recorded_file_presence(&record.path) == Some(false)
                })
                .map(|(key, _)| key)
                .collect();
            pending.sort();
            entries.sort();
            (pending, entries)
        })
    }

    /// ``(key, recorded path)`` in the requested retry-entry scope.
    #[pyo3(signature = (path=None, recursive=false))]
    fn entry_paths(&self, path: Option<&str>, recursive: bool) -> Vec<(String, String)> {
        let expected = path.map(path_key);
        let data = self.lock();
        let mut paths: Vec<_> = if let Some(key) = expected.as_ref().filter(|_| !recursive) {
            data.entries
                .get(key)
                .map(|record| (key.clone(), record.path.clone()))
                .into_iter()
                .collect()
        } else {
            data.entries
                .iter()
                .filter(|(key, _)| {
                    expected
                        .as_ref()
                        .is_none_or(|expected| *key == expected || is_path_under(key, expected))
                })
                .map(|(key, record)| (key.clone(), record.path.clone()))
                .collect()
        };
        paths.sort();
        paths
    }

    #[staticmethod]
    fn file_presence(py: Python<'_>, path: &str) -> Option<bool> {
        py.detach(|| recorded_file_presence(path))
    }

    fn watch_cursors<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let cursors = self.lock().cursors.clone();
        let result = PyDict::new(py);
        for (key, cursor) in cursors {
            result.set_item(key, cursor_dict(py, cursor)?)?;
        }
        Ok(result)
    }

    fn watch_cursor<'py>(
        &self,
        py: Python<'py>,
        volume_key: &str,
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        let cursor = self.lock().cursors.get(&volume_key.to_lowercase()).copied();
        cursor.map(|cursor| cursor_dict(py, cursor)).transpose()
    }

    /// Validate journal operations; raises ``ValueError``/``TypeError`` like the WAL replay.
    fn decode_operations(&self, operations: &Bound<'_, PyAny>) -> PyResult<NativeWatchOperations> {
        if let Ok(native) = operations.extract::<PyRef<NativeWatchOperations>>() {
            return Ok((*native).clone());
        }
        let values = operations.try_iter()?.map(|v| py_to_json(&v?)).collect::<PyResult<Vec<_>>>()?;
        NativeWatchOperations::from_values(values)
    }

    fn fold_owned_outputs(&self, operations: &Bound<'_, PyAny>) -> PyResult<NativeWatchOperations> {
        let mut values = operations.try_iter()?.map(|v| py_to_json(&v?)).collect::<PyResult<Vec<_>>>()?;
        let retained: std::collections::HashSet<String> = values.iter()
            .filter(|op| op["value"]["owner"].as_str() == Some("")
                && op["value"]["state"].as_str() == Some("retained"))
            .filter_map(|op| op["key"].as_str().map(str::to_owned)).collect();
        for operation in &mut values {
            let Some(key) = operation["key"].as_str() else { continue; };
            if !retained.contains(key) { continue; }
            let key = key.to_owned();
            let mut parent = key.as_str();
            while let Some((ancestor, _)) = parent.rsplit_once('\\') {
                if retained.contains(ancestor) {
                    *operation = serde_json::json!({"op":"runtime","key":key});
                    break;
                }
                parent = ancestor;
            }
        }
        NativeWatchOperations::from_values(values)
    }

    fn apply(&self, operations: PyRef<'_, NativeWatchOperations>) {
        let mut data = self.lock();
        for operation in operations.operations.iter() {
            data.apply(operation);
        }
    }

    fn capture(&self, checkpoint_seq: u64) -> NativeWatchSnapshot {
        NativeWatchSnapshot {
            checkpoint_seq,
            data: self.lock().clone(),
        }
    }

    /// Replace the maps with the snapshot at ``path``.
    fn load_snapshot(&self, py: Python<'_>, path: String) -> PyResult<u64> {
        let (checkpoint_seq, data) = py.detach(|| load_snapshot_file(&path))?;
        *self.lock() = data;
        Ok(checkpoint_seq)
    }

    /// Apply one journal segment after ``checkpoint_seq``; errors carry the WAL diagnosis.
    fn replay_segment(
        &self,
        py: Python<'_>,
        path: String,
        checkpoint_seq: u64,
        expected_seq: u64,
    ) -> PyResult<NativeWatchReplay> {
        let mut data = std::mem::take(&mut *self.lock());
        let replay =
            py.detach(|| replay_segment_file(&mut data, &path, checkpoint_seq, expected_seq));
        *self.lock() = data;
        replay
    }
}

/// Absolute Windows filesystem key shared with discovery and Python.
#[pyfunction]
pub(crate) fn watch_path_key(path: &str) -> String {
    path_key(path)
}

fn path_key(path: &str) -> String {
    let absolute = if path.is_empty() {
        std::env::current_dir().unwrap_or_default()
    } else {
        std::path::absolute(path).unwrap_or_else(|_| Path::new(path).to_path_buf())
    };
    crate::path_keys::path_key(&absolute.to_string_lossy())
}

fn is_path_under(path: &str, root: &str) -> bool {
    let root = root.trim_end_matches('\\');
    path.len() > root.len() && path.starts_with(root) && path.as_bytes()[root.len()] == b'\\'
}

fn cursor_dict<'py>(py: Python<'py>, cursor: Cursor) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("journal_id", cursor.journal_id)?;
    dict.set_item("next_usn", cursor.next_usn)?;
    Ok(dict)
}

fn invalid(message: impl Into<String>) -> PyErr {
    PyValueError::new_err(message.into())
}

fn require_fields(object: &Map<String, Value>, required: &[&str]) -> PyResult<()> {
    if required.iter().any(|name| !object.contains_key(*name))
        || object.keys().any(|name| !required.contains(&name.as_str()))
    {
        return Err(invalid("invalid journal operation fields"));
    }
    Ok(())
}

fn decode_record<T: for<'de> Deserialize<'de>>(value: &Value) -> PyResult<T> {
    if !value.is_object() {
        return Err(PyTypeError::new_err("state record value must be an object"));
    }
    T::deserialize(value).map_err(|error| PyTypeError::new_err(error.to_string()))
}

fn decode_operation(operation: &Value) -> PyResult<Operation> {
    let Some(object) = operation.as_object() else {
        return Err(PyTypeError::new_err("journal operation must be an object"));
    };
    let action = object
        .get("op")
        .and_then(Value::as_str)
        .ok_or_else(|| PyTypeError::new_err("journal operation op must be a string"))?;
    match action {
        "runtime" => {
            let key = object.get("key").and_then(Value::as_str).ok_or_else(|| invalid("runtime key missing"))?;
            let value=object.get("value").filter(|v|!v.is_null()).map(|value| {
                if key.starts_with("file|") {
                    serde_json::from_value(value.clone()).map(RuntimeRecord::File).map_err(|e|invalid(e.to_string()))
                } else {Ok(RuntimeRecord::Other(value.clone()))}
            }).transpose()?.map(Arc::new);
            return Ok(Operation::Runtime(key.to_owned(), value));
        }
        "set_metadata" => {
            require_fields(object, &["op", "value"])?;
            let value = object
                .get("value")
                .and_then(Value::as_object)
                .ok_or_else(|| PyTypeError::new_err("metadata value must be an object"))?;
            require_fields(value, &["password_generation", "password_source_signature"])?;
            let generation = value
                .get("password_generation")
                .and_then(Value::as_i64)
                .ok_or_else(|| invalid("metadata password_generation must be an integer"))?;
            let signature = value
                .get("password_source_signature")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("metadata password_source_signature must be a string"))?;
            if generation < 0 {
                return Err(invalid("metadata password_generation must not be negative"));
            }
            return Ok(Operation::SetMetadata(generation, signature.to_owned()));
        }
        "set_watch_cursors" => {
            require_fields(object, &["op", "value"])?;
            let value = object
                .get("value")
                .and_then(Value::as_object)
                .ok_or_else(|| PyTypeError::new_err("watch cursor value must be an object"))?;
            let cursors =
                serde_json::from_value::<BTreeMap<String, Cursor>>(Value::Object(value.clone()))
                    .map_err(|error| invalid(format!("invalid watch cursor value: {error}")))?;
            return Ok(Operation::SetCursors(
                cursors
                    .into_iter()
                    .map(|(key, cursor)| (key.to_lowercase(), cursor))
                    .collect(),
            ));
        }
        _ => {}
    }
    let collection_name = object
        .get("collection")
        .and_then(Value::as_str)
        .ok_or_else(|| PyTypeError::new_err("journal operation collection must be a string"))?;
    let collection = match collection_name {
        "pending_work" => Collection::Pending,
        "entries" => Collection::Entries,
        other => return Err(invalid(format!("unknown state collection: {other}"))),
    };
    if action == "put" {
        require_fields(object, &["op", "collection", "key", "value"])?;
    } else {
        require_fields(object, &["op", "collection", "key"])?;
    }
    let key = object
        .get("key")
        .and_then(Value::as_str)
        .ok_or_else(|| PyTypeError::new_err("journal operation key must be a string"))?
        .to_owned();
    if key.is_empty() {
        return Err(invalid("state operation key must not be empty"));
    }
    match action {
        "delete" => Ok(Operation::Delete(collection, key)),
        "put" => {
            let value = object
                .get("value")
                .ok_or_else(|| PyTypeError::new_err("journal put operation requires value"))?;
            Ok(match collection {
                Collection::Pending => {
                    let record: PendingRecord = decode_record(value)?;
                    Operation::PutPending(path_key(&record.path), Arc::new(record))
                }
                Collection::Entries => {
                    let record: EntryRecord = decode_record(value)?;
                    Operation::PutEntry(path_key(&record.path), Arc::new(record))
                }
            })
        }
        other => Err(invalid(format!("unknown state operation: {other}"))),
    }
}

fn load_snapshot_file(path: &str) -> PyResult<(u64, StateData)> {
    let mut file = TrackedFile::open(path, "watch_state_snapshot_input")?;
    let mut raw = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut raw)?;
    let snapshot: SnapshotInput = serde_json::from_slice(&raw)
        .map_err(|error| invalid(format!("corrupt watch state snapshot at {path}: {error}")))?;
    if snapshot.password_generation < 0 {
        return Err(invalid(format!(
            "corrupt watch state snapshot at {path}: negative password_generation"
        )));
    }
    let checkpoint_seq = snapshot.checkpoint_seq;
    let password_generation = snapshot.password_generation;
    let mut data = StateData {
        catalogs: BTreeMap::new(),
        owners: HashMap::new(),
        runtime: BTreeMap::new(),
        pending: snapshot
            .pending_work
            .into_values()
            .map(|record| (path_key(&record.path), Arc::new(record)))
            .collect(),
        entries: snapshot
            .entries
            .into_values()
            .map(|record| (path_key(&record.path), Arc::new(record)))
            .collect(),
        password_generation,
        password_source_signature: snapshot.password_source_signature,
        cursors: snapshot
            .watch_cursors
            .into_iter()
            .map(|(key, cursor)| (key.to_lowercase(), cursor))
            .collect(),
    };
    for (key,value) in snapshot.runtime { data.apply(&Operation::Runtime(key,Some(Arc::new(value)))); }
    Ok((checkpoint_seq, data))
}

fn replay_segment_file(
    data: &mut StateData,
    path: &str,
    checkpoint_seq: u64,
    mut expected_seq: u64,
) -> PyResult<NativeWatchReplay> {
    let file = TrackedFile::open(path, "watch_state_journal_input")?;
    let mut reader = BufReader::new(file);
    let mut replay = NativeWatchReplay {
        applied_seq: 0,
        expected_seq,
        records: 0,
        bytes: 0,
    };
    let mut line = Vec::new();
    let mut line_number = 0usize;
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line)? == 0 {
            break;
        }
        line_number += 1;
        // A torn final append is harmless in a sealed segment; a
        // lost transaction is still caught by the next sequence gap.
        if line.last() != Some(&b'\n') {
            break;
        }
        let at = || format!("{path}:{line_number}");
        let transaction: JournalTransaction = serde_json::from_slice(&line)
            .map_err(|_| invalid(format!("corrupt watch state journal at {}", at())))?;
        let seq = transaction.seq;
        if transaction.operations.is_empty() {
            return Err(invalid(format!(
                "invalid watch state operations at {}",
                at()
            )));
        }
        if seq <= checkpoint_seq {
            continue;
        }
        if seq != expected_seq {
            return Err(invalid(format!(
                "non-contiguous watch state sequence at {}: expected {expected_seq}, got {seq}",
                at()
            )));
        }
        let decoded = transaction
            .operations
            .iter()
            .map(decode_operation)
            .collect::<PyResult<Vec<_>>>()
            .map_err(|_| invalid(format!("invalid watch state operation at {}", at())))?;
        for operation in &decoded {
            data.apply(operation);
        }
        replay.applied_seq = seq;
        expected_seq = seq + 1;
        replay.records += 1;
        replay.bytes += line.len() as u64;
    }
    replay.expected_seq = expected_seq;
    Ok(replay)
}

fn to_py_dict<T: Serialize>(py: Python<'_>, record: &T) -> PyResult<Py<PyDict>> {
    let value = serde_json::to_value(record).map_err(|error| invalid(error.to_string()))?;
    json_to_py(py, &value)?
        .bind(py)
        .cast::<PyDict>()
        .map(|dict| dict.clone().unbind())
        .map_err(|_| invalid("Watch record did not encode as an object"))
}

fn json_to_py(py: Python<'_>, value: &Value) -> PyResult<Py<PyAny>> {
    use pyo3::IntoPyObjectExt;
    Ok(match value {
        Value::Null => py.None(),
        Value::Bool(flag) => flag.into_py_any(py)?,
        Value::Number(number) => {
            if let Some(value) = number.as_i64() {
                value.into_py_any(py)?
            } else if let Some(value) = number.as_u64() {
                value.into_py_any(py)?
            } else {
                number.as_f64().unwrap_or(0.0).into_py_any(py)?
            }
        }
        Value::String(text) => text.into_py_any(py)?,
        Value::Array(items) => {
            let list = PyList::empty(py);
            for item in items {
                list.append(json_to_py(py, item)?)?;
            }
            list.into_any().unbind()
        }
        Value::Object(items) => {
            let dict = PyDict::new(py);
            for (key, item) in items {
                dict.set_item(key, json_to_py(py, item)?)?;
            }
            dict.into_any().unbind()
        }
    })
}

fn py_to_json(value: &Bound<'_, PyAny>) -> PyResult<Value> {
    if value.is_none() {
        return Ok(Value::Null);
    }
    if value.is_instance_of::<PyBool>() {
        return Ok(Value::Bool(value.extract::<bool>()?));
    }
    if value.is_instance_of::<PyInt>() {
        if let Ok(number) = value.extract::<i64>() {
            return Ok(Value::from(number));
        }
        return Ok(Value::from(value.extract::<u64>()?));
    }
    if value.is_instance_of::<PyFloat>() {
        return serde_json::Number::from_f64(value.extract::<f64>()?)
            .map(Value::Number)
            .ok_or_else(|| PyTypeError::new_err("Watch state floats must be finite"));
    }
    if value.is_instance_of::<PyString>() {
        return Ok(Value::String(value.extract::<String>()?));
    }
    if let Ok(dict) = value.cast::<PyDict>() {
        let mut object = Map::with_capacity(dict.len());
        for (key, item) in dict.iter() {
            let key = if key.is_instance_of::<PyString>() {
                key.extract::<String>()?
            } else {
                key.str()?.to_string_lossy().into_owned()
            };
            object.insert(key, py_to_json(&item)?);
        }
        return Ok(Value::Object(object));
    }
    if value.is_instance_of::<PyList>() || value.is_instance_of::<PyTuple>() {
        let mut items = Vec::new();
        for item in value.try_iter()? {
            items.push(py_to_json(&item?)?);
        }
        return Ok(Value::Array(items));
    }
    Err(PyTypeError::new_err(
        "Watch state contains a value that is not JSON serializable",
    ))
}

#[cfg(test)]
mod tests {
    use super::is_path_under;

    #[test]
    fn path_under_requires_a_component_boundary() {
        assert!(is_path_under("c:\\a\\b", "c:\\a"));
        assert!(is_path_under("c:\\a\\b", "c:\\a\\"));
        assert!(!is_path_under("c:\\ab", "c:\\a"));
        assert!(!is_path_under("c:\\a", "c:\\a"));
        assert!(is_path_under("c:\\a", "c:\\"));
    }
}
