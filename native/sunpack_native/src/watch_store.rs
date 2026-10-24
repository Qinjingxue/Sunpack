//! Resident Watch state records owned by Rust.
//!
//! `WatchStateStore` (Python) keeps sequencing, WAL submission and checkpoint
//! orchestration. The record maps, their snapshot/journal decoding, operation
//! application and snapshot encoding live here, so the long-running Watch
//! process never keeps every pending item and retry entry as Python objects.

use crate::io::resource_lifecycle::TrackedFile;
use crate::wal::{self, Kind};
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyFloat, PyInt, PyList, PyString, PyTuple};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

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
    discovery_scope: Map<String, Value>,
    durable_owner: bool,
    active_outputs: BTreeMap<String, String>,
    committed_roots: Vec<String>,
    completed_sources: Vec<String>,
    output_identities: BTreeMap<String, String>,
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
    Runtime(String, Option<Value>),
}

// Fixed numeric opcodes and tuple fields; put records persist their path once.
impl Serialize for Operation {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::PutPending(_, record) => (0u8, record).serialize(serializer),
            Self::PutEntry(_, record) => (1u8, record).serialize(serializer),
            Self::Delete(Collection::Pending, key) => (2u8, key).serialize(serializer),
            Self::Delete(Collection::Entries, key) => (3u8, key).serialize(serializer),
            Self::SetMetadata(generation, signature) => {
                (4u8, generation, signature).serialize(serializer)
            }
            Self::SetCursors(cursors) => (5u8, cursors).serialize(serializer),
            Self::Runtime(key, value) => (6u8, key, value).serialize(serializer),
        }
    }
}
impl<'de> Deserialize<'de> for Operation {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Operation;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a typed Watch operation")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Operation, A::Error> {
                use serde::de::Error;
                fn field<'de, A: serde::de::SeqAccess<'de>, T: Deserialize<'de>>(
                    seq: &mut A,
                ) -> Result<T, A::Error> {
                    seq.next_element()?
                        .ok_or_else(|| A::Error::custom("missing operation field"))
                }
                let tag: u8 = field(&mut seq)?;
                let op = match tag {
                    0 => {
                        let record: Arc<PendingRecord> = field(&mut seq)?;
                        Operation::PutPending(path_key(&record.path), record)
                    }
                    1 => {
                        let record: Arc<EntryRecord> = field(&mut seq)?;
                        Operation::PutEntry(path_key(&record.path), record)
                    }
                    2 | 3 => {
                        let key: String = field(&mut seq)?;
                        if key.is_empty() {
                            return Err(A::Error::custom("empty record key"));
                        }
                        Operation::Delete(
                            if tag == 2 {
                                Collection::Pending
                            } else {
                                Collection::Entries
                            },
                            key,
                        )
                    }
                    4 => {
                        let generation = field(&mut seq)?;
                        if generation < 0 {
                            return Err(A::Error::custom("negative password generation"));
                        }
                        Operation::SetMetadata(generation, field(&mut seq)?)
                    }
                    5 => Operation::SetCursors(field(&mut seq)?),
                    6 => {
                        let key: String = field(&mut seq)?;
                        if !key.starts_with("owned|") {
                            return Err(A::Error::custom("unknown runtime record"));
                        }
                        Operation::Runtime(key, field(&mut seq)?)
                    }
                    _ => return Err(A::Error::custom("unknown operation opcode")),
                };
                if seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
                    return Err(A::Error::custom("unexpected operation field"));
                }
                Ok(op)
            }
        }
        deserializer.deserialize_seq(Visitor)
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct StateData {
    pending: HashMap<String, Arc<PendingRecord>>,
    entries: HashMap<String, Arc<EntryRecord>>,
    password_generation: i64,
    password_source_signature: String,
    cursors: BTreeMap<String, Cursor>,
    pub(crate) runtime: BTreeMap<String, Value>,
}

impl StateData {
    fn apply(&mut self, operation: &Operation) {
        match operation {
            Operation::Runtime(key, value) => {
                if let Some(value) = value {
                    self.runtime.insert(key.clone(), value.clone());
                } else {
                    self.runtime.remove(key);
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

#[derive(Default, Serialize)]
#[serde(transparent)]
pub(crate) struct Operations(Vec<Operation>);

/// Decoded journal operations, validated before their WAL record is submitted.
#[pyclass(module = "sunpack_native", frozen)]
pub(crate) struct NativeWatchOperations {
    pub(crate) operations: Arc<Operations>,
}

/// Frozen checkpoint view; writing it never touches the live maps.
#[pyclass(module = "sunpack_native", frozen)]
pub(crate) struct NativeWatchSnapshot {
    checkpoint_seq: u64,
    data: StateData,
}

// Serialize map values directly: derived path keys never reach disk, and no
// sorted pointer map is allocated for a checkpoint.
struct Records<'a, T>(&'a HashMap<String, Arc<T>>);
impl<T: Serialize> Serialize for Records<'_, T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for record in self.0.values() {
            seq.serialize_element(record)?;
        }
        seq.end()
    }
}

trait RecordPath {
    fn path(&self) -> &str;
}
impl RecordPath for PendingRecord {
    fn path(&self) -> &str {
        &self.path
    }
}
impl RecordPath for EntryRecord {
    fn path(&self) -> &str {
        &self.path
    }
}

fn read_records<'de, D, T>(deserializer: D) -> Result<HashMap<String, Arc<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + RecordPath,
{
    struct Visitor<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de> + RecordPath> serde::de::Visitor<'de> for Visitor<T> {
        type Value = HashMap<String, Arc<T>>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("state records")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Self::Value, A::Error> {
            let mut records = HashMap::with_capacity(seq.size_hint().unwrap_or(0).min(4096));
            while let Some(record) = seq.next_element::<T>()? {
                if records
                    .insert(path_key(record.path()), Arc::new(record))
                    .is_some()
                {
                    return Err(serde::de::Error::custom("duplicate state record"));
                }
            }
            Ok(records)
        }
    }
    deserializer.deserialize_seq(Visitor(std::marker::PhantomData))
}

#[derive(Serialize)]
struct SnapshotDocument<'a> {
    password_generation: i64,
    password_source_signature: &'a str,
    watch_cursors: &'a BTreeMap<String, Cursor>,
    pending_work: Records<'a, PendingRecord>,
    entries: Records<'a, EntryRecord>,
    runtime: &'a BTreeMap<String, Value>,
}

#[derive(Deserialize)]
struct SnapshotInput {
    password_generation: i64,
    password_source_signature: String,
    watch_cursors: BTreeMap<String, Cursor>,
    #[serde(deserialize_with = "read_records")]
    pending_work: HashMap<String, Arc<PendingRecord>>,
    #[serde(deserialize_with = "read_records")]
    entries: HashMap<String, Arc<EntryRecord>>,
    runtime: BTreeMap<String, Value>,
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
                password_generation: self.data.password_generation,
                password_source_signature: &self.data.password_source_signature,
                watch_cursors: &self.data.cursors,
                pending_work: Records(&self.data.pending),
                entries: Records(&self.data.entries),
                runtime: &self.data.runtime,
            };
            let mut file = TrackedFile::open_with(&path, "watch_state_snapshot", |options| {
                options.write(true).truncate(true);
                #[cfg(windows)]
                {
                    use std::os::windows::fs::OpenOptionsExt;
                    const FILE_FLAG_SEQUENTIAL_SCAN: u32 = 0x0800_0000;
                    options.custom_flags(FILE_FLAG_SEQUENTIAL_SCAN);
                }
            })?;
            let bytes = wal::write_snapshot(
                &mut file,
                Kind::TaskSnapshot,
                self.checkpoint_seq,
                &document,
            )?;
            file.sync_all()?;
            Ok(bytes)
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
    #[pyo3(get)]
    valid_bytes: u64,
}

#[pyclass(module = "sunpack_native", frozen)]
pub(crate) struct NativeWatchState {
    pub(crate) data: Arc<Mutex<StateData>>,
    events: Mutex<Option<std::sync::Weak<crate::event_log::Shared>>>,
}

impl NativeWatchState {
    pub(crate) fn with_event_projection<T>(&self, publish: impl FnOnce(Vec<Value>) -> T) -> T {
        let data = self.lock();
        let mut rows = Vec::new();
        let mut member_presence = HashMap::new();
        for record in data.pending.values() {
            rows.push(serde_json::json!({"event":"task_queued","path":record.path}));
        }
        let mut entries: Vec<_> = data.entries.values().collect();
        entries.sort_by(|a, b| {
            a.last_attempt_at
                .total_cmp(&b.last_attempt_at)
                .then_with(|| a.path.cmp(&b.path))
        });
        for record in entries {
            if !matches!(
                record.status.as_str(),
                "failed_password" | "suspended_missing_volume"
            ) {
                continue;
            }
            if let Some(group) = record.failure_payload.get("ui_group") {
                // A member can disappear after its blocker WAL commit (even
                // while offline). Verify only recorded member presence; never
                // probe or rediscover an archive for the GUI projection.
                let mut group = group.clone();
                if let Some(members) = group["members"].as_array_mut() {
                    members.retain(|member| {
                        member.as_str().is_some_and(|member| {
                            *member_presence
                                .entry(path_key(member))
                                .or_insert_with(|| recorded_file_presence(member))
                                != Some(false)
                        })
                    });
                    if !members.is_empty() {
                        rows.push(serde_json::json!({"event":"pipeline_sources_claimed","groups":[group]}));
                    }
                }
            }
            rows.push(serde_json::json!({"event":record.status,"path":record.path,
                "ts":record.last_attempt_at,"error":record.last_error}));
        }
        publish(rows)
    }
    pub(crate) fn lock(&self) -> MutexGuard<'_, StateData> {
        self.data
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[pymethods]
impl NativeWatchState {
    fn runtime_record(&self, py: Python<'_>, key: &str) -> PyResult<Option<Py<PyDict>>> {
        self.lock()
            .runtime
            .get(key)
            .map(|v| to_py_dict(py, v))
            .transpose()
    }

    fn runtime_keys(&self, prefix: &str) -> Vec<String> {
        self.lock()
            .runtime
            .range(prefix.to_owned()..)
            .take_while(|(key, _)| key.starts_with(prefix))
            .map(|(key, _)| key.clone())
            .collect()
    }

    fn output_root_in_use(&self, path: &str) -> bool {
        let root = path_key(path);
        let intersects = |path: &str| {
            let key = path_key(path);
            key == root || is_path_under(&key, &root) || is_path_under(&root, &key)
        };
        self.lock().pending.values().any(|record| {
            let source = path_key(&record.path);
            source == root
                || is_path_under(&source, &root)
                || record.active_outputs.values().any(|path| intersects(path))
                || record.committed_roots.iter().any(|path| intersects(path))
        })
    }

    fn owned_root(&self, path: &str) -> Option<String> {
        let key = crate::path_keys::path_key(path);
        let mut current = key.trim_end_matches('\\');
        let data = self.lock();
        loop {
            if data
                .runtime
                .get(&format!("owned|{current}"))
                .is_some_and(output_identity_matches)
            {
                return Some(current.to_owned());
            }
            let Some((parent, _)) = current.rsplit_once('\\') else {
                return None;
            };
            current = parent;
        }
    }

    #[new]
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(StateData::default())),
            events: Mutex::new(None),
        }
    }

    fn attach_events(&self, log: PyRef<'_, crate::event_log::NativeEventLog>) -> PyResult<()> {
        *self.events.lock().unwrap() = Some(Arc::downgrade(log.shared()?));
        Ok(())
    }

    fn invalidate_events(&self) {
        if let Some(events) = self
            .events
            .lock()
            .unwrap()
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
        {
            events.invalidate();
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

    /// Configuration retirement only visits resident state, never file-index rows.
    fn unused_scope_keys(
        &self,
        py: Python<'_>,
        scopes: Vec<Py<crate::scan::scope::NativeDiscoveryScope>>,
    ) -> (Vec<String>, Vec<String>) {
        let scopes: Vec<_> = scopes
            .iter()
            .map(|scope| scope.borrow(py).clone())
            .collect();
        py.detach(|| {
            let data = self.lock();
            let recovery_paths: Vec<_> = data
                .pending
                .values()
                .flat_map(|record| {
                    record
                        .active_outputs
                        .keys()
                        .chain(record.active_outputs.values())
                        .chain(record.committed_roots.iter())
                        .map(|path| path_key(path))
                })
                .collect();
            let entries = data
                .entries
                .iter()
                .filter(|(key, record)| {
                    !scopes.iter().any(|scope| scope.contains(&record.path))
                        && !data.pending.contains_key(*key)
                        && !recovery_paths
                            .iter()
                            .any(|root| *key == root || is_path_under(key, root))
                })
                .map(|(key, _)| key.clone())
                .collect();
            if data.cursors.is_empty() {
                return (entries, Vec::new());
            }

            // Resolve each root/recovery directory once using the existing
            // volume resolver. An inaccessible volume is not proof of disuse.
            let directories: HashSet<_> = scopes
                .iter()
                .map(|scope| scope.root.as_str())
                .chain(data.pending.values().map(|record| {
                    Path::new(&record.path)
                        .parent()
                        .and_then(Path::to_str)
                        .unwrap_or(&record.path)
                }))
                .collect();
            let mut volumes = HashSet::new();
            for directory in directories {
                match crate::filesystem::resolve_output_volume_key(directory) {
                    Ok(Some(volume)) => {
                        volumes.insert(volume.to_lowercase());
                    }
                    _ => return (entries, Vec::new()),
                }
            }
            let cursors = data
                .cursors
                .keys()
                .filter(|key| !volumes.contains(*key))
                .cloned()
                .collect();
            (entries, cursors)
        })
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
        let mut decoded = Vec::new();
        for operation in operations.try_iter()? {
            let mut operation = decode_operation(&py_to_json(&operation?)?)?;
            if let Operation::PutEntry(_, record) = &mut operation {
                if let Some(events) = self
                    .events
                    .lock()
                    .unwrap()
                    .as_ref()
                    .and_then(std::sync::Weak::upgrade)
                {
                    if let Some(group) = events.group(&record.path) {
                        Arc::make_mut(record)
                            .failure_payload
                            .insert("ui_group".into(), group);
                    }
                }
            }
            decoded.push(operation);
        }
        Ok(NativeWatchOperations {
            operations: Arc::new(Operations(decoded)),
        })
    }

    fn apply(&self, operations: PyRef<'_, NativeWatchOperations>) {
        let mut data = self.lock();
        for operation in operations.operations.0.iter() {
            data.apply(operation);
            if let Operation::Delete(Collection::Entries, path) = operation {
                if let Some(events) = self
                    .events
                    .lock()
                    .unwrap()
                    .as_ref()
                    .and_then(std::sync::Weak::upgrade)
                {
                    let group = events.group(path);
                    let remaining = group
                        .as_ref()
                        .and_then(|group| group["members"].as_array())
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .filter_map(|member| data.entries.get(&path_key(member)))
                        .max_by(|a, b| a.last_attempt_at.total_cmp(&b.last_attempt_at));
                    if let Some(record) = remaining {
                        events.submit(serde_json::json!({"event":record.status,"path":record.path,
                            "ts":record.last_attempt_at,"error":record.last_error,"failures":[record.failure_payload]}));
                    } else {
                        events.submit(serde_json::json!({"event":"blocker_cleared","path":path}));
                    }
                }
            }
            if let Operation::PutEntry(_, record) = operation {
                if matches!(
                    record.status.as_str(),
                    "failed_password" | "suspended_missing_volume"
                ) {
                    if let Some(events) = self
                        .events
                        .lock()
                        .unwrap()
                        .as_ref()
                        .and_then(std::sync::Weak::upgrade)
                    {
                        events.submit(serde_json::json!({"event":record.status,"path":record.path,
                            "ts":record.last_attempt_at,"error":record.last_error,"failures":[record.failure_payload]}));
                    }
                }
            }
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

    /// Replay already established this boundary while holding the path gate.
    #[staticmethod]
    fn truncate_journal_tail(py: Python<'_>, path: String, valid_bytes: u64) -> PyResult<()> {
        py.detach(|| -> PyResult<()> {
            let file = TrackedFile::open_with(&path, "watch_journal_repair", |options| {
                options.read(true).write(true);
            })?;
            if file.metadata()?.len() != valid_bytes {
                file.set_len(valid_bytes)?;
                file.sync_all()?;
            }
            Ok(())
        })
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

pub(crate) fn is_path_under(path: &str, root: &str) -> bool {
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
            require_fields(
                object,
                if object.contains_key("value") {
                    &["op", "key", "value"]
                } else {
                    &["op", "key"]
                },
            )?;
            let key = object
                .get("key")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("runtime key missing"))?;
            if !key.starts_with("owned|") {
                return Err(invalid("unknown runtime record"));
            }
            return Ok(Operation::Runtime(
                key.to_owned(),
                object.get("value").filter(|v| !v.is_null()).cloned(),
            ));
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
    let file = TrackedFile::open(path, "watch_state_snapshot_input")?;
    let (checkpoint_seq, snapshot): (_, SnapshotInput) =
        wal::read_snapshot(file, Kind::TaskSnapshot)
            .map_err(|error| invalid(format!("corrupt watch state snapshot at {path}: {error}")))?;
    if snapshot.password_generation < 0 {
        return Err(invalid(format!(
            "corrupt watch state snapshot at {path}: negative password_generation"
        )));
    }
    let password_generation = snapshot.password_generation;
    let data = StateData {
        runtime: snapshot.runtime,
        pending: snapshot.pending_work,
        entries: snapshot.entries,
        password_generation,
        password_source_signature: snapshot.password_source_signature,
        cursors: snapshot
            .watch_cursors
            .into_iter()
            .map(|(key, cursor)| (key.to_lowercase(), cursor))
            .collect(),
    };
    Ok((checkpoint_seq, data))
}

fn replay_segment_file(
    data: &mut StateData,
    path: &str,
    checkpoint_seq: u64,
    mut expected_seq: u64,
) -> PyResult<NativeWatchReplay> {
    let diagnose = |error| invalid(format!("corrupt watch state journal at {path}: {error}"));
    let file = TrackedFile::open(path, "watch_state_journal_input")?;
    let mut reader = wal::Reader::new(file, Kind::TaskWal).map_err(diagnose)?;
    let mut replay = NativeWatchReplay {
        applied_seq: 0,
        expected_seq,
        records: 0,
        bytes: 0,
        valid_bytes: 0,
    };
    while let Some(seq) = reader.next().map_err(diagnose)? {
        let decoded: Vec<Operation> = wal::decode(&reader.payload).map_err(|error| {
            invalid(format!("invalid watch state operation at {path}: {error}"))
        })?;
        if decoded.is_empty() {
            return Err(invalid(format!("invalid watch state operations at {path}")));
        }
        if seq <= checkpoint_seq {
            continue;
        }
        if seq != expected_seq {
            return Err(invalid(format!(
                "non-contiguous watch state sequence at {path}: expected {expected_seq}, got {seq}"
            )));
        }
        for operation in &decoded {
            data.apply(operation);
        }
        replay.applied_seq = seq;
        expected_seq = seq
            .checked_add(1)
            .ok_or_else(|| invalid("watch state sequence overflow"))?;
        replay.records += 1;
        replay.bytes += (wal::FRAME_HEADER_BYTES + reader.payload.len()) as u64;
    }
    replay.valid_bytes = reader.valid_end;
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

pub(crate) fn py_to_json(value: &Bound<'_, PyAny>) -> PyResult<Value> {
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

/// Ignore only the directory actually recorded; a reused path is ordinary input.
pub(crate) fn output_identity_matches(record: &Value) -> bool {
    let Some(path) = record["path"].as_str() else {
        return false;
    };
    match crate::filesystem::watch_path_identity(path) {
        Ok((volume, id, _)) => record["identities"].as_array().is_some_and(|ids| {
            ids.iter()
                .any(|value| value.as_str() == Some(&format!("{volume}|{id}")))
        }),
        Err(_) => false,
    }
}
