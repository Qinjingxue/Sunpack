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
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

const SNAPSHOT_BUFFER_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingRecord {
    path: String,
    size: i64,
    mtime: f64,
    #[serde(default)]
    file_id: String,
    #[serde(default)]
    change_usn: i64,
    #[serde(default)]
    force: bool,
    #[serde(default)]
    password_scope_dir: String,
    #[serde(default)]
    source_input_root: String,
    #[serde(default)]
    internal_recovery: bool,
    #[serde(default)]
    durable_owner: bool,
    #[serde(default)]
    active_outputs: BTreeMap<String, String>,
    #[serde(default)]
    committed_roots: Vec<String>,
    #[serde(default)]
    completed_sources: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryRecord {
    path: String,
    size: i64,
    mtime: f64,
    #[serde(default)]
    file_id: String,
    #[serde(default)]
    change_usn: i64,
    #[serde(default = "pending_status")]
    status: String,
    #[serde(default)]
    last_error: String,
    #[serde(default)]
    attempt_count: i64,
    #[serde(default)]
    failure_kind: String,
    #[serde(default)]
    failure_stage: String,
    #[serde(default)]
    failure_payload: Map<String, Value>,
    #[serde(default)]
    last_attempt_at: f64,
    #[serde(default)]
    password_generation: i64,
}

fn pending_status() -> String {
    "pending".to_string()
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
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
}

#[derive(Debug, Clone, Default)]
struct StateData {
    pending: HashMap<String, Arc<PendingRecord>>,
    entries: HashMap<String, Arc<EntryRecord>>,
    password_generation: i64,
    password_source_signature: String,
    cursors: BTreeMap<String, Cursor>,
}

impl StateData {
    fn apply(&mut self, operation: &Operation) {
        match operation {
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

/// Decoded journal operations, validated before their WAL record is submitted.
#[pyclass(module = "sunpack_native", frozen)]
pub(crate) struct NativeWatchOperations {
    operations: Vec<Operation>,
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
    fn lock(&self) -> MutexGuard<'_, StateData> {
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

    fn reset(&self) {
        *self.lock() = StateData::default();
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

    /// Keys of both collections at ``path`` (or under it when recursive).
    fn keys_matching(&self, path: &str, recursive: bool) -> (Vec<String>, Vec<String>) {
        let expected = path_key(path);
        let matches =
            |key: &String| key == &expected || (recursive && is_path_under(key, &expected));
        let data = self.lock();
        let mut pending: Vec<String> = data
            .pending
            .keys()
            .filter(|key| matches(key))
            .cloned()
            .collect();
        let mut entries: Vec<String> = data
            .entries
            .keys()
            .filter(|key| matches(key))
            .cloned()
            .collect();
        pending.sort();
        entries.sort();
        (pending, entries)
    }

    /// ``(key, recorded path)`` of every retry entry.
    fn entry_paths(&self) -> Vec<(String, String)> {
        let mut paths: Vec<_> = self
            .lock()
            .entries
            .iter()
            .map(|(key, value)| (key.clone(), value.path.clone()))
            .collect();
        paths.sort();
        paths
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
            decoded.push(decode_operation(&py_to_json(&operation?)?)?);
        }
        Ok(NativeWatchOperations {
            operations: decoded,
        })
    }

    fn apply(&self, operations: PyRef<'_, NativeWatchOperations>) {
        let mut data = self.lock();
        for operation in &operations.operations {
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
        let replay = py.detach(|| {
            replay_segment_file(&mut data, &path, checkpoint_seq, expected_seq)
        });
        *self.lock() = data;
        replay
    }
}

/// ``os.path.normcase(os.path.abspath(path))`` for Watch record keys.
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
    absolute.to_string_lossy().replace('/', "\\").to_lowercase()
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
    let action = object.get("op").and_then(Value::as_str).unwrap_or("");
    match action {
        "set_metadata" => {
            let value = object
                .get("value")
                .and_then(Value::as_object)
                .ok_or_else(|| PyTypeError::new_err("metadata value must be an object"))?;
            let generation = value
                .get("password_generation")
                .and_then(json_int)
                .ok_or_else(|| invalid("metadata password_generation must be an integer"))?;
            let signature = json_text(value.get("password_source_signature"));
            return Ok(Operation::SetMetadata(generation.max(0) as i64, signature));
        }
        "set_watch_cursors" => {
            let value = object
                .get("value")
                .and_then(Value::as_object)
                .ok_or_else(|| PyTypeError::new_err("watch cursor value must be an object"))?;
            return Ok(Operation::SetCursors(decode_cursors(value)));
        }
        _ => {}
    }
    let collection = match object
        .get("collection")
        .and_then(Value::as_str)
        .unwrap_or("")
    {
        "pending_work" => Collection::Pending,
        "entries" => Collection::Entries,
        other => return Err(invalid(format!("unknown state collection: {other}"))),
    };
    let key = json_text(object.get("key"));
    if key.is_empty() {
        return Err(invalid("state operation key must not be empty"));
    }
    match action {
        "delete" => Ok(Operation::Delete(collection, key)),
        "put" => {
            let value = object.get("value").unwrap_or(&Value::Null);
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

fn decode_cursors(value: &Map<String, Value>) -> BTreeMap<String, Cursor> {
    value
        .iter()
        .filter_map(|(key, item)| {
            let item = item.as_object()?;
            let field = |name: &str| item.get(name).and_then(json_int).unwrap_or(0);
            Some((
                key.to_lowercase(),
                Cursor {
                    journal_id: field("journal_id"),
                    next_usn: field("next_usn"),
                },
            ))
        })
        .collect()
}

fn json_int(value: &Value) -> Option<i128> {
    value
        .as_i64()
        .map(i128::from)
        .or_else(|| value.as_u64().map(i128::from))
        .or_else(|| value.is_null().then_some(0))
}

fn json_text(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(text)) => text.clone(),
        Some(other) => other.to_string(),
    }
}

fn load_records<T: for<'de> Deserialize<'de>>(
    payload: Option<&Value>,
    path_of: impl Fn(&T) -> &str,
) -> HashMap<String, Arc<T>> {
    let mut records = HashMap::new();
    let Some(payload) = payload.and_then(Value::as_object) else {
        return records;
    };
    for value in payload.values() {
        // A record that no longer matches the schema is dropped, as a
        // dataclass(**value) TypeError was before.
        if let Ok(record) = decode_record::<T>(value) {
            records.insert(path_key(path_of(&record)), Arc::new(record));
        }
    }
    records
}

fn load_snapshot_file(path: &str) -> PyResult<(u64, StateData)> {
    let mut file = TrackedFile::open(path, "watch_state_snapshot_input")?;
    let mut raw = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut raw)?;
    let payload: Value = serde_json::from_slice(&raw)
        .map_err(|_| invalid(format!("corrupt watch state snapshot at {path}")))?;
    let Some(object) = payload.as_object() else {
        return Err(invalid(format!("invalid watch state snapshot at {path}")));
    };
    let metadata = |name: &str| -> PyResult<i128> {
        match object.get(name) {
            None => Ok(0),
            Some(value) => json_int(value)
                .ok_or_else(|| invalid(format!("invalid watch state snapshot metadata at {path}"))),
        }
    };
    let checkpoint_seq = metadata("checkpoint_seq")?.max(0) as u64;
    let password_generation = metadata("password_generation")?.max(0) as i64;
    let data = StateData {
        pending: load_records::<PendingRecord>(object.get("pending_work"), |record| &record.path),
        entries: load_records::<EntryRecord>(object.get("entries"), |record| &record.path),
        password_generation,
        password_source_signature: json_text(object.get("password_source_signature")),
        cursors: object
            .get("watch_cursors")
            .and_then(Value::as_object)
            .map(decode_cursors)
            .unwrap_or_default(),
    };
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
        // A torn final append is harmless in any immutable old segment; a
        // lost transaction is still caught by the next sequence gap.
        if line.last() != Some(&b'\n') {
            break;
        }
        let at = || format!("{path}:{line_number}");
        let transaction: Value = serde_json::from_slice(&line)
            .map_err(|_| invalid(format!("corrupt watch state journal at {}", at())))?;
        let Some(object) = transaction.as_object() else {
            return Err(invalid(format!(
                "invalid watch state journal record at {}",
                at()
            )));
        };
        let seq = object
            .get("seq")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid(format!("invalid watch state sequence at {}", at())))?;
        if seq <= checkpoint_seq {
            continue;
        }
        if seq != expected_seq {
            return Err(invalid(format!(
                "non-contiguous watch state sequence at {}: expected {expected_seq}, got {seq}",
                at()
            )));
        }
        let operations = object
            .get("operations")
            .and_then(Value::as_array)
            .filter(|operations| !operations.is_empty())
            .ok_or_else(|| invalid(format!("invalid watch state operations at {}", at())))?;
        let decoded = operations
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
