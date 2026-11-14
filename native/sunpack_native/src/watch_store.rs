//! Resident Watch state records owned by Rust.
//!
//! Typed record maps, operation application, and the snapshot and journal codecs
//! share one durable representation with the Watch scheduler.

use crate::collections::trim_map;
use crate::io::resource_lifecycle::TrackedFile;
use crate::wal::{self, Kind};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

pub(crate) mod active_outputs;

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

// Serialize the existing path list schema; index canonical keys only in memory.
// Ancestor lookup and subtree retirement do not scan unrelated sibling outputs.
#[derive(Debug, Clone, Default)]
pub(crate) struct PathSet(BTreeMap<String, String>);
impl Serialize for PathSet {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.values())
    }
}
impl<'de> Deserialize<'de> for PathSet {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let paths = Vec::<String>::deserialize(deserializer)?;
        Ok(Self(paths.into_iter().map(|p| (path_key(&p), p)).collect()))
    }
}
impl PathSet {
    pub(crate) fn iter(&self) -> impl Iterator<Item = &String> {
        self.0.values()
    }
    pub(crate) fn contains(&self, path: &str) -> bool {
        self.0.contains_key(&path_key(path))
    }
    fn covers(&self, path: &str) -> bool {
        let key = path_key(path);
        let mut ancestor = key.as_str();
        loop {
            if self.0.contains_key(ancestor) {
                return true;
            }
            let Some((parent, _)) = ancestor.rsplit_once('\\') else {
                return false;
            };
            ancestor = parent;
        }
    }
    fn remove_under(&mut self, path: &str) -> Vec<String> {
        let key = path_key(path);
        let prefix = format!("{}\\", key.trim_end_matches('\\'));
        let mut keys: Vec<_> = self
            .0
            .range(prefix.clone()..)
            .take_while(|(k, _)| k.starts_with(&prefix))
            .map(|(k, _)| k.clone())
            .collect();
        if self.0.contains_key(&key) {
            keys.push(key);
        }
        keys.into_iter().filter_map(|k| self.0.remove(&k)).collect()
    }
    fn insert(&mut self, path: String) {
        self.0.insert(path_key(&path), path);
    }
    fn retain_root(&mut self, path: &str) -> Vec<String> {
        if self.covers(path) {
            return Vec::new();
        }
        let removed = self.remove_under(path);
        self.insert(path.to_owned());
        removed
    }
}

// A carrier and its logical segments can have the same physical source.
// Keep their output ownership independent without inventing synthetic paths.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct ActiveOutputs(BTreeMap<String, Vec<String>>);

impl ActiveOutputs {
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn keys(&self) -> impl Iterator<Item = &String> {
        self.0.keys()
    }

    pub(crate) fn values(&self) -> impl Iterator<Item = &String> {
        self.0.values().flatten()
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.0.iter().flat_map(|(task, outputs)| outputs.iter().map(move |output| (task, output)))
    }

    fn contains(&self, task: &str, output: &str) -> bool {
        self.0.get(task).is_some_and(|outputs| outputs.iter().any(|value| value == output))
    }

    fn insert(&mut self, task: String, output: String) {
        let outputs = self.0.entry(task).or_default();
        if !outputs.contains(&output) {
            outputs.push(output);
        }
    }

    fn remove(&mut self, task: &str, output: &str) {
        if let Some(outputs) = self.0.get_mut(task) {
            outputs.retain(|value| value != output);
            if outputs.is_empty() {
                self.0.remove(task);
            }
        }
    }

    fn relocate(&mut self, relocate: impl Fn(&str) -> String) {
        self.0 = std::mem::take(&mut self.0).into_iter()
            .map(|(task, outputs)| (relocate(&task), outputs.iter().map(|output| relocate(output)).collect()))
            .collect();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum OutputChange {
    Start {
        task: String,
        output: String,
        identity: String,
    },
    Finish {
        task: String,
        output: String,
        keep: bool,
        identity: Option<String>,
    },
    Relocate {
        source: String,
        destination: String,
        identity: String,
    },
    Protect {
        sources: Vec<String>,
    },
}

impl PendingRecord {
    fn change_output(&mut self, change: &OutputChange) {
        match change {
            OutputChange::Start {
                task,
                output,
                identity,
            } => {
                self.active_outputs.insert(task.clone(), output.clone());
                self.output_identities
                    .insert(output.clone(), identity.clone());
            }
            OutputChange::Finish {
                task,
                output,
                keep,
                identity,
            } => {
                self.active_outputs.remove(task, output);
                let removed = if *keep {
                    if path_key(task) != path_key(&self.path)
                        && !self.active_outputs.keys().any(|active| active == task)
                    {
                        self.completed_sources.insert(task.clone());
                    }
                    let output_key = path_key(output);
                    let mut removed = self.committed_roots.retain_root(output);
                    // Once a segment commits, its enclosing active carrier is
                    // no longer disposable. Unfinished siblings remain active
                    // and can still be removed individually on recovery.
                    for (source, parent) in self.active_outputs.iter() {
                        if source == task && is_path_under(&output_key, &path_key(parent)) {
                            removed.extend(self.committed_roots.retain_root(parent));
                        }
                    }
                    removed
                } else {
                    self.completed_sources.remove_under(output);
                    self.committed_roots.remove_under(output)
                };
                if let Some(identity) = identity {
                    self.output_identities
                        .insert(output.clone(), identity.clone());
                }
                for path in removed
                    .iter()
                    .chain(std::iter::once(output))
                {
                    if !self.committed_roots.contains(path)
                        && !self.active_outputs.values().any(|p| p == path)
                    {
                        self.output_identities.remove(path);
                    }
                }
            }
            OutputChange::Relocate {
                source,
                destination,
                identity,
            } => {
                let source_key = path_key(source);
                let source_depth = Path::new(source).components().count();
                let relocate = |path: &str| {
                    let key = path_key(path);
                    if key == source_key {
                        destination.clone()
                    } else if is_path_under(&key, &source_key) {
                        Path::new(destination)
                            .join(
                                Path::new(path)
                                    .components()
                                    .skip(source_depth)
                                    .collect::<std::path::PathBuf>(),
                            )
                            .to_string_lossy()
                            .into_owned()
                    } else {
                        path.to_owned()
                    }
                };
                self.active_outputs.relocate(&relocate);
                for path in self.committed_roots.remove_under(source) {
                    self.committed_roots.retain_root(&relocate(&path));
                }
                for path in self.completed_sources.remove_under(source) {
                    self.completed_sources.insert(relocate(&path));
                }
                let prefix = format!("{}\\", source.trim_end_matches('\\'));
                let mut moved: Vec<_> = self
                    .output_identities
                    .range(prefix.clone()..)
                    .take_while(|(path, _)| path.starts_with(&prefix))
                    .map(|(path, _)| path.clone())
                    .collect();
                if self.output_identities.contains_key(source) {
                    moved.push(source.clone());
                }
                for path in moved {
                    if let Some(id) = self.output_identities.remove(&path) {
                        self.output_identities.insert(relocate(&path), id);
                    }
                }
                if self.committed_roots.contains(destination)
                    || self.active_outputs.values().any(|p| p == destination)
                {
                    self.output_identities
                        .insert(destination.clone(), identity.clone());
                }
            }
            OutputChange::Protect {
                sources,
            } => {
                self.durable_owner = true;
                let source_keys: Vec<_> = sources.iter().map(|p| path_key(p)).collect();
                for output in self.active_outputs.values() {
                    let root = path_key(output);
                    if source_keys
                        .iter()
                        .any(|key| *key == root || is_path_under(key, &root))
                    {
                        for path in self.committed_roots.retain_root(output) {
                            if !self.active_outputs.values().any(|p| p == &path) {
                                self.output_identities.remove(&path);
                            }
                        }
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingRecord {
    pub(crate) path: String,
    pub(crate) size: i64,
    pub(crate) mtime: f64,
    pub(crate) file_id: String,
    pub(crate) change_usn: i64,
    pub(crate) force: bool,
    pub(crate) password_scope_dir: String,
    pub(crate) source_input_root: String,
    pub(crate) internal_recovery: bool,
    pub(crate) discovery_scope: Map<String, Value>,
    pub(crate) durable_owner: bool,
    pub(crate) active_outputs: ActiveOutputs,
    pub(crate) committed_roots: PathSet,
    pub(crate) completed_sources: PathSet,
    pub(crate) output_identities: BTreeMap<String, String>,
}

impl PendingRecord {
    pub(crate) fn matches_observation(&self, candidate: &crate::postprocess::WatchCandidateRow) -> bool {
        self.size == candidate.size.min(i64::MAX as u64) as i64
            && self.mtime == candidate.mtime
            && self.file_id == candidate.observation.file_id
            && self.change_usn == candidate.observation.change_usn
    }

    pub(crate) fn has_output_work(&self) -> bool {
        !self.active_outputs.is_empty()
            || self.committed_roots.iter().next().is_some()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EntryRecord {
    pub(crate) path: String,
    pub(crate) size: i64,
    pub(crate) mtime: f64,
    pub(crate) file_id: String,
    pub(crate) change_usn: i64,
    pub(crate) status: String,
    pub(crate) last_error: String,
    pub(crate) attempt_count: i64,
    pub(crate) failure_kind: String,
    pub(crate) failure_stage: String,
    pub(crate) failure_payload: Map<String, Value>,
    pub(crate) last_attempt_at: f64,
}

impl EntryRecord {
    fn blocks(&self, blocker: &str) -> bool {
        self.failure_payload
            .get("blockers")
            .and_then(Value::as_array)
            .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(blocker)))
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Cursor {
    pub(crate) journal_id: i128,
    pub(crate) next_usn: i128,
}

pub(crate) struct PendingObservation(pub String, pub i64, pub f64, pub String, pub i64);

pub(crate) type PendingUpdate = (PendingObservation, String, Option<Map<String, Value>>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Collection {
    Pending,
    Entries,
}

#[derive(Debug, Clone)]
enum Operation {
    Output(String, OutputChange),
    PutPending(String, Arc<PendingRecord>),
    PutEntry(String, Arc<EntryRecord>),
    Delete(Collection, String),
    SetMetadata(i64, String),
    SetCursors(BTreeMap<String, Cursor>),
    Runtime(String, Option<Arc<Value>>),
}

// Fixed numeric opcodes and tuple fields; put records persist their path once.
impl Serialize for Operation {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Output(key, change) => (7u8, key, change).serialize(serializer),
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
                        if !key.starts_with("flatten|")
                        {
                            return Err(A::Error::custom("unknown runtime record"));
                        }
                        Operation::Runtime(key, field(&mut seq)?)
                    }
                    7 => Operation::Output(field(&mut seq)?, field(&mut seq)?),
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
    runtime: BTreeMap<String, Arc<Value>>,
}

impl StateData {
    fn apply(&mut self, operation: &Operation) {
        match operation {
            Operation::Output(key, change) => {
                if let Some(record) = self.pending.get_mut(key) {
                    Arc::make_mut(record).change_output(change);
                }
                if let OutputChange::Finish {
                    output,
                    keep: false,
                    ..
                } = change
                {
                    let output_key = path_key(output);
                    let retired: Vec<_> = self
                        .runtime
                        .range("flatten|".to_owned()..)
                        .take_while(|(runtime_key, _)| runtime_key.starts_with("flatten|"))
                        .filter(|(_, record)| {
                            record["owner"]
                                .as_str()
                                .is_some_and(|p| path_key(p) == *key)
                                && ["root", "work"].iter().any(|field| {
                                    record[*field]
                                        .as_str()
                                        .is_some_and(|p| path_key(p) == output_key)
                                })
                        })
                        .map(|(runtime_key, _)| runtime_key.clone())
                        .collect();
                    for key in retired {
                        self.runtime.remove(&key);
                    }
                }
            }
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

#[derive(Default, Serialize, Clone)]
#[serde(transparent)]
pub(crate) struct Operations(Vec<Operation>);

/// Decoded journal operations, validated before their WAL record is submitted.
pub(crate) struct NativeWatchOperations {
    pub(crate) operations: Arc<Operations>,
}

impl NativeWatchOperations {
    pub(crate) fn empty() -> Self {
        Self {
            operations: Arc::new(Operations::default()),
        }
    }

    pub(crate) fn set_runtime(&mut self, key: String, value: Option<Value>) {
        Arc::make_mut(&mut self.operations)
            .0
            .push(Operation::Runtime(key, value.map(Arc::new)));
    }

    pub(crate) fn relocate_output(
        &mut self,
        owner: &str,
        source: String,
        destination: String,
        identity: String,
    ) {
        Arc::make_mut(&mut self.operations).0.push(Operation::Output(
            path_key(owner),
            OutputChange::Relocate { source, destination, identity },
        ));
    }

    pub(crate) fn put_entry(&mut self, entry: Arc<EntryRecord>) {
        Arc::make_mut(&mut self.operations)
            .0
            .push(Operation::PutEntry(path_key(&entry.path), entry));
    }

    pub(crate) fn finish_pending(path: &str, entry: Option<Arc<EntryRecord>>) -> Self {
        let key = path_key(path);
        let retry = match entry {
            Some(entry) => Operation::PutEntry(key.clone(), entry),
            None => Operation::Delete(Collection::Entries, key.clone()),
        };
        Self {
            operations: Arc::new(Operations(vec![
                retry,
                Operation::Delete(Collection::Pending, key),
            ])),
        }
    }

    pub(crate) fn retire_pending(key: String) -> Self {
        Self {
            operations: Arc::new(Operations(vec![Operation::Delete(Collection::Pending, key)])),
        }
    }

    pub(crate) fn retire_entries(keys: impl IntoIterator<Item = String>) -> Self {
        Self {
            operations: Arc::new(Operations(
                keys.into_iter()
                    .map(|key| Operation::Delete(Collection::Entries, key))
                    .collect(),
            )),
        }
    }

    pub(crate) fn password_generation(generation: i64, signature: String) -> Self {
        Self {
            operations: Arc::new(Operations(vec![Operation::SetMetadata(
                generation, signature,
            )])),
        }
    }

    pub(crate) fn extend(&mut self, other: Self) {
        Arc::make_mut(&mut self.operations)
            .0
            .extend(Arc::unwrap_or_clone(other.operations).0);
    }
}

impl NativeWatchOperations {
    pub(crate) fn __len__(&self) -> usize {
        self.operations.0.len()
    }
}

/// Frozen checkpoint view; writing it never touches the live maps.
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
    runtime: &'a BTreeMap<String, Arc<Value>>,
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
    runtime: BTreeMap<String, Arc<Value>>,
}

impl NativeWatchSnapshot {

    /// Encode, write and fsync the snapshot to an existing temporary file.
    pub(crate) fn write(&self, path: String) -> std::io::Result<u64> {
        (|| -> std::io::Result<u64> {
            let document = SnapshotDocument {
                password_generation: self.data.password_generation,
                password_source_signature: &self.data.password_source_signature,
                watch_cursors: &self.data.cursors,
                pending_work: Records(&self.data.pending),
                entries: Records(&self.data.entries),
                runtime: &self.data.runtime,
            };
            let mut file = TrackedFile::open_with(&path, |options| {
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
        })()
    }
}

/// Records applied from one journal segment.
pub(crate) struct NativeWatchReplay {
    pub(crate) applied_seq: u64,
    pub(crate) expected_seq: u64,
    pub(crate) records: u64,
    pub(crate) bytes: u64,
    pub(crate) valid_bytes: u64,
}

fn entry_event(record: &EntryRecord) -> Value {
    serde_json::json!({"event":record.status,"path":record.path,"ts":record.last_attempt_at,
        "error":crate::event_log::diagnostic_text(&record.last_error),"error_kind":record.failure_kind})
}

pub(crate) struct NativeWatchState {
    pub(crate) data: Arc<Mutex<StateData>>,
    pub(crate) outputs: active_outputs::OutputReservations,
    events: Mutex<Option<std::sync::Weak<crate::event_log::Shared>>>,
}

impl NativeWatchState {
    pub(crate) fn with_event_projection<T>(&self, publish: impl FnOnce(Vec<Value>) -> T) -> T {
        // Use the existing sink mutex to order snapshot publication with apply's
        // state mutation + notifications. The data-map lock still ends before
        // member checks and projection serialization.
        let _publication = self.events.lock().unwrap();
        publish(Self::event_projection(&self.data))
    }
    pub(crate) fn event_projection(data: &Mutex<StateData>) -> Vec<Value> {
        let mut entries: Vec<_> = {
            let data = data.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            data.entries
                .values()
                .filter(|record| {
                    matches!(
                        record.status.as_str(),
                        "failed_password" | "suspended_missing_volume"
                    )
                })
                .cloned()
                .collect()
        };
        let mut rows = Vec::new();
        let mut member_presence = HashMap::new();
        entries.sort_by(|a, b| {
            a.last_attempt_at
                .total_cmp(&b.last_attempt_at)
                .then_with(|| a.path.cmp(&b.path))
        });
        for record in &entries {
            if let Some(group) = record.failure_payload.get("source_group") {
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
            rows.push(entry_event(record));
        }
        rows
    }
    pub(crate) fn lock(&self) -> MutexGuard<'_, StateData> {
        self.data
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
    fn apply_operations(&self, operations: &Operations) {
        let publication = self.events.lock().unwrap();
        let events = publication.as_ref().and_then(std::sync::Weak::upgrade);
        let mut notifications = Vec::new();
        {
            let mut data = self.lock();
            let mut removed = Vec::new();
            for operation in operations.0.iter() {
                if let (Some(_), Operation::Delete(Collection::Entries, path)) = (&events, operation) {
                    if let Some(record) = data.entries.get(path) {
                        removed.push(Arc::clone(record));
                    }
                }
                data.apply(operation);
            }
            // One WAL batch can replace a provisional member with its real
            // head. Publish the committed state, never the temporary gap
            // between Delete(old) and PutEntry(head), which clears GUI groups.
            if events.is_some() {
                for record in removed {
                    let group = record.failure_payload.get("source_group");
                    let remaining = group
                        .and_then(|g| g["members"].as_array())
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .chain(std::iter::once(record.path.as_str()))
                        .filter_map(|member| data.entries.get(&path_key(member)))
                        .max_by(|a, b| a.last_attempt_at.total_cmp(&b.last_attempt_at));
                    if let Some(record) = remaining {
                        notifications.push(entry_event(record));
                    } else {
                        notifications.push(serde_json::json!({"event":"blocker_cleared","path":record.path,
                        "task_path":group.and_then(|g| g["path"].as_str()).unwrap_or(&record.path)}));
                    }
                }
                for operation in operations.0.iter() {
                    if let Operation::PutEntry(path, record) = operation {
                        if data.entries.get(path).is_some_and(|current| Arc::ptr_eq(current, record))
                            && matches!(record.status.as_str(), "failed_password" | "suspended_missing_volume") {
                            notifications.push(entry_event(record));
                        }
                    }
                }
            }
        }
        // The authoritative map lock never covers log projection/serialization.
        if let Some(events) = events {
            for notification in notifications {
                events.submit(notification);
            }
        }
    }
}

impl NativeWatchState {
    /// Preserve output ownership while updating the input observation. The same
    /// operations back in-memory queues, admissions and durable USN checkpoints.
    pub(crate) fn pending_operations(
        &self,
        updates: impl IntoIterator<Item = PendingUpdate>,
        force: bool,
        password_scope_dir: &str,
        internal_recovery: bool,
        durable_owner: bool,
        cursors: Option<BTreeMap<String, Cursor>>,
    ) -> std::io::Result<(NativeWatchOperations, bool)> {
        let recovery_batch = cursors.is_some();
        let mut operations = Vec::with_capacity(1);
        let mut persist_attempt = false;
        for (PendingObservation(path, size, mtime, file_id, change_usn), root, scope) in updates {
            let key = crate::path_keys::path_key(&path);
            let previous = {
                let data = self.lock();
                let previous = data.pending.get(&key);
                // The cursor barrier also covers previously persisted observations.
                if recovery_batch
                    && previous.is_some_and(|record| {
                        record.durable_owner
                            && record.size == size
                            && record.mtime == mtime
                            && record.file_id == file_id
                            && record.change_usn == change_usn
                            && record.force == force
                            && (root.is_empty() || record.source_input_root == root)
                            && scope
                                .as_ref()
                                .is_none_or(|scope| record.discovery_scope == *scope)
                    })
                {
                    continue;
                }
                previous.cloned()
            };
            let previous = previous.as_deref();
            persist_attempt |= previous.is_none_or(|record| record.durable_owner);
            let mut record = previous.cloned().unwrap_or_default();
            if !password_scope_dir.is_empty() {
                record.password_scope_dir = password_scope_dir.to_owned();
            } else if record.password_scope_dir.is_empty() {
                record.password_scope_dir = Path::new(&path)
                    .parent()
                    .and_then(Path::to_str)
                    .unwrap_or_default()
                    .to_owned();
            }
            if !root.is_empty() {
                record.source_input_root = root;
            }
            if let Some(scope) = scope.filter(|scope| !scope.is_empty()) {
                record.discovery_scope = scope;
            }
            record.path = path;
            record.size = size;
            record.mtime = mtime;
            record.file_id = file_id;
            record.change_usn = change_usn;
            record.force = force;
            record.internal_recovery |= internal_recovery;
            record.durable_owner |= durable_owner;
            operations.push(Operation::PutPending(key, Arc::new(record)));
        }
        if let Some(cursors) = cursors {
            let mut merged = self.lock().cursors.clone();
            merged.extend(cursors);
            operations.push(Operation::SetCursors(merged));
        }
        Ok((
            NativeWatchOperations {
                operations: Arc::new(Operations(operations)),
            },
            persist_attempt,
        ))
    }

    pub(crate) fn protect_output_operation(
        &self,
        owner: &str,
        sources: Vec<String>,
    ) -> Option<NativeWatchOperations> {
        let key = path_key(owner);
        self.lock()
            .pending
            .contains_key(&key)
            .then(|| NativeWatchOperations {
                operations: Arc::new(Operations(vec![Operation::Output(
                    key,
                    OutputChange::Protect {
                                sources,
                    },
                )])),
            })
    }
    /// Build a bounded WAL delta without exporting a growing pending record.
    pub(crate) fn output_operation(
        &self,

        owner: &str,
        task: String,
        output: String,
        keep: Option<bool>,
        exclusive: bool,
    ) -> std::io::Result<Option<NativeWatchOperations>> {
        if exclusive && keep.is_some() {
            return Err(invalid("output registration requires a start"));
        }
        let key = path_key(owner);
        let refresh = {
            let data = self.lock();
            let Some(record) = data.pending.get(&key) else {
                return Ok(None);
            };
            if let Some(keep) = keep {
                let active = record.active_outputs.contains(&task, &output);
                if !active {
                    if !keep {
                        // Rollback can remove a previously committed output.
                        // Finish must revoke its retained recovery output
                        // even after the active reservation has been cleared.
                        if !record.committed_roots.covers(&output) {
                            return Ok(None);
                        }
                    } else if !record.committed_roots.contains(&output) {
                        return Ok(record.committed_roots.covers(&output).then(|| {
                            NativeWatchOperations {
                                operations: Arc::new(Operations::default()),
                            }
                        }));
                    }
                }
                keep && (!active || !record.output_identities.contains_key(&output))
            } else {
                true
            }
        };
        let mut owned_paths = Vec::new();
        let identity = (|| -> std::io::Result<Option<String>> {
            let path = Path::new(&output);
            if exclusive {
                crate::scan::scope::create_output_root_exclusive(path)
                    .map_err(|error| {
                        // A name collision retries the existing reservation.
                        // Other mkdir errors are infrastructure failures: keep
                        // the durable owner on Watch's request recovery path.
                        if error.kind() == std::io::ErrorKind::AlreadyExists {
                            crate::pipeline::OutputCreateError::wrap(error)
                        } else { error }
                    })?;
                // Aliases are sampled after mkdir, under the publication
                // gate. An alias retargeted since reservation cannot create an
                // unregistered tree in another watched namespace.
                let paths = crate::path_keys::output_path_aliases(path)?;
                if !paths.iter().any(|path| self.owned_root(path).is_some())
                {
                    owned_paths = paths;
                }
            } else if keep.is_none() {
                std::fs::create_dir_all(path)?;
                let paths = crate::path_keys::output_path_aliases(path)?;
                if !paths.iter().any(|path| self.owned_root(path).is_some()) { owned_paths = paths; }
            }
            if refresh && path.is_dir() {
                let (volume, identity, _) = crate::filesystem::watch_path_identity(&output)?;
                Ok(Some(format!("{volume}|{identity}")))
            } else {
                Ok(None)
            }
        })()?;
        let register = !owned_paths.is_empty();
        let mut operations = Vec::with_capacity(1);
        let change = if let Some(keep) = keep {
            OutputChange::Finish {
                task,
                output,
                keep,
                identity,
            }
        } else {
            let identity = identity.ok_or_else(|| invalid("output root has no identity"))?;
            // Flatten finalization can already have published the new identity
            // at the active path. A repeated start then has no state delta.
            if !register
                && self.lock().pending.get(&key).is_some_and(|record| {
                    record.active_outputs.contains(&task, &output)
                        && record.output_identities.get(&output) == Some(&identity)
                })
            {
                return Ok(Some(NativeWatchOperations {
                    operations: Arc::new(Operations::default()),
                }));
            }
            if register {
                self.register_output_paths(&owned_paths, &[&identity]);
            }
            OutputChange::Start {
                task,
                output,
                identity,
            }
        };
        operations.push(Operation::Output(key, change));
        Ok(Some(NativeWatchOperations {
            operations: Arc::new(Operations(operations)),
        }))
    }

    pub(crate) fn runtime_record(&self, key: &str) -> Option<Arc<Value>> {
        self.lock().runtime.get(key).cloned()
    }

    pub(crate) fn runtime_keys(&self, prefix: &str) -> Vec<String> {
        self.lock()
            .runtime
            .range(prefix.to_owned()..)
            .take_while(|(key, _)| key.starts_with(prefix))
            .map(|(key, _)| key.clone())
            .collect()
    }

    pub(crate) fn owned_root(&self, path: &str) -> Option<String> {
        active_outputs::find_owned_root(&self.outputs, path)
    }

    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(StateData::default())),
            outputs: Arc::default(),
            events: Mutex::new(None),
        }
    }

    pub(crate) fn attach_events(
        &self,
        log: &crate::event_log::NativeEventLog,
    ) -> std::io::Result<()> {
        *self.events.lock().unwrap() = Some(Arc::downgrade(log.shared()?));
        Ok(())
    }

    pub(crate) fn unload(&self) {
        *self.lock() = StateData::default();
    }

    /// Capacity-only maintenance: never changes records or checkpoint views.
    pub(crate) fn trim_idle_storage(&self) {
        let mut data = self.lock();
        trim_map(&mut data.pending);
        trim_map(&mut data.entries);
    }

    pub(crate) fn password_generation(&self) -> i64 {
        self.lock().password_generation
    }

    pub(crate) fn password_source_signature(&self) -> String {
        self.lock().password_source_signature.clone()
    }

    pub(crate) fn pending(&self, path: &str) -> Option<Arc<PendingRecord>> {
        self.lock().pending.get(&path_key(path)).cloned()
    }

    pub(crate) fn entry(&self, path: &str) -> Option<Arc<EntryRecord>> {
        self.entry_by_key(&path_key(path))
    }

    pub(crate) fn entry_by_key(&self, key: &str) -> Option<Arc<EntryRecord>> {
        self.lock().entries.get(key).cloned()
    }

    pub(crate) fn pending_items(&self) -> Vec<Arc<PendingRecord>> {
        self.lock().pending.values().cloned().collect()
    }

    pub(crate) fn entry_items(&self, blocker: Option<&str>) -> Vec<Arc<EntryRecord>> {
        self.lock()
            .entries
            .values()
            .filter(|value| blocker.is_none_or(|blocker| value.blocks(blocker)))
            .cloned()
            .collect()
    }

    /// Configuration retirement only visits resident state, never file-index rows.
    pub(crate) fn scope_retirement_operations(
        &self,

        scopes: &[crate::scan::scope::NativeDiscoveryScope],
    ) -> NativeWatchOperations {
        let operations = (|| {
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
            let mut operations: Vec<_> = data
                .entries
                .iter()
                .filter(|(key, record)| {
                    !scopes.iter().any(|scope| scope.contains(&record.path))
                        && !record
                            .failure_payload
                            .get("source_input_root")
                            .and_then(Value::as_str)
                            .filter(|_| record.failure_payload.contains_key("discovery_scope"))
                            .is_some_and(|root| {
                                scopes
                                    .iter()
                                    .any(|scope| path_key(&scope.root) == path_key(root))
                            })
                        && !data.pending.contains_key(*key)
                        && !recovery_paths
                            .iter()
                            .any(|root| *key == root || is_path_under(key, root))
                })
                .map(|(key, _)| Operation::Delete(Collection::Entries, key.clone()))
                .collect();
            if data.cursors.is_empty() {
                return operations;
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
                    Some(volume) => {
                        volumes.insert(volume.to_lowercase());
                    }
                    _ => return operations,
                }
            }
            if data.cursors.keys().any(|key| !volumes.contains(key)) {
                let cursors = data
                    .cursors
                    .iter()
                    .filter(|(key, _)| volumes.contains(*key))
                    .map(|(key, cursor)| (key.clone(), *cursor))
                    .collect();
                operations.push(Operation::SetCursors(cursors));
            }
            operations
        })();
        NativeWatchOperations {
            operations: Arc::new(Operations(operations)),
        }
    }

    /// ``(key, recorded path)`` in the requested retry-entry scope.
    pub(crate) fn entry_paths(&self, path: Option<&str>, recursive: bool) -> Vec<(String, String)> {
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

    pub(crate) fn file_presence(path: &str) -> Option<bool> {
        recorded_file_presence(path)
    }

    #[cfg(test)]
    pub(crate) fn watch_cursors(&self) -> BTreeMap<String, Cursor> {
        self.lock().cursors.clone()
    }

    pub(crate) fn watch_cursor(&self, volume_key: &str) -> Option<Cursor> {
        self.lock().cursors.get(&volume_key.to_lowercase()).copied()
    }

    pub(crate) fn apply(&self, operations: &NativeWatchOperations) {
        self.apply_operations(&operations.operations);
    }

    pub(crate) fn capture(&self, checkpoint_seq: u64) -> NativeWatchSnapshot {
        NativeWatchSnapshot {
            checkpoint_seq,
            data: self.lock().clone(),
        }
    }

    /// Replace the maps with the snapshot at ``path``.
    pub(crate) fn load_snapshot(&self, path: String) -> std::io::Result<u64> {
        let (checkpoint_seq, data) = (load_snapshot_file(&path))?;
        *self.lock() = data;
        Ok(checkpoint_seq)
    }

    /// Replay already established this boundary while holding the path gate.
    pub(crate) fn truncate_journal_tail(path: String, valid_bytes: u64) -> std::io::Result<()> {
        (|| -> std::io::Result<()> {
            let file = TrackedFile::open_with(&path, |options| {
                options.read(true).write(true);
            })?;
            if file.metadata()?.len() != valid_bytes {
                file.set_len(valid_bytes)?;
                file.sync_all()?;
            }
            Ok(())
        })()
    }

    /// Apply one journal segment after ``checkpoint_seq``; errors carry the WAL diagnosis.
    pub(crate) fn replay_segment(
        &self,

        path: String,
        checkpoint_seq: u64,
        expected_seq: u64,
    ) -> std::io::Result<NativeWatchReplay> {
        replay_segment_file(&mut self.lock(), &path, checkpoint_seq, expected_seq)
    }
}

/// Absolute Windows filesystem key shared with discovery.
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

fn invalid(message: impl Into<String>) -> std::io::Error {
    std::io::Error::other(message.into())
}

fn load_snapshot_file(path: &str) -> std::io::Result<(u64, StateData)> {
    let file = TrackedFile::open(path)?;
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
) -> std::io::Result<NativeWatchReplay> {
    let diagnose = |error| invalid(format!("corrupt watch state journal at {path}: {error}"));
    let file = TrackedFile::open(path)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replayed_entry_event_keeps_business_failure_kind_and_message() {
        let entry = EntryRecord {
            path: r"C:\input\archive.zip".into(),
            status: "failed_retryable".into(),
            failure_kind: "wrong_password".into(),
            last_error: "密码不在密码列表中".into(),
            size: 0, mtime: 0.0, file_id: String::new(), change_usn: 0,
            attempt_count: 1, failure_stage: String::new(),
            failure_payload: Map::new(), last_attempt_at: 0.0
        };
        let event = entry_event(&entry);
        assert_eq!(event["error_kind"], "wrong_password");
        assert_eq!(event["error"], entry.last_error);
    }

    #[test]
    fn carrier_outputs_survive_snapshot_and_incremental_replay() {
        use std::fs::{self, OpenOptions};
        use std::io::Write;

        let snapshot = crate::test_support::temp_file("carrier_owner_snapshot", b"");
        let journal = snapshot.with_extension("wal");
        let base = snapshot.with_extension("outputs");
        let owner = base.join("outer.zip").to_string_lossy().into_owned();
        let task = base.join("nested.data").to_string_lossy().into_owned();
        let container = base.join("carrier").to_string_lossy().into_owned();
        let first = base.join("carrier").join("first").to_string_lossy().into_owned();
        let second = base.join("carrier").join("second").to_string_lossy().into_owned();
        let moved = base.join("relocated").to_string_lossy().into_owned();
        let mut pending = PendingRecord { path: owner.clone(), ..Default::default() };
        pending.change_output(&OutputChange::Start {
            task: task.clone(),
            output: container.clone(),
            identity: "container-id".into(),
        });
        let state = NativeWatchState::new();
        state.apply(&NativeWatchOperations {
            operations: Arc::new(Operations(vec![Operation::PutPending(path_key(&owner), Arc::new(pending))])),
        });
        assert!(state.pending(&owner).unwrap().active_outputs.contains(&task, &container));
        fs::write(&journal, wal::file_header(Kind::TaskWal)).unwrap();
        let append = |seq, changes: Vec<OutputChange>| {
            let operations = Operations(changes.into_iter()
                .map(|change| Operation::Output(path_key(&owner), change)).collect());
            let mut file = OpenOptions::new().append(true).open(&journal).unwrap();
            wal::append_frame(&mut file, seq, |out| {
                rmp_serde::encode::write(out, &operations).map_err(wal::invalid)
            }).unwrap();
            file.flush().unwrap();
        };
        append(2, vec![
            OutputChange::Start { task: task.clone(), output: first.clone(), identity: "first-id".into() },
            OutputChange::Start { task: task.clone(), output: second.clone(), identity: "second-id".into() },
        ]);
        state.replay_segment(journal.to_string_lossy().into_owned(), 1, 2).unwrap();
        assert_eq!(state.pending(&owner).unwrap().active_outputs.values().count(), 3);
        state.capture(2).write(snapshot.to_string_lossy().into_owned()).unwrap();
        let resumed = NativeWatchState::new();
        assert_eq!(resumed.load_snapshot(snapshot.to_string_lossy().into_owned()).unwrap(), 2);
        assert_eq!(resumed.pending(&owner).unwrap().active_outputs.values().count(), 3);
        append(3, vec![OutputChange::Finish {
            task: task.clone(), output: first.clone(), keep: true, identity: None,
        }]);
        resumed.replay_segment(journal.to_string_lossy().into_owned(), 2, 3).unwrap();
        let pending = resumed.pending(&owner).unwrap();
        assert!(pending.active_outputs.contains(&task, &container));
        assert!(pending.active_outputs.contains(&task, &second));
        assert!(!pending.active_outputs.contains(&task, &first));
        assert!(pending.committed_roots.contains(&container));
        assert!(!pending.completed_sources.contains(&task));
        assert_eq!(pending.output_identities[&container], "container-id");
        // Recovery preserves the carrier holding the committed first segment,
        // but the unfinished sibling remains an independently disposable root.
        assert_eq!(pending.active_outputs.values()
            .filter(|output| !pending.committed_roots.contains(output)).collect::<Vec<_>>(), vec![&second]);
        // Rollback may still discard the committed child after its active
        // reservation is retired. It must preserve the enclosing carrier.
        let rollback = resumed.output_operation(&owner, task.clone(), first.clone(), Some(false), false)
            .unwrap().unwrap();
        resumed.apply(&rollback);
        assert!(resumed.pending(&owner).unwrap().committed_roots.contains(&container));
        append(4, vec![OutputChange::Finish {
            task: task.clone(), output: second.clone(), keep: false, identity: None,
        }, OutputChange::Relocate {
            source: container.clone(), destination: moved.clone(), identity: "moved-id".into(),
        }]);
        resumed.replay_segment(journal.to_string_lossy().into_owned(), 3, 4).unwrap();
        let pending = resumed.pending(&owner).unwrap();
        assert_eq!(pending.active_outputs.iter().collect::<Vec<_>>(), vec![(&task, &moved)]);
        assert!(pending.committed_roots.contains(&moved));
        assert_eq!(pending.output_identities[&moved], "moved-id");
        assert!(!pending.output_identities.contains_key(&second));
        fs::remove_file(snapshot).unwrap();
        fs::remove_file(journal).unwrap();
    }

    #[test]
    fn recovery_publication_orders_concurrent_blocker_changes() {
        // Python-thread tests retain the GIL across native recover, masking the
        // actual native publication gap. Exercise deletion and status change
        // from a real native thread while the snapshot callback is paused.
        for delete in [true, false] {
            let state = Arc::new(NativeWatchState::new());
            let record: EntryRecord = serde_json::from_value(serde_json::json!({
                "path":"c:\\input\\opaque.001", "size":1, "mtime":1.0,
                "file_id":"", "change_usn":0, "status":"failed_password",
                "last_error":"locked", "attempt_count":1, "failure_kind":"",
                "failure_stage":"", "failure_payload":{}, "last_attempt_at":1.0
            }))
            .unwrap();
            let key = path_key(&record.path);
            state.apply_operations(&Operations(vec![Operation::PutEntry(
                key.clone(),
                Arc::new(record.clone()),
            )]));
            let (captured, start) = std::sync::mpsc::channel();
            let (finished, done) = std::sync::mpsc::channel();
            let worker_state = state.clone();
            let worker = std::thread::spawn(move || {
                start.recv().unwrap();
                let operation = if delete {
                    Operation::Delete(Collection::Entries, key)
                } else {
                    let mut record = record;
                    record.status = "suspended_missing_volume".into();
                    Operation::PutEntry(key, Arc::new(record))
                };
                worker_state.apply_operations(&Operations(vec![operation]));
                finished.send(()).unwrap();
            });
            state.with_event_projection(|rows| {
                assert_eq!(rows[0]["event"], "failed_password");
                captured.send(()).unwrap();
                assert_eq!(
                    done.recv_timeout(std::time::Duration::from_millis(100)),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                );
            });
            done.recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
            worker.join().unwrap();
            state.with_event_projection(|rows| {
                if delete {
                    assert!(rows.is_empty());
                } else {
                    assert_eq!(rows[0]["event"], "suspended_missing_volume");
                }
            });
        }
    }

    #[test]
    fn path_under_requires_a_component_boundary() {
        assert!(is_path_under("c:\\a\\b", "c:\\a"));
        assert!(is_path_under("c:\\a\\b", "c:\\a\\"));
        assert!(!is_path_under("c:\\ab", "c:\\a"));
        assert!(!is_path_under("c:\\a", "c:\\a"));
        assert!(is_path_under("c:\\a", "c:\\"));
    }
}
