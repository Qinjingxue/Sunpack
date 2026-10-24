//! Bounded, asynchronous GUI projection. The task WAL remains authoritative.
use crate::io::resource_lifecycle::{NativeResourceGuard, TrackedFile};
use crate::watch_store::{py_to_json, NativeWatchState};
use pyo3::exceptions::{PyOSError, PyRuntimeError};
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyFloat, PyInt, PyList, PySlice, PyString, PyTuple};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex, OnceLock, Weak};
use std::thread::JoinHandle;

const QUEUE_BYTES: usize = 1024 * 1024;
type Record = Arc<Vec<u8>>;
fn encode(value: &Value) -> Record {
    let mut bytes = serde_json::to_vec(value).expect("JSON value");
    bytes.push(b'\n');
    Arc::new(bytes)
}
fn key(path: &str) -> String {
    crate::path_keys::path_key(path)
}
fn field<'a>(v: &'a Value, name: &str) -> &'a str {
    v[name].as_str().unwrap_or("")
}

const DIAGNOSTIC_TEXT_BYTES: usize = 4096;
pub(crate) fn diagnostic_text(text: &str) -> &str {
    let mut end = text.len().min(DIAGNOSTIC_TEXT_BYTES);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}
fn short_string<'py>(
    text: &Bound<'py, PyString>,
    chars: usize,
    truncated: &mut bool,
) -> PyResult<Bound<'py, PyString>> {
    if text.len()? <= chars {
        return Ok(text.clone());
    }
    *truncated = true;
    // Slice before requesting UTF-8: PyUnicode's UTF-8 cache would otherwise
    // convert/copy the entire huge original string just to retain its prefix.
    Ok(text
        .get_item(PySlice::new(text.py(), 0, chars as isize, 1))?
        .cast_into::<PyString>()?)
}
fn bounded_value(
    value: &Bound<'_, PyAny>,
    budget: &mut usize,
    depth: usize,
    truncated: &mut bool,
) -> PyResult<Value> {
    if *budget == 0 || depth == 8 {
        *truncated = true;
        return Ok(Value::Null);
    }
    *budget = budget.saturating_sub(8);
    if let Ok(text) = value.cast::<PyString>() {
        let text = short_string(text, *budget, truncated)?;
        let text = text.to_str()?;
        let mut end = text.len().min(*budget);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        *truncated |= end != text.len();
        *budget -= end;
        return Ok(Value::String(text[..end].to_owned()));
    }
    if let Ok(dict) = value.cast::<PyDict>() {
        let mut result = serde_json::Map::new();
        for (i, (key, item)) in dict.iter().enumerate() {
            if i == 64 || *budget == 0 {
                *truncated = true;
                break;
            }
            let key = short_string(key.cast::<PyString>()?, (*budget).min(64), truncated)?;
            let key = key.to_str()?;
            *budget = budget.saturating_sub(key.len());
            result.insert(
                key.to_owned(),
                bounded_value(&item, budget, depth + 1, truncated)?,
            );
        }
        return Ok(Value::Object(result));
    }
    if value.is_instance_of::<PyList>() || value.is_instance_of::<PyTuple>() {
        let mut items = Vec::new();
        for (i, item) in value.try_iter()?.enumerate() {
            if i == 64 || *budget == 0 {
                *truncated = true;
                break;
            }
            items.push(bounded_value(&item?, budget, depth + 1, truncated)?);
        }
        return Ok(Value::Array(items));
    }
    if value.is_none()
        || value.is_instance_of::<PyBool>()
        || value.is_instance_of::<PyInt>()
        || value.is_instance_of::<PyFloat>()
    {
        return py_to_json(value);
    }
    Ok(Value::Null)
}
fn event_value(value: &Bound<'_, PyAny>) -> PyResult<Value> {
    let dict = value.cast::<PyDict>()?;
    let mut truncated = false;
    let event = dict.get_item("event")?;
    let event = event
        .as_ref()
        .map(|v| short_string(v.cast::<PyString>()?, 64, &mut truncated))
        .transpose()?;
    let event = event
        .as_ref()
        .map(|v| v.to_str())
        .transpose()?
        .unwrap_or("");
    let state = matches!(
        event,
        "pipeline_sources_claimed"
            | "processing_started"
            | "failed_password"
            | "suspended_missing_volume"
            | "done"
            | "failed_terminal"
            | "partial_rejected"
            | "task_retired"
            | "blocker_cleared"
            | "candidate_departed"
            | "no_tasks_found"
            | "pipeline_request_coalesced"
            | "pipeline_sources_released"
    );
    let mut budget = DIAGNOSTIC_TEXT_BYTES;
    let mut result = serde_json::Map::new();
    // Preserve identity/relations regardless of diagnostic field order/size.
    result.insert("event".into(), json!(diagnostic_text(event)));
    for name in [
        "ts",
        "time",
        "path",
        "task_path",
        "groups",
        "paths",
        "processing",
        "output_dirs",
        "recursive",
        "scope",
        "retire_group",
        "owner",
    ] {
        if state || matches!(name, "ts" | "time") {
            if let Some(item) = dict.get_item(name)? {
                result.insert(name.to_owned(), py_to_json(&item)?);
            }
        }
    }
    for (i, (key, item)) in dict.iter().enumerate() {
        if i == 64 {
            truncated = true;
            break;
        }
        let key = short_string(key.cast::<PyString>()?, 64, &mut truncated)?;
        let key = key.to_str()?;
        if result.contains_key(key) {
            continue;
        }
        if budget == 0 {
            truncated = true;
            continue;
        }
        let mut end = key.len().min(budget);
        while !key.is_char_boundary(end) {
            end -= 1;
        }
        truncated |= end != key.len();
        budget -= end;
        result.insert(
            key[..end].to_owned(),
            bounded_value(&item, &mut budget, 0, &mut truncated)?,
        );
    }
    if truncated {
        result.insert("truncated".into(), json!(true));
    }
    Ok(Value::Object(result))
}

#[derive(Default)]
struct Task {
    group: Option<Value>,
    group_row: Option<Record>,
    members: HashSet<String>,
    status: Option<Record>,
    terminal: bool,
    blocked: bool,
    owner: String,
    order: u64,
}
impl Task {
    fn bytes(&self) -> usize {
        self.status.as_ref().map_or(0, |r| r.len()) + self.group_row.as_ref().map_or(0, |r| r.len())
    }
}
struct Projection {
    tasks: HashMap<String, Task>,
    aliases: HashMap<String, String>,
    recent: BTreeMap<u64, String>,
    diagnostics: VecDeque<Record>,
    bytes: usize,
    recent_bytes: usize,
    diagnostic_bytes: usize,
    order: u64,
    budget: usize,
}
impl Projection {
    fn new(budget: usize) -> Self {
        Self {
            tasks: HashMap::new(),
            aliases: HashMap::new(),
            recent: BTreeMap::new(),
            diagnostics: VecDeque::new(),
            bytes: 0,
            recent_bytes: 0,
            diagnostic_bytes: 0,
            order: 0,
            budget,
        }
    }
    fn remove(&mut self, id: &str) -> Option<Task> {
        let task = self.tasks.remove(id)?;
        self.bytes -= task.bytes();
        if task.terminal {
            self.recent.remove(&task.order);
            self.recent_bytes -= task.bytes();
        }
        for member in &task.members {
            self.aliases.remove(member);
        }
        Some(task)
    }
    fn insert(&mut self, id: String, task: Task) {
        self.bytes += task.bytes();
        if task.terminal {
            self.recent_bytes += task.bytes();
            self.recent.insert(task.order, id.clone());
        }
        for member in &task.members {
            self.aliases.insert(member.clone(), id.clone());
        }
        self.tasks.insert(id, task);
        while self.recent_bytes > self.budget {
            let Some((_, oldest)) = self.recent.first_key_value() else {
                break;
            };
            let oldest = oldest.clone();
            self.remove(&oldest);
        }
    }
    fn trim(&mut self) {
        // Run after the whole transition, not during remove/reinsert updates.
        if (self.tasks.is_empty() && self.tasks.capacity() != 0)
            || self.tasks.capacity() > 256.max(self.tasks.len() * 4)
        {
            self.tasks.shrink_to_fit();
        }
        if (self.aliases.is_empty() && self.aliases.capacity() != 0)
            || self.aliases.capacity() > 256.max(self.aliases.len() * 4)
        {
            self.aliases.shrink_to_fit();
        }
    }
    fn apply(&mut self, value: &Value, record: &Record) {
        self.order += 1;
        let event = field(value, "event");
        if event == "pipeline_sources_claimed" {
            if let Some(groups) = value["groups"].as_array() {
                for group in groups {
                    let path = field(group, "path");
                    if path.is_empty() {
                        continue;
                    }
                    let members: HashSet<_> = group["members"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .filter(|s| !s.is_empty())
                        .map(key)
                        .collect();
                    if members.is_empty() {
                        continue;
                    }
                    let id = key(path);
                    let mut previous: HashSet<_> = members
                        .iter()
                        .map(|m| self.aliases.get(m).unwrap_or(m).clone())
                        .collect();
                    previous.insert(id.clone());
                    let mut task = Task::default();
                    for old in previous {
                        if let Some(candidate) = self.remove(&old) {
                            if candidate.order > task.order {
                                task = candidate;
                            }
                        }
                    }
                    let multipart = members.len() > 1
                        || task
                            .group
                            .as_ref()
                            .is_some_and(|g| g["multipart"].as_bool().unwrap_or(false));
                    let mut group = group.clone();
                    group["multipart"] = json!(multipart);
                    if task
                        .group
                        .as_ref()
                        .is_none_or(|old| old["path"] != group["path"])
                    {
                        // The first group can absorb a provisional member card.
                        // Its status must address the canonical path before that
                        // member retires, otherwise a snapshot resurrects it.
                        if let Some(status) = &task.status {
                            let mut value: Value =
                                serde_json::from_slice(status).expect("encoded status");
                            value["path"] = group["path"].clone();
                            task.status = Some(encode(&value));
                        }
                    }
                    if !field(value, "owner").is_empty() {
                        task.owner = field(value, "owner").to_owned();
                    }
                    task.group_row = Some(encode(
                        &json!({"event":"pipeline_sources_claimed","path":group["path"],"groups":[group],"owner":task.owner}),
                    ));
                    task.members = members;
                    task.group = Some(group);
                    if value["processing"].as_bool().unwrap_or(false) {
                        task.status =
                            Some(encode(&json!({"event":"processing_started","path":path,
                        "ts":value["ts"],"time":value["time"],"owner":task.owner})));
                        task.order = self.order;
                        task.terminal = false;
                        task.blocked = false;
                    }
                    self.insert(id, task);
                }
            }
            return;
        }
        let path = field(value, "path");
        let physical = key(path);
        let id = self.aliases.get(&physical).unwrap_or(&physical).clone();
        if event == "pipeline_sources_released" {
            let ids: HashSet<_> = value["paths"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .chain((!path.is_empty()).then_some(path))
                .map(key)
                .map(|p| self.aliases.get(&p).unwrap_or(&p).clone())
                .collect();
            for id in ids {
                if self
                    .tasks
                    .get(&id)
                    .is_some_and(|t| !t.terminal && !t.blocked && t.owner == field(value, "owner"))
                {
                    self.remove(&id);
                }
            }
            return;
        }
        if event == "task_retired" && field(value, "scope") == "task" {
            self.remove(&id);
            return;
        }
        if event == "blocker_cleared" {
            let path = if field(value, "task_path").is_empty() {
                path
            } else {
                field(value, "task_path")
            };
            let physical = key(path);
            let id = self.aliases.get(&physical).unwrap_or(&physical).clone();
            if self.tasks.get(&id).is_some_and(|t| t.blocked) {
                self.remove(&id);
            }
            return;
        }
        if event == "candidate_departed" || event == "task_retired" {
            let recursive = value["recursive"].as_bool().unwrap_or(false);
            let affected: Vec<_> = if recursive {
                self.tasks
                    .iter()
                    .filter(|(id, t)| {
                        !t.terminal
                            && (if t.members.is_empty() {
                                **id == physical || crate::watch_store::is_path_under(id, &physical)
                            } else {
                                t.members.iter().any(|m| {
                                    *m == physical
                                        || crate::watch_store::is_path_under(m, &physical)
                                })
                            })
                    })
                    .map(|(id, _)| id.clone())
                    .collect()
            } else {
                self.tasks
                    .get(&id)
                    .filter(|t| !t.terminal)
                    .map(|_| vec![id])
                    .unwrap_or_default()
            };
            for id in affected {
                let mut task = self.remove(&id).unwrap();
                task.members.retain(|m| {
                    *m != physical
                        && !(recursive && crate::watch_store::is_path_under(m, &physical))
                });
                if task.members.is_empty() {
                    continue;
                }
                if let Some(g) = task.group.as_mut() {
                    if let Some(members) = g["members"].as_array_mut() {
                        members
                            .retain(|m| m.as_str().is_some_and(|m| task.members.contains(&key(m))));
                    }
                    task.group_row = Some(encode(
                        &json!({"event":"pipeline_sources_claimed","path":g["path"],"groups":[g],"owner":task.owner}),
                    ));
                }
                self.insert(id, task);
            }
            return;
        }
        if event == "no_tasks_found" || event == "pipeline_request_coalesced" {
            if self.tasks.get(&id).is_some_and(|t| {
                !t.terminal
                    && (t.group.is_none()
                        || (event == "no_tasks_found"
                            && (t.members.len() == 1
                                || value["retire_group"].as_bool().unwrap_or(false))))
            }) {
                self.remove(&id);
            }
            return;
        }
        if !path.is_empty()
            && matches!(
                event,
                "processing_started"
                    | "failed_password"
                    | "suspended_missing_volume"
                    | "done"
                    | "failed_terminal"
                    | "partial_rejected"
            )
        {
            let mut task = self.remove(&id).unwrap_or_default();
            // Snapshot status always addresses its canonical group, even when
            // the original event named a member retired by a later regrouping.
            task.status = if task
                .group
                .as_ref()
                .is_some_and(|group| group["path"] != value["path"])
            {
                let mut status = value.clone();
                status["path"] = task.group.as_ref().unwrap()["path"].clone();
                Some(encode(&status))
            } else {
                Some(record.clone())
            };
            task.blocked = matches!(event, "failed_password" | "suspended_missing_volume");
            if !field(value, "owner").is_empty() {
                task.owner = field(value, "owner").to_owned();
            }
            task.order = self.order;
            task.terminal = matches!(event, "done" | "failed_terminal" | "partial_rejected");
            self.insert(id, task);
            return;
        }
        self.diagnostic(record);
    }
    fn diagnostic(&mut self, record: &Record) {
        self.diagnostic_bytes += record.len();
        self.diagnostics.push_back(record.clone());
        while self.diagnostic_bytes > self.budget {
            if let Some(old) = self.diagnostics.pop_front() {
                self.diagnostic_bytes -= old.len();
            }
        }
    }
    fn snapshot(&self) -> Vec<Record> {
        let mut rows = Vec::new();
        rows.extend(self.diagnostics.iter().cloned());
        let mut tasks: Vec<_> = self.tasks.values().collect();
        tasks.sort_by_key(|t| t.order);
        for task in tasks {
            if let Some(group) = &task.group_row {
                rows.push(group.clone());
            }
            if let Some(status) = &task.status {
                rows.push(status.clone());
            }
        }
        rows
    }
}

// One fault notification per writer lifetime. Ordinary task updates perform no
// cross-process signalling. A repaired snapshot gets a new generation/lease.
mod win {
    use super::*;
    use std::ffi::c_void;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    type Handle = *mut c_void;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateEventW(a: *const c_void, manual: i32, initial: i32, name: *const u16) -> Handle;
        fn SetEvent(h: Handle) -> i32;
        fn CloseHandle(h: Handle) -> i32;
        fn GetCurrentProcess() -> Handle;
        fn GetProcessTimes(
            h: Handle,
            created: *mut u64,
            exit: *mut u64,
            kernel: *mut u64,
            user: *mut u64,
        ) -> i32;
        fn MoveFileExW(from: *const u16, to: *const u16, flags: u32) -> i32;
    }
    pub(super) struct Publication {
        pub header: Value,
        fault: usize,
        failed: AtomicBool,
    }
    impl Drop for Publication {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.fault as Handle);
            }
        }
    }
    impl Publication {
        pub fn new() -> io::Result<Self> {
            static NEXT: AtomicU64 = AtomicU64::new(1);
            let (mut created, mut exit, mut kernel, mut user) = (0, 0, 0, 0);
            if unsafe {
                GetProcessTimes(
                    GetCurrentProcess(),
                    &mut created,
                    &mut exit,
                    &mut kernel,
                    &mut user,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            let name = format!(
                "Local\\SunPack.Log.{}.{}.{}",
                std::process::id(),
                created,
                NEXT.fetch_add(1, Ordering::Relaxed)
            );
            let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
            let fault = unsafe { CreateEventW(std::ptr::null(), 1, 0, wide.as_ptr()) };
            if fault.is_null() {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                header: json!({"event":"state_begin","schema":1,"generation":name,
                "fault_event":name,"owner_pid":std::process::id(),"owner_started":created.to_string()}),
                fault: fault as usize,
                failed: AtomicBool::new(false),
            })
        }
        pub fn invalidate(&self) {
            if !self.failed.swap(true, Ordering::AcqRel) {
                unsafe {
                    SetEvent(self.fault as Handle);
                }
            }
        }
        pub fn failed(&self) -> bool {
            self.failed.load(Ordering::Acquire)
        }
    }
    pub(super) fn replace(from: &std::path::Path, to: &std::path::Path) -> io::Result<()> {
        use std::os::windows::ffi::OsStrExt;
        let from: Vec<u16> = from.as_os_str().encode_wide().chain(Some(0)).collect();
        let to: Vec<u16> = to.as_os_str().encode_wide().chain(Some(0)).collect();
        if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 1 | 8) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}
struct State {
    projection: Projection,
    queue: Vec<Record>,
    queue_bytes: usize,
    rewrite: bool,
    revision: u64,
    ready: bool,
    stopping: bool,
    working: bool,
    error: Option<String>,
}
pub(crate) struct Shared {
    state: Mutex<State>,
    wake: Condvar,
    publication: Mutex<Option<Arc<win::Publication>>>,
    stateful: bool,
}
impl Shared {
    fn fault(&self) {
        if let Some(publication) = self.publication.lock().unwrap().as_ref() {
            publication.invalidate();
        }
    }
    pub(crate) fn invalidate(&self) {
        let mut state = self.state.lock().unwrap();
        self.fault();
        state.ready = false;
        state.revision += 1;
    }
    pub(crate) fn submit(&self, value: Value) {
        let row = encode(&value);
        let mut state = self.state.lock().unwrap();
        if self.stateful {
            state.projection.apply(&value, &row);
        } else {
            state.projection.diagnostic(&row);
        }
        state.projection.trim();
        if state.revision == 0
            || state.error.is_some()
            || state.queue_bytes + row.len() > QUEUE_BYTES
        {
            state.rewrite = true;
            state.queue.clear();
            state.queue_bytes = 0;
        }
        state.revision += 1;
        if !state.rewrite {
            state.queue_bytes += row.len();
            state.queue.push(row);
        }
        self.wake.notify_one();
    }
}
struct Owner {
    key: String,
    shared: Arc<Shared>,
    thread: Mutex<Option<JoinHandle<()>>>,
}
impl Drop for Owner {
    fn drop(&mut self) {
        self.shared.invalidate();
        {
            let mut state = self.shared.state.lock().unwrap();
            state.stopping = true;
            self.shared.wake.notify_one();
        }
        if let Some(thread) = self.thread.lock().unwrap().take() {
            let _ = thread.join();
        }
        let (owners, retired) = owners();
        owners.lock().unwrap().remove(&self.key);
        retired.notify_all();
    }
}
fn owners() -> &'static (Mutex<HashMap<String, Weak<Owner>>>, Condvar) {
    static OWNERS: OnceLock<(Mutex<HashMap<String, Weak<Owner>>>, Condvar)> = OnceLock::new();
    OWNERS.get_or_init(|| (Mutex::new(HashMap::new()), Condvar::new()))
}
fn write_batch(path: &PathBuf, rows: &[Record], rewrite: bool) -> io::Result<()> {
    let temporary = path.with_file_name(format!(
        "{}.tmp",
        path.file_name().unwrap().to_string_lossy()
    ));
    // Closing the temporary handle must not open a promotion window before
    // MoveFileEx publishes it. Reuse the native resource lifecycle gate.
    let _publication = if rewrite {
        Some(NativeResourceGuard::register(
            "event_log_publish",
            [path.clone(), temporary.clone()],
        )?)
    } else {
        None
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let target = if rewrite { &temporary } else { path };
    let result = (|| {
        let mut file = TrackedFile::open_with(target, "event_log", |o| {
            o.write(true).create(true);
            if rewrite {
                o.truncate(true);
            } else {
                o.append(true);
            }
        })
        .map_err(|error| {
            io::Error::new(error.kind(), format!("open event log {target:?}: {error}"))
        })?;
        // Buffer at most 64 KiB; avoid one syscall per short event.
        let mut buffer = std::io::BufWriter::with_capacity(64 * 1024, &mut file);
        for row in rows {
            buffer.write_all(row)?;
        }
        buffer.flush()?;
        drop(buffer);
        if rewrite {
            file.sync_all()?;
        }
        drop(file);
        if rewrite {
            win::replace(&temporary, path).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("replace event log {temporary:?} -> {path:?}: {error}"),
                )
            })?;
        }
        Ok(())
    })();
    if result.is_err() && rewrite {
        let _ = std::fs::remove_file(temporary);
    }
    result
}
fn writer(shared: Arc<Shared>, path: PathBuf) {
    if !shared.stateful {
        // Diagnostics keep their recent tail across host restarts. Read only
        // the byte budget on the writer, never on the submitting thread.
        let budget = shared.state.lock().unwrap().projection.budget;
        let previous = (|| -> io::Result<Vec<u8>> {
            let mut file = TrackedFile::open_reader(&path, "event_log")?;
            let start = file.metadata()?.len().saturating_sub(budget as u64);
            file.seek(SeekFrom::Start(start))?;
            let mut bytes = Vec::new();
            file.take(budget as u64).read_to_end(&mut bytes)?;
            if start != 0 {
                let end = bytes
                    .iter()
                    .position(|b| *b == b'\n')
                    .map_or(bytes.len(), |i| i + 1);
                bytes.drain(..end);
            }
            Ok(bytes)
        })()
        .unwrap_or_default();
        let mut state = shared.state.lock().unwrap();
        let p = &mut state.projection;
        let mut history = VecDeque::new();
        for line in previous.split_inclusive(|b| *b == b'\n') {
            if line.last() == Some(&b'\n') && serde_json::from_slice::<Value>(line).is_ok() {
                p.diagnostic_bytes += line.len();
                history.push_back(Arc::new(line.to_vec()));
            }
        }
        history.append(&mut p.diagnostics);
        p.diagnostics = history;
        while p.diagnostic_bytes > budget {
            if let Some(old) = p.diagnostics.pop_front() {
                p.diagnostic_bytes -= old.len();
            }
        }
    }
    let mut file_bytes = std::fs::metadata(&path).map_or(0, |m| m.len() as usize);
    loop {
        let (mut rows, rewrite, revision, ready) = {
            let mut state = shared.state.lock().unwrap();
            while state.queue.is_empty() && !state.rewrite && !state.stopping {
                state = shared.wake.wait(state).unwrap();
            }
            if state.stopping && state.queue.is_empty() && !state.rewrite {
                break;
            }
            let live = state.projection.bytes + state.projection.diagnostic_bytes;
            let rewrite = state.rewrite
                || file_bytes
                    .saturating_add(state.queue_bytes)
                    .saturating_sub(live)
                    >= state.projection.budget.max(live / 2);
            state.rewrite = false;
            state.working = true;
            let rows = if rewrite {
                state.queue.clear();
                state.projection.snapshot()
            } else {
                std::mem::take(&mut state.queue)
            };
            state.queue_bytes = 0;
            (rows, rewrite, state.revision, state.ready)
        };
        let result = (|| -> io::Result<Option<Arc<win::Publication>>> {
            let publication = if rewrite && shared.stateful {
                let previous = shared.publication.lock().unwrap().clone().unwrap();
                let publication = if ready && previous.failed() {
                    Arc::new(win::Publication::new()?)
                } else {
                    previous
                };
                rows.insert(0, encode(&publication.header));
                if ready {
                    rows.push(encode(&json!({"event":"state_ready","generation":publication.header["generation"]})));
                }
                Some(publication)
            } else {
                None
            };
            write_batch(&path, &rows, rewrite)?;
            Ok(publication)
        })();
        let mut state = shared.state.lock().unwrap();
        state.working = false;
        match result {
            Ok(publication) => {
                let bytes: usize = rows.iter().map(|r| r.len()).sum();
                file_bytes = if rewrite { bytes } else { file_bytes + bytes };
                state.error = None;
                if let Some(publication) = publication {
                    if !state.ready {
                        publication.invalidate();
                    }
                    *shared.publication.lock().unwrap() = Some(publication);
                }
            }
            Err(error) => {
                state.error = Some(error.to_string());
                shared.fault();
                // A partial append must be replaced, never continued. Retry on
                // the next real submission, without an idle retry timer.
            }
        }
        shared.wake.notify_all();
        if state.error.is_some() {
            state.rewrite = state.revision != revision;
        }
    }
}

#[pyclass(module = "sunpack_native")]
pub(crate) struct NativeEventLog {
    owner: Option<Arc<Owner>>,
}
impl NativeEventLog {
    pub(crate) fn shared(&self) -> PyResult<&Arc<Shared>> {
        self.owner
            .as_ref()
            .map(|o| &o.shared)
            .ok_or_else(|| PyRuntimeError::new_err("event log is closed"))
    }
    fn submit(&self, value: Value) -> PyResult<()> {
        self.shared()?.submit(value);
        Ok(())
    }
}
#[pymethods]
impl NativeEventLog {
    #[new]
    #[pyo3(signature=(path, budget=262144, stateful=true))]
    fn new(path: PathBuf, budget: usize, stateful: bool) -> PyResult<Self> {
        let path = std::path::absolute(path)?;
        let (registry, retired) = owners();
        let mut owners = registry.lock().unwrap();
        let id = key(&path.to_string_lossy());
        while let Some(owner) = owners.get(&id) {
            if let Some(owner) = owner.upgrade() {
                return Ok(Self { owner: Some(owner) });
            }
            // The last owner is draining. A replacement cannot overlap its
            // final write; Drop signals this gate after joining the worker.
            owners = retired.wait(owners).unwrap();
        }
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                projection: Projection::new(budget.max(1)),
                queue: Vec::new(),
                queue_bytes: 0,
                rewrite: false,
                revision: 0,
                ready: !stateful,
                stopping: false,
                working: false,
                error: None,
            }),
            wake: Condvar::new(),
            publication: Mutex::new(if stateful {
                Some(Arc::new(win::Publication::new()?))
            } else {
                None
            }),
            stateful,
        });
        let worker = Arc::clone(&shared);
        let thread = std::thread::Builder::new()
            .name("sunpack-events".into())
            .spawn(move || writer(worker, path))?;
        let owner = Arc::new(Owner {
            key: id.clone(),
            shared,
            thread: Mutex::new(Some(thread)),
        });
        owners.insert(id, Arc::downgrade(&owner));
        Ok(Self { owner: Some(owner) })
    }
    fn write(&self, value: &Bound<'_, PyAny>) -> PyResult<()> {
        self.submit(event_value(value)?)
    }
    fn begin_recovery(&self) -> PyResult<()> {
        self.reset(Vec::new(), false)
    }
    #[pyo3(signature=(state=None))]
    fn recover(&self, state: Option<PyRef<'_, NativeWatchState>>) -> PyResult<()> {
        match state {
            Some(state) => state.with_event_projection(|rows| self.reset(rows, true)),
            None => self.reset(Vec::new(), true),
        }
    }
    fn invalidate(&self) -> PyResult<()> {
        self.shared()?.invalidate();
        Ok(())
    }
    fn flush(&self, py: Python<'_>) -> PyResult<()> {
        let shared = Arc::clone(self.shared()?);
        py.detach(move || {
            let mut state = shared.state.lock().unwrap();
            while state.working || !state.queue.is_empty() || state.rewrite {
                state = shared.wake.wait(state).unwrap();
            }
            match &state.error {
                Some(e) => Err(PyOSError::new_err(e.clone())),
                None => Ok(()),
            }
        })
    }
    #[getter]
    fn error(&self) -> PyResult<Option<String>> {
        Ok(self.shared()?.state.lock().unwrap().error.clone())
    }
    fn close(&mut self, py: Python<'_>) {
        let owner = self.owner.take();
        py.detach(move || drop(owner));
    }
}
impl NativeEventLog {
    fn reset(&self, rows: Vec<Value>, ready: bool) -> PyResult<()> {
        let shared = self.shared()?;
        let mut state = shared.state.lock().unwrap();
        if !ready {
            shared.fault();
        }
        let diagnostics = std::mem::take(&mut state.projection.diagnostics);
        let diagnostic_bytes = state.projection.diagnostic_bytes;
        state.projection = Projection::new(state.projection.budget);
        state.projection.diagnostics = diagnostics;
        state.projection.diagnostic_bytes = diagnostic_bytes;
        for value in rows {
            let row = encode(&value);
            state.projection.apply(&value, &row);
        }
        state.queue.clear();
        state.queue_bytes = 0;
        state.ready = ready;
        state.rewrite = true;
        state.revision += 1;
        shared.wake.notify_one();
        Ok(())
    }
}
