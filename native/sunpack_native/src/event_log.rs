//! Best-effort display history. Business state remains in the existing task store.
use crate::io::display_store::{utc_us, Store, DAY_US};
use crate::io::display_wake::Wake;
use crate::watch_store::NativeWatchState;
use serde_json::{json, Value};
use serde::ser::{SerializeSeq, SerializeStruct};
use std::collections::{HashMap, HashSet};

use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex, OnceLock, Weak};
use std::thread::JoinHandle;

mod diagnostic;
use diagnostic::{short_string, MAX_DEPTH, MAX_ITEMS};

/// Per-archive evidence never walks the shared carrier recovery receipts.
/// Complete recovery data retains its ordinary serializer for durable state/reports.
struct DiagnosticFailure<'a>(pub &'a crate::pipeline::Failure);
impl serde::Serialize for DiagnosticFailure<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let failure = self.0;
        let mut object = serializer.serialize_struct("FailureDiagnostic", 7)?;
        object.serialize_field("kind", &failure.kind)?;
        object.serialize_field("message", &failure.message)?;
        if let Some(context) = &failure.context { object.serialize_field("context", context)?; }
        if let Some(scope) = &failure.discovery_scope { object.serialize_field("discovery_scope", scope)?; }
        if !failure.causes.is_empty() { object.serialize_field("causes", &Causes(&failure.causes))?; }
        if let Some(evidence) = &failure.evidence { object.serialize_field("evidence", evidence)?; }
        if failure.password_retry { object.serialize_field("password_retry", &true)?; }
        object.end()
    }
}
struct Causes<'a>(&'a [crate::pipeline::Failure]);
impl serde::Serialize for Causes<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut list = serializer.serialize_seq(Some(self.0.len()))?;
        for failure in self.0 { list.serialize_element(&DiagnosticFailure(failure))?; }
        list.end()
    }
}

const QUEUE_BYTES: usize = 4 * 1024 * 1024;
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

fn bounded_value(value: Value, budget: &mut usize, depth: usize, truncated: &mut bool) -> Value {
    if *budget == 0 || depth == MAX_DEPTH {
        *truncated = true;
        return Value::Null;
    }
    *budget = budget.saturating_sub(8);
    match value {
        Value::String(mut text) => {
            let length = short_string(&text, *budget, truncated).len();
            *budget -= length;
            text.truncate(length);
            if text.capacity() > length.saturating_mul(2) {
                text.shrink_to_fit();
            }
            Value::String(text)
        }
        Value::Array(values) => {
            *truncated |= values.len() > MAX_ITEMS;
            let mut result = Vec::with_capacity(values.len().min(MAX_ITEMS));
            for value in values.into_iter().take(MAX_ITEMS) {
                if *budget == 0 {
                    *truncated = true;
                    break;
                }
                result.push(bounded_value(value, budget, depth + 1, truncated));
            }
            Value::Array(result)
        }
        Value::Object(values) => {
            *truncated |= values.len() > MAX_ITEMS;
            let mut result = serde_json::Map::new();
            for (key, value) in values.into_iter().take(MAX_ITEMS) {
                if *budget == 0 {
                    *truncated = true;
                    break;
                }
                let key = short_string(&key, (*budget).min(64), truncated);
                *budget -= key.len();
                result.insert(
                    key.to_owned(),
                    bounded_value(value, budget, depth + 1, truncated),
                );
            }
            Value::Object(result)
        }
        scalar => scalar,
    }
}

fn event_value(value: Value) -> std::io::Result<Value> {
    event_value_with(value, None)
}

type DiagnosticProjection<'a> = (&'a str, &'a dyn Fn(&mut usize, &mut bool) -> Value);
fn event_value_with(value: Value, diagnostic: Option<DiagnosticProjection<'_>>) -> std::io::Result<Value> {
    let Value::Object(mut fields) = value else {
        return Err(std::io::Error::other("event must be an object"));
    };
    if let Some((name, _)) = diagnostic { fields.insert(name.to_owned(), Value::Null); }
    let event_value = fields.remove("event");
    let mut truncated = false;
    let event = short_string(
        event_value.as_ref().and_then(Value::as_str).unwrap_or(""),
        64,
        &mut truncated,
    );
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
    result.insert("event".into(), Value::String(event.to_owned()));
    for name in [
        "ts",
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
        "task_id",
    ] {
        if state || name == "ts" {
            if let Some(item) = fields.remove(name) {
                result.insert(name.to_owned(), item);
            }
        }
    }
    // main's call sites put locating/classifying facts before free-form
    // diagnostics. serde_json's sorted map must not give a large errors array
    // the budget intended for those facts. Keep the same shared budget.
    let priority = [
        (event == "catalog_rebuilt").then(|| fields.remove_entry("root")).flatten(),
        (event == "catalog_rebuilt").then(|| fields.remove_entry("reason")).flatten(),
        fields.remove_entry("error_kind"),
    ];
    for (i, (key, item)) in priority.into_iter().flatten().chain(fields).enumerate() {
        if i == MAX_ITEMS || budget == 0 {
            truncated = true;
            break;
        }
        let key = short_string(&key, budget.min(64), &mut truncated);
        if result.contains_key(key) {
            continue;
        }
        budget -= key.len();
        let item = match diagnostic.filter(|(name, _)| *name == key) {
            Some((_, project)) => project(&mut budget, &mut truncated),
            None => bounded_value(item, &mut budget, 0, &mut truncated),
        };
        result.insert(key.to_owned(), item);
    }
    if truncated {
        result.insert("truncated".into(), Value::Bool(true));
    }
    Ok(Value::Object(result))
}

#[derive(Default)]
struct Task {
    group: Option<Arc<Value>>,
    members: HashSet<String>,
    status: Option<Record>,
    stamp: i64,
    expired: bool,
    blocked: bool,
    owner: String,
    owners: HashSet<String>,
    order: u64,
}
impl Task {
    fn processing(&self) -> bool {
        self.status.is_some() && !self.blocked
    }
}
struct Retiring {
    members: HashSet<String>,
    owners: HashSet<String>,
}
#[derive(Default)]
struct Projection {
    // Completion removes the live task; only routing metadata may retire later.
    tasks: HashMap<String, Task>,
    retiring: HashMap<String, Retiring>,
    owner_tasks: HashMap<String, HashSet<String>>,
    aliases: HashMap<String, String>,
    order: u64,
    dirty: HashSet<String>,
    dirty_bytes: usize,
    full_dirty: bool,
}
impl Projection {
    fn mark(&mut self, id: &str) {
        if self.full_dirty {
            return;
        }
        if self.dirty.insert(id.to_owned()) {
            self.dirty_bytes += id.len();
        }
        if self.dirty_bytes > 1024 * 1024 {
            self.dirty = HashSet::new();
            self.dirty_bytes = 0;
            self.full_dirty = true;
        }
    }
    fn unbind(&mut self, id: &str, owners: &HashSet<String>) {
        for owner in owners {
            if let Some(ids) = self.owner_tasks.get_mut(owner) {
                ids.remove(id);
                if ids.is_empty() {
                    self.owner_tasks.remove(owner);
                }
            }
        }
    }
    fn release_owner(&mut self, owner: &str) {
        if let Some(ids) = self.owner_tasks.remove(owner) {
            for id in ids {
                if let Some(task) = self.tasks.get_mut(&id) {
                    task.owners.remove(owner);
                }
                if self
                    .tasks
                    .get(&id)
                    .is_some_and(|task| task.expired && task.owners.is_empty())
                {
                    self.drop_expired(&id);
                }
                if let Some(retiring) = self.retiring.get_mut(&id) {
                    retiring.owners.remove(owner);
                    if retiring.owners.is_empty() {
                        let retiring = self.retiring.remove(&id).unwrap();
                        for member in retiring.members {
                            if self.aliases.get(&member).is_some_and(|value| value == &id) {
                                self.aliases.remove(&member);
                            }
                        }
                    }
                }
            }
        }
    }
    fn drop_expired(&mut self, id: &str) {
        self.remove(id);
        if self.dirty.remove(id) {
            self.dirty_bytes = self.dirty_bytes.saturating_sub(id.len());
        }
    }
    fn expire_live(&mut self, ids: Vec<String>, cutoff: i64) {
        for id in ids {
            if let Some(task) = self.tasks.get_mut(&id) {
                if task.stamp > cutoff {
                    continue;
                }
                task.expired = true;
                if task.owners.is_empty() {
                    self.drop_expired(&id);
                }
            }
        }
        self.trim();
    }
    fn remove(&mut self, id: &str) -> Option<Task> {
        let task = self.tasks.remove(id)?;
        self.mark(id);
        self.unbind(id, &task.owners);
        for member in &task.members {
            if self
                .aliases
                .get(member)
                .is_some_and(|current| current == id)
            {
                self.aliases.remove(member);
            }
        }
        if let Some(group) = &task.group {
            let path = key(field(group, "path"));
            if self.aliases.get(&path).is_some_and(|current| current == id) {
                self.aliases.remove(&path);
            }
        }
        Some(task)
    }
    fn insert(&mut self, id: String, task: Task) {
        self.mark(&id);
        for owner in &task.owners {
            self.owner_tasks
                .entry(owner.clone())
                .or_default()
                .insert(id.clone());
        }
        for member in &task.members {
            self.aliases.insert(member.clone(), id.clone());
        }
        if let Some(group) = &task.group {
            self.aliases.insert(key(field(group, "path")), id.clone());
        }
        self.tasks.insert(id, task);
    }
    fn trim(&mut self) {
        crate::collections::trim_map(&mut self.tasks);
        crate::collections::trim_map(&mut self.aliases);
        crate::collections::trim_map(&mut self.retiring);
        crate::collections::trim_map(&mut self.owner_tasks);
    }
    fn resolve(&self, value: &Value, physical: &str) -> String {
        let explicit = field(value, "task_id");
        if !explicit.is_empty() {
            return explicit.to_owned();
        }
        self.aliases
            .get(physical)
            .cloned()
            .unwrap_or_else(|| physical.to_owned())
    }
    fn instance_id(&self, owner: &str, physical: &str) -> String {
        // Watch supplies a UUID per submission. Ownerless recovery must also
        // avoid IDs already present in history from an earlier writer.
        let owner = if owner.is_empty() {
            let epoch = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            format!("@{epoch}:{}", self.order)
        } else {
            owner.to_owned()
        };
        format!("{}|{}", owner, physical)
    }
    fn apply(&mut self, value: &mut Value) -> Option<Record> {
        self.order += 1;
        let event = field(value, "event").to_owned();
        if event == "pipeline_sources_claimed" {
            let owner = field(value, "owner").to_owned();
            let processing = value["processing"].as_bool().unwrap_or(false);
            let ts = value["ts"].clone();
            if let Some(groups) = value["groups"].as_array_mut() {
                for group in groups {
                    let path = field(group, "path").to_owned();
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
                    let explicit = field(group, "task_id").to_owned();
                    let mut previous: HashSet<_> = members
                        .iter()
                        .map(|m| self.aliases.get(m).unwrap_or(m).clone())
                        .filter(|id| {
                            self.tasks.contains_key(id) && (explicit.is_empty() || *id == explicit)
                        })
                        .collect();
                    if !explicit.is_empty() && self.tasks.contains_key(&explicit) {
                        previous.insert(explicit.clone());
                    }
                    // Keep an established group's ID across first-volume
                    // arrival; a provisional request card can be absorbed.
                    let id = if !explicit.is_empty() {
                        explicit
                    } else {
                        previous
                            .iter()
                            .filter(|id| self.tasks[*id].group.is_some())
                            .min()
                            .cloned()
                            .or_else(|| previous.iter().min().cloned())
                            .unwrap_or_else(|| self.instance_id(&owner, &key(&path)))
                    };
                    let mut task = Task::default();
                    let mut owners = HashSet::new();
                    for old in previous {
                        if let Some(mut candidate) = self.remove(&old) {
                            owners.extend(candidate.owners.drain());
                            if candidate.order > task.order {
                                task = candidate;
                            }
                        }
                    }
                    task.owners = owners;
                    group["task_id"] = json!(id);
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
                            value["task_id"] = json!(id);
                            task.status = Some(encode(&value));
                        }
                    }
                    if !owner.is_empty() {
                        task.owners.insert(owner.clone());
                        task.owner = owner.clone();
                    }
                    task.members = members;
                    task.group = Some(Arc::new(group.clone()));
                    if processing {
                        task.stamp = (ts.as_f64().unwrap_or(0.0) * 1_000_000.0) as i64;
                        task.expired = false;
                        task.status =
                            Some(encode(&json!({"event":"processing_started","path":path,
                        "ts":ts,"owner":task.owner,"task_id":id})));
                        task.order = self.order;
                        task.blocked = false;
                    }
                    self.insert(id, task);
                }
            }
            return None;
        }
        let path = field(value, "path").to_owned();
        let physical = key(&path);
        let mut id = self.resolve(value, &physical);
        if event == "pipeline_sources_released" {
            self.release_owner(field(value, "owner"));
            let ids: HashSet<_> = value["paths"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .chain((!path.is_empty()).then_some(path.as_str()))
                .map(key)
                .map(|p| self.aliases.get(&p).unwrap_or(&p).clone())
                .collect();
            for id in ids {
                if self
                    .tasks
                    .get(&id)
                    .is_some_and(|t| !t.blocked && t.owner == field(value, "owner"))
                {
                    self.remove(&id);
                }
            }
            return None;
        }
        if event == "task_retired" && field(value, "scope") == "task" {
            value["task_id"] = json!(id);
            self.remove(&id);
            return None;
        }
        if event == "blocker_cleared" {
            let path = if field(value, "task_path").is_empty() {
                path.as_str()
            } else {
                field(value, "task_path")
            };
            let id = self.resolve(value, &key(path));
            value["task_id"] = json!(id);
            if self.tasks.get(&id).is_some_and(|t| t.blocked) {
                self.remove(&id);
            }
            return None;
        }
        if event == "candidate_departed" || event == "task_retired" {
            // Source cleanup does not end an in-flight execution. Its original
            // members still route completion until the request releases them.
            let recursive = value["recursive"].as_bool().unwrap_or(false);
            let affected: Vec<_> = if recursive {
                self.tasks
                    .iter()
                    .filter(|(_, t)| {
                        !t.processing()
                            && t.members.iter().any(|m| {
                                *m == physical || crate::watch_store::is_path_under(m, &physical)
                            })
                    })
                    .map(|(id, _)| id.clone())
                    .collect()
            } else {
                self.tasks
                    .get(&id)
                    .filter(|t| !t.processing())
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
                    // A queued publication may still own the previous group.
                    let g = Arc::make_mut(g);
                    if let Some(members) = g["members"].as_array_mut() {
                        members
                            .retain(|m| m.as_str().is_some_and(|m| task.members.contains(&key(m))));
                    }
                }
                self.insert(id, task);
            }
            return None;
        }
        if event == "no_tasks_found" || event == "pipeline_request_coalesced" {
            value["task_id"] = json!(id);
            if self.tasks.get(&id).is_some_and(|t| {
                (field(value, "owner").is_empty() || t.owner == field(value, "owner"))
                    && (t.group.is_none()
                        || (event == "no_tasks_found"
                            && (t.members.len() == 1
                                || value["retire_group"].as_bool().unwrap_or(false))))
            }) {
                self.remove(&id);
            }
            return None;
        }
        if !path.is_empty()
            && matches!(
                event.as_str(),
                "processing_started"
                    | "failed_password"
                    | "suspended_missing_volume"
                    | "done"
                    | "failed_terminal"
                    | "partial_rejected"
            )
        {
            let terminal = matches!(
                event.as_str(),
                "done" | "failed_terminal" | "partial_rejected"
            );
            let owner = field(value, "owner");
            if terminal
                && (self.owner_tasks.get(owner).is_some_and(|ids| {
                    ids.iter().any(|previous| {
                        self.retiring
                            .get(previous)
                            .is_some_and(|task| task.members.contains(&physical))
                    })
                }) || self
                    .retiring
                    .get(&id)
                    .is_some_and(|task| task.owners.contains(owner)))
            {
                // A transferred request can finish after the real owner. Keep
                // only routing metadata until those in-flight owners release.
                return None;
            }
            if field(value, "task_id").is_empty() && !self.tasks.contains_key(&id) {
                id = self.instance_id(owner, &physical);
            }
            // A transferred family may still receive an older request's
            // completion. It cannot overwrite the current owner's result.
            if event != "processing_started"
                && !owner.is_empty()
                && self
                    .tasks
                    .get(&id)
                    .is_some_and(|t| !t.owner.is_empty() && t.owner != owner)
            {
                value["task_id"] = json!(self.instance_id(owner, &physical));
                value["event"] = json!("stale_task_completion");
                return None;
            }
            value["task_id"] = json!(id);
            let mut task = self.remove(&id).unwrap_or_default();
            if task.group.is_none() {
                task.members.insert(physical);
            }
            // Snapshot status always addresses its canonical group, even when
            // the original event named a member retired by a later regrouping.
            if let Some(group) = &task.group {
                // Publish the same canonical path that the snapshot retains.
                value["path"] = group["path"].clone();
            }
            task.stamp = timestamp(value);
            task.expired = false;
            task.blocked = matches!(
                event.as_str(),
                "failed_password" | "suspended_missing_volume"
            );
            if !field(value, "owner").is_empty() {
                task.owners.insert(field(value, "owner").to_owned());
                task.owner = field(value, "owner").to_owned();
            }
            task.order = self.order;
            if terminal {
                if !task.owners.is_empty() {
                    let mut members = std::mem::take(&mut task.members);
                    if let Some(group) = &task.group {
                        members.insert(key(field(group, "path")));
                    }
                    for member in &members {
                        self.aliases.insert(member.clone(), id.clone());
                    }
                    for owner in &task.owners {
                        self.owner_tasks
                            .entry(owner.clone())
                            .or_default()
                            .insert(id.clone());
                    }
                    self.retiring.insert(
                        id.clone(),
                        Retiring {
                            members,
                            owners: std::mem::take(&mut task.owners),
                        },
                    );
                }
                if let Some(group) = task.group {
                    value["group"] = Arc::unwrap_or_clone(group);
                }
                return Some(encode(value));
            }
            task.status = Some(encode(value));
            self.insert(id, task);
            return None;
        }
        Some(encode(value))
    }
    fn updates(
        &mut self,
        mut reset: bool,
    ) -> (Vec<(String, Option<(Record, Option<Arc<Value>>)>)>, bool) {
        reset |= std::mem::take(&mut self.full_dirty);
        self.dirty_bytes = 0;
        let dirty = std::mem::take(&mut self.dirty);
        let project_status = |task: &Task| {
            task.status
                .as_ref()
                .map(|status| (status.clone(), task.group.clone()))
        };
        let rows = if reset {
            drop(dirty);
            self.tasks
                .iter()
                .map(|(id, task)| (id.clone(), project_status(task)))
                .collect()
        } else {
            dirty
                .into_iter()
                .map(|id| {
                    let row = self.tasks.get(&id).and_then(project_status);
                    (id, row)
                })
                .collect()
        };
        (rows, reset)
    }
}

struct State {
    projection: Projection,
    queue: Vec<Record>,
    queue_bytes: usize,
    live_dirty: bool,
    reset_live: bool,
    rebuild: bool,
    revision: u64,
    published: u64,
    stopping: bool,
    working: bool,
    error: Option<String>,
    retention_days: u32,
    dropped: u64,
}
pub(crate) struct Shared {
    state: Mutex<State>,
    wake: Wake,
    drained: Condvar,
    stateful: bool,
}
impl Shared {
    fn configure_retention(&self, retention_days: u32) {
        let retention_days = retention_days.max(1);
        let mut state = self.state.lock().unwrap();
        if state.retention_days != retention_days {
            state.retention_days = retention_days;
            state.live_dirty = self.stateful;
            state.revision += 1;
            self.wake.notify();
        }
    }

    pub(crate) fn submit(&self, mut value: Value) {
        let mut state = self.state.lock().unwrap();
        if state.stopping {
            return;
        }
        if !value["ts"].as_f64().is_some_and(|ts| ts.is_finite()) {
            value["ts"] = json!(utc_us() as f64 / 1_000_000.0);
        }
        let row = if self.stateful {
            state.projection.apply(&mut value)
        } else {
            Some(encode(&value))
        };
        let changed = !state.projection.dirty.is_empty() || state.projection.full_dirty;
        state.live_dirty |= changed;
        state.projection.trim();
        if row.is_none() && !changed {
            return;
        }
        if let Some(row) = row {
            // Display logging must never stall extraction or grow without bound
            // when storage stops making progress. Report overload in the manifest.
            if state.queue.is_empty() || state.queue_bytes + row.len() <= QUEUE_BYTES {
                state.queue_bytes += row.len();
                state.queue.push(row);
            } else {
                state.dropped += 1;
            }
        }
        state.revision += 1;
        self.wake.notify();
    }
}
struct Owner {
    key: String,
    shared: Arc<Shared>,
    thread: Mutex<Option<JoinHandle<()>>>,
}
impl Drop for Owner {
    fn drop(&mut self) {
        {
            let mut state = self.shared.state.lock().unwrap();
            state.stopping = true;
            self.shared.wake.notify();
        }
        if let Some(thread) = self.thread.lock().unwrap().take() {
            let _ = thread.join();
        }
        let (owners, retired) = owners();
        {
            let mut owners = owners.lock().unwrap();
            owners.remove(&self.key);
            crate::collections::trim_map(&mut owners);
        }
        retired.notify_all();
    }
}
fn owners() -> &'static (Mutex<HashMap<String, Weak<Owner>>>, Condvar) {
    static OWNERS: OnceLock<(Mutex<HashMap<String, Weak<Owner>>>, Condvar)> = OnceLock::new();
    OWNERS.get_or_init(|| (Mutex::new(HashMap::new()), Condvar::new()))
}
fn timestamp(value: &Value) -> i64 {
    (value["ts"].as_f64().unwrap_or(0.0) * 1_000_000.0) as i64
}
fn writer(shared: Arc<Shared>, path: PathBuf) {
    let mut store = None;
    let mut deadline = None;
    loop {
        let now = utc_us();
        let (rows, live, days, dropped, revision, rebuild) = {
            let mut state = shared.state.lock().unwrap();
            let due = deadline.is_some_and(|time| time <= now);
            if state.published == state.revision && !due {
                state.working = false;
                shared.drained.notify_all();
                if state.stopping {
                    break;
                }
                drop(state);
                if let Err(error) = shared.wake.wait(deadline) {
                    let mut state = shared.state.lock().unwrap();
                    state.error = Some(error.to_string());
                    // A broken OS wait is terminal; never turn it into polling.
                    state.stopping = true;
                    state.published = state.revision;
                    shared.drained.notify_all();
                    break;
                }
                continue;
            }
            state.working = true;
            if state.rebuild {
                // Recovery initializes the projection from WAL before work
                // starts. Online mutations already update this same projection
                // synchronously, including processing groups and owner routes.
                // Publish it at this queue boundary; never rescan/retry on traffic.
                state.live_dirty = shared.stateful;
                state.reset_live = true;
            }
            let rebuild = std::mem::take(&mut state.rebuild);
            let live = if state.live_dirty {
                state.live_dirty = false;
                let reset = std::mem::take(&mut state.reset_live);
                Some(state.projection.updates(reset))
            } else {
                None
            };
            state.queue_bytes = 0;
            (
                std::mem::take(&mut state.queue),
                live,
                state.retention_days,
                state.dropped,
                state.revision,
                rebuild,
            )
        };
        let result = (|| -> std::io::Result<()> {
            if rebuild {
                store = None; // Release all handles before deleting the log.
                store = Some(Store::rebuild(path.clone())?);
            }
            if store.is_none() {
                store = Some(Store::open(path.clone())?);
            }
            let store = store.as_mut().unwrap();
            let retention = i64::from(days).saturating_mul(DAY_US);
            let cutoff = now.saturating_sub(retention);
            for row in rows {
                let value: Value = serde_json::from_slice(&row)?;
                let ts = timestamp(&value);
                if ts > cutoff {
                    store.append(&value, ts)?;
                }
            }
            if let Some((live, reset)) = live {
                let mut values = Vec::with_capacity(live.len());
                for (id, row) in live {
                    let value = if let Some((status, group)) = row {
                        let mut value: Value = serde_json::from_slice(&status)?;
                        if let Some(group) = group {
                            value["group"] = Arc::unwrap_or_clone(group);
                        }
                        Some((timestamp(&value), value))
                    } else {
                        None
                    };
                    values.push((id, value));
                }
                store.update_live(values, reset, cutoff)?;
            }
            deadline = store.expire(cutoff)?.map(|ts| ts.saturating_add(retention));
            store.manifest.dropped += dropped;
            store.publish()
        })();
        let expired = store
            .as_mut()
            .map(|store| std::mem::take(&mut store.expired_live))
            .unwrap_or_default();
        let mut state = shared.state.lock().unwrap();
        if result.is_ok() && !expired.is_empty() {
            state.projection.expire_live(
                expired,
                now.saturating_sub(i64::from(days).saturating_mul(DAY_US)),
            );
        }
        state.working = false;
        state.error = result.err().map(|error| error.to_string());
        if state.error.is_some() {
            deadline = None;
            store = None;
            state.live_dirty = true;
            state.reset_live = true;
            state.rebuild = true;
            // Try recovery once for this operation. A failed rebuild stays
            // pending until the next operation, never an idle retry loop.
            if !rebuild {
                state.revision += 1;
            }
        }
        state.dropped = state.dropped.saturating_sub(dropped);
        state.published = revision;
        shared.drained.notify_all();
    }
}

pub(crate) struct NativeEventLog {
    owner: Option<Arc<Owner>>,
}
impl NativeEventLog {
    pub(crate) fn shared(&self) -> std::io::Result<&Arc<Shared>> {
        self.owner
            .as_ref()
            .map(|o| &o.shared)
            .ok_or_else(|| std::io::Error::other("event log is closed"))
    }
}
impl NativeEventLog {
    pub(crate) fn new(path: PathBuf, retention_days: u32, stateful: bool) -> std::io::Result<Self> {
        let path = std::path::absolute(path)?;
        let (registry, retired) = owners();
        let mut owners = registry.lock().unwrap();
        let id = key(&path.to_string_lossy());
        while let Some(owner) = owners.get(&id) {
            if let Some(owner) = owner.upgrade() {
                owner.shared.configure_retention(retention_days);
                return Ok(Self { owner: Some(owner) });
            }
            owners = retired.wait(owners).unwrap();
        }
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                projection: Projection::default(),
                queue: Vec::new(),
                queue_bytes: 0,
                live_dirty: stateful,
                reset_live: stateful,
                rebuild: false,
                revision: 1,
                published: 0,
                stopping: false,
                working: true,
                error: None,
                retention_days: retention_days.max(1),
                dropped: 0,
            }),
            wake: Wake::new()?,
            drained: Condvar::new(),
            stateful,
        });
        let worker = Arc::clone(&shared);
        let thread = std::thread::Builder::new()
            .name("sunpack-display".into())
            .spawn(move || writer(worker, path))?;
        let owner = Arc::new(Owner {
            key: id.clone(),
            shared,
            thread: Mutex::new(Some(thread)),
        });
        owners.insert(id, Arc::downgrade(&owner));
        Ok(Self { owner: Some(owner) })
    }
    pub(crate) fn configure_retention(&self, retention_days: u32) -> std::io::Result<()> {
        self.shared()?.configure_retention(retention_days);
        Ok(())
    }
    pub(crate) fn write(&self, value: Value) -> std::io::Result<()> {
        self.shared()?.submit(event_value(value)?);
        Ok(())
    }
    pub(crate) fn write_failure(&self, value: Value, failure: &crate::pipeline::Failure) -> std::io::Result<()> {
        let project = |budget: &mut usize, truncated: &mut bool|
            diagnostic::value(&DiagnosticFailure(failure), budget, truncated);
        self.shared()?.submit(event_value_with(value, Some(("failure", &project)))?);
        Ok(())
    }
    pub(crate) fn recover(&self, state: Option<&NativeWatchState>) -> std::io::Result<()> {
        match state {
            Some(state) => state.with_event_projection(|rows| self.reset(rows)),
            None => self.reset(Vec::new()),
        }
    }
    pub(crate) fn rebuild(&self) -> std::io::Result<()> {
        let shared = self.shared()?;
        let mut state = shared.state.lock().unwrap();
        state.rebuild = true;
        state.revision += 1;
        shared.wake.notify();
        Ok(())
    }
    pub(crate) fn flush(&self) -> std::io::Result<()> {
        let shared = Arc::clone(self.shared()?);
        (move || {
            let mut state = shared.state.lock().unwrap();
            if state.error.is_some() && !state.stopping {
                state.revision += 1;
                shared.wake.notify();
            }
            while state.working || state.published != state.revision {
                state = shared.drained.wait(state).unwrap();
            }
            match &state.error {
                Some(e) => Err(std::io::Error::other(e.clone())),
                None => Ok(()),
            }
        })()
    }
    pub(crate) fn error(&self) -> std::io::Result<Option<String>> {
        Ok(self.shared()?.state.lock().unwrap().error.clone())
    }
}
impl NativeEventLog {
    pub(crate) fn reset(&self, rows: Vec<Value>) -> std::io::Result<()> {
        let shared = self.shared()?;
        let mut state = shared.state.lock().unwrap();
        state.reset_live = true;
        state.projection = Projection::default();
        for mut value in rows {
            let _ = state.projection.apply(&mut value);
        }
        state.live_dirty = true;
        state.revision += 1;
        shared.wake.notify();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_diagnostics_do_not_expand_or_change_shared_recovery_receipts() {
        let input = crate::io::archive_state::ArchiveInput::file("C:/input.zip".into(), "zip".into(), "input.zip".into());
        let checkpoint = json!({"schema_version":1,"carrier":"C:/input.zip","input":input,
            "sources":[],"output":"C:/output","container":"C:/output","files":1,"bytes":1,
            "encrypted":false,"discovery_source":"direct"});
        let mut expected = None;
        for count in [1, 1024] {
            let failure: crate::pipeline::Failure = serde_json::from_value(json!({
                "kind":"damaged","message":"CRC error","evidence":{"stage":"item_extract"},
                "recovery":{"inputs":vec![checkpoint.clone();count],"output":"C:/output",
                    "input_count":count,"had_checkpoints":true,"retry_output":true}
            })).unwrap();
            let project = |budget: &mut usize, truncated: &mut bool|
                diagnostic::value(&DiagnosticFailure(&failure), budget, truncated);
            let output = event_value_with(json!({"event":"archive_failure_evidence","path":"C:/input.zip"}),
                Some(("failure", &project))).unwrap();
            assert_eq!(output["failure"]["kind"], "damaged");
            assert_eq!(output["failure"]["evidence"]["stage"], "item_extract");
            assert!(output["failure"].get("recovery").is_none());
            if let Some(expected) = &expected { assert_eq!(&output, expected); }
            else { expected = Some(output); }
            // Ordinary failure serialization still owns the complete durable
            // contract. Only the per-archive diagnostic view omits the group.
            assert_eq!(serde_json::to_value(&failure).unwrap()["recovery"]["inputs"].as_array().unwrap().len(), count);
        }
    }

    #[test]
    fn diagnostic_budget_keeps_catalog_location_and_failure_classification() {
        let rebuilt = event_value(json!({"event":"catalog_rebuilt", "root":"C:/downloads",
            "reason":"incremental_failed", "errors":vec!["access denied".repeat(300); 64],
            "zzz":"after exhausted diagnostics"})).unwrap();
        assert_eq!(rebuilt["root"], "C:/downloads");
        assert_eq!(rebuilt["reason"], "incremental_failed");
        assert_eq!(rebuilt["truncated"], true);
        assert!(rebuilt.get("").is_none());
        assert!(rebuilt.get("zzz").is_none());
        assert!(serde_json::to_vec(&rebuilt).unwrap().len() < DIAGNOSTIC_TEXT_BYTES + 256);

        let failed = event_value(json!({"event":"failed_terminal", "path":"C:/archive.zip",
            "error_kind":"damaged", "error":"failure details".repeat(1000), "zzz":1})).unwrap();
        assert_eq!(failed["path"], "C:/archive.zip");
        assert_eq!(failed["error_kind"], "damaged");
        assert!(failed["error"].as_str().unwrap().len() < DIAGNOSTIC_TEXT_BYTES);
        assert_eq!(failed["truncated"], true);
        assert!(failed.get("").is_none());
        assert!(failed.get("zzz").is_none());
    }

    // Hold a writer snapshot across member retirement and completion. Existing
    // disk tests cannot force this overlap; this checks snapshot isolation and
    // release of both group generations without threads or disk I/O.
    #[test]
    fn queued_groups_survive_live_mutation_and_release_after_completion() {
        let mut projection = Projection::default();
        let path = "C:/nested.fake";
        let member = "C:/opaque.002";
        projection.apply(
            &mut json!({"event":"pipeline_sources_claimed","owner":"run",
            "groups":[{"path":path,"members":[path,member]}]}),
        );
        projection.apply(&mut json!({"event":"suspended_missing_volume",
            "path":path,"owner":"run","ts":1}));
        let old = projection
            .updates(false)
            .0
            .pop()
            .unwrap()
            .1
            .unwrap()
            .1
            .unwrap();
        let old_lifetime = Arc::downgrade(&old);

        projection.apply(&mut json!({"event":"candidate_departed","path":member}));
        let current = projection
            .updates(false)
            .0
            .pop()
            .unwrap()
            .1
            .unwrap()
            .1
            .unwrap();
        let current_lifetime = Arc::downgrade(&current);
        assert_eq!(old["members"], json!([path, member]));
        assert_eq!(current["members"], json!([path]));

        let row = projection
            .apply(&mut json!({"event":"done","path":path,
            "owner":"run","ts":2}))
            .unwrap();
        let row: Value = serde_json::from_slice(&row).unwrap();
        assert_eq!(row["group"], *current);
        assert!(projection.tasks.is_empty());
        projection.apply(&mut json!({"event":"pipeline_sources_released",
            "owner":"run","path":path}));
        assert!(projection.aliases.is_empty() && projection.retiring.is_empty());
        drop(old);
        drop(current);
        assert!(old_lifetime.upgrade().is_none());
        assert!(current_lifetime.upgrade().is_none());
    }

    #[test]
    fn completed_families_leave_no_resident_history_or_aliases() {
        // Disk/GUI checks cannot see producer references. Removing this test
        // loses detection of retained completed families; no disk I/O is needed.
        let mut projection = Projection::default();
        for index in 0..2000 {
            let path = format!("C:/carrier-{index}.fake");
            let sibling = format!("C:/opaque-{index}.002");
            let mut claim = json!({"event":"pipeline_sources_claimed","owner":index.to_string(),
                "processing":true,"ts":1,"groups":[{"path":path,"members":[path,sibling]}]});
            projection.apply(&mut claim);
            let mut completion =
                json!({"event":"done","path":sibling,"owner":index.to_string(),"ts":2});
            let row = projection.apply(&mut completion).unwrap();
            let row: Value = serde_json::from_slice(&row).unwrap();
            assert_eq!(row["group"]["members"].as_array().unwrap().len(), 2);
            assert!(projection.tasks.is_empty());
            assert!(projection
                .apply(&mut json!({"event":"done","path":path,"owner":index.to_string(),"ts":2}))
                .is_none());
            projection.apply(&mut json!({"event":"pipeline_sources_released","owner":index.to_string(),"path":path}));
            assert!(
                projection.aliases.is_empty()
                    && projection.retiring.is_empty()
                    && projection.owner_tasks.is_empty()
            );
        }
        let mut waiting =
            json!({"event":"suspended_missing_volume","path":"C:/abandoned.002","ts":1});
        projection.apply(&mut waiting);
        let id = projection.tasks.keys().next().unwrap().clone();
        projection.expire_live(vec![id], 2_000_000);
        assert!(projection.tasks.is_empty() && projection.aliases.is_empty());
    }
}

#[cfg(test)]
#[path = "event_log/gui_contract.rs"]
mod gui_contract;
