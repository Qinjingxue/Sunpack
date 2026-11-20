//! Best-effort display history. Business state remains in the existing task store.
use crate::collections::SmallOrderedSet;
use crate::io::display_store::{utc_us, EventField, HistoryRecord, LiveEvent, Store, DAY_US};
use crate::io::display_wake::Wake;
use crate::watch_store::NativeWatchState;
use serde_json::{json, Value};
use serde::ser::SerializeMap;
use std::collections::{HashMap, HashSet};

use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex, OnceLock, Weak};
use std::thread::JoinHandle;

/// Per-archive evidence never walks the shared carrier recovery receipts.
/// Complete recovery data retains its ordinary serializer for durable state/reports.
struct DiagnosticFailure<'a>(pub &'a crate::pipeline::Failure);
impl serde::Serialize for DiagnosticFailure<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let failure = self.0;
        let count = 2 + usize::from(failure.context.is_some())
            + usize::from(failure.discovery_scope.is_some())
            + usize::from(failure.evidence.is_some())
            + usize::from(failure.password_retry);
        let mut object = serializer.serialize_map(Some(count))?;
        object.serialize_entry("kind", &failure.kind)?;
        object.serialize_entry("message", &failure.message)?;
        if let Some(context) = &failure.context { object.serialize_entry("context", context)?; }
        if let Some(scope) = &failure.discovery_scope { object.serialize_entry("discovery_scope", scope)?; }
        if let Some(evidence) = &failure.evidence { object.serialize_entry("evidence", evidence)?; }
        if failure.password_retry { object.serialize_entry("password_retry", &true)?; }
        object.end()
    }
}
const QUEUE_BYTES: usize = 4 * 1024 * 1024;
type Record = Arc<Vec<u8>>;
fn encode(value: &Value) -> Record {
    Arc::new(serde_json::to_vec(value).expect("JSON value"))
}
fn key(path: &str) -> String {
    crate::path_keys::path_key(path)
}
fn field<'a>(v: &'a Value, name: &str) -> &'a str {
    v[name].as_str().unwrap_or("")
}

fn take_segments(value: &mut Value) -> Option<Vec<Value>> {
    match value.as_object_mut()?.remove("segments")? {
        Value::Array(segments) if !segments.is_empty() => Some(segments),
        _ => None,
    }
}

pub(crate) fn retain_waiting_members(value: &mut Value, mut present: impl FnMut(&str) -> bool) {
    if let Some(segments) = value.get_mut("segments").and_then(Value::as_array_mut) {
        for row in segments.iter_mut().filter(|row|
            matches!(field(row, "event"), "failed_password" | "suspended_missing_volume")) {
            if let Some(members) = row.get_mut("members").and_then(Value::as_array_mut) {
                members.retain(|member| member.as_str().is_some_and(&mut present));
            }
        }
    }
}

fn segment_id(id: &Arc<str>, index: usize) -> Arc<str> {
    // Keep the first slot on the physical ID so retention expires the group.
    if index == 0 { Arc::clone(id) } else { format!("{id}|segment:{index}").into() }
}

fn segment_row(parent: &Value, id: &str, mut row: Value) -> Value {
    if row.get("event").is_none() {
        row["event"] = parent["event"].clone();
    }
    row["owner"] = parent["owner"].clone();
    row["ts"] = parent["ts"].clone();
    row["task_id"] = json!(id);
    row
}

fn state_event(event: &str) -> bool {
    matches!(
        event,
        "pipeline_sources_claimed"
            | "failed_password"
            | "suspended_missing_volume"
            | "done"
            | "watch_deduplicated"
            | "failed_terminal"
            | "partial_rejected"
            | "task_retired"
            | "blocker_cleared"
            | "candidate_departed"
            | "no_tasks_found"
            | "pipeline_request_coalesced"
            | "pipeline_sources_released"
    )
}

#[derive(Default)]
enum TaskStatus {
    #[default]
    Unpublished,
    Published { record: Record, segmented: bool },
    Expired,
}
impl TaskStatus {
    fn publish(value: &Value) -> Self {
        Self::Published { record: encode(value), segmented: value.get("segments").is_some() }
    }
}

#[derive(Default)]
struct Task {
    group: Option<Arc<Value>>,
    members: HashSet<Arc<str>>,
    status: TaskStatus,
    stamp: i64,
    blocked: bool,
    owner: String,
    owners: HashSet<String>,
    order: u64,
}
impl Task {
    fn processing(&self) -> bool {
        !matches!(self.status, TaskStatus::Unpublished) && !self.blocked
    }

    fn additional_group_path(&self) -> Option<String> {
        let path = key(field(self.group.as_ref()?, "path"));
        (!self.members.contains(path.as_str())).then_some(path)
    }
}
struct Retiring {
    members: Box<[Arc<str>]>,
    owners: HashSet<String>,
}
#[derive(Default)]
struct Alias {
    current: Option<Arc<str>>,
    // A newly claimed group can replace the current alias while an older
    // owner still has a completion in flight for the same physical path.
    retiring: Option<SmallOrderedSet<Arc<str>>>,
}
#[derive(Default)]
struct Projection {
    // Routing indexes and the writer share each task ID's allocation.
    // Completion removes the live task; only routing metadata may retire later.
    tasks: HashMap<Arc<str>, Task>,
    retiring: HashMap<Arc<str>, Retiring>,
    owner_tasks: HashMap<String, HashSet<Arc<str>>>,
    aliases: HashMap<Arc<str>, Alias>,
    order: u64,
    dirty: HashSet<Arc<str>>,
    dirty_bytes: usize,
    full_dirty: bool,
}
impl Projection {
    fn mark(&mut self, id: &Arc<str>) {
        if self.full_dirty {
            return;
        }
        if self.dirty.insert(Arc::clone(id)) {
            self.dirty_bytes += id.len();
        }
        if self.dirty_bytes > 1024 * 1024 {
            self.mark_all();
        }
    }
    fn mark_all(&mut self) {
        self.dirty = HashSet::new();
        self.dirty_bytes = 0;
        self.full_dirty = true;
    }
    fn changed(&self) -> bool {
        self.full_dirty || !self.dirty.is_empty()
    }
    fn unbind(&mut self, id: &str, owners: &HashSet<String>) {
        for owner in owners {
            self.unbind_owner(id, owner);
        }
    }
    fn unbind_owner(&mut self, id: &str, owner: &str) {
        if self.retiring.get(id).is_some_and(|task| task.owners.contains(owner)) {
            return;
        }
        if let Some(ids) = self.owner_tasks.get_mut(owner) {
            ids.remove(id);
            if ids.is_empty() {
                self.owner_tasks.remove(owner);
            }
        }
    }
    fn release_owner(&mut self, owner: &str) {
        if let Some(ids) = self.owner_tasks.remove(owner) {
            for id in ids {
                self.release_task_owner(&id, owner, None);
            }
        }
    }
    fn release_task_owner(&mut self, id: &Arc<str>, owner: &str, path: Option<&str>) {
        if let Some(task) = self.tasks.get_mut(id) {
            if path.is_none_or(|path| task.group.as_ref().is_some_and(|group| key(field(group, "path")) == path))
                && task.owners.remove(owner)
            {
                if matches!(task.status, TaskStatus::Expired) {
                    if task.owners.is_empty() {
                        self.drop_expired(id);
                    }
                } else if !task.blocked && task.owner == owner {
                    self.remove(id);
                }
            }
        }
        if let Some(retiring) = self.retiring.get_mut(id) {
            if path.is_none_or(|path| retiring.members[0].as_ref() == path)
                && retiring.owners.remove(owner) && retiring.owners.is_empty()
            {
                let retiring = self.retiring.remove(id).unwrap();
                for member in retiring.members.iter() {
                    self.unbind_alias(member, id, true);
                }
            }
        }
        if path.is_some() && !self.tasks.get(id).is_some_and(|task| task.owners.contains(owner)) {
            self.unbind_owner(id, owner);
        }
    }
    fn alias_id(&self, path: &str) -> Option<&Arc<str>> {
        self.aliases.get(path)?.current.as_ref()
    }
    fn unbind_alias(&mut self, path: &str, id: &Arc<str>, retiring: bool) {
        if let Some(alias) = self.aliases.get_mut(path) {
            if alias.current.as_ref() == Some(id) {
                alias.current = None;
            }
            if retiring && alias.retiring.as_mut().is_some_and(|ids| ids.remove(id)) {
                alias.retiring = None;
            }
            if alias.current.is_none() && alias.retiring.is_none() {
                self.aliases.remove(path);
            }
        }
    }
    fn drop_expired(&mut self, id: &str) {
        self.remove(id);
        if self.dirty.remove(id) {
            self.dirty_bytes = self.dirty_bytes.saturating_sub(id.len());
        }
    }
    fn expire_live(&mut self, ids: Vec<Arc<str>>, cutoff: i64) {
        for id in ids {
            if let Some(task) = self.tasks.get_mut(id.as_ref()) {
                if task.stamp > cutoff {
                    continue;
                }
                task.status = TaskStatus::Expired;
                if task.owners.is_empty() {
                    self.drop_expired(&id);
                }
            }
        }
        self.trim();
    }
    fn remove(&mut self, id: &str) -> Option<Task> {
        let (owned_id, task) = self.tasks.remove_entry(id)?;
        if !matches!(task.status, TaskStatus::Expired) {
            self.mark(&owned_id);
        }
        self.unbind(id, &task.owners);
        for member in &task.members {
            self.unbind_alias(member, &owned_id, false);
        }
        if let Some(primary) = task.additional_group_path() {
            self.unbind_alias(&primary, &owned_id, false);
        }
        Some(task)
    }
    fn insert(&mut self, id: Arc<str>, task: Task) {
        self.mark(&id);
        for owner in &task.owners {
            self.owner_tasks
                .entry(owner.clone())
                .or_default()
                .insert(id.clone());
        }
        for member in &task.members {
            self.aliases.entry(member.clone()).or_default().current = Some(id.clone());
        }
        if let Some(primary) = task.additional_group_path() {
            self.aliases.entry(primary.into()).or_default().current = Some(id.clone());
        }
        self.tasks.insert(id, task);
    }
    fn trim(&mut self) {
        crate::collections::trim_map(&mut self.tasks);
        crate::collections::trim_map(&mut self.aliases);
        crate::collections::trim_map(&mut self.retiring);
        crate::collections::trim_map(&mut self.owner_tasks);
    }
    fn instance_id(&self, owner: &str, physical: &str) -> Arc<str> {
        // Watch supplies a UUID per submission. Ownerless recovery must also
        // avoid IDs already present in history from an earlier writer.
        if owner.is_empty() {
            let epoch = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            format!("@{epoch}:{}|{physical}", self.order).into()
        } else {
            format!("{owner}|{physical}").into()
        }
    }
    /// Update the live projection and report whether to persist this event in history.
    fn apply(&mut self, value: &mut Value) -> bool {
        self.order += 1;
        let event = field(value, "event");
        if event == "pipeline_sources_claimed" {
            let owner = field(value, "owner").to_owned();
            let processing = value["processing"].as_bool().unwrap_or(false);
            let ts = value["ts"].clone();
            if let Some(groups) = value["groups"].as_array_mut() {
                for group in groups {
                    let path = field(group, "path");
                    if path.is_empty() {
                        continue;
                    }
                    let members: HashSet<Arc<str>> = group["members"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .filter(|s| !s.is_empty())
                        .map(key)
                        .map(Arc::from)
                        .collect();
                    if members.is_empty() {
                        continue;
                    }
                    let previous: HashSet<_> = members
                        .iter()
                        .filter_map(|member| self.alias_id(member))
                        .filter(|id| self.tasks.contains_key(*id))
                        .cloned()
                        .collect();
                    // Keep an established group's ID across first-volume
                    // arrival; a provisional request card can be absorbed.
                    let id = previous
                        .iter()
                        .filter(|id| self.tasks[*id].group.is_some())
                        .min()
                        .or_else(|| previous.iter().min())
                        .cloned()
                        .unwrap_or_else(|| self.instance_id(&owner, &key(path)));
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
                    if !processing && task
                        .group
                        .as_ref()
                        .is_none_or(|old| old["path"] != group["path"])
                    {
                        // The first group can absorb a provisional member card.
                        // Its status must address the canonical path before that
                        // member retires, otherwise a snapshot resurrects it.
                        if let TaskStatus::Published { record, .. } = &task.status {
                            let mut value: Value =
                                serde_json::from_slice(record).expect("encoded status");
                            value["path"] = group["path"].clone();
                            value["task_id"] = json!(id);
                            task.status = TaskStatus::publish(&value);
                        }
                    }
                    if !owner.is_empty() {
                        task.owners.insert(owner.clone());
                        task.owner = owner.clone();
                    }
                    task.members = members;
                    if processing {
                        task.stamp = (ts.as_f64().unwrap_or(0.0) * 1_000_000.0) as i64;
                        let mut status = json!({"event":"processing_started","path":group["path"],
                            "ts":ts,"owner":task.owner,"task_id":id});
                        if let Some(segments) = take_segments(group) {
                            status["segments"] = Value::Array(segments);
                        }
                        task.status = TaskStatus::publish(&status);
                        task.order = self.order;
                        task.blocked = false;
                    }
                    task.group = Some(Arc::new(std::mem::take(group)));
                    self.insert(id, task);
                }
            }
            return false;
        }
        let path = field(value, "path");
        if event == "pipeline_sources_released" {
            let owner = field(value, "owner");
            if path.is_empty() {
                self.release_owner(owner);
                return false;
            }
            // A root completion can arrive while sibling roots still own
            // claims. Find the routes by canonical path before releasing them.
            let physical = key(path);
            if let Some(alias) = self.aliases.get(physical.as_str()) {
                let current = alias.current.clone();
                let retired: Vec<_> = alias.retiring.iter().flat_map(|ids| ids.iter())
                    .filter(|id| current.as_ref() != Some(*id)).cloned().collect();
                for id in current.into_iter().chain(retired) {
                    self.release_task_owner(&id, owner, Some(&physical));
                }
            }
            return false;
        }
        if event == "blocker_cleared" {
            let path = if field(value, "task_path").is_empty() {
                path
            } else {
                field(value, "task_path")
            };
            if let Some(id) = self.alias_id(&key(path)).cloned() {
                if self.tasks.get(&id).is_some_and(|t| t.blocked) {
                    self.remove(&id);
                }
            }
            return false;
        }
        let physical = key(path);
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
                                m.as_ref() == physical || crate::watch_store::is_path_under(m, &physical)
                            })
                    })
                    .map(|(id, _)| id.clone())
                    .collect()
            } else {
                self.alias_id(&physical)
                    .filter(|id| self.tasks.get(*id).is_some_and(|task| !task.processing()))
                    .cloned()
                    .into_iter()
                    .collect()
            };
            for id in affected {
                let mut task = self.remove(&id).unwrap();
                let present = |m: &str| {
                    m != physical
                        && !(recursive && crate::watch_store::is_path_under(m, &physical))
                };
                task.members.retain(|member| present(member));
                if task.members.is_empty() {
                    continue;
                }
                if let TaskStatus::Published { record, segmented: true } = &task.status {
                    let mut status: Value = serde_json::from_slice(record).expect("encoded status");
                    retain_waiting_members(&mut status, |member| present(&key(member)));
                    task.status = TaskStatus::publish(&status);
                }
                if let Some(g) = task.group.as_mut() {
                    // A queued publication may still own the previous group.
                    let g = Arc::make_mut(g);
                    if let Some(members) = g["members"].as_array_mut() {
                        members
                            .retain(|m| m.as_str().is_some_and(|m| task.members.contains(key(m).as_str())));
                    }
                }
                self.insert(id, task);
            }
            return false;
        }
        if event == "no_tasks_found" || event == "pipeline_request_coalesced" {
            if let Some(id) = self.alias_id(&physical).cloned() {
                if self.tasks.get(&id).is_some_and(|t| {
                    (field(value, "owner").is_empty() || t.owner == field(value, "owner"))
                        && (t.group.is_none()
                            || (event == "no_tasks_found"
                                && (t.members.len() == 1
                                    || value["retire_group"].as_bool().unwrap_or(false))))
                }) {
                    self.remove(&id);
                }
            }
            return false;
        }
        if !path.is_empty()
            && matches!(
                event,
                "failed_password"
                    | "suspended_missing_volume"
                    | "done"
                    | "watch_deduplicated"
                    | "failed_terminal"
                    | "partial_rejected"
            )
        {
            let terminal = matches!(
                event,
                "done" | "watch_deduplicated" | "failed_terminal" | "partial_rejected"
            );
            let owner = field(value, "owner");
            if terminal
                && self.aliases.get(physical.as_str()).and_then(|alias| alias.retiring.as_ref())
                    .is_some_and(|ids| ids.iter().any(|id| self.retiring[id].owners.contains(owner)))
            {
                // A transferred request can finish after the real owner. Keep
                // only routing metadata until those in-flight owners release.
                return false;
            }
            let id = self.alias_id(&physical)
                .filter(|id| self.tasks.contains_key(*id))
                .cloned()
                .unwrap_or_else(|| self.instance_id(owner, &physical));
            // A transferred family may still receive an older request's
            // completion. It cannot overwrite the current owner's result.
            if !owner.is_empty()
                && self
                    .tasks
                    .get(&id)
                    .is_some_and(|t| !t.owner.is_empty() && t.owner != owner)
            {
                return false;
            }
            let blocked = matches!(event, "failed_password" | "suspended_missing_volume");
            let deduplicated = event == "watch_deduplicated";
            value["task_id"] = json!(id);
            let mut task = self.remove(&id).unwrap_or_default();
            if task.group.is_none() {
                task.members.insert(physical.into());
            }
            // Snapshot status always addresses its canonical group, even when
            // the original event named a member retired by a later regrouping.
            if let Some(group) = &task.group {
                // Publish the same canonical path that the snapshot retains.
                value["path"] = group["path"].clone();
            }
            task.stamp = timestamp(value);
            task.blocked = blocked;
            if !terminal && !field(value, "owner").is_empty() {
                task.owner = field(value, "owner").to_owned();
            }
            task.order = self.order;
            if terminal {
                if deduplicated {
                    if let TaskStatus::Published { record, segmented: true } = &task.status {
                        let mut processing: Value = serde_json::from_slice(record).expect("encoded status");
                        if field(&processing, "event") == "processing_started" {
                            value["segments"] = processing["segments"].take();
                        }
                    }
                }
                // Only a source claim owns a route that can receive a later completion.
                if !task.owners.is_empty() {
                    if let Some(previous) = self.retiring.remove(&id) {
                        self.unbind(&id, &previous.owners);
                        for path in previous.members.iter() {
                            self.unbind_alias(path, &id, true);
                        }
                    }
                    let primary = key(field(value, "path"));
                    let primary = task.members.take(primary.as_str()).unwrap_or_else(|| primary.into());
                    // Store the canonical route first for a scoped release.
                    let members: Box<[_]> = std::iter::once(primary).chain(task.members)
                        .collect();
                    for member in members.iter() {
                        let alias = self.aliases.entry(member.clone()).or_default();
                        alias.current = Some(id.clone());
                        match &mut alias.retiring {
                            Some(ids) => ids.insert(id.clone()),
                            None => alias.retiring = Some(SmallOrderedSet::One(id.clone())),
                        }
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
                if let Some(group) = task.group.filter(|_| value.get("segments").is_none()) {
                    value["group"] = Arc::unwrap_or_clone(group);
                }
                return true;
            }
            task.status = TaskStatus::publish(value);
            self.insert(id, task);
            return false;
        }
        true
    }
    fn updates(&mut self) -> (Vec<(Arc<str>, Option<(Record, Option<Arc<Value>>)>)>, bool) {
        let reset = std::mem::take(&mut self.full_dirty);
        self.dirty_bytes = 0;
        let dirty = std::mem::take(&mut self.dirty);
        let project_status = |task: &Task| match &task.status {
            TaskStatus::Published { record, .. } => Some((Arc::clone(record), task.group.clone())),
            TaskStatus::Unpublished | TaskStatus::Expired => None,
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
    queue: Vec<HistoryRecord>,
    queue_bytes: usize,
    rebuild: bool,
    revision: u64,
    published: u64,
    stopping: bool,
    working: bool,
    error: Option<String>,
    retention_days: u32,
}
pub(crate) struct Shared {
    state: Mutex<State>,
    wake: Wake,
    drained: Condvar,
    stateful: bool,
}
impl Shared {
    fn schedule(&self, state: &mut State) {
        let idle = !state.working && state.revision == state.published;
        state.revision += 1;
        if idle {
            self.wake.notify();
        }
    }

    fn configure_retention(&self, retention_days: u32) {
        let retention_days = retention_days.max(1);
        let mut state = self.state.lock().unwrap();
        if state.retention_days != retention_days {
            state.retention_days = retention_days;
            self.schedule(&mut state);
        }
    }

    pub(crate) fn submit(&self, value: Value) -> std::io::Result<()> {
        self.submit_event(value, None)
    }

    fn submit_event(&self, mut value: Value, failure: Option<&crate::pipeline::Failure>) -> std::io::Result<()> {
        let fields = value.as_object_mut().ok_or_else(|| std::io::Error::other("event must be an object"))?;
        if failure.is_some() {
            fields.remove("failure");
        }
        let mut state = self.state.lock().unwrap();
        // Drain asynchronously in bounded batches. Keep events in order and
        // let the producer wait for the writer only when the queue is full.
        while state.queue_bytes >= QUEUE_BYTES && !state.stopping {
            state = self.drained.wait(state).unwrap();
        }
        if state.stopping {
            return Err(std::io::Error::other("display writer stopped"));
        }
        if !value["ts"].as_f64().is_some_and(|ts| ts.is_finite()) {
            value["ts"] = json!(utc_us() as f64 / 1_000_000.0);
        }
        let mut history = true;
        if self.stateful && state_event(field(&value, "event")) {
            history = state.projection.apply(&mut value);
            let changed = state.projection.changed();
            state.projection.trim();
            if !history && !changed {
                return Ok(());
            }
        }
        let result = if history {
            let segments = take_segments(&mut value);
            let ts = timestamp(&value);
            if let Some(segments) = segments {
                state.push_segment_history(&value, ts, segments)
            } else {
                let row = match failure {
                    Some(failure) => HistoryRecord::new(&value, ts, &EventField {
                        fields: value.as_object().unwrap(),
                        name: "failure",
                        value: DiagnosticFailure(failure),
                    }),
                    None => HistoryRecord::new(&value, ts, &value),
                };
                row.map(|row| state.push_history(row))
            }
        } else {
            Ok(())
        };
        self.schedule(&mut state);
        result
    }
}
impl State {
    fn push_history(&mut self, row: HistoryRecord) {
        self.queue_bytes += row.memory_bytes();
        self.queue.push(row);
    }

    fn push_segment_history(&mut self, summary: &Value, ts: i64, segments: Vec<Value>) -> std::io::Result<()> {
        let id: Arc<str> = field(summary, "task_id").into();
        let diagnostic = HistoryRecord::diagnostic(ts, summary)?;
        let (previous_len, previous_bytes) = (self.queue.len(), self.queue_bytes);
        self.queue.reserve(segments.len() + 1);
        self.push_history(diagnostic);
        let result = segments.into_iter().enumerate().try_for_each(|(index, segment)| {
            let segment = segment_row(summary, &segment_id(&id, index), segment);
            self.push_history(HistoryRecord::new(&segment, ts, &segment)?);
            Ok(())
        });
        if result.is_err() {
            // A partly serialized carrier must not enter the writer's batch.
            self.queue.truncate(previous_len);
            self.queue_bytes = previous_bytes;
        }
        result
    }
}
struct Owner {
    key: String,
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
}
impl Drop for Owner {
    fn drop(&mut self) {
        {
            let mut state = self.shared.state.lock().unwrap();
            state.stopping = true;
            self.shared.wake.notify();
        }
        if let Some(thread) = self.thread.take() {
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

type LiveChange = (Arc<str>, Option<LiveEvent>);

fn live_changes(
    id: Arc<str>, row: Option<(Record, Option<Arc<Value>>)>,
    counts: &mut HashMap<Arc<str>, usize>,
) -> std::io::Result<impl Iterator<Item = LiveChange> + use<>> {
    let previous = counts.remove(&id).unwrap_or(1);
    let mut parent = row.map(|(status, group)| {
        let value = serde_json::from_slice(&status)?;
        Ok::<_, serde_json::Error>(LiveEvent { ts: timestamp(&value), value, group })
    }).transpose()?;
    let segments = parent.as_mut().and_then(|event| take_segments(&mut event.value));
    let next = segments.as_ref().map_or(1, Vec::len);
    if next > 1 {
        counts.insert(Arc::clone(&id), next);
    }
    let split = segments.is_some();
    let mut segments = segments.into_iter().flatten();
    Ok((0..next.max(previous)).map(move |index| {
        let id = segment_id(&id, index);
        let value = if split {
            segments.next().map(|segment| {
                let parent = parent.as_ref().expect("segments have a task status");
                LiveEvent { ts: parent.ts, value: segment_row(&parent.value, &id, segment), group: None }
            })
        } else if index == 0 {
            parent.take()
        } else {
            None
        };
        (id, value)
    }))
}

fn writer(shared: Arc<Shared>, path: PathBuf) {
    let mut store = None;
    let mut deadline = None;
    let mut live_segments = HashMap::new();
    loop {
        let now = utc_us();
        let (rows, live, days, revision, rebuild) = {
            let mut state = shared.state.lock().unwrap();
            let due = deadline.is_some_and(|time| time <= now);
            if state.published == state.revision && !due {
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
            let rebuild = std::mem::take(&mut state.rebuild);
            if rebuild && shared.stateful {
                // Recovery initializes the projection from WAL before work
                // starts. Online mutations already update this same projection
                // synchronously, including processing groups and owner routes.
                // Publish it at this queue boundary; never rescan/retry on traffic.
                state.projection.mark_all();
            }
            let live = state.projection.changed().then(|| state.projection.updates());
            if std::mem::take(&mut state.queue_bytes) >= QUEUE_BYTES {
                shared.drained.notify_all();
            }
            (
                std::mem::take(&mut state.queue),
                live,
                state.retention_days,
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
                if row.timestamp() > cutoff {
                    store.append(&row)?;
                }
            }
            if let Some((live, reset)) = live {
                if reset { live_segments = HashMap::new(); }
                let values = live.into_iter().flat_map(|(id, row)| {
                    let (error, rows) = match live_changes(id, row, &mut live_segments) {
                        Ok(rows) => (None, Some(rows)),
                        Err(error) => (Some(Err(error)), None),
                    };
                    error.into_iter().chain(rows.into_iter().flatten().map(Ok))
                });
                store.update_live(values, reset, cutoff)?;
                crate::collections::trim_map(&mut live_segments);
            }
            deadline = store.expire(cutoff)?.map(|ts| ts.saturating_add(retention));
            Ok(())
        })();
        let records_written = result.is_ok();
        let result = result.and_then(|()| store.as_mut().unwrap().publish());
        // A sharing conflict at publication leaves the written records and
        // pending manifest intact. Retry on the next event or explicit flush.
        let publication_blocked = records_written && result.as_ref().is_err_and(|error| {
            crate::io::atomic_file::sharing_conflict(error)
        });
        let expired = store
            .as_mut()
            .map(|store| std::mem::take(&mut store.expired_live))
            .unwrap_or_default();
        let mut state = shared.state.lock().unwrap();
        if records_written && !expired.is_empty() {
            for id in &expired { live_segments.remove(id); }
            crate::collections::trim_map(&mut live_segments);
            state.projection.expire_live(
                expired,
                now.saturating_sub(i64::from(days).saturating_mul(DAY_US)),
            );
        }
        state.working = false;
        state.error = result.err().map(|error| error.to_string());
        if state.error.is_some() && !publication_blocked {
            deadline = None;
            store = None;
            state.rebuild = true;
            // Try recovery once for this operation. A failed rebuild stays
            // pending until the next operation, never an idle retry loop.
            if !rebuild {
                state.revision += 1;
            }
        }
        state.published = revision;
        shared.drained.notify_all();
    }
}

pub(crate) struct NativeEventLog {
    owner: Arc<Owner>,
}
impl NativeEventLog {
    pub(crate) fn shared(&self) -> &Arc<Shared> {
        &self.owner.shared
    }
    pub(crate) fn new(path: PathBuf, retention_days: u32, stateful: bool) -> std::io::Result<Self> {
        let path = std::path::absolute(path)?;
        let (registry, retired) = owners();
        let mut owners = registry.lock().unwrap();
        let id = key(&path.to_string_lossy());
        while let Some(owner) = owners.get(&id) {
            if let Some(owner) = owner.upgrade() {
                drop(owners);
                owner.shared.configure_retention(retention_days);
                return Ok(Self { owner });
            }
            owners = retired.wait(owners).unwrap();
        }
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                projection: Projection { full_dirty: stateful, ..Projection::default() },
                queue: Vec::new(),
                queue_bytes: 0,
                rebuild: false,
                revision: 1,
                published: 0,
                stopping: false,
                working: false,
                error: None,
                retention_days: retention_days.max(1),
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
            thread: Some(thread),
        });
        owners.insert(id, Arc::downgrade(&owner));
        Ok(Self { owner })
    }
    pub(crate) fn configure_retention(&self, retention_days: u32) {
        self.shared().configure_retention(retention_days);
    }
    pub(crate) fn write(&self, value: Value) -> std::io::Result<()> {
        self.shared().submit(value)
    }
    pub(crate) fn write_failure(&self, value: Value, failure: &crate::pipeline::Failure) -> std::io::Result<()> {
        self.shared().submit_event(value, Some(failure))
    }
    pub(crate) fn recover(&self, watch: &NativeWatchState) {
        watch.with_event_projection(|rows| {
            let shared = self.shared();
            let mut state = shared.state.lock().unwrap();
            state.projection = Projection { full_dirty: true, ..Projection::default() };
            for mut value in rows {
                let _ = state.projection.apply(&mut value);
            }
            shared.schedule(&mut state);
        });
    }
    pub(crate) fn rebuild(&self) {
        let shared = self.shared();
        let mut state = shared.state.lock().unwrap();
        state.rebuild = true;
        shared.schedule(&mut state);
    }
    pub(crate) fn flush(&self) -> std::io::Result<()> {
        let shared = self.shared();
        let mut state = shared.state.lock().unwrap();
        if state.error.is_some() && !state.stopping {
            shared.schedule(&mut state);
        }
        while state.working || state.published != state.revision {
            state = shared.drained.wait(state).unwrap();
        }
        match &state.error {
            Some(e) => Err(std::io::Error::other(e.clone())),
            None => Ok(()),
        }
    }
    pub(crate) fn error(&self) -> Option<String> {
        self.shared().state.lock().unwrap().error.clone()
    }
}

#[cfg(test)]
#[path = "../tests/unit/event_log/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "../tests/unit/event_log/gui_contract.rs"]
pub(crate) mod gui_contract;
