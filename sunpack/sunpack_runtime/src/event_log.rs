//! Best-effort display history. Business state remains in the existing task store.
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

fn state_event(event: &str) -> bool {
    matches!(
        event,
        "pipeline_sources_claimed"
            | "processing_started"
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
    fn expire_live(&mut self, ids: Vec<Arc<str>>, cutoff: i64) {
        for id in ids {
            if let Some(task) = self.tasks.get_mut(id.as_ref()) {
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
            return false;
        }
        let path = field(value, "path");
        if event == "pipeline_sources_released" {
            self.release_owner(field(value, "owner"));
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
                    .is_some_and(|t| !t.blocked && t.owner == field(value, "owner"))
                {
                    self.remove(&id);
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
            let id = self.resolve(value, &key(path));
            if self.tasks.get(&id).is_some_and(|t| t.blocked) {
                self.remove(&id);
            }
            return false;
        }
        let physical = key(path);
        let mut id = self.resolve(value, &physical);
        if event == "task_retired" && field(value, "scope") == "task" {
            self.remove(&id);
            return false;
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
            return false;
        }
        if event == "no_tasks_found" || event == "pipeline_request_coalesced" {
            if self.tasks.get(&id).is_some_and(|t| {
                (field(value, "owner").is_empty() || t.owner == field(value, "owner"))
                    && (t.group.is_none()
                        || (event == "no_tasks_found"
                            && (t.members.len() == 1
                                || value["retire_group"].as_bool().unwrap_or(false))))
            }) {
                self.remove(&id);
            }
            return false;
        }
        if !path.is_empty()
            && matches!(
                event,
                "processing_started"
                    | "failed_password"
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
                return false;
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
                return false;
            }
            let blocked = matches!(event, "failed_password" | "suspended_missing_volume");
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
            task.blocked = blocked;
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
                return true;
            }
            task.status = Some(encode(value));
            self.insert(id, task);
            return false;
        }
        true
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
    queue: Vec<HistoryRecord>,
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
            state.revision += 1;
            self.wake.notify();
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
            let changed = !state.projection.dirty.is_empty() || state.projection.full_dirty;
            state.live_dirty |= changed;
            state.projection.trim();
            if !history && !changed {
                return Ok(());
            }
        }
        let result = if history {
            let ts = timestamp(&value);
            let row = match failure {
                Some(failure) => HistoryRecord::new(&value, ts, &EventField {
                    fields: value.as_object().unwrap(),
                    name: "failure",
                    value: DiagnosticFailure(failure),
                }),
                None => HistoryRecord::new(&value, ts, &value),
            };
            row.map(|row| {
                state.queue_bytes += row.memory_bytes();
                state.queue.push(row);
            })
        } else {
            Ok(())
        };
        state.revision += 1;
        self.wake.notify();
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
fn writer(shared: Arc<Shared>, path: PathBuf) {
    let mut store = None;
    let mut deadline = None;
    loop {
        let now = utc_us();
        let (rows, live, days, revision, rebuild) = {
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
                let values = live.into_iter().map(|(id, row)| {
                    let value = if let Some((status, group)) = row {
                        let value = serde_json::from_slice(&status)?;
                        Some(LiveEvent { ts: timestamp(&value), value, group })
                    } else {
                        None
                    };
                    Ok((id, value))
                });
                store.update_live(values, reset, cutoff)?;
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
            state.live_dirty = true;
            state.reset_live = true;
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
            state.reset_live = true;
            state.projection = Projection::default();
            for mut value in rows {
                let _ = state.projection.apply(&mut value);
            }
            state.live_dirty = true;
            state.revision += 1;
            shared.wake.notify();
        });
    }
    pub(crate) fn rebuild(&self) {
        let shared = self.shared();
        let mut state = shared.state.lock().unwrap();
        state.rebuild = true;
        state.revision += 1;
        shared.wake.notify();
    }
    pub(crate) fn flush(&self) -> std::io::Result<()> {
        let shared = self.shared();
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
