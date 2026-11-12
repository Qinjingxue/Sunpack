use super::windows::ToastLibrary;
use crate::core::i18n::Language;
use crate::failure_report::{append_failure_report, publish_failure_report, FailureRecord};
use crate::pipeline::{
    Cancellation, CleanupStatus, Event, FailureKind, InputErrorKind, Outcome, ResourceWait, TaskId,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};
use std::{fs, io};

const COMPLETION_DEBOUNCE: Duration = Duration::from_millis(800);

pub(super) struct Snapshot {
    batch: String,
    kind: u8,
    title: String,
    body: String,
    progress: Option<f64>,
    label: String,
    status: String,
    value: String,
    action: Option<(u8, String, String)>,
    report_action: Option<(u8, String, String)>,
}

impl Snapshot {
    fn progress(group: &Group) -> Self {
        let language = group.language;
        let totals = &group.totals;
        let completed = totals.done_bytes + totals.written;
        let total = totals.done_bytes + totals.planned;
        let finished = group.summary.completed();
        let count = finished + group.active_roots;
        let disk = totals.disk != 0;
        let memory = totals.memory != 0;
        let progress = (totals.unknown == 0 && total != 0 && !disk && !memory && !group.stopping)
            .then(|| (completed as f64 / total as f64).min(1.0));
        let (title, status) = if group.stopping {
            (
                "interrupt.stopping_title",
                language.text("interrupt.stopping").to_owned(),
            )
        } else if disk || memory {
            let volume_error = if totals.volume_errors == 0 {
                None
            } else {
                group
                    .requests
                    .values()
                    .flat_map(|request| request.tasks.values())
                    .find_map(|task| task.wait.volume_error)
            };
            let status = if let Some(error) = volume_error {
                language.translate(
                    "report.status.disk_unavailable",
                    &[("error", &error.to_string())],
                )
            } else {
                language
                    .text(if disk && memory {
                        "report.status.resources_resume_hint"
                    } else if memory {
                        "toast.progress.memory_paused"
                    } else {
                        "toast.progress.disk_paused"
                    })
                    .to_owned()
            };
            ("toast.progress.paused_title", status)
        } else {
            (
                "toast.progress.title",
                language.translate(
                    "toast.progress.status",
                    &[
                        ("completed", &finished.to_string()),
                        ("total", &count.to_string()),
                    ],
                ),
            )
        };
        let value = if group.stopping {
            String::new()
        } else if total != 0 && totals.unknown == 0 {
            language.translate(
                "toast.progress.value",
                &[
                    (
                        "percent",
                        &(completed.saturating_mul(100) / total).to_string(),
                    ),
                    ("completed_bytes", &format_bytes(completed)),
                    ("total_bytes", &format_bytes(total)),
                ],
            )
        } else if total != 0 {
            language.translate(
                "toast.progress.known_bytes",
                &[
                    ("completed_bytes", &format_bytes(completed)),
                    ("total_bytes", &format_bytes(total)),
                ],
            )
        } else if !disk && !memory {
            language.text("toast.progress.indeterminate").to_owned()
        } else {
            String::new()
        };
        Self {
            batch: group.id.to_string(),
            kind: 1,
            title: language.text(title).to_owned(),
            body: language.translate(
                "toast.progress.body",
                &[
                    ("completed", &finished.to_string()),
                    ("total", &count.to_string()),
                ],
            ),
            progress,
            label: if count == 1 {
                group.requests.values()
                    .find(|request| request.visible)
                    .and_then(|request| request.name.as_ref())
                    .or(group.name.as_ref())
                    .map_or_else(
                        || language.text("toast.progress.one").to_owned(),
                        |(_, name)| name.clone(),
                    )
            } else {
                language.translate("toast.progress.multiple", &[("count", &count.to_string())])
            },
            status,
            value,
            action: Some((
                3,
                language.text("interrupt.stop").to_owned(),
                group.id.to_string(),
            )),
            report_action: None,
        }
    }

    fn completed(group: &Completed, report: Option<PathBuf>) -> Self {
        let language = group.language;
        let summary = &group.summary;
        let succeeded = summary.succeeded;
        let failed = summary.failed;
        let (mut kind, suffix) = match (succeeded, failed) {
            (_, 0) => (2, "success"),
            (0, _) => (3, "failure"),
            _ => (4, "mixed"),
        };
        let seconds = group.elapsed.as_secs();
        let duration = if seconds >= 60 {
            language.translate(
                "duration.minutes_seconds",
                &[
                    ("minutes", &(seconds / 60).to_string()),
                    ("seconds", &(seconds % 60).to_string()),
                ],
            )
        } else {
            language.translate("duration.seconds", &[("seconds", &seconds.to_string())])
        };
        let mut title = language
            .text(&format!("toast.final.{suffix}.title"))
            .to_owned();
        let mut body = language.translate(
            &format!("toast.final.{suffix}.body"),
            &[
                ("succeeded", &succeeded.to_string()),
                ("failed", &failed.to_string()),
                ("duration", &duration),
            ],
        );
        if summary.interrupted != 0 {
            let interrupted = language.text(if summary.rollback_failed {
                "interrupt.cleanup_failed"
            } else {
                "interrupt.cleaned"
            });
            if succeeded == 0 && failed == 0 {
                title = language.text("interrupt.finished").to_owned();
                body = interrupted.to_owned();
                kind = if summary.rollback_failed { 3 } else { 2 };
            } else {
                body.push('\n');
                body.push_str(interrupted);
            }
        }
        if summary.cleanup_failed != 0 {
            body.push('\n');
            body.push_str(&language.translate(
                "toast.final.cleanup_warning",
                &[("count", &summary.cleanup_failed.to_string())],
            ));
        }
        if kind == 2 && (summary.rollback_failed || summary.cleanup_failed != 0) {
            kind = if succeeded == 0 { 3 } else { 4 };
        }
        let action = summary.output.as_ref().map(|path| {
            (
                1,
                language.text("toast.action.open_output").to_owned(),
                path.to_string_lossy().into_owned(),
            )
        });
        let report_action = report.map(|path| {
            (
                2,
                language.text("toast.action.open_failure_log").to_owned(),
                path.to_string_lossy().into_owned(),
            )
        });
        Self {
            batch: group.id.to_string(),
            kind,
            title,
            body,
            progress: None,
            label: String::new(),
            status: String::new(),
            value: String::new(),
            action,
            report_action,
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mode = if self.kind != 1 {
            0
        } else if self.progress.is_some() {
            1
        } else {
            2
        };
        let mut result = Vec::new();
        let action_count = u8::from(self.action.is_some()) + u8::from(self.report_action.is_some());
        result.extend([self.kind, mode, action_count, 0]);
        result.extend(self.progress.unwrap_or_default().to_le_bytes());
        for field in [
            &self.batch,
            &self.title,
            &self.body,
            &self.label,
            &self.status,
            &self.value,
        ] {
            push_text(&mut result, field);
        }
        for (kind, label, target) in self.action.iter().chain(&self.report_action) {
            result.push(*kind);
            push_text(&mut result, label);
            push_text(&mut result, target);
        }
        result
    }
}

fn format_bytes(bytes: u128) -> String {
    let mut divisor = 1;
    let mut unit = "B";
    for candidate in ["KiB", "MiB", "GiB", "TiB", "PiB", "EiB"] {
        if bytes / divisor < 1024 {
            break;
        }
        divisor *= 1024;
        unit = candidate;
    }
    if divisor == 1 {
        format!("{bytes} {unit}")
    } else {
        format!("{:.1} {unit}", bytes as f64 / divisor as f64)
    }
}

fn push_text(output: &mut Vec<u8>, value: &str) {
    let mut end = value.len().min(8192);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    output.extend((end as u32).to_le_bytes());
    output.extend(&value.as_bytes()[..end]);
}

#[derive(Default)]
struct State {
    groups: VecDeque<Group>,
    completed: VecDeque<Completed>,
    dirty: bool,
    stopping: bool,
    clear: bool,
}

struct Group {
    id: Arc<str>,
    name: Option<(TaskId, String)>,
    language: Language,
    began: Instant,
    visible: bool,
    stopping: bool,
    requests: HashMap<Arc<str>, RequestProgress>,
    active_roots: usize,
    finalize_at: Option<Instant>,
    finalizing: bool,
    generation: u64,
    totals: Totals,
    summary: Summary,
    report: Arc<Mutex<ReportDraft>>,
}

#[derive(Clone, Default)]
struct Summary {
    succeeded: usize,
    failed: usize,
    interrupted: usize,
    rollback_failed: bool,
    report_failed: bool,
    cleanup_failed: usize,
    output: Option<PathBuf>,
}

struct Completed {
    generation: u64,
    id: Arc<str>,
    language: Language,
    elapsed: Duration,
    summary: Summary,
    report: Arc<Mutex<ReportDraft>>,
}

#[derive(Default)]
struct RequestProgress {
    tasks: HashMap<TaskId, TaskProgress>,
    paths: HashMap<TaskId, PathBuf>,
    started: HashSet<PathBuf>,
    roots: HashMap<TaskId, PathBuf>,
    task_roots: HashMap<TaskId, TaskId>,
    visible_roots: HashSet<TaskId>,
    settled: HashSet<String>,
    settled_tasks: HashSet<TaskId>,
    pending_reports: HashSet<TaskId>,
    name: Option<(TaskId, String)>,
    visible: bool,
    done_bytes: u128,
    root_done_bytes: HashMap<TaskId, u128>,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct TaskProgress {
    visible: bool,
    written: u64,
    planned: u64,
    wait: ResourceWait,
}

#[derive(Default)]
struct Totals {
    unknown: usize,
    disk: usize,
    memory: usize,
    volume_errors: usize,
    written: u128,
    planned: u128,
    done_bytes: u128,
}

impl Totals {
    fn add(&mut self, task: TaskProgress) {
        if !task.visible {
            return;
        }
        self.unknown += usize::from(task.planned == 0);
        self.disk += usize::from(task.wait.disk);
        self.memory += usize::from(task.wait.memory);
        self.volume_errors += usize::from(task.wait.volume_error.is_some());
        self.planned += u128::from(task.planned);
        self.written += u128::from(task.written.min(task.planned));
    }

    fn remove(&mut self, task: TaskProgress, finished: bool) {
        if !task.visible {
            return;
        }
        self.unknown -= usize::from(task.planned == 0);
        self.disk -= usize::from(task.wait.disk);
        self.memory -= usize::from(task.wait.memory);
        self.volume_errors -= usize::from(task.wait.volume_error.is_some());
        self.planned -= u128::from(task.planned);
        self.written -= u128::from(task.written.min(task.planned));
        if finished {
            self.done_bytes += u128::from(task.planned);
        }
    }
}

impl Group {
    fn new(request: &str, language: Language) -> Self {
        // Reserve the upper token space for UI activations. A fresh suffix
        // also distinguishes batches seeded by the same still-invisible scan,
        // so an old draft can never share the next batch's spool filename.
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let prefix = u64::from_str_radix(&request[..request.len().min(16)], 16)
            .expect("hex request ID");
        debug_assert!(prefix < (1u64 << 63));
        Self {
            id: Arc::from(format!("{:016x}{:016x}", prefix | (1u64 << 63),
                NEXT.fetch_add(1, Ordering::Relaxed))),
            language,
            name: None,
            began: Instant::now(),
            visible: false,
            stopping: false,
            requests: HashMap::new(),
            active_roots: 0,
            finalize_at: None,
            finalizing: false,
            generation: 0,
            totals: Totals::default(),
            summary: Summary::default(),
            report: Arc::default(),
        }
    }

    fn event(&mut self, request: &str, event: Event) -> bool {
        let Some(request) = self.requests.get_mut(request) else {
            return false;
        };
        let tasks = &mut request.tasks;
        let id = match event {
            Event::Queued { id, parent, segment, path, .. } => {
                if segment.is_some() {
                    if let Some(parent) = parent { request.paths.remove(&parent); }
                    if let Some(task) = parent.and_then(|parent| tasks.remove(&parent)) {
                        self.totals.remove(task, false);
                    }
                }
                let root = parent.and_then(|parent| request.task_roots.get(&parent).copied())
                    .unwrap_or(id);
                request.task_roots.insert(id, root);
                if parent.is_none() { request.roots.insert(id, path.clone()); }
                if parent.is_none() && request.name.is_none() {
                    let name = path.file_name().unwrap_or(path.as_os_str())
                        .to_string_lossy().into_owned();
                    request.name = Some((id, name));
                }
                request.paths.insert(id, path);
                tasks.entry(id).or_default();
                return request.visible;
            }
            Event::Finished { id, .. } | Event::Skipped { id } => {
                request.paths.remove(&id);
                if let Some(task) = tasks.remove(&id) {
                    let finished = matches!(event, Event::Finished { .. });
                    self.totals.remove(task, finished);
                    if finished && task.visible {
                        request.done_bytes += u128::from(task.planned);
                        *request.root_done_bytes.entry(request.task_roots[&id]).or_default() += u128::from(task.planned);
                    }
                    if tasks.capacity() > 256 {
                        crate::collections::trim_map(tasks);
                    }
                    return request.visible;
                }
                return false;
            }
            Event::Working { id }
            | Event::Finalizing { id }
            | Event::Progress { id, .. }
            | Event::ResourceWait { id, .. } => id,
            _ => return false,
        };
        let Some(task) = tasks.get_mut(&id) else {
            return false;
        };
        let before = *task;
        match event {
            Event::Working { .. } => {
                *task = TaskProgress { visible: true, ..TaskProgress::default() };
            }
            Event::Progress { completed_bytes, total_bytes, .. } => {
                task.visible = true;
                task.written = completed_bytes;
                task.planned = total_bytes;
            }
            Event::ResourceWait { state, .. } => {
                task.visible |= state.disk || state.memory;
                task.wait = state;
            }
            Event::Finalizing { .. } => task.wait = ResourceWait::default(),
            _ => unreachable!(),
        }
        if task.visible && !before.visible {
            if let Some(path) = request.paths.get(&id) {
                request.started.insert(path.clone());
            }
        }
        if task.visible && request.visible_roots.insert(request.task_roots[&id]) {
            if !request.visible {
                if let Some(path) = request.roots.get(&request.task_roots[&id]) {
                    let name = path.file_name().unwrap_or(path.as_os_str())
                        .to_string_lossy().into_owned();
                    request.name = Some((request.task_roots[&id], name));
                }
                request.visible = true;
            }
            self.active_roots += 1;
            self.generation = self.generation.wrapping_add(1);
            self.finalize_at = None;
            if !self.visible {
                self.began = Instant::now();
                self.visible = true;
            }
            if self.summary.completed() == 0 {
                self.name = request.name.clone();
            }
        }
        if before != *task {
            self.totals.remove(before, false);
            self.totals.add(*task);
            true
        } else {
            false
        }
    }

    fn finish(&mut self, request: &str, summary: Summary) -> bool {
        let Some(request) = self.requests.remove(request) else {
            return false;
        };
        let accepted = summary.completed() != 0;
        for task in request.tasks.into_values() {
            self.totals.remove(task, accepted);
        }
        if !accepted {
            self.totals.done_bytes -= request.done_bytes;
        }
        self.active_roots -= request.visible_roots.difference(&request.settled_tasks).count();
        if self.requests.capacity() > 256 {
            crate::collections::trim_map(&mut self.requests);
        }
        if accepted {
            if !self.visible {
                self.began = Instant::now();
                self.visible = true;
                self.name = request.name;
            }
            self.finalize_at = None;
            self.summary.merge(summary);
            self.generation = self.generation.wrapping_add(1);
        }
        true
    }

    fn pending(&self) -> bool {
        self.active_roots != 0 || self.requests.values().any(|request| !request.pending_reports.is_empty())
            || (self.stopping && !self.requests.is_empty())
    }
}

impl State {
    fn retire_front(&mut self) {
        let mut group = self.groups.pop_front().unwrap();
        if !group.requests.is_empty() {
            // Invisible scans neither postpone completion nor lose their
            // activity when the completed batch is retired.
            if self.groups.is_empty() {
                let request = group.requests.keys().next().unwrap();
                self.groups.push_back(Group::new(request, group.language));
            }
            for request in group.requests.values_mut() {
                if request.visible_roots.iter().all(|id| request.settled_tasks.contains(id)) {
                    request.visible = false;
                    request.name = None;
                }
            }
            self.groups.front_mut().unwrap().requests.extend(group.requests);
        }
        self.dirty = true;
    }

    fn settle(&mut self, now: Instant) -> bool {
        let mut changed = false;
        while let Some(group) = self.groups.front_mut() {
            if group.pending() || group.finalizing {
                break;
            }
            if group.summary.completed() != 0 {
                let deadline = *group.finalize_at.get_or_insert(now + COMPLETION_DEBOUNCE);
                if now < deadline {
                    break;
                }
                group.finalizing = true;
                group.finalize_at = None;
                self.completed.push_back(Completed {
                    generation: group.generation,
                    id: Arc::clone(&group.id),
                    language: group.language,
                    elapsed: now.saturating_duration_since(group.began),
                    summary: group.summary.clone(),
                    report: Arc::clone(&group.report),
                });
                changed = true;
                break;
            }
            if !group.visible && !group.requests.is_empty() {
                break;
            }
            self.clear |= group.visible;
            self.retire_front();
            changed = true;
        }
        changed
    }
}

impl Summary {
    fn completed(&self) -> usize {
        self.succeeded + self.failed + self.interrupted
    }

    fn for_result(
        result: &io::Result<Outcome>,
        cancelled: bool,
        output_cleanup_failed: bool,
        visible: bool,
        owner: &impl Fn(&Path) -> Option<String>,
        started: Option<&HashSet<String>>,
    ) -> Self {
        if cancelled {
            return Self {
                interrupted: started.map_or(1, HashSet::len),
                rollback_failed: output_cleanup_failed,
                ..Self::default()
            };
        }
        if !visible {
            return Self::default();
        }
        let mut summary = Self::default();
        match result {
            Ok(outcome) => return Self::for_outcome(outcome, output_cleanup_failed, visible, owner, started),
            Err(_) => summary.failed = started.map_or(1, HashSet::len),
        }
        summary.cleanup_failed += usize::from(output_cleanup_failed);
        summary
    }

    fn for_outcome(
        outcome: &Outcome,
        output_cleanup_failed: bool,
        visible: bool,
        owner: &impl Fn(&Path) -> Option<String>,
        started: Option<&HashSet<String>>,
    ) -> Self {
        if !visible { return Self::default(); }
        let mut summary = Self::default();

        let roots = completion_roots(outcome, owner);
        for (root, completion) in &roots {
            if started.is_some_and(|started| !started.contains(root)) {
                continue;
            }
            if completion.terminal {
                summary.failed += 1;
            } else if !completion.retry && completion.accepted {
                summary.succeeded += 1;
            }
        }
        if summary.succeeded != 0 {
            let mut outputs = outcome.archives.iter().filter(|archive| {
                let root = archive_owner(archive, owner);
                roots.get(&root).is_some_and(|completion| completion.accepted
                    && !completion.terminal && !completion.retry)
                    && started.is_none_or(|started| started.contains(&root))
            }).filter_map(|archive| archive.output.as_deref());
            summary.output = crate::pipeline::common_ancestor(outputs.clone())
                .or_else(|| outputs.next().map(Path::to_owned));
        }
        summary.cleanup_failed = outcome.cleanup_results.iter()
            .filter(|result| result.status == CleanupStatus::Failed
                && started.is_none_or(|started| started.contains(&result_owner(&result.path, owner)))).count();
        summary.cleanup_failed += usize::from(output_cleanup_failed);
        summary
    }

    fn merge(&mut self, other: Self) {
        self.succeeded += other.succeeded;
        self.failed += other.failed;
        self.interrupted += other.interrupted;
        self.rollback_failed |= other.rollback_failed;
        self.report_failed |= other.report_failed;
        self.cleanup_failed += other.cleanup_failed;
        if let Some(output) = other.output {
            self.output = match self.output.take() {
                Some(previous) => {
                    crate::pipeline::common_ancestor([previous.as_path(), output.as_path()])
                        .or(Some(previous))
                }
                None => Some(output),
            };
        }
    }
}

// A native batch can contain many independent top-level tasks. Keep carrier
// retry evidence physical-input scoped, then project each input to its owner.
#[derive(Default)]
struct RootCompletion {
    accepted: bool,
    terminal: bool,
    retry: bool,
}

fn result_owner(path: &Path, owner: &impl Fn(&Path) -> Option<String>) -> String {
    owner(path).unwrap_or_else(|| crate::path_keys::path_key(&path.to_string_lossy()))
}

fn archive_owner(
    archive: &crate::pipeline::ArchiveResult,
    owner: &impl Fn(&Path) -> Option<String>,
) -> String {
    result_owner(archive.promotion_original_path.as_deref().unwrap_or(&archive.path), owner)
}

fn completion_roots(
    outcome: &Outcome,
    owner: &impl Fn(&Path) -> Option<String>,
) -> HashMap<String, RootCompletion> {
    let failures = outcome.input_failures();
    let mut roots: HashMap<String, RootCompletion> = HashMap::new();
    for archive in &outcome.archives {
        let root = roots.entry(archive_owner(archive, owner)).or_default();
        root.accepted |= archive.failure.is_none() || archive.partial;
        if let Some(input) = failures.get(&crate::path_keys::path_key(&archive.path.to_string_lossy())) {
            root.retry |= input.retryable();
            root.terminal |= input.failed && !input.retryable();
        }
    }
    for error in outcome.errors.iter().filter(|error| error.kind == InputErrorKind::InvalidInput) {
        roots.entry(result_owner(&error.path, owner)).or_default().terminal = true;
    }
    roots
}

#[derive(Default)]
struct Shared {
    state: Mutex<State>,
    changed: Condvar,
}

impl Shared {
    fn present(&self, show: impl FnOnce()) -> bool {
        let state = self.state.lock().unwrap();
        if state.stopping {
            return false;
        }
        show();
        true
    }

    fn present_completed(&self, completed: &Completed, show: impl FnOnce()) -> bool {
        let mut state = self.state.lock().unwrap();
        if state.stopping {
            return false;
        }
        let Some(group) = state.groups.front_mut()
            .filter(|group| group.id == completed.id && group.finalizing)
        else {
            return false;
        };
        group.finalizing = false;
        if group.generation != completed.generation || group.pending() {
            // New visible work owns the same batch and report draft. Discard
            // the stale published copy, then debounce again when it drains.
            state.settle(Instant::now());
            return false;
        }
        show();
        state.retire_front();
        state.settle(Instant::now());
        true
    }
}

#[derive(Clone)]
struct Publisher {
    shared: Arc<Shared>,
    reports: Arc<Reports>,
}

#[derive(Clone)]
pub(super) struct Activity {
    publisher: Publisher,
    request: Arc<str>,
}

impl Publisher {
    fn register(&self, request: Arc<str>, language: Language) -> Activity {
        let mut state = self.shared.state.lock().unwrap();
        if state.settle(Instant::now()) {
            self.shared.changed.notify_one();
        }
        if state.groups.back().is_none_or(|group| group.stopping) {
            state.groups.push_back(Group::new(&request, language));
        }
        let group = state.groups.back_mut().unwrap();
        group.requests.insert(Arc::clone(&request), RequestProgress::default());
        Activity { publisher: self.clone(), request }
    }

    fn stop_group(&self, id: &str) -> Vec<Arc<str>> {
        let mut state = self.shared.state.lock().unwrap();
        let Some(group) = state
            .groups
            .front_mut()
            .filter(|group| group.id.as_ref() == id && group.visible
                && !group.stopping && !group.requests.is_empty())
        else {
            return Vec::new();
        };
        group.stopping = true;
        group.generation = group.generation.wrapping_add(1);
        group.finalize_at = None;
        let requests = group.requests.keys().cloned().collect();
        self.mark_dirty(&mut state);
        requests
    }

    fn mark_dirty(&self, state: &mut State) {
        if !std::mem::replace(&mut state.dirty, true) {
            self.shared.changed.notify_one();
        }
    }
}

impl Activity {
    pub(super) fn event(&self, event: Event) {
        let mut state = self.publisher.shared.state.lock().unwrap();
        if state.stopping {
            return;
        }
        if state.settle(Instant::now()) {
            self.publisher.shared.changed.notify_one();
        }
        if let Some((index, group)) = state
            .groups
            .iter_mut()
            .enumerate()
            .find(|(_, group)| group.requests.contains_key(&self.request))
        {
            if group.event(&self.request, event) && group.visible && index == 0 {
                self.publisher.mark_dirty(&mut state);
            }
        }
    }

    pub(super) fn record_root(&self, id: TaskId, path: &Path, outcome: &Outcome) {
        let (group_id, language, report) = {
            let state = self.publisher.shared.state.lock().unwrap();
            if state.stopping { return; }
            let Some(group) = state.groups.iter().find(|group| group.requests.contains_key(&self.request))
                else { return; };
            if !group.requests[&self.request].visible_roots.contains(&id) { return; }
            (Arc::clone(&group.id), group.language, Arc::clone(&group.report))
        };
        let key = crate::path_keys::path_key(&path.to_string_lossy());
        if let Err(error) = self.publisher.reports.append_data(&group_id, language, &report,
            path, Ok(outcome), &|_| Some(key.clone()), None)
        {
            if !self.publisher.reports.cancellation.cancelled() {
                eprintln!("SunPack toast failure report: {error}");
            }
        }
    }

    pub(super) fn root_finished(&self, id: TaskId, outcome: &Outcome) {
        let mut state = self.publisher.shared.state.lock().unwrap();
        if state.stopping { return; }
        let Some(group) = state.groups.iter_mut()
            .find(|group| group.requests.contains_key(&self.request)) else { return; };
        let request = group.requests.get_mut(&self.request).unwrap();
        let Some(path) = request.roots.get(&id) else { return; };
        let key = crate::path_keys::path_key(&path.to_string_lossy());
        if !request.settled.insert(key.clone()) { return; }
        request.done_bytes -= request.root_done_bytes.remove(&id).unwrap_or(0);
        let visible = request.visible_roots.contains(&id);
        request.settled_tasks.insert(id);
        if visible { group.active_roots -= 1; }
        let summary = Summary::for_outcome(outcome, false, visible, &|_| Some(key.clone()), None);
        if summary.failed != 0 || summary.cleanup_failed != 0 { request.pending_reports.insert(id); }
        group.summary.merge(summary);
        group.generation = group.generation.wrapping_add(1);
        state.dirty = true;
        self.publisher.shared.changed.notify_one();
    }

    pub(super) fn report_finished(&self, id: TaskId, failed: bool) {
        let mut state = self.publisher.shared.state.lock().unwrap();
        if state.stopping { return; }
        if let Some(group) = state.groups.iter_mut()
            .find(|group| group.requests.contains_key(&self.request))
        {
            if group.requests.get_mut(&self.request).unwrap().pending_reports.remove(&id) {
                group.summary.report_failed |= failed;
            }
        }
        state.settle(Instant::now());
        state.dirty = true;
        self.publisher.shared.changed.notify_one();
    }

    pub(super) fn finish(
        &self,
        result: &io::Result<Outcome>,
        cancelled: bool,
        output_cleanup_failed: bool,
        owner: impl Fn(&Path) -> Option<String>,
    ) {
        let (visible, started, settled) = {
            let state = self.publisher.shared.state.lock().unwrap();
            if state.stopping {
                return;
            }
            let Some(request) = state.groups.iter()
                .find_map(|group| group.requests.get(&self.request))
            else {
                return;
            };
            (request.visible, if cancelled { request.roots.values().cloned().collect() } else { request.started.clone() }, request.settled.clone())
        };
        // Receipt projection can be large. It must not hold the presentation
        // gate or prevent disable from cancelling an active report writer.
        let started = started.iter().map(|path| result_owner(path, &owner))
            .filter(|root| !settled.contains(root)).collect();
        let summary = Summary::for_result(result, cancelled, output_cleanup_failed, visible,
            &owner, Some(&started));
        let mut state = self.publisher.shared.state.lock().unwrap();
        if state.stopping {
            return;
        }
        let Some(group) = state.groups.iter_mut()
            .find(|group| group.requests.contains_key(&self.request))
        else {
            return;
        };
        group.finish(&self.request, summary);
        state.settle(Instant::now());
        state.dirty = true;
        self.publisher.shared.changed.notify_one();
    }

    pub(super) fn record(
        &self,
        path: &Path,
        result: &io::Result<Outcome>,
        ignore_request_error: bool,
        owner: impl Fn(&Path) -> Option<String>,
    ) {
        self.record_data(path, result.as_ref(), ignore_request_error, owner);
    }

    pub(super) fn record_data(
        &self, path: &Path, result: Result<&Outcome, &io::Error>, ignore_request_error: bool,
        owner: impl Fn(&Path) -> Option<String>,
    ) {
        let (id, language, report, started, settled) = {
            let state = self.publisher.shared.state.lock().unwrap();
            if state.stopping || ignore_request_error {
                return;
            }
            let Some(group) = state.groups.iter()
                .find(|group| group.requests.contains_key(&self.request))
            else {
                return;
            };
            if !group.requests[&self.request].visible {
                return;
            }
            (Arc::clone(&group.id), group.language, Arc::clone(&group.report),
                group.requests[&self.request].started.clone(), group.requests[&self.request].settled.clone())
        };
        let started = started.iter().map(|path| result_owner(path, &owner))
            .filter(|root| result.is_ok() || !settled.contains(root)).collect::<HashSet<_>>();
        if result.is_err() && !started.contains(&result_owner(path, &owner)) { return; }
        if let Err(error) = self.publisher.reports.append_data(&id, language, &report, path, result,
            &owner, Some(&started)) {
            if !self.publisher.reports.cancellation.cancelled() {
                eprintln!("SunPack toast failure report: {error}");
            }
        }
    }

}

struct Reports {
    cancellation: Cancellation,
    directory: PathBuf,
    retention: AtomicU64,
}

#[derive(Default)]
struct ReportDraft {
    poisoned: bool,
    path: Option<PathBuf>,
    failures: usize,
}

impl Drop for ReportDraft {
    fn drop(&mut self) {
        if let Some(path) = &self.path {
            let _ = fs::remove_file(path);
        }
    }
}

struct FailureSpool<'a> {
    path: &'a Path,
    language: Language,
    cancellation: &'a Cancellation,
    error_prefix: String,
    details_prefix: String,
    failures: usize,
}

impl FailureSpool<'_> {
    fn append(
        &mut self,
        path: &Path,
        error: &String,
        details: &impl serde::Serialize,
    ) -> io::Result<()> {
        let index = self.failures + 1;
        let header = self.language.translate(
            "toast.report.failure",
            &[
                ("index", &index.to_string()),
                ("path", &path.to_string_lossy()),
            ],
        );
        append_failure_report(
            self.path,
            &FailureRecord {
                header: &header,
                error_prefix: &self.error_prefix,
                errors: std::slice::from_ref(error),
                unknown_error: self.language.text("toast.report.unknown_error"),
                details_prefix: &self.details_prefix,
                details: Some(details),
            },
            self.cancellation,
        )?;
        self.failures = index;
        Ok(())
    }
}

impl Reports {
    fn append(
        &self,
        id: &str,
        language: Language,
        report: &Mutex<ReportDraft>,
        path: &Path,
        result: &io::Result<Outcome>,
        owner: &impl Fn(&Path) -> Option<String>,
        started: Option<&HashSet<String>>,
    ) -> io::Result<()> {
        self.append_data(id, language, report, path, result.as_ref(), owner, started)
    }

    fn append_data(
        &self, id: &str, language: Language, report: &Mutex<ReportDraft>, path: &Path,
        result: Result<&Outcome, &io::Error>, owner: &impl Fn(&Path) -> Option<String>,
        started: Option<&HashSet<String>>,
    ) -> io::Result<()> {
        self.cancellation.check_io()?;
        let inputs = result.ok().map(Outcome::input_failures);
        let roots = result.ok().map(|outcome| completion_roots(outcome, owner));
        let terminal = |root: &str| started.is_none_or(|started| started.contains(root))
            && roots.as_ref().is_some_and(|roots| roots.get(root).is_some_and(|root| root.terminal));
        let cleanup = result.ok().is_some_and(|outcome| outcome.cleanup_results.iter().any(|cleanup|
            cleanup.status == CleanupStatus::Failed
                && started.is_none_or(|started| started.contains(&result_owner(&cleanup.path, owner)))));
        if !cleanup && roots.as_ref().is_some_and(|roots| !roots.keys().any(|root| terminal(root))) {
            return Ok(());
        }
        let mut draft = report.lock().unwrap();
        if draft.poisoned {
            return Ok(());
        }
        let failures = draft.failures;
        let details = draft
            .path
            .get_or_insert_with(|| self.directory.join(format!("batch-{id}.tmp")));
        let mut spool = FailureSpool {
            path: details,
            language,
            cancellation: &self.cancellation,
            error_prefix: language.translate("toast.report.error", &[("error", "")]),
            details_prefix: language.translate("toast.report.details", &[("details", "")]),
            failures,
        };
        let written = (|| {
            match result {
                Ok(outcome) => {
                    for archive in &outcome.archives {
                        let Some(failure) = archive.failure.as_ref()
                            .filter(|failure| failure.kind != FailureKind::Cancelled)
                        else {
                            continue;
                        };
                        let key = crate::path_keys::path_key(&archive.path.to_string_lossy());
                        if terminal(&archive_owner(archive, owner))
                            && inputs.as_ref().unwrap().get(&key)
                            .is_some_and(|input| input.failed && !input.retryable())
                        {
                            spool.append(&archive.path, &failure.message, failure)?;
                        }
                    }
                    for error in outcome
                        .errors
                        .iter()
                        .filter(|error| error.kind == InputErrorKind::InvalidInput
                            && terminal(&result_owner(&error.path, owner)))
                    {
                        spool.append(&error.path, &error.message, error)?;
                    }
                    for cleanup in outcome
                        .cleanup_results
                        .iter()
                        .filter(|cleanup| cleanup.status == CleanupStatus::Failed
                            && started.is_none_or(|started| started.contains(&result_owner(&cleanup.path, owner))))
                    {
                        spool.append(&cleanup.path, &cleanup.message, cleanup)?;
                    }
                }
                Err(error) => spool.append(path, &error.to_string(), &None::<String>)?,
            }
            Ok(())
        })();
        draft.failures = spool.failures;
        draft.poisoned |= written.is_err();
        written
    }

    fn publish(&self, completed: &Completed, shared: &Shared) -> io::Result<Option<PathBuf>> {
        if completed.summary.report_failed { return Ok(None); }
        let draft = completed.report.lock().unwrap();
        self.cancellation.check_io()?;
        if draft.poisoned || draft.failures == 0 {
            return Ok(None);
        }
        let now = SystemTime::now();
        let seconds = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let output = self
            .directory
            .join(format!("failed-{seconds:020}-{}.txt", completed.id));
        let language = completed.language;
        let title = language.text("toast.report.title");
        let timestamp = report_time();
        let generated = language.translate("toast.report.generated", &[("timestamp", &timestamp)]);
        let summary = language.translate(
            "toast.report.summary",
            &[("failed", &(completed.summary.failed
                + usize::from(completed.summary.rollback_failed)).to_string())],
        );
        publish_failure_report(
            draft.path.as_deref(),
            &output.with_extension("tmp"),
            &output,
            [title, "\n", &generated, "\n", &summary, "\n\n"],
            &self.cancellation,
        )?;
        drop(draft);
        self.trim(now, shared);
        Ok(Some(output))
    }

    fn trim(&self, now: SystemTime, shared: &Shared) {
        let age = Duration::from_secs(
            self.retention
                .load(Ordering::Relaxed)
                .max(1)
                .saturating_mul(86_400),
        );
        let Ok(entries) = fs::read_dir(&self.directory) else {
            return;
        };
        for entry in entries.flatten() {
            if self.cancellation.cancelled() {
                break;
            }
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !(name.starts_with("failed-") && (name.ends_with(".txt") || name.ends_with(".tmp"))
                || name.starts_with("batch-") && name.ends_with(".tmp"))
            {
                continue;
            }
            if entry
                .metadata()
                .ok()
                .filter(|metadata| metadata.is_file())
                .and_then(|metadata| metadata.modified().ok())
                .and_then(|modified| now.duration_since(modified).ok())
                .is_some_and(|elapsed| elapsed > age)
            {
                if let Some(id) = name
                    .strip_prefix("batch-")
                    .and_then(|name| name.strip_suffix(".tmp"))
                {
                    let state = shared.state.lock().unwrap();
                    if state.groups.iter().any(|group| group.id.as_ref() == id)
                        || state.completed.iter().any(|group| group.id.as_ref() == id)
                    {
                        continue;
                    }
                }
                let _ = fs::remove_file(entry.path());
            }
        }
    }
}

fn report_time() -> String {
    use windows_sys::Win32::Foundation::SYSTEMTIME;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetSystemTime(time: *mut SYSTEMTIME);
    }
    let mut time = SYSTEMTIME::default();
    unsafe {
        GetSystemTime(&mut time);
    }
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond
    )
}

pub(super) struct Toast {
    publisher: Publisher,
    thread: Option<JoinHandle<()>>,
}

impl Toast {
    pub(super) fn start(cwd: &Path, diagnostic: PathBuf, retention: u64) -> io::Result<Self> {
        let cwd = cwd.to_owned();
        let reports = Arc::new(Reports {
            cancellation: Cancellation::new(),
            directory: diagnostic
                .parent()
                .unwrap_or_else(|| Path::new(""))
                .join("failures"),
            retention: AtomicU64::new(retention),
        });
        let shared = Arc::new(Shared::default());
        let presenter_shared = Arc::clone(&shared);
        let presenter_reports = Arc::clone(&reports);
        let (send, receive) = mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name("sunpack-toast".into())
            .stack_size(512 * 1024)
            .spawn(move || {
                let library = match ToastLibrary::load(&cwd) {
                    Ok(library) => library,
                    Err(error) => {
                        let _ = send.send(Err(error));
                        return;
                    }
                };
                let presenter = match library.presenter(&diagnostic) {
                    Ok(presenter) => presenter,
                    Err(error) => {
                        let _ = send.send(Err(error));
                        return;
                    }
                };
                let _ = send.send(Ok(()));
                let mut sequence = 0u64;
                let mut last_update: Option<Instant> = None;
                let minimum_interval = Duration::from_millis(50);
                'presenter: loop {
                    let mut state = presenter_shared.state.lock().unwrap();
                    let display = loop {
                        if state.stopping {
                            break 'presenter;
                        }
                        state.settle(Instant::now());
                        if std::mem::take(&mut state.clear) {
                            break Display::Clear;
                        }
                        if let Some(completed) = state.completed.pop_front() {
                            if state.completed.capacity() > 256 {
                                crate::collections::trim_deque(&mut state.completed);
                            }
                            break Display::Completed(completed);
                        }
                        if state.dirty {
                            let group = state.groups.front().filter(|group| group.visible);
                            if group.is_none() {
                                state.dirty = false;
                                continue;
                            }
                            let remaining = last_update.map_or(Duration::ZERO, |last| {
                                minimum_interval.saturating_sub(last.elapsed())
                            });
                            if remaining.is_zero() {
                                let snapshot = Snapshot::progress(group.unwrap());
                                state.dirty = false;
                                break Display::Progress(snapshot);
                            }
                            let remaining = state.groups.front()
                                .and_then(|group| group.finalize_at)
                                .map_or(remaining, |deadline| remaining.min(
                                    deadline.saturating_duration_since(Instant::now())));
                            state = presenter_shared
                                .changed
                                .wait_timeout(state, remaining)
                                .unwrap()
                                .0;
                        } else if let Some(deadline) = state.groups.front()
                            .and_then(|group| group.finalize_at)
                        {
                            let remaining = deadline.saturating_duration_since(Instant::now());
                            state = presenter_shared.changed.wait_timeout(state, remaining).unwrap().0;
                        } else {
                            state = presenter_shared.changed.wait(state).unwrap();
                        }
                    };
                    if matches!(display, Display::Clear) {
                        let _ = presenter.clear();
                        continue;
                    }
                    drop(state);
                    let mut published_report = None;
                    let mut completion = None;
                    let snapshot = match display {
                        Display::Clear => unreachable!(),
                        Display::Progress(snapshot) => snapshot,
                        Display::Completed(completed) => {
                            let report =
                                match presenter_reports.publish(&completed, &presenter_shared) {
                                    Ok(report) => report,
                                    Err(error) => {
                                        if !presenter_reports.cancellation.cancelled() {
                                            eprintln!("SunPack toast failure report: {error}");
                                        }
                                        None
                                    }
                                };
                            published_report = report.clone();
                            let snapshot = Snapshot::completed(&completed, report);
                            completion = Some(completed);
                            snapshot
                        }
                    };
                    let payload = snapshot.encode();
                    // Stop and native publication share this short gate. Report
                    // IO never holds it, so disable cannot wait on the writer.
                    let show = || {
                        sequence = sequence.wrapping_add(1);
                        let _ = presenter.show(&payload, sequence);
                    };
                    let shown = match completion.as_ref() {
                        Some(completed) => presenter_shared.present_completed(completed, show),
                        None => presenter_shared.present(show),
                    };
                    if !shown {
                        if let Some(path) = published_report {
                            let _ = fs::remove_file(path);
                        }
                        continue;
                    }
                    last_update = Some(Instant::now());
                }
                let drafts = {
                    let mut state = presenter_shared.state.lock().unwrap();
                    (std::mem::take(&mut state.groups), std::mem::take(&mut state.completed))
                };
                // The presenter thread owns filesystem cleanup, even while
                // disabled activities are still held by extraction workers.
                drop(drafts);
            })?;
        match receive.recv().map_err(io::Error::other)? {
            Ok(()) => Ok(Self {
                publisher: Publisher { shared, reports },
                thread: Some(thread),
            }),
            Err(error) => {
                let _ = thread.join();
                Err(error)
            }
        }
    }

    pub(super) fn register(&self, request: Arc<str>, language: Language) -> Activity {
        self.publisher.register(request, language)
    }

    pub(super) fn stop_group(&self, id: &str) -> Vec<Arc<str>> {
        self.publisher.stop_group(id)
    }

    pub(super) fn set_report_retention(&self, days: u64) {
        self.publisher
            .reports
            .retention
            .store(days, Ordering::Relaxed);
    }
}

enum Display {
    Clear,
    Progress(Snapshot),
    Completed(Completed),
}

impl Drop for Toast {
    fn drop(&mut self) {
        self.publisher.shared.state.lock().unwrap().stopping = true;
        self.publisher.reports.cancellation.cancel();
        self.publisher.shared.changed.notify_one();
        // A writer may be inside a filesystem call. It owns the presenter and
        // draft cleanup; cancellation makes it exit without showing a stale
        // toast. Never synchronously join that IO from Watch's service thread.
        drop(self.thread.take());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::{ArchiveResult, CleanupResult, Segment};

    fn one_root(_: &Path) -> Option<String> { Some("root".into()) }

    fn queued(id: TaskId, path: &str, parent: Option<TaskId>, index: usize) -> Event {
        Event::Queued {
            id,
            parent,
            path: PathBuf::from(path),
            depth: 1,
            segment: parent.map(|_| Segment {
                index,
                count: 2,
                offset: 0,
                end_offset: None,
            }),
        }
    }

    fn progress(
        activity: &Activity,
        id: TaskId,
        path: &str,
        completed_bytes: u64,
        total_bytes: u64,
    ) {
        activity.event(Event::Progress {
            id,
            path: PathBuf::from(path),
            completed_bytes,
            total_bytes,
        });
    }

    fn current(publisher: &Publisher) -> Snapshot {
        let state = publisher.shared.state.lock().unwrap();
        Snapshot::progress(state.groups.front().unwrap())
    }

    #[test]
    fn overlapping_requests_share_progress_stop_and_cleanup_result() {
        // Exercise the same state consumed by the presenter, without opening
        // Windows notifications or depending on update timing.
        let publisher = publisher(PathBuf::new());
        let first = Arc::<str>::from("00000000000000000000000000000001");
        let second = Arc::<str>::from("00000000000000000000000000000002");
        let a = publisher.register(Arc::clone(&first), Language::En);
        let b = publisher.register(Arc::clone(&second), Language::En);
        a.event(queued(1, "carrier", None, 0));
        a.event(queued(2, "carrier", Some(1), 1));
        a.event(queued(3, "carrier", Some(1), 2));
        b.event(queued(4, "ordinary.7z", None, 0));
        progress(&a, 2, "carrier", 20, 100);
        progress(&a, 3, "carrier", 80, 200);
        progress(&b, 4, "ordinary.7z", 100, 200);
        let initial = current(&publisher);
        assert_eq!(initial.progress, Some(0.4));
        assert_eq!(initial.label, "2 archives");
        assert_eq!(initial.value, "40% · 200 B / 500 B");

        a.event(Event::ResourceWait {
            id: 2,
            path: "carrier".into(),
            state: ResourceWait {
                memory: true,
                ..ResourceWait::default()
            },
        });
        b.event(Event::ResourceWait {
            id: 4,
            path: "ordinary.7z".into(),
            state: ResourceWait {
                disk: true,
                ..ResourceWait::default()
            },
        });
        assert_eq!(
            current(&publisher).status,
            Language::En.text("report.status.resources_resume_hint")
        );
        b.event(Event::Finalizing { id: 4 });
        assert_eq!(
            current(&publisher).status,
            Language::En.text("toast.progress.memory_paused")
        );
        a.event(Event::Finalizing { id: 2 });
        a.event(Event::Finished {
            id: 2,
            path: "carrier".into(),
            depth: 1,
            success: true,
        });
        let snapshot = current(&publisher);
        assert_eq!(snapshot.status, "0/2 finished");
        assert_eq!(snapshot.progress, Some(0.56));

        let mut stopped = publisher.stop_group(&snapshot.action.unwrap().2);
        stopped.sort_unstable();
        assert_eq!(stopped, [first, second]);
        let later = publisher.register(Arc::from("00000000000000000000000000000003"), Language::En);
        later.event(queued(5, "later.zip", None, 0));
        progress(&later, 5, "later.zip", 5, 10);
        assert_eq!(
            current(&publisher).title,
            Language::En.text("interrupt.stopping_title")
        );

        a.finish(&Err(io::Error::other("output deletion failed")), true, true, one_root);
        b.finish(&Ok(Outcome::default()), true, false, one_root);
        assert!(publisher.stop_group(&initial.batch).is_empty());
        assert!(publisher.shared.state.lock().unwrap().completed.is_empty());
        finish_debounce(&publisher);
        let interrupted = Snapshot::completed(&take_completed(&publisher), None);
        assert_eq!(current(&publisher).label, "later.zip");
        let state = publisher.shared.state.lock().unwrap();
        assert_eq!(
            interrupted.body,
            Language::En.text("interrupt.cleanup_failed")
        );
        assert!(state.completed.is_empty());
        drop(state);

        let mut outcome = Outcome::default();
        outcome.archives.push(archive("later.zip", None));
        outcome.cleanup_results.push(CleanupResult {
            path: "later.zip".into(),
            mode: "delete",
            status: CleanupStatus::Failed,
            error_code: 5,
            message: "Access denied".to_owned(),
        });
        later.finish(&Ok(outcome), false, false, one_root);
        finish_debounce(&publisher);
        let completed = Snapshot::completed(&take_completed(&publisher), None);
        let state = publisher.shared.state.lock().unwrap();
        assert!(completed.body.contains("Paths with cleanup errors: 1."));
        assert!(state.groups.is_empty());
    }
    fn publisher(directory: PathBuf) -> Publisher {
        Publisher {
            shared: Arc::default(),
            reports: Arc::new(Reports {
                cancellation: Cancellation::new(),
                directory,
                retention: AtomicU64::new(30),
            }),
        }
    }

    fn archive(name: &str, failure: Option<FailureKind>) -> ArchiveResult {
        ArchiveResult {
            path: name.into(), format: "zip".into(), output: Some(name.into()),
            failure: failure.map(|kind| crate::pipeline::Failure::new(kind, name)),
            files: 1, bytes: 42, encrypted: None, depth: 1,
            offset: 0, end_offset: None, volume_completeness: None,
            volume_attempts: None, source_paths: Vec::new(), password: None,
            discovery_source: crate::pipeline::DiscoverySource::Direct, damage_flags: None,
            partial: false, retained: false, recovered_complete_files: 0,
            promoted: false, promotion_original_path: None,
        }
    }

    fn success() -> io::Result<Outcome> {
        let mut outcome = Outcome::default();
        outcome.archives.push(archive("outer.zip", None));
        outcome.archives.push(archive("nested.zip", None));
        Ok(outcome)
    }

    fn finish_debounce(publisher: &Publisher) {
        let mut state = publisher.shared.state.lock().unwrap();
        let deadline = state.groups.front().unwrap().finalize_at.unwrap();
        state.settle(deadline);
    }

    fn take_completed(publisher: &Publisher) -> Completed {
        let completed = publisher.shared.state.lock().unwrap().completed.pop_front().unwrap();
        assert!(publisher.shared.present_completed(&completed, || {}));
        completed
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            Self(std::env::temp_dir().join(format!(
                "sunpack-toast-{}-{}-{}", std::process::id(),
                SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_nanos(),
                NEXT.fetch_add(1, Ordering::Relaxed),
            )))
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn failed_report_service_releases_completion_gate_without_publishing_partial_report() {
        let directory = TestDirectory::new();
        let publisher = publisher(directory.0.clone());
        let activity = publisher.register(Arc::from("42"), Language::En);
        activity.event(queued(1, "a.zip", None, 0));
        progress(&activity, 1, "a.zip", 1, 2);
        activity.event(Event::Finished { id: 1, path: "a.zip".into(), depth: 1, success: false });
        let mut outcome = Outcome::default();
        outcome.archives.push(archive("a.zip", Some(FailureKind::Damaged)));
        activity.root_finished(1, &outcome);
        assert!(publisher.shared.state.lock().unwrap().groups.front().unwrap().pending());
        activity.report_finished(1, true);
        assert!(!publisher.shared.state.lock().unwrap().groups.front().unwrap().pending());
        activity.finish(&Ok(Outcome::default()), false, false, |_| Some("a.zip".into()));
        finish_debounce(&publisher);
        let completed = take_completed(&publisher);
        assert!(completed.summary.report_failed);
        assert!(publisher.reports.publish(&completed, &publisher.shared).unwrap().is_none());
    }

    #[test]
    fn later_root_uses_its_own_name_after_an_earlier_completion_is_published() {
        let directory = TestDirectory::new();
        let publisher = publisher(directory.0.clone());
        let activity = publisher.register(Arc::from("41"), Language::En);
        activity.event(queued(1, "a.zip", None, 0));
        activity.event(queued(2, "b.zip", None, 0));
        progress(&activity, 1, "a.zip", 1, 2);
        let mut outcome = Outcome::default();
        outcome.archives.push(archive("a.zip", None));
        activity.event(Event::Finished { id: 1, path: "a.zip".into(), depth: 1, success: true });
        activity.root_finished(1, &outcome);
        activity.report_finished(1, false);
        finish_debounce(&publisher);
        take_completed(&publisher);
        progress(&activity, 2, "b.zip", 1, 2);
        assert_eq!(current(&publisher).label, "b.zip");
    }

    #[test]
    fn settled_roots_survive_sibling_cancel_or_request_error_without_duplicate_reports() {
        // Unlike projection-only tests, this exercises real incremental root
        // publication followed by both batch termination paths.
        for cancelled in [false, true] {
            let directory = TestDirectory::new();
            let publisher = publisher(directory.0.clone());
            let activity = publisher.register(Arc::from("40"), Language::En);
            for (id, path) in [(1, "a.zip"), (2, "b.zip"), (3, "c.zip")] {
                activity.event(queued(id, path, None, 0));
                progress(&activity, id, path, 1, 2);
            }
            activity.event(Event::Finished { id: 1, path: "a.zip".into(), depth: 1, success: true });
            assert_eq!(current(&publisher).status, "0/3 finished");
            let mut done = Outcome::default();
            done.archives.push(archive("a.zip", None));
            done.archives.push(archive("a/nested.zip", None));
            done.cleanup_results.push(crate::pipeline::CleanupResult {
                path: "a.zip".into(), mode: "delete", status: CleanupStatus::Failed,
                error_code: 5, message: "source busy".into(),
            });
            activity.root_finished(1, &done);
            activity.record_root(1, Path::new("a.zip"), &done);
            activity.report_finished(1, false);
            assert_eq!(current(&publisher).status, "1/3 finished");
            let mut failed = Outcome::default();
            failed.archives.push(archive("c.zip", Some(FailureKind::Damaged)));
            activity.event(Event::Finished { id: 3, path: "c.zip".into(), depth: 1, success: false });
            activity.root_finished(3, &failed);
            activity.record_root(3, Path::new("c.zip"), &failed);
            activity.report_finished(3, false);
            assert_eq!(current(&publisher).status, "2/3 finished");
            let owner = |path: &Path| {
                let path = path.to_string_lossy();
                Some(if path.starts_with("a") { "a.zip" } else if path.starts_with("c") {
                    "c.zip"
                } else { "b.zip" }.to_owned())
            };
            let result = if cancelled { Ok(Outcome::default()) } else { Err(io::Error::other("sibling failed")) };
            activity.record(Path::new("b.zip"), &result, cancelled, &owner);
            activity.finish(&result, cancelled, false, &owner);
            let state = publisher.shared.state.lock().unwrap();
            let group = state.groups.front().unwrap();
            assert_eq!(group.summary.succeeded, 1);
            assert_eq!(group.summary.failed, if cancelled { 1 } else { 2 });
            assert_eq!(group.summary.interrupted, usize::from(cancelled));
            assert_eq!(group.summary.cleanup_failed, 1);
            // Root C and A's cleanup were written before publishing their
            // completion. Final projection must not append either again.
            assert_eq!(group.report.lock().unwrap().failures, if cancelled { 2 } else { 3 });
        }
    }

    #[test]
    fn batched_top_level_tasks_keep_independent_completion_and_reports() {
        // Covers batched scheduling, nested/carrier ownership, invisible
        // failures, promotion and report admission in one production flow.
        let directory = TestDirectory::new();
        let publisher = publisher(directory.0.clone());
        let activity = publisher.register(Arc::from("30"), Language::En);
        for (id, path) in [(1, "a.zip"), (2, "b.zip"), (3, "c.zip"), (4, "d.zip")] {
            activity.event(queued(id, path, None, 0));
            if id != 4 { progress(&activity, id, path, 1, 2); }
        }
        assert_eq!(current(&publisher).status, "0/3 finished");
        assert_eq!(current(&publisher).label, "3 archives");
        // A root can finish before later descendants are queued. Retain its
        // scalar ancestry until the native request itself has completed.
        activity.event(Event::Finished { id: 1, path: "a.zip".into(), depth: 1, success: true });
        activity.event(queued(5, "a/nested.zip", Some(1), 1));
        progress(&activity, 5, "a/nested.zip", 1, 2);
        assert_eq!(current(&publisher).status, "0/3 finished");
        let owner = |path: &Path| {
            let path = path.to_string_lossy().to_ascii_lowercase();
            if path.starts_with("a") { Some("a".into()) }
            else if path.starts_with("b") { Some("b".into()) }
            else if path.starts_with("c") { Some("c".into()) }
            else if path.starts_with("d") { Some("d".into()) }
            else { None }
        };
        let mut outcome = Outcome::default();
        outcome.archives.push(archive("a.zip", None));
        outcome.archives.push(archive("a/nested.zip", None));
        outcome.archives.push(archive("b.zip", None));
        let mut promoted = archive("promoted.zip", Some(FailureKind::WrongPassword));
        promoted.promotion_original_path = Some("b/nested.zip".into());
        outcome.archives.push(promoted);
        outcome.archives.push(archive("c.zip", None));
        outcome.archives.push(archive("c/nested.zip", Some(FailureKind::Damaged)));
        outcome.archives.push(archive("d.zip", Some(FailureKind::Damaged)));
        let result = Ok(outcome);
        activity.record(Path::new("a.zip"), &result, false, &owner);
        activity.finish(&result, false, false, &owner);
        finish_debounce(&publisher);
        let completed = take_completed(&publisher);
        assert_eq!((completed.summary.succeeded, completed.summary.failed), (1, 1));
        let draft = completed.report.lock().unwrap();
        assert_eq!(draft.failures, 1);
        let text = fs::read_to_string(draft.path.as_ref().unwrap()).unwrap();
        assert!(text.contains("c/nested.zip"));
        assert!(!text.contains("promoted.zip"));
        assert!(!text.contains("d.zip"));

        // No owner metadata: independent paths stay independent, while
        // case-folded segments of one physical carrier remain one task.
        let mut outcome = Outcome::default();
        outcome.archives.push(archive("a.zip", None));
        outcome.archives.push(archive("A.ZIP", None));
        outcome.archives.push(archive("b.zip", None));
        let summary = Summary::for_result(&Ok(outcome), false, false, true, &|_| None, None);
        assert_eq!((summary.succeeded, summary.failed), (2, 0));

        // Cancellation can precede receipts or Working events entirely.
        let activity = publisher.register(Arc::from("31"), Language::En);
        activity.event(queued(1, "a.zip", None, 0));
        activity.event(queued(2, "b.zip", None, 0));
        activity.finish(&Ok(Outcome::default()), true, false, &owner);
        finish_debounce(&publisher);
        assert_eq!(take_completed(&publisher).summary.interrupted, 2);
    }

    #[test]
    fn request_projection_suppresses_invisible_retry_and_partial_diagnostics() {
        // Unlike aggregate-count tests this exercises report admission: a
        // retry or pre-extraction error must not create a diagnostic file.
        let directory = TestDirectory::new();
        let publisher = publisher(directory.0.clone());
        let invisible = publisher.register(Arc::from("01"), Language::En);
        invisible.event(queued(1, "invisible.zip", None, 0));
        let error = Err(io::Error::other("pre-extraction failure"));
        invisible.record(Path::new("invisible.zip"), &error, false, one_root);
        invisible.finish(&error, false, false, one_root);
        assert!(!directory.0.exists());
        assert!(publisher.shared.state.lock().unwrap().completed.is_empty());

        for (index, kind) in [FailureKind::PasswordRequired, FailureKind::WrongPassword,
            FailureKind::MissingVolume].into_iter().enumerate()
        {
            let activity = publisher.register(Arc::from(format!("1{index}")), Language::En);
            activity.event(queued(1, "retry.zip", None, 0));
            progress(&activity, 1, "retry.zip", 1, 2);
            let mut outcome = Outcome::default();
            outcome.archives.push(archive("successful-sibling.zip", None));
            outcome.archives.push(archive("retry.zip", Some(kind)));
            let result = Ok(outcome);
            activity.record(Path::new("retry.zip"), &result, false, one_root);
            activity.finish(&result, false, false, one_root);
            let mut state = publisher.shared.state.lock().unwrap();
            assert!(state.groups.is_empty());
            assert!(state.completed.is_empty());
            assert!(std::mem::take(&mut state.clear));
            assert!(!directory.0.exists());
        }

        // Retry evidence from an accepted segment still owns a failed
        // physical carrier, but an entirely accepted carrier stays successful.
        for (index, kind) in [FailureKind::MissingVolume, FailureKind::WrongPassword]
            .into_iter().enumerate()
        {
            let activity = publisher.register(Arc::from(format!("3{index}")), Language::En);
            activity.event(queued(1, "carrier.bin", None, 0));
            progress(&activity, 1, "carrier.bin", 1, 2);
            let mut outcome = Outcome::default();
            let mut partial = archive("carrier.bin", Some(kind));
            partial.partial = true;
            outcome.archives.push(partial);
            outcome.archives.push(archive("CARRIER.bin", Some(FailureKind::Damaged)));
            let result = Ok(outcome);
            activity.record(Path::new("carrier.bin"), &result, false, one_root);
            activity.finish(&result, false, false, one_root);
            assert!(publisher.shared.state.lock().unwrap().groups.is_empty());
            assert!(publisher.shared.state.lock().unwrap().completed.is_empty());
            assert!(!directory.0.exists());

            let mut accepted = archive("carrier.bin", Some(kind));
            accepted.partial = true;
            let mut outcome = Outcome::default();
            outcome.archives.push(accepted);
            let summary = Summary::for_result(&Ok(outcome), false, false, true, &one_root, None);
            assert_eq!((summary.succeeded, summary.failed), (1, 0));
        }

        let activity = publisher.register(Arc::from("20"), Language::En);
        activity.event(queued(1, "terminal.zip", None, 0));
        progress(&activity, 1, "terminal.zip", 1, 2);
        let mut outcome = Outcome::default();
        outcome.archives.push(archive("successful-sibling.zip", None));
        outcome.archives.push(archive("terminal.zip", Some(FailureKind::Damaged)));
        outcome.archives.push(archive("password-only.zip", Some(FailureKind::WrongPassword)));
        let mut carrier = archive("blocked-carrier.bin", Some(FailureKind::MissingVolume));
        carrier.partial = true;
        outcome.archives.push(carrier);
        outcome.archives.push(archive("blocked-carrier.bin", Some(FailureKind::Damaged)));
        let mut partial = archive("accepted-recovery.zip", Some(FailureKind::Damaged));
        partial.partial = true;
        outcome.archives.push(partial);
        outcome.errors.push(crate::pipeline::InputError {
            path: "log-only-scan".into(), message: "log-only-scan".into(),
            kind: InputErrorKind::FilesystemScan, scan_operation: Some("read".into()),
            scan_count: Some(7),
        });
        let result = Ok(outcome);
        activity.record(Path::new("terminal.zip"), &result, false, one_root);
        activity.finish(&result, false, false, one_root);
        finish_debounce(&publisher);
        let completed = take_completed(&publisher);
        assert_eq!((completed.summary.succeeded, completed.summary.failed), (0, 1));
        let draft = completed.report.lock().unwrap();
        assert_eq!(draft.failures, 1);
        let text = fs::read_to_string(draft.path.as_ref().unwrap()).unwrap();
        assert!(text.contains("terminal.zip"));
        assert!(!text.contains("password-only.zip"));
        assert!(!text.contains("blocked-carrier.bin"));
        assert!(!text.contains("accepted-recovery.zip"));
        assert!(!text.contains("log-only-scan"));
    }

    #[test]
    fn debounce_coalesces_requests_without_waiting_for_invisible_scans() {
        // Drive the production deadline directly. This catches early final
        // notifications, recursive archive counts, and orphaned activities
        // after an invisible scan moves to the next batch, without sleeping.
        let publisher = publisher(PathBuf::new());
        // This first request seeds the original batch but outlives it. Its
        // next batch must have a new notification tag and spool filename.
        let c = publisher.register(Arc::from("03"), Language::En);
        c.event(queued(3, "slow-scan.zip", None, 0));
        let a = publisher.register(Arc::from("01"), Language::En);
        a.event(queued(1, "outer.zip", None, 0));
        progress(&a, 1, "outer.zip", 2, 2);
        a.finish(&success(), false, false, one_root);
        let first_deadline = publisher.shared.state.lock().unwrap()
            .groups.front().unwrap().finalize_at.unwrap();
        let b = publisher.register(Arc::from("02"), Language::En);
        b.event(queued(2, "next.zip", None, 0));
        {
            let mut state = publisher.shared.state.lock().unwrap();
            assert_eq!(state.groups.front().unwrap().finalize_at, Some(first_deadline));
            state.settle(first_deadline - Duration::from_millis(1));
            assert!(state.completed.is_empty());
        }
        progress(&b, 2, "next.zip", 1, 2);
        assert!(publisher.shared.state.lock().unwrap().groups.front().unwrap().finalize_at.is_none());
        assert_eq!(current(&publisher).status, "1/2 finished");
        b.finish(&success(), false, false, one_root);
        finish_debounce(&publisher);
        {
            let completed = take_completed(&publisher);
            let state = publisher.shared.state.lock().unwrap();
            assert_eq!(completed.summary.succeeded, 2);
            assert_eq!(state.groups.front().unwrap().requests.len(), 1);
            assert_ne!(state.groups.front().unwrap().id, completed.id);
        }
        progress(&c, 3, "slow-scan.zip", 1, 2);
        assert_eq!(current(&publisher).label, "slow-scan.zip");
        assert_eq!(current(&publisher).status, "0/1 finished");
        c.finish(&success(), false, false, one_root);
        finish_debounce(&publisher);
        assert_eq!(take_completed(&publisher).summary.succeeded, 1);
        assert!(publisher.shared.state.lock().unwrap().groups.is_empty());
    }

    #[test]
    fn a_failed_append_poisons_previously_written_report_records() {
        // A single failed record must invalidate the whole report, including
        // earlier successful appends. Low-level append rollback tests cannot
        // detect publication of that otherwise well-formed incomplete file.
        let directory = TestDirectory::new();
        let publisher = publisher(directory.0.clone());
        let draft = Arc::new(Mutex::new(ReportDraft::default()));
        let error = Err(io::Error::other("terminal failure"));
        publisher.reports.append("81", Language::En, &draft, Path::new("a.zip"), &error, &one_root, None).unwrap();
        let path = draft.lock().unwrap().path.clone().unwrap();
        let original = fs::read(&path).unwrap();
        // Point the next append at a directory, an actual deterministic IO
        // failure on Windows and Unix, then restore the valid first record.
        draft.lock().unwrap().path = Some(directory.0.clone());
        assert!(publisher.reports.append("81", Language::En, &draft, Path::new("b.zip"), &error, &one_root, None).is_err());
        draft.lock().unwrap().path = Some(path.clone());
        publisher.reports.append("81", Language::En, &draft, Path::new("c.zip"), &error, &one_root, None).unwrap();
        assert!(draft.lock().unwrap().poisoned);
        assert_eq!(fs::read(&path).unwrap(), original);
        let completed = Completed {
            generation: 0,
            id: Arc::from("81"), language: Language::En, elapsed: Duration::ZERO,
            summary: Summary { failed: 3, ..Summary::default() }, report: draft,
        };
        assert!(publisher.reports.publish(&completed, &publisher.shared).unwrap().is_none());
        drop(completed);
        assert!(!path.exists());
    }

    #[test]
    fn disabling_toasts_cancels_and_detaches_an_active_report_writer() {
        // Hold a writer on a channel rather than timing large disk writes.
        // Drop must return before release, and both the report IO and the
        // presentation gate must reject the writer's late completion.
        let directory = TestDirectory::new();
        let publisher = publisher(directory.0.clone());
        let draft = Arc::new(Mutex::new(ReportDraft::default()));
        let result = Err(io::Error::other("failure"));
        publisher.reports.append("81", Language::En, &draft, Path::new("a.zip"), &result, &one_root, None).unwrap();
        let path = draft.lock().unwrap().path.clone().unwrap();
        let completed = Completed {
            generation: 0,
            id: Arc::from("81"), language: Language::En, elapsed: Duration::ZERO,
            summary: Summary { failed: 1, ..Summary::default() }, report: draft,
        };
        let (entered, ready) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let (done, finished) = mpsc::channel();
        let worker = publisher.clone();
        let thread = thread::spawn(move || {
            let draft = completed.report.lock().unwrap();
            entered.send(()).unwrap();
            released.recv().unwrap();
            drop(draft);
            assert!(worker.reports.cancellation.cancelled());
            assert!(worker.reports.append("81", Language::En, &completed.report,
                Path::new("b.zip"), &result, &one_root, None).is_err());
            assert!(worker.reports.publish(&completed, &worker.shared).is_err());
            assert!(!worker.shared.present(|| panic!("stale toast after disable")));
            drop(completed);
            done.send(()).unwrap();
        });
        ready.recv().unwrap();
        let toast = Toast { publisher: publisher.clone(), thread: Some(thread) };
        let (stopped, stop_complete) = mpsc::channel();
        let stop = thread::spawn(move || {
            drop(toast);
            stopped.send(()).unwrap();
        });
        let returned = stop_complete.recv_timeout(Duration::from_secs(5));
        // Always release before asserting, so a regression cannot leak a
        // blocked test thread or leave the temporary report locked.
        release.send(()).unwrap();
        stop.join().unwrap();
        assert!(returned.is_ok(), "disable synchronously joined the active writer");
        finished.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(!path.exists());
        assert!(!fs::read_dir(&directory.0).unwrap().any(|entry| {
            entry.unwrap().path().extension().is_some_and(|ext| ext == "txt")
        }));
    }
    #[test]
    fn new_visible_work_invalidates_in_flight_completion_without_losing_report() {
        // Pause at the report/presentation boundary, where checking only
        // shutdown allowed an old final toast to overwrite fresh progress.
        let directory = TestDirectory::new();
        let publisher = publisher(directory.0.clone());
        let first = publisher.register(Arc::from("01"), Language::En);
        first.event(queued(1, "first.zip", None, 0));
        progress(&first, 1, "first.zip", 1, 2);
        let failure = Err(io::Error::other("first failure"));
        first.record(Path::new("first.zip"), &failure, false, one_root);
        first.finish(&failure, false, false, one_root);
        finish_debounce(&publisher);
        let completed = publisher.shared.state.lock().unwrap().completed.pop_front().unwrap();
        let batch = Arc::clone(&completed.id);
        let (entered, ready) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let worker = publisher.clone();
        let thread = thread::spawn(move || {
            let report = worker.reports.publish(&completed, &worker.shared).unwrap().unwrap();
            entered.send(report.clone()).unwrap();
            released.recv().unwrap();
            assert!(!worker.shared.present_completed(&completed, || {
                panic!("old completion replaced active batch progress");
            }));
            fs::remove_file(report).unwrap();
        });
        let stale_report = ready.recv().unwrap();
        let next = publisher.register(Arc::from("02"), Language::En);
        next.event(queued(2, "next.zip", None, 0));
        progress(&next, 2, "next.zip", 1, 2);
        assert_eq!(current(&publisher).batch, batch.as_ref());
        assert_eq!(current(&publisher).status, "1/2 finished");
        let failure = Err(io::Error::other("second failure"));
        next.record(Path::new("next.zip"), &failure, false, one_root);
        next.finish(&failure, false, false, one_root);
        release.send(()).unwrap();
        thread.join().unwrap();
        assert!(!stale_report.exists());
        assert_eq!(publisher.shared.state.lock().unwrap().groups.front().unwrap().summary.failed, 2);
        finish_debounce(&publisher);
        let completed = publisher.shared.state.lock().unwrap().completed.pop_front().unwrap();
        let report = publisher.reports.publish(&completed, &publisher.shared).unwrap().unwrap();
        assert!(publisher.shared.present_completed(&completed, || {}));
        assert!(publisher.shared.state.lock().unwrap().groups.is_empty());
        let text = fs::read_to_string(report).unwrap();
        assert!(text.contains("first failure"));
        assert!(text.contains("second failure"));
        assert_eq!(completed.summary.failed, 2);
    }
}
