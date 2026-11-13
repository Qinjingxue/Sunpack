use super::failure::report::{self, Report};
use super::windows::ToastLibrary;
use crate::core::i18n::Language;
use crate::failure_report::{append_failure_report, publish_failure_report, FailureRecord};
use crate::pipeline::{
    ArchiveResult, Cancellation, CleanupStatus, Event, FailureKind, InputError, InputErrorKind,
    Outcome, ResourceWait, TaskId,
};
use serde::{ser::SerializeSeq, Serialize, Serializer};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
#[cfg(test)]
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};
use std::{fs, io};

const COMPLETION_DEBOUNCE: Duration = Duration::from_millis(800);

// A failed snapshot is consumed. Recreate only when a later snapshot arrives;
// component initialization failure is terminal, matching the host's lifecycle.
fn show_snapshot<P>(
    presenter: &mut Option<P>,
    create: impl FnOnce() -> io::Result<P>,
    show: impl FnOnce(&P) -> io::Result<()>,
    report_error: &mut impl FnMut(&'static str, io::Error),
) -> bool {
    if presenter.is_none() {
        match create() {
            Ok(current) => *presenter = Some(current),
            Err(error) => {
                report_error("toast_unavailable", error);
                return false;
            }
        }
    }
    if let Err(error) = show(presenter.as_ref().unwrap()) {
        report_error("toast_error", error);
        presenter.take();
    }
    true
}

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
    pub(super) fn stop_failed(batch: &str, language: Language) -> Self {
        Self {
            batch: format!("{batch}-cancel"), kind: 3,
            title: language.text("interrupt.stop_failed_title").to_owned(),
            body: language.text("interrupt.stop_failed").to_owned(),
            progress: None, label: String::new(), status: String::new(), value: String::new(),
            action: None, report_action: None,
        }
    }

    fn progress(group: &Group) -> Self {
        let language = group.language;
        let stopping = group.stopping();
        let totals = &group.totals;
        let completed = totals.done_bytes + totals.written;
        let total = totals.done_bytes + totals.planned;
        let finished = group.summary.completed();
        let count = finished + group.active_roots;
        let disk = totals.disk != 0;
        let memory = totals.memory != 0;
        let progress = if disk || memory || stopping {
            None
        } else if group.active_roots == 0 && total == 0 {
            Some(1.0)
        } else if totals.unknown == 0 && total != 0 {
            Some((completed as f64 / total as f64).min(1.0))
        } else {
            None
        };
        let (title, status) = if stopping {
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
        let value = if stopping {
            String::new()
        } else if disk || memory {
            language.text(if disk && memory {
                "report.status.resources_paused"
            } else if memory {
                "report.status.memory_paused"
            } else {
                "report.status.disk_paused"
            }).to_owned()
        } else if let Some(progress) = progress {
            language.translate(
                "toast.progress.value",
                &[
                    (
                        "percent",
                        &((progress * 100.0) as u64).to_string(),
                    ),
                    ("completed_bytes", &format_bytes(completed)),
                    ("total_bytes", &format_bytes(total)),
                ],
            )
        } else {
            language.text("toast.progress.indeterminate").to_owned()
        };
        Self {
            batch: group.id.to_string(),
            kind: 1,
            title: language.text(title).to_owned(),
            body: if stopping {
                language.text("interrupt.stopping").to_owned()
            } else { language.translate(
                "toast.progress.body",
                &[
                    ("completed", &finished.to_string()),
                    ("total", &count.to_string()),
                ],
            ) },
            progress,
            label: if count == 1 {
                group.requests.values()
                    .find(|request| request.visible)
                    .and_then(|request| request.name.as_ref())
                    .or(group.name.as_ref())
                    .map_or_else(String::new, |(_, name)| name.clone())
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
        let failed = summary.failed + usize::from(summary.rollback_failed);
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
        if !summary.cleanup_warnings.is_empty() {
            body.push('\n');
            body.push_str(&summary.cleanup_warnings);
        }
        if summary.interrupted != 0 {
            let interrupted = language.text(if summary.rollback_failed {
                "interrupt.cleanup_failed"
            } else {
                "interrupt.cleaned"
            });
            if succeeded == 0 && summary.failed == 0 {
                title = language.text("interrupt.finished").to_owned();
                body = interrupted.to_owned();
                kind = if summary.rollback_failed { 3 } else { 2 };
            } else {
                body.push('\n');
                body.push_str(interrupted);
            }
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

    pub(super) fn encode(&self) -> Vec<u8> {
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
    for candidate in ["KiB", "MiB", "GiB", "TiB"] {
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
    output.extend((value.len() as u32).to_le_bytes());
    output.extend(value.as_bytes());
}

#[derive(Default)]
struct State {
    group: Option<Group>,
    completed: VecDeque<Completed>,
    published: VecDeque<(Completed, Option<PathBuf>)>,
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
    requests: HashMap<Arc<str>, RequestProgress>,
    active_roots: usize,
    finalize_at: Option<Instant>,
    finalizing: bool,
    generation: u64,
    totals: Totals,
    summary: Summary,
    report: Arc<Mutex<ReportDraft>>,
    cancellation: Cancellation,
}

// Match main's bounded per-request warning lines; completed batches never
// retain an unbounded list of request receipts.
fn append_warning(warnings: &mut String, warning: &str) {
    if warning.is_empty() { return; }
    let remaining = 2048usize.saturating_sub(warnings.chars().count() + usize::from(!warnings.is_empty()));
    if remaining == 0 { return; }
    if !warnings.is_empty() { warnings.push('\n'); }
    if warning.chars().count() >= remaining {
        warnings.extend(warning.chars().take(remaining - 1));
        warnings.push('…');
    } else {
        warnings.push_str(warning);
    }
}

#[derive(Clone, Default)]
struct Summary {
    succeeded: usize,
    failed: usize,
    interrupted: usize,
    rollback_failed: bool,
    report_failed: bool,
    cleanup_warnings: String,
    output: Option<PathBuf>,
}

struct Completed {
    generation: u64,
    id: Arc<str>,
    language: Language,
    elapsed: Duration,
    summary: Summary,
    report: Arc<Mutex<ReportDraft>>,
    cancellation: Cancellation,
}

impl Completed {
    fn needs_report(&self) -> bool {
        !self.summary.report_failed && (self.summary.failed != 0
            || (self.summary.rollback_failed && self.summary.succeeded != 0))
    }
}

#[derive(Default)]
struct RequestProgress {
    stopping: bool,
    tasks: HashMap<TaskId, TaskProgress>,
    paths: HashMap<TaskId, PathBuf>,
    started: HashMap<TaskId, HashSet<PathBuf>>,
    roots: HashMap<TaskId, PathBuf>,
    task_roots: HashMap<TaskId, TaskId>,
    root_tasks: HashMap<TaskId, Vec<TaskId>>,
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
    fn stopping(&self) -> bool {
        self.requests.values().any(|request| request.stopping)
            && self.requests.values().filter(|request| request.visible).all(|request| request.stopping)
    }

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
            requests: HashMap::new(),
            active_roots: 0,
            finalize_at: None,
            finalizing: false,
            generation: 0,
            totals: Totals::default(),
            summary: Summary::default(),
            report: Arc::default(),
            cancellation: Cancellation::new(),
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
                request.root_tasks.entry(root).or_default().push(id);
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
            Event::Replanned { id, path } => {
                if let Some(previous) = tasks.insert(id, TaskProgress::default()) {
                    self.totals.remove(previous, false);
                }
                if let Some(root) = request.roots.get_mut(&id) { *root = path.clone(); }
                if request.name.as_ref().is_some_and(|(root, _)| *root == id) {
                    request.name = Some((id, path.file_name().unwrap_or(path.as_os_str())
                        .to_string_lossy().into_owned()));
                }
                request.paths.insert(id, path);
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
                request.started.entry(request.task_roots[&id]).or_default().insert(path.clone());
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
            || self.requests.values().any(|request| request.stopping)
    }
}

impl State {
    fn retire_batch(&mut self) {
        let mut group = self.group.take().unwrap();
        if !group.requests.is_empty() {
            // Invisible scans neither postpone completion nor lose their
            // activity when the completed batch is retired.
            let request = group.requests.keys().next().unwrap();
            let mut next = Group::new(request, group.language);
            for request in group.requests.values_mut() {
                if request.visible_roots.iter().all(|id| request.settled_tasks.contains(id)) {
                    request.visible = false;
                    request.name = None;
                }
            }
            next.requests = group.requests;
            self.group = Some(next);
        }
        self.dirty = true;
    }

    fn settle(&mut self, now: Instant) -> bool {
        let mut changed = false;
        while let Some(group) = self.group.as_mut() {
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
                    cancellation: group.cancellation.clone(),
                });
                changed = true;
                break;
            }
            if !group.visible && !group.requests.is_empty() {
                break;
            }
            self.clear |= group.visible;
            self.retire_batch();
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
        language: Language,
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
            Ok(outcome) => return Self::for_outcome(language, outcome, output_cleanup_failed, visible, owner, started),
            Err(_) => summary.failed = started.map_or(1, HashSet::len),
        }
        if output_cleanup_failed {
            summary.cleanup_warnings = language.translate("cleanup.incomplete", &[("count", "1")]);
        }
        summary
    }

    fn for_outcome(
        language: Language,
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
        let cleanup_failed = outcome.cleanup_results.iter()
            .filter(|result| result.status == CleanupStatus::Failed
                && started.is_none_or(|started| started.contains(&result_owner(&result.path, owner)))).count() + usize::from(output_cleanup_failed);
        if cleanup_failed != 0 {
            summary.cleanup_warnings = language.translate("cleanup.incomplete", &[("count", &cleanup_failed.to_string())]);
        }
        summary
    }

    fn merge(&mut self, other: Self) {
        self.succeeded += other.succeeded;
        self.failed += other.failed;
        self.interrupted += other.interrupted;
        self.rollback_failed |= other.rollback_failed;
        self.report_failed |= other.report_failed;
        append_warning(&mut self.cleanup_warnings, &other.cleanup_warnings);
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
    for error in outcome.errors.iter().filter(|error| is_terminal_input_error(error)) {
        roots.entry(result_owner(&error.path, owner)).or_default().terminal = true;
    }
    roots
}

fn is_terminal_input_error(error: &InputError) -> bool {
    matches!(error.kind, InputErrorKind::InvalidInput | InputErrorKind::EmbeddedDiscovery)
}

#[derive(Default)]
struct Shared {
    state: Mutex<State>,
    changed: Condvar,
}

impl Shared {
    fn discard_batches(&self) {
        let (groups, completed, published) = {
            let mut state = self.state.lock().unwrap();
            (std::mem::take(&mut state.group), std::mem::take(&mut state.completed),
                std::mem::take(&mut state.published))
        };
        // Unpresented reports are invalid, like main's detached finalize result.
        // File removal and draft destruction must never hold the state gate.
        for (_, report) in published {
            if let Some(path) = report { let _ = fs::remove_file(path); }
        }
        drop((groups, completed));
    }

    fn present(&self, batch: &str, show: impl FnOnce()) -> bool {
        let state = self.state.lock().unwrap();
        if state.stopping || state.group.as_ref().is_none_or(|group| group.id.as_ref() != batch) {
            return false;
        }
        drop(state);
        show();
        true
    }

    fn present_completed(&self, completed: &Completed, show: impl FnOnce()) -> bool {
        let mut state = self.state.lock().unwrap();
        if state.stopping {
            return false;
        }
        let Some(group) = state.group.as_mut()
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
        // Accept this generation before releasing the snapshot. New work
        // can publish independently while the sole presenter sends it.
        state.retire_batch();
        state.settle(Instant::now());
        drop(state);
        show();
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
    // Report copies and retention enumeration use the existing shared I/O
    // admission, never the sole native presenter thread.
    fn publish(&self, engine: &crate::pipeline::Engine, completed: Completed) -> crate::pipeline::RequestHandle<()> {
        let reports = Arc::clone(&self.reports);
        let shared = Arc::clone(&self.shared);
        let cancel = completed.cancellation.clone();
        engine.spawn_control(crate::pipeline::Origin::Watch, &cancel.clone(), async move {
            let result = async {
                crate::pipeline::stage("watch_failure_report", &cancel).await?;
                reports.publish(&completed, &shared)
            }.await;
            let report = match result {
                Ok(report) => report,
                Err(error) => {
                    if !cancel.cancelled() {
                        eprintln!("SunPack toast failure report: {error}");
                    }
                    None
                }
            };
            let mut state = shared.state.lock().unwrap();
            if state.stopping || !state.group.iter().any(|group| group.id == completed.id) {
                drop(state);
                if let Some(path) = report { let _ = fs::remove_file(path); }
            } else {
                state.published.push_back((completed, report));
                shared.changed.notify_one();
            }
        })
    }

    fn register(&self, request: Arc<str>, language: Language) -> Activity {
        let mut state = self.shared.state.lock().unwrap();
        if state.stopping {
            return Activity { publisher: self.clone(), request };
        }
        if state.settle(Instant::now()) {
            self.shared.changed.notify_one();
        }
        if state.group.is_none() {
            state.group = Some(Group::new(&request, language));
        }
        let group = state.group.as_mut().unwrap();
        group.requests.insert(Arc::clone(&request), RequestProgress::default());
        Activity { publisher: self.clone(), request }
    }

    fn reset_batches(&self) {
        let retired = {
            let mut state = self.shared.state.lock().unwrap();
            if let Some(group) = &state.group { group.cancellation.cancel(); }
            let retired = (std::mem::take(&mut state.group), std::mem::take(&mut state.completed));
            state.clear = true;
            self.mark_dirty(&mut state);
            retired
        };
        // Old activities can no longer publish; active report copies observe
        // the batch cancellation and completed copies fail the presentation gate.
        drop(retired);
    }

    fn stop_group(&self, id: &str) -> Vec<Arc<str>> {
        let mut state = self.shared.state.lock().unwrap();
        let Some(group) = state
            .group
            .as_mut()
            .filter(|group| group.id.as_ref() == id && group.visible
                && !group.requests.is_empty())
        else {
            return Vec::new();
        };
        // Stopping extraction keeps this batch valid: earlier failures still
        // need their final report. Only reset/disable invalidates report I/O.
        for request in group.requests.values_mut() { request.stopping = true; }
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
        if let Some(group) = state
            .group
            .iter_mut()
            .find(|group| group.requests.contains_key(&self.request))
        {
            if group.event(&self.request, event) && group.visible {
                self.publisher.mark_dirty(&mut state);
            }
        }
    }

    pub(super) fn needs_root_report(&self, id: TaskId) -> bool {
        let state = self.publisher.shared.state.lock().unwrap();
        !state.stopping && state.group.iter()
            .filter_map(|group| group.requests.get(&self.request))
            .any(|request| request.pending_reports.contains(&id))
    }

    pub(super) fn record_root(&self, id: TaskId, path: &Path, outcome: &Outcome) {
        let (group_id, language, report) = {
            let state = self.publisher.shared.state.lock().unwrap();
            if state.stopping { return; }
            let Some(group) = state.group.iter().find(|group| group.requests.contains_key(&self.request))
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
        let Some(group) = state.group.iter_mut()
            .find(|group| group.requests.contains_key(&self.request)) else { return; };
        let request = group.requests.get_mut(&self.request).unwrap();
        let Some(path) = request.roots.get(&id) else { return; };
        let key = crate::path_keys::path_key(&path.to_string_lossy());
        if !request.settled.insert(key.clone()) { return; }
        request.done_bytes -= request.root_done_bytes.remove(&id).unwrap_or(0);
        let visible = request.visible_roots.contains(&id);
        request.settled_tasks.insert(id);
        if visible { group.active_roots -= 1; }
        let summary = Summary::for_outcome(group.language, outcome, false, visible, &|_| Some(key.clone()), None);
        if summary.failed != 0 { request.pending_reports.insert(id); }
        group.summary.merge(summary);
        group.generation = group.generation.wrapping_add(1);
        state.dirty = true;
        self.publisher.shared.changed.notify_one();
    }

    pub(super) fn report_finished(&self, id: TaskId, failed: bool) {
        let mut state = self.publisher.shared.state.lock().unwrap();
        if state.stopping { return; }
        if let Some(group) = state.group.iter_mut()
            .find(|group| group.requests.contains_key(&self.request))
        {
            let request = group.requests.get_mut(&self.request).unwrap();
            if request.pending_reports.remove(&id) {
                group.summary.report_failed |= failed;
            }
            if request.settled_tasks.remove(&id) {
                if let Some(path) = request.roots.remove(&id) {
                    request.settled.remove(&crate::path_keys::path_key(&path.to_string_lossy()));
                }
                request.started.remove(&id);
                request.visible_roots.remove(&id);
                for task in request.root_tasks.remove(&id).into_iter().flatten() {
                    request.task_roots.remove(&task);
                }
                if request.name.as_ref().is_some_and(|(root, _)| *root == id) { request.name = None; }
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
        let (language, visible, started, settled) = {
            let state = self.publisher.shared.state.lock().unwrap();
            if state.stopping {
                return;
            }
            let Some(group) = state.group.iter()
                .find(|group| group.requests.contains_key(&self.request))
            else {
                return;
            };
            let request = &group.requests[&self.request];
            (group.language, request.visible, if cancelled { request.roots.values().cloned().collect::<HashSet<_>>() }
                else { request.started.values().flatten().cloned().collect() }, request.settled.clone())
        };
        // Receipt projection can be large. It must not hold the presentation
        // gate or prevent disable from cancelling an active report writer.
        let started = started.iter().map(|path| result_owner(path, &owner))
            .filter(|root| !settled.contains(root)).collect();
        let summary = Summary::for_result(language, result, cancelled, output_cleanup_failed, visible,
            &owner, Some(&started));
        let mut state = self.publisher.shared.state.lock().unwrap();
        if state.stopping {
            return;
        }
        let Some(group) = state.group.iter_mut()
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
            let Some(group) = state.group.iter()
                .find(|group| group.requests.contains_key(&self.request))
            else {
                return;
            };
            let request = &group.requests[&self.request];
            if !request.visible {
                return;
            }
            (Arc::clone(&group.id), group.language, Arc::clone(&group.report),
                request.visible_roots.iter().filter_map(|id| request.roots.get(id).cloned()).collect::<Vec<_>>(),
                request.settled.clone())
        };
        let started: HashMap<_, _> = started.into_iter().filter_map(|path| {
            let root = result_owner(&path, &owner);
            (!settled.contains(&root)).then_some((root, path))
        }).collect();
        if result.is_err() && !started.contains_key(&result_owner(path, &owner)) { return; }
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
        errors: &[String],
        details: Option<&RootFailureReport<'_>>,
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
                errors,
                unknown_error: self.language.text("toast.report.unknown_error"),
                details_prefix: &self.details_prefix,
                details,
            },
            self.cancellation,
        )?;
        self.failures = index;
        Ok(())
    }
}

#[derive(Default)]
struct RootFailures<'a> {
    archives: Vec<&'a ArchiveResult>,
    input_errors: Vec<&'a InputError>,
}

struct RootFailureReport<'a> {
    archives: Vec<Vec<&'a ArchiveResult>>,
    input_errors: Vec<&'a InputError>,
    language: Language,
}

impl Serialize for RootFailureReport<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut array = serializer.serialize_seq(None)?;
        for error in self.input_errors.iter().filter(|error| error.kind == InputErrorKind::EmbeddedDiscovery) {
            array.serialize_element(&Report::input_error(error, self.language))?;
        }
        for entries in &self.archives {
            if let Some(report) = report::archive_report(entries, self.language) {
                array.serialize_element(&report)?;
            }
        }
        for error in self.input_errors.iter().filter(|error| error.kind == InputErrorKind::InvalidInput) {
            array.serialize_element(&Report::input_error(error, self.language))?;
        }
        array.end()
    }
}

impl RootFailureReport<'_> {
    fn errors(&self) -> Vec<String> {
        let mut messages: Vec<_> = self.archives.iter().filter_map(|entries| {
            let path = &entries.first()?.path;
            let name = if entries.iter().any(|entry| entry.promoted) {
                path.as_os_str()
            } else {
                path.file_name().unwrap_or(path.as_os_str())
            };
            let message = report::carrier_message(entries, self.language);
            Some(format!("{} [{message}]", name.to_string_lossy()))
        }).collect();
        messages.extend(self.input_errors.iter()
            .filter(|error| error.kind == InputErrorKind::InvalidInput)
            .map(|error| report::invalid_input_message(error, self.language)));
        if messages.is_empty() {
            messages.extend(self.input_errors.iter().filter_map(|error| error.failure.as_deref()).map(|failure| {
                if failure.message.is_empty() {
                    self.language.text("watch.failure.extraction_failed").to_owned()
                } else {
                    failure.message.clone()
                }
            }));
        }
        messages
    }
}

impl Reports {
    #[cfg(test)]
    fn append(
        &self,
        id: &str,
        language: Language,
        report: &Mutex<ReportDraft>,
        path: &Path,
        result: &io::Result<Outcome>,
        owner: &impl Fn(&Path) -> Option<String>,
        started: Option<&HashMap<String, PathBuf>>,
    ) -> io::Result<()> {
        self.append_data(id, language, report, path, result.as_ref(), owner, started)
    }

    fn append_data(
        &self, id: &str, language: Language, report: &Mutex<ReportDraft>, path: &Path,
        result: Result<&Outcome, &io::Error>, owner: &impl Fn(&Path) -> Option<String>,
        started: Option<&HashMap<String, PathBuf>>,
    ) -> io::Result<()> {
        self.cancellation.check_io()?;
        let mut roots = HashMap::<String, RootFailures<'_>>::new();
        let visible = |root: &str| started.is_none_or(|started| started.contains_key(root));
        if let Ok(outcome) = result {
            let inputs = outcome.input_failures();
            if !inputs.is_empty() {
                for archive in &outcome.archives {
                    let key = crate::path_keys::path_key(&archive.path.to_string_lossy());
                    if inputs.get(&key).is_some_and(|input| input.failed && !input.retryable())
                        && archive.failure.as_ref().is_none_or(|failure| failure.kind != FailureKind::Cancelled)
                    {
                        let root = archive_owner(archive, owner);
                        if visible(&root) {
                            roots.entry(root).or_default().archives.push(archive);
                        }
                    }
                }
            }
            for error in outcome.errors.iter().filter(|error| is_terminal_input_error(error)) {
                let root = result_owner(&error.path, owner);
                if visible(&root) {
                    roots.entry(root).or_default().input_errors.push(error);
                }
            }
            if roots.is_empty() {
                return Ok(());
            }
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
        let written = match result {
            Err(error) => spool.append(path, &[error.to_string()], None),
            Ok(_) => roots.into_iter().try_for_each(|(key, root)| {
                let source = started.and_then(|paths| paths.get(&key)).map_or(path, PathBuf::as_path);
                let report = RootFailureReport {
                    archives: report::archive_groups(root.archives),
                    input_errors: root.input_errors,
                    language,
                };
                spool.append(source, &report.errors(), Some(&report))
            }),
        };
        draft.failures = spool.failures;
        draft.poisoned |= written.is_err();
        written
    }

    fn publish(&self, completed: &Completed, shared: &Shared) -> io::Result<Option<PathBuf>> {
        if !completed.needs_report() { return Ok(None); }
        let draft = completed.report.lock().unwrap();
        self.cancellation.check_io()?;
        completed.cancellation.check_io()?;
        if draft.poisoned {
            return Ok(None);
        }
        let now = SystemTime::now();
        let (timestamp, file_stamp) = report_time()?;
        let suffix = u32::from_be_bytes(super::windows::random_bytes()?);
        let output = self.directory.join(format!("failed-{file_stamp}-{suffix:08x}.txt"));
        let language = completed.language;
        let title = language.text("toast.report.title");
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
            &completed.cancellation,
        )?;
        drop(draft);
        self.trim(now, shared, &completed.cancellation);
        Ok(Some(output))
    }

    fn trim(&self, now: SystemTime, shared: &Shared, cancellation: &Cancellation) {
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
            if cancellation.cancelled() {
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
                    if state.group.iter().any(|group| group.id.as_ref() == id)
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

fn report_time() -> io::Result<(String, String)> {
    use windows_sys::Win32::Foundation::{FILETIME, SYSTEMTIME};
    use windows_sys::Win32::System::SystemInformation::GetSystemTimeAsFileTime;
    use windows_sys::Win32::System::Time::{FileTimeToSystemTime, SystemTimeToFileTime, SystemTimeToTzSpecificLocalTimeEx};
    let mut instant = FILETIME::default();
    let mut utc = SYSTEMTIME::default();
    let mut local = SYSTEMTIME::default();
    let mut local_ticks = FILETIME::default();
    unsafe {
        GetSystemTimeAsFileTime(&mut instant);
        if FileTimeToSystemTime(&instant, &mut utc) == 0
            || SystemTimeToTzSpecificLocalTimeEx(std::ptr::null(), &utc, &mut local) == 0
            || SystemTimeToFileTime(&local, &mut local_ticks) == 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    let ticks = |time: FILETIME| i64::from(time.dwHighDateTime) << 32 | i64::from(time.dwLowDateTime);
    let utc_ticks = ticks(instant);
    let offset = (ticks(local_ticks) - (utc_ticks / 10_000 * 10_000)) / 600_000_000;
    let sign = if offset < 0 { '-' } else { '+' };
    let offset = offset.abs();
    let SYSTEMTIME { wYear: year, wMonth: month, wDay: day,
        wHour: hour, wMinute: minute, wSecond: second, .. } = local;
    Ok((format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}{sign}{:02}:{:02}",
        offset / 60, offset % 60), format!("{year:04}{month:02}{day:02}-{hour:02}{minute:02}{second:02}")))
}

pub(super) struct Toast {
    publisher: Publisher,
    thread: Option<JoinHandle<()>>,
}

impl Toast {
    pub(super) fn start(
        cwd: &Path,
        engine: Arc<crate::pipeline::Engine>,
        diagnostic: PathBuf,
        retention: u64,
        report_error: impl Fn(&'static str, &io::Error) + Send + 'static,
    ) -> io::Result<Self> {
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
        let thread = thread::Builder::new()
            .name("sunpack-toast".into())
            .stack_size(512 * 1024)
            .spawn(move || {
                // Main initializes the DLL/presenter only for the first snapshot.
                let library = std::cell::OnceCell::new();
                let mut presenter: Option<super::windows::ToastPresenter<'_>> = None;
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
                        if let Some((completed, report)) = state.published.pop_front() {
                            break Display::Published(completed, report);
                        }
                        if let Some(completed) = state.completed.pop_front() {
                            if state.completed.capacity() > 256 {
                                crate::collections::trim_deque(&mut state.completed);
                            }
                            break if completed.needs_report() { Display::Completed(completed) }
                                else { Display::Published(completed, None) };
                        }
                        if state.dirty {
                            let group = state.group.as_ref().filter(|group| group.visible);
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
                            let remaining = state.group.as_ref()
                                .and_then(|group| group.finalize_at)
                                .map_or(remaining, |deadline| remaining.min(
                                    deadline.saturating_duration_since(Instant::now())));
                            state = presenter_shared
                                .changed
                                .wait_timeout(state, remaining)
                                .unwrap()
                                .0;
                        } else if let Some(deadline) = state.group.as_ref()
                            .and_then(|group| group.finalize_at)
                        {
                            let remaining = deadline.saturating_duration_since(Instant::now());
                            state = presenter_shared.changed.wait_timeout(state, remaining).unwrap().0;
                        } else {
                            state = presenter_shared.changed.wait(state).unwrap();
                        }
                    };
                    drop(state);
                    if matches!(display, Display::Clear) {
                        let error = presenter.as_ref().and_then(|current| current.clear().err());
                        if error.is_some() { presenter.take(); }
                        if let Some(error) = error { report_error("toast_error", &error); }
                        continue;
                    }
                    if let Display::Completed(completed) = display {
                        Publisher { shared: Arc::clone(&presenter_shared), reports: Arc::clone(&presenter_reports) }
                            .publish(&engine, completed);
                        continue;
                    }
                    let (snapshot, completion, published_report) = match display {
                        Display::Clear | Display::Completed(_) => unreachable!(),
                        Display::Progress(snapshot) => (snapshot, None, None),
                        Display::Published(completed, report) => {
                            (Snapshot::completed(&completed, report.clone()), Some(completed), report)
                        }
                    };
                    let payload = snapshot.encode();
                    // Validate and consume under the state gate, then call
                    // WinRT outside it. Only this thread performs native effects;
                    // newer progress, clear or stop is consumed on its next turn.
                    let mut available = true;
                    let mut failure = None;
                    let show = || {
                        sequence = sequence.wrapping_add(1);
                        available = show_snapshot(
                            &mut presenter,
                            || match library.get_or_init(|| ToastLibrary::load(&cwd)) {
                                Ok(library) => library.presenter(&diagnostic),
                                Err(error) => Err(io::Error::new(error.kind(), error.to_string())),
                            },
                            |presenter| presenter.show(&payload, sequence),
                            &mut |event, error| failure = Some((event, error)),
                        );
                    };
                    let shown = match completion.as_ref() {
                        Some(completed) => presenter_shared.present_completed(completed, show),
                        None => presenter_shared.present(&snapshot.batch, show),
                    };
                    if let Some((event, error)) = failure {
                        report_error(event, &error);
                    }
                    if !shown {
                        if let Some(path) = published_report {
                            let _ = fs::remove_file(path);
                        }
                        continue;
                    }
                    if !available {
                        {
                            let mut state = presenter_shared.state.lock().unwrap();
                            state.stopping = true;
                            if let Some(group) = &state.group { group.cancellation.cancel(); }
                        }
                        presenter_reports.cancellation.cancel();
                        break;
                    }
                    last_update = Some(Instant::now());
                }
                // Drain queued publications too: Activities may keep Shared
                // alive after the presenter exits, but cannot own stale files.
                presenter_shared.discard_batches();
            })?;
        Ok(Self {
            publisher: Publisher { shared, reports },
            thread: Some(thread),
        })
    }

    pub(super) fn register(&self, request: Arc<str>, language: Language) -> Activity {
        self.publisher.register(request, language)
    }

    pub(super) fn stop_group(&self, id: &str) -> Vec<Arc<str>> {
        self.publisher.stop_group(id)
    }

    pub(super) fn reset_batches(&self) {
        self.publisher.reset_batches();
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
    Published(Completed, Option<PathBuf>),
}

impl Drop for Toast {
    fn drop(&mut self) {
        {
            let mut state = self.publisher.shared.state.lock().unwrap();
            state.stopping = true;
            if let Some(group) = &state.group { group.cancellation.cancel(); }
        }
        self.publisher.reports.cancellation.cancel();
        self.publisher.shared.changed.notify_one();
        // Release presenter/COM before reload starts another activator.
        // Cancel and wake first, then join without holding the state lock.
        if let Some(thread) = self.thread.take() { let _ = thread.join(); }
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
                format: "zip".into(),
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
        Snapshot::progress(state.group.as_ref().unwrap())
    }

    #[test]
    fn failed_native_snapshot_is_consumed_and_next_snapshot_recreates_presenter() {
        use std::cell::{Cell, RefCell};
        struct Presenter<'a>(&'a Cell<usize>);
        impl Drop for Presenter<'_> {
            fn drop(&mut self) { self.0.set(self.0.get() + 1); }
        }
        let drops = Cell::new(0);
        let created = Cell::new(0);
        let events = RefCell::new(Vec::new());
        let mut log = |event, _: io::Error| events.borrow_mut().push(event);
        let mut presenter = Some(Presenter(&drops));
        assert!(show_snapshot(&mut presenter,
            || panic!("existing presenter must be reused"),
            |_| Err(io::Error::other("native Show failure")), &mut log));
        assert!(presenter.is_none());
        assert_eq!(drops.get(), 1);
        assert_eq!(events.borrow().as_slice(), ["toast_error"]);
        // No eager retry or replay: only this next snapshot creates a presenter.
        assert!(show_snapshot(&mut presenter,
            || { created.set(created.get() + 1); Ok(Presenter(&drops)) },
            |_| Ok(()), &mut log));
        assert_eq!(created.get(), 1);
        assert!(presenter.is_some());
        presenter.take();
        assert!(!show_snapshot(&mut presenter,
            || Err(io::Error::other("component initialization failure")),
            |_| panic!("unavailable component cannot show"), &mut log));
        assert_eq!(events.borrow().as_slice(), ["toast_error", "toast_unavailable"]);
    }

    #[test]
    fn terminal_progress_and_rollback_failure_keep_main_presentation() {
        let mut group = Group::new("00000000000000000000000000000001", Language::En);
        group.requests.insert(Arc::from("request"), RequestProgress::default());
        group.summary.succeeded = 1;
        let snapshot = Snapshot::progress(&group);
        assert_eq!(snapshot.progress, Some(1.0));
        assert_eq!(snapshot.value, "100% · 0 B / 0 B");
        group.active_roots = 1;
        assert_eq!(Snapshot::progress(&group).progress, None);
        group.totals.planned = 100;
        group.totals.written = 50;
        group.totals.unknown = 1;
        let snapshot = Snapshot::progress(&group);
        assert_eq!(snapshot.progress, None);
        assert_eq!(snapshot.value, Language::En.text("toast.progress.indeterminate"));
        // Stopping extraction keeps this batch valid: earlier failures still
        // need their final report. Only reset/disable invalidates report I/O.
        for request in group.requests.values_mut() { request.stopping = true; }
        let snapshot = Snapshot::progress(&group);
        assert_eq!(snapshot.body, Language::En.text("interrupt.stopping"));
        assert_eq!(snapshot.status, snapshot.body);
        assert!(snapshot.value.is_empty());
        for request in group.requests.values_mut() { request.stopping = false; }
        group.totals.unknown = 0;
        for (disk, memory, key) in [
            (0, 1, "report.status.memory_paused"),
            (1, 0, "report.status.disk_paused"),
            (1, 1, "report.status.resources_paused"),
        ] {
            group.totals.disk = disk;
            group.totals.memory = memory;
            let snapshot = Snapshot::progress(&group);
            assert_eq!(snapshot.progress, None);
            assert_eq!(snapshot.value, Language::En.text(key));
        }
        let mut completed = Completed {
            generation: 0, id: Arc::from("presentation"), language: Language::En,
            elapsed: Duration::ZERO, report: Arc::default(), cancellation: Cancellation::new(),
            summary: Summary { succeeded: 1, interrupted: 1, rollback_failed: true,
                ..Summary::default() },
        };
        let directory = TestDirectory::new();
        let publisher = publisher(directory.0.clone());
        let report = publisher.reports.publish(&completed, &publisher.shared).unwrap().unwrap();
        let text = fs::read_to_string(&report).unwrap();
        assert!(text.contains(&Language::En.translate("toast.report.summary", &[("failed", "1")])));
        assert_eq!(text.lines().count(), 4);
        let snapshot = Snapshot::completed(&completed, Some(report));
        assert_eq!(snapshot.kind, 4);
        assert!(snapshot.report_action.is_some());
        assert_eq!(snapshot.title, Language::En.text("toast.final.mixed.title"));
        let duration = Language::En.translate("duration.seconds", &[("seconds", "0")]);
        assert!(snapshot.body.starts_with(&Language::En.translate("toast.final.mixed.body",
            &[("succeeded", "1"), ("failed", "1"), ("duration", &duration)])));
        // Ordinary source cleanup is only a warning, not a rollback failure.
        completed.summary.interrupted = 0;
        completed.summary.rollback_failed = false;
        completed.summary.cleanup_warnings = Language::En.translate("cleanup.incomplete", &[("count", "1")]);
        let snapshot = Snapshot::completed(&completed, None);
        assert_eq!(snapshot.kind, 2);
        assert_eq!(snapshot.title, Language::En.text("toast.final.success.title"));
        assert!(snapshot.body.ends_with(&completed.summary.cleanup_warnings));
        let warning = Language::En.translate("cleanup.incomplete", &[("count", "2")]);
        completed.summary.merge(Summary { cleanup_warnings: warning.clone(), ..Summary::default() });
        let snapshot = Snapshot::completed(&completed, None);
        assert!(snapshot.body.ends_with(&format!("{}\n{}",
            Language::En.translate("cleanup.incomplete", &[("count", "1")]), warning)));
        // Match main's Unicode-character bound, including its ellipsis.
        let mut warnings = "界".repeat(2046);
        append_warning(&mut warnings, "两个警告");
        assert_eq!(warnings.chars().count(), 2048);
        assert!(warnings.ends_with("\n…"));
        let full = warnings.clone();
        append_warning(&mut warnings, "more");
        assert_eq!(warnings, full);
        let mut snapshot = Snapshot::stop_failed("batch", Language::En);
        assert_eq!(snapshot.kind, 3);
        assert_eq!(snapshot.title, "SunPack could not confirm stop");
        assert_eq!(snapshot.body, "Stop unconfirmed. Check the current processing status.");
        let target = format!("C:\\{}", "路径".repeat(1500));
        snapshot.action = Some((1, "Open".into(), target.clone()));
        assert!(snapshot.encode().ends_with(target.as_bytes()));
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
            result: crate::pipeline::TaskCompletion { discovery: None, status: crate::pipeline::TaskStatus::Complete, failure: None, output: None },
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
        assert_eq!(current(&publisher).title, Language::En.text("toast.progress.title"));
        // Earlier requests remain in cancellation cleanup; new work is visible
        // immediately and another Stop captures it in the same batch.
        let stopped_again = publisher.stop_group(&initial.batch);
        assert!(stopped_again.contains(&later.request));
        assert_eq!(stopped_again.len(), 3);
        a.finish(&Err(io::Error::other("output deletion failed")), true, true, one_root);
        b.finish(&Ok(Outcome::default()), true, false, one_root);
        assert!(publisher.shared.state.lock().unwrap().completed.is_empty());

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
        assert!(completed.body.contains(&Language::En.translate("cleanup.incomplete", &[("count", "1")])));
        assert!(state.group.is_none());
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
            promoted: false, promotion_original_path: None, scan_layout: Default::default(),
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
        let deadline = state.group.as_ref().unwrap().finalize_at.unwrap();
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
        activity.event(Event::Finished { id: 1, path: "a.zip".into(), depth: 1, result: crate::pipeline::TaskCompletion { discovery: None, status: crate::pipeline::TaskStatus::Failed, failure: None, output: None } });
        let mut outcome = Outcome::default();
        outcome.archives.push(archive("a.zip", Some(FailureKind::Damaged)));
        activity.root_finished(1, &outcome);
        assert!(publisher.shared.state.lock().unwrap().group.as_ref().unwrap().pending());
        activity.report_finished(1, true);
        assert!(!publisher.shared.state.lock().unwrap().group.as_ref().unwrap().pending());
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
        activity.event(Event::Finished { id: 1, path: "a.zip".into(), depth: 1, result: crate::pipeline::TaskCompletion { discovery: None, status: crate::pipeline::TaskStatus::Complete, failure: None, output: None } });
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
            activity.event(Event::Finished { id: 1, path: "a.zip".into(), depth: 1, result: crate::pipeline::TaskCompletion { discovery: None, status: crate::pipeline::TaskStatus::Complete, failure: None, output: None } });
            assert_eq!(current(&publisher).status, "0/3 finished");
            let mut done = Outcome::default();
            done.archives.push(archive("a.zip", None));
            done.archives.push(archive("a/nested.zip", None));
            done.cleanup_results.push(crate::pipeline::CleanupResult {
                path: "a.zip".into(), mode: "delete", status: CleanupStatus::Failed,
                error_code: 5, message: "source busy".into(),
            });
            activity.root_finished(1, &done);
            assert!(!activity.needs_root_report(1));
            activity.record_root(1, Path::new("a.zip"), &done);
            activity.report_finished(1, false);
            {
                let state = publisher.shared.state.lock().unwrap();
                let request = &state.group.as_ref().unwrap().requests[&activity.request];
                assert!(!request.roots.contains_key(&1));
                assert!(!request.task_roots.values().any(|root| *root == 1));
                assert!(!request.started.contains_key(&1));
                assert!(!request.visible_roots.contains(&1));
                let report = state.group.as_ref().unwrap().report.lock().unwrap();
                assert_eq!(report.failures, 0);
                assert!(report.path.as_ref().is_none_or(|path| !path.exists()));
            }
            assert_eq!(current(&publisher).status, "1/3 finished");
            let mut failed = Outcome::default();
            failed.archives.push(archive("c.zip", Some(FailureKind::Damaged)));
            activity.event(Event::Finished { id: 3, path: "c.zip".into(), depth: 1, result: crate::pipeline::TaskCompletion { discovery: None, status: crate::pipeline::TaskStatus::Failed, failure: None, output: None } });
            activity.root_finished(3, &failed);
            assert!(activity.needs_root_report(3));
            activity.record_root(3, Path::new("c.zip"), &failed);
            activity.report_finished(3, false);
            assert!(!activity.needs_root_report(3));
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
            let group = state.group.as_ref().unwrap();
            assert_eq!(group.summary.succeeded, 1);
            assert_eq!(group.summary.failed, if cancelled { 1 } else { 2 });
            assert_eq!(group.summary.interrupted, usize::from(cancelled));
            assert_eq!(group.summary.cleanup_warnings, Language::En.translate("cleanup.incomplete", &[("count", "1")]));
            // Only failed roots belong in the report; A's source cleanup
            // remains a warning and must not add a failure entry.
            assert_eq!(group.report.lock().unwrap().failures, if cancelled { 1 } else { 2 });
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
        activity.event(Event::Finished { id: 1, path: "a.zip".into(), depth: 1, result: crate::pipeline::TaskCompletion { discovery: None, status: crate::pipeline::TaskStatus::Complete, failure: None, output: None } });
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
        let mut segment = archive("c/nested.zip", Some(FailureKind::Damaged));
        segment.offset = 100;
        outcome.archives.push(segment);
        outcome.archives.push(archive("c/another.zip", Some(FailureKind::Damaged)));
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
        assert!(text.lines().any(|line| line == "[1] c.zip"));
        assert!(!text.lines().any(|line| line.starts_with("[2] ")));
        let prefix = Language::En.translate("toast.report.details", &[("details", "")]);
        let details: serde_json::Value = serde_json::from_str(
            text.lines().find_map(|line| line.strip_prefix(&prefix)).unwrap()).unwrap();
        assert_eq!(details.as_array().unwrap().len(), 2);
        assert_eq!(details[0]["kind"], "inputs_failed");
        assert_eq!(details[0]["causes"].as_array().unwrap().len(), 2);
        assert_eq!(details[1]["kind"], "damaged");
        assert!(!text.contains("promoted.zip"));
        assert!(!text.lines().any(|line| line.ends_with("] d.zip")));

        // No owner metadata: independent paths stay independent, while
        // case-folded segments of one physical carrier remain one task.
        let mut outcome = Outcome::default();
        outcome.archives.push(archive("a.zip", None));
        outcome.archives.push(archive("A.ZIP", None));
        outcome.archives.push(archive("b.zip", None));
        let summary = Summary::for_result(Language::En, &Ok(outcome), false, false, true, &|_| None, None);
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
            assert!(state.group.is_none());
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
            assert!(publisher.shared.state.lock().unwrap().group.is_none());
            assert!(publisher.shared.state.lock().unwrap().completed.is_empty());
            assert!(!directory.0.exists());

            let mut accepted = archive("carrier.bin", Some(kind));
            accepted.partial = true;
            let mut outcome = Outcome::default();
            outcome.archives.push(accepted);
            let summary = Summary::for_result(Language::En, &Ok(outcome), false, false, true, &one_root, None);
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
            scan_count: Some(7), failure: None,
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
            .group.as_ref().unwrap().finalize_at.unwrap();
        let b = publisher.register(Arc::from("02"), Language::En);
        b.event(queued(2, "next.zip", None, 0));
        {
            let mut state = publisher.shared.state.lock().unwrap();
            assert_eq!(state.group.as_ref().unwrap().finalize_at, Some(first_deadline));
            state.settle(first_deadline - Duration::from_millis(1));
            assert!(state.completed.is_empty());
        }
        progress(&b, 2, "next.zip", 1, 2);
        assert!(publisher.shared.state.lock().unwrap().group.as_ref().unwrap().finalize_at.is_none());
        assert_eq!(current(&publisher).status, "1/2 finished");
        b.finish(&success(), false, false, one_root);
        finish_debounce(&publisher);
        {
            let completed = take_completed(&publisher);
            let state = publisher.shared.state.lock().unwrap();
            assert_eq!(completed.summary.succeeded, 2);
            assert_eq!(state.group.as_ref().unwrap().requests.len(), 1);
            assert_ne!(state.group.as_ref().unwrap().id, completed.id);
        }
        progress(&c, 3, "slow-scan.zip", 1, 2);
        assert_eq!(current(&publisher).label, "slow-scan.zip");
        assert_eq!(current(&publisher).status, "0/1 finished");
        c.finish(&success(), false, false, one_root);
        finish_debounce(&publisher);
        assert_eq!(take_completed(&publisher).summary.succeeded, 1);
        assert!(publisher.shared.state.lock().unwrap().group.is_none());
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
            summary: Summary { failed: 3, ..Summary::default() }, report: draft, cancellation: Cancellation::new(),
        };
        assert!(publisher.reports.publish(&completed, &publisher.shared).unwrap().is_none());
        drop(completed);
        assert!(!path.exists());
    }

    #[test]
    fn idle_toast_start_stop_does_not_require_a_native_presenter() {
        let directory = TestDirectory::new();
        let errors = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let engine = Arc::new(crate::pipeline::Engine::new(directory.0.join("unused-worker.exe")));
        for _ in 0..3 {
            let reported = Arc::clone(&errors);
            let host = Toast::start(&directory.0, Arc::clone(&engine), directory.0.join("toast.log"), 7,
                move |_, _| { reported.fetch_add(1, Ordering::Relaxed); }).unwrap();
            drop(host);
        }
        assert_eq!(errors.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn disabling_toasts_cancels_then_joins_an_active_report_writer() {
        // Hold a writer on a channel rather than timing large disk writes.
        // Cancellation is immediate; stop must still await owner teardown.
        let directory = TestDirectory::new();
        let publisher = publisher(directory.0.clone());
        let draft = Arc::new(Mutex::new(ReportDraft::default()));
        let result = Err(io::Error::other("failure"));
        publisher.reports.append("81", Language::En, &draft, Path::new("a.zip"), &result, &one_root, None).unwrap();
        let path = draft.lock().unwrap().path.clone().unwrap();
        let completed = Completed {
            generation: 0,
            id: Arc::from("81"), language: Language::En, elapsed: Duration::ZERO,
            summary: Summary { failed: 1, ..Summary::default() }, report: draft, cancellation: Cancellation::new(),
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
            assert!(!worker.shared.present("81", || panic!("stale toast after disable")));
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
        let mut state = publisher.shared.state.lock().unwrap();
        while !state.stopping { state = publisher.shared.changed.wait(state).unwrap(); }
        drop(state);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !publisher.reports.cancellation.cancelled() && Instant::now() < deadline { thread::yield_now(); }
        assert!(publisher.reports.cancellation.cancelled());
        let returned = stop_complete.try_recv();
        // Always release before asserting, so a regression cannot leak a
        // blocked test thread or leave the temporary report locked.
        release.send(()).unwrap();
        stop.join().unwrap();
        assert!(matches!(returned, Err(mpsc::TryRecvError::Empty)), "disable returned before owner exit");
        stop_complete.recv_timeout(Duration::from_secs(5)).unwrap();
        finished.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(!path.exists());
        assert!(!fs::read_dir(&directory.0).unwrap().any(|entry| {
            entry.unwrap().path().extension().is_some_and(|ext| ext == "txt")
        }));
    }
    #[test]
    fn semantic_reload_retires_debouncing_and_in_flight_batches() {
        for in_flight in [false, true] {
            let directory = TestDirectory::new();
            let publisher = publisher(directory.0.clone());
            let old = publisher.register(Arc::from("01"), Language::En);
            old.event(queued(1, "old.zip", None, 0));
            progress(&old, 1, "old.zip", 1, 2);
            let stale_progress = current(&publisher);
            let failure = Err(io::Error::other("old failure"));
            old.record(Path::new("old.zip"), &failure, false, one_root);
            old.finish(&failure, false, false, one_root);
            let completed = if in_flight {
                finish_debounce(&publisher);
                publisher.shared.state.lock().unwrap().completed.pop_front()
            } else { None };
            publisher.reset_batches();
            assert!(publisher.shared.state.lock().unwrap().clear);
            let new = publisher.register(Arc::from("02"), Language::Zh);
            new.event(queued(2, "new.zip", None, 0));
            progress(&new, 2, "new.zip", 1, 2);
            assert!(!publisher.shared.present(&stale_progress.batch, || panic!("stale progress")));
            if let Some(completed) = completed {
                assert!(!publisher.shared.present_completed(&completed, || panic!("stale completion")));
            }
            let state = publisher.shared.state.lock().unwrap();
            assert_eq!(state.group.iter().count(), 1);
            assert!(state.completed.is_empty());
            let group = state.group.as_ref().unwrap();
            assert!(group.requests.contains_key("02"));
            assert_ne!(group.id.as_ref(), stale_progress.batch);
            assert_eq!(group.language, Language::Zh);
            assert_eq!(group.summary.failed, 0);
            assert!(group.report.lock().unwrap().path.is_none());
        }
    }

    #[test]
    fn presenter_shutdown_discards_queued_report_and_draft_with_live_activity() {
        let directory = TestDirectory::new();
        let publisher = publisher(directory.0.clone());
        let activity = publisher.register(Arc::from("01"), Language::En);
        activity.event(queued(1, "failed.zip", None, 0));
        progress(&activity, 1, "failed.zip", 1, 2);
        let failure = Err(io::Error::other("failure"));
        activity.record(Path::new("failed.zip"), &failure, false, one_root);
        activity.finish(&failure, false, false, one_root);
        finish_debounce(&publisher);
        let completed = publisher.shared.state.lock().unwrap().completed.pop_front().unwrap();
        let draft_path = completed.report.lock().unwrap().path.clone().unwrap();
        let engine = crate::pipeline::Engine::new(PathBuf::new());
        publisher.publish(&engine, completed).join().unwrap();
        let report_path = publisher.shared.state.lock().unwrap().published.front()
            .unwrap().1.clone().unwrap();
        assert!(report_path.exists());
        assert!(draft_path.exists());
        // Both disable and unrecoverable presenter failure exit through this
        // cleanup, while extraction observers may still retain the Activity.
        publisher.shared.state.lock().unwrap().stopping = true;
        publisher.shared.discard_batches();
        assert!(!report_path.exists());
        assert!(!draft_path.exists());
        let state = activity.publisher.shared.state.lock().unwrap();
        assert!(state.group.is_none());
        assert!(state.completed.is_empty());
        assert!(state.published.is_empty());
    }

    #[test]
    fn stopping_remaining_work_preserves_the_batch_failure_report() {
        let directory = TestDirectory::new();
        let publisher = publisher(directory.0.clone());
        let failed = publisher.register(Arc::from("01"), Language::En);
        let running = publisher.register(Arc::from("02"), Language::En);
        failed.event(queued(1, "failed.zip", None, 0));
        progress(&failed, 1, "failed.zip", 1, 2);
        running.event(queued(2, "running.zip", None, 0));
        progress(&running, 2, "running.zip", 1, 2);
        let failure = Err(io::Error::other("archive failure before user stop"));
        failed.record(Path::new("failed.zip"), &failure, false, one_root);
        failed.finish(&failure, false, false, one_root);
        let batch = current(&publisher).batch;
        assert_eq!(publisher.stop_group(&batch), vec![Arc::<str>::from("02")]);
        running.finish(&Ok(Outcome::default()), true, false, one_root);
        finish_debounce(&publisher);
        let completed = publisher.shared.state.lock().unwrap().completed.pop_front().unwrap();
        assert_eq!(completed.summary.failed, 1);
        assert_eq!(completed.summary.interrupted, 1);
        assert!(!completed.cancellation.cancelled());
        let engine = crate::pipeline::Engine::new(PathBuf::new());
        publisher.publish(&engine, completed).join().unwrap();
        let (completed, report) = publisher.shared.state.lock().unwrap().published.pop_front().unwrap();
        let report = report.expect("stopping must retain previous failures");
        assert!(fs::read_to_string(&report).unwrap().contains("archive failure before user stop"));
        assert!(Snapshot::completed(&completed, Some(report)).report_action.is_some());
        assert!(publisher.shared.present_completed(&completed, || {}));
    }

    #[test]
    fn report_publication_does_not_block_progress_and_reset_cancels_its_io() {
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
        let cancel = completed.cancellation.clone();
        let draft = Arc::clone(&completed.report);
        // Hold the actual report I/O gate, not a timed large-file simulation.
        // Dispatch and progress must remain usable until this gate is released.
        let held = draft.lock().unwrap();
        let engine = crate::pipeline::Engine::new(PathBuf::new());
        let publication = publisher.publish(&engine, completed);
        let next = publisher.register(Arc::from("02"), Language::En);
        next.event(queued(2, "next.zip", None, 0));
        progress(&next, 2, "next.zip", 1, 2);
        progress(&next, 2, "next.zip", 1, 2);
        let snapshot = current(&publisher);
        assert!(publisher.shared.present(&snapshot.batch, || {}));
        assert!(!cancel.cancelled());
        publisher.reset_batches();
        assert!(cancel.cancelled());
        assert!(publisher.shared.state.lock().unwrap().clear);
        drop(held);
        publication.join().unwrap();
        assert!(publisher.shared.state.lock().unwrap().published.is_empty());
        assert!(fs::read_dir(&directory.0).unwrap().flatten().all(|entry| {
            !entry.file_name().to_string_lossy().starts_with("failed-")
        }));
    }

    #[test]
    fn native_presentation_releases_state_before_sending_progress_and_completion() {
        let directory = TestDirectory::new();
        let publisher = publisher(directory.0.clone());
        let first = publisher.register(Arc::from("01"), Language::En);
        first.event(queued(1, "first.zip", None, 0));
        progress(&first, 1, "first.zip", 1, 2);
        assert!(publisher.shared.present(&current(&publisher).batch, || {
            assert!(publisher.shared.state.try_lock().is_ok());
            progress(&first, 1, "first.zip", 1, 2);
        }));
        first.finish(&success(), false, false, one_root);
        finish_debounce(&publisher);
        let completed = publisher.shared.state.lock().unwrap().completed.pop_front().unwrap();
        assert!(publisher.shared.present_completed(&completed, || {
            assert!(publisher.shared.state.try_lock().is_ok());
            let next = publisher.register(Arc::from("02"), Language::En);
            next.event(queued(2, "next.zip", None, 0));
            progress(&next, 2, "next.zip", 1, 2);
            progress(&next, 2, "next.zip", 1, 2);
            assert_ne!(current(&publisher).batch, completed.id.as_ref());
        }));
        assert_eq!(publisher.shared.state.lock().unwrap().group.iter().count(), 1);
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
        assert_eq!(publisher.shared.state.lock().unwrap().group.as_ref().unwrap().summary.failed, 2);
        finish_debounce(&publisher);
        let completed = publisher.shared.state.lock().unwrap().completed.pop_front().unwrap();
        let report = publisher.reports.publish(&completed, &publisher.shared).unwrap().unwrap();
        assert!(publisher.shared.present_completed(&completed, || {}));
        assert!(publisher.shared.state.lock().unwrap().group.is_none());
        let text = fs::read_to_string(report).unwrap();
        assert!(text.contains("first failure"));
        assert!(text.contains("second failure"));
        assert_eq!(completed.summary.failed, 2);
    }
}
