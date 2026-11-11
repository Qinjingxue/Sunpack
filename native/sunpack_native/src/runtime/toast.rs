use super::windows::ToastLibrary;
use crate::core::i18n::Language;
use crate::failure_report::{append_failure_report, publish_failure_report, FailureRecord};
use crate::pipeline::{
    Cancellation, CleanupStatus, Event, FailureKind, InputErrorKind, Outcome, ResourceWait, TaskId,
};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};
use std::{fs, io};

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
        let count = totals.finished + totals.active;
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
                    .flat_map(|tasks| tasks.values())
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
                        ("completed", &totals.finished.to_string()),
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
                    ("completed", &totals.finished.to_string()),
                    ("total", &count.to_string()),
                ],
            ),
            progress,
            label: if count == 1 {
                group.name.as_ref().map_or_else(
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

    fn completed(group: Completed, report: Option<PathBuf>) -> Self {
        let language = group.language;
        let summary = group.summary;
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
        if summary.interrupted {
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
        let action = summary.output.map(|path| {
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
}

struct Group {
    id: Arc<str>,
    name: Option<(TaskId, String)>,
    language: Language,
    began: Instant,
    visible: bool,
    stopping: bool,
    requests: HashMap<Arc<str>, HashMap<TaskId, TaskProgress>>,
    totals: Totals,
    summary: Summary,
    report: Arc<Mutex<ReportDraft>>,
}

#[derive(Default)]
struct Summary {
    succeeded: usize,
    failed: usize,
    interrupted: bool,
    rollback_failed: bool,
    cleanup_failed: usize,
    output: Option<PathBuf>,
}

struct Completed {
    id: Arc<str>,
    language: Language,
    elapsed: Duration,
    summary: Summary,
    report: Arc<Mutex<ReportDraft>>,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct TaskProgress {
    written: u64,
    planned: u64,
    wait: ResourceWait,
}

#[derive(Default)]
struct Totals {
    active: usize,
    unknown: usize,
    disk: usize,
    memory: usize,
    volume_errors: usize,
    written: u128,
    planned: u128,
    finished: usize,
    done_bytes: u128,
}

impl Totals {
    fn add(&mut self, task: TaskProgress) {
        self.active += 1;
        self.unknown += usize::from(task.planned == 0);
        self.disk += usize::from(task.wait.disk);
        self.memory += usize::from(task.wait.memory);
        self.volume_errors += usize::from(task.wait.volume_error.is_some());
        self.planned += u128::from(task.planned);
        self.written += u128::from(task.written.min(task.planned));
    }

    fn remove(&mut self, task: TaskProgress, finished: bool) {
        self.active -= 1;
        self.unknown -= usize::from(task.planned == 0);
        self.disk -= usize::from(task.wait.disk);
        self.memory -= usize::from(task.wait.memory);
        self.volume_errors -= usize::from(task.wait.volume_error.is_some());
        self.planned -= u128::from(task.planned);
        self.written -= u128::from(task.written.min(task.planned));
        if finished {
            self.finished += 1;
            self.done_bytes += u128::from(task.planned);
        }
    }
}

impl Group {
    fn event(&mut self, request: &str, event: Event) -> bool {
        let Some(tasks) = self.requests.get_mut(request) else {
            return false;
        };
        let id = match event {
            Event::Queued {
                id,
                parent,
                segment,
                path,
                ..
            } => {
                if segment.is_some() {
                    if let Some(task) = parent.and_then(|parent| tasks.remove(&parent)) {
                        self.totals.remove(task, false);
                    }
                }
                if let std::collections::hash_map::Entry::Vacant(slot) = tasks.entry(id) {
                    if self.totals.active == 0 && self.totals.finished == 0 {
                        let name = path
                            .file_name()
                            .unwrap_or(path.as_os_str())
                            .to_string_lossy()
                            .into_owned();
                        self.name = Some((id, name));
                    }
                    let task = TaskProgress::default();
                    slot.insert(task);
                    self.totals.add(task);
                    return true;
                }
                return false;
            }
            Event::Finished { id, .. } | Event::Skipped { id } => {
                if let Some(task) = tasks.remove(&id) {
                    let finished = matches!(event, Event::Finished { .. });
                    if !finished && self.name.as_ref().is_some_and(|(named, _)| *named == id) {
                        self.name = None;
                    }
                    self.totals.remove(task, finished);
                    if tasks.capacity() > 256 {
                        crate::collections::trim_map(tasks);
                    }
                    return true;
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
        let visible = self.visible;
        let before = *task;
        match event {
            Event::Working { .. } => {
                self.visible = true;
                *task = TaskProgress::default();
            }
            Event::Progress {
                completed_bytes,
                total_bytes,
                ..
            } => {
                self.visible = true;
                task.written = completed_bytes;
                task.planned = total_bytes;
            }
            Event::ResourceWait { state, .. } => {
                self.visible |= state.disk || state.memory;
                task.wait = state;
            }
            Event::Finalizing { .. } => task.wait = ResourceWait::default(),
            _ => unreachable!(),
        }
        if before != *task {
            self.totals.remove(before, false);
            self.totals.add(*task);
            true
        } else {
            visible != self.visible
        }
    }

    fn finish(&mut self, request: &str, summary: Summary) -> bool {
        let Some(tasks) = self.requests.remove(request) else {
            return false;
        };
        for task in tasks.into_values() {
            self.totals.remove(task, true);
        }
        if self.requests.capacity() > 256 {
            crate::collections::trim_map(&mut self.requests);
        }
        self.summary.merge(summary);
        true
    }
}

impl Summary {
    fn for_result(
        result: &io::Result<Outcome>,
        cancelled: bool,
        output_cleanup_failed: bool,
    ) -> Self {
        let mut summary = Self {
            interrupted: cancelled,
            rollback_failed: cancelled && output_cleanup_failed,
            cleanup_failed: usize::from(!cancelled && output_cleanup_failed),
            ..Self::default()
        };
        match result {
            Ok(outcome) => {
                summary.failed = outcome
                    .errors
                    .iter()
                    .filter(|error| error.kind != InputErrorKind::Cleanup)
                    .map(|error| error.count())
                    .sum();
                for archive in &outcome.archives {
                    if archive.failure.is_none() || archive.partial {
                        summary.succeeded += 1;
                    } else if archive
                        .failure
                        .as_ref()
                        .is_some_and(|failure| failure.kind == FailureKind::Cancelled)
                    {
                        summary.interrupted = true;
                    } else {
                        summary.failed += 1;
                    }
                }
                let mut outputs = outcome
                    .archives
                    .iter()
                    .filter_map(|archive| archive.output.as_deref());
                summary.output = crate::pipeline::common_ancestor(outputs.clone())
                    .or_else(|| outputs.next().map(Path::to_owned));
                summary.cleanup_failed += outcome
                    .cleanup_results
                    .iter()
                    .filter(|result| result.status == CleanupStatus::Failed)
                    .count();
            }
            Err(_) if !cancelled => summary.failed = 1,
            Err(_) => {}
        }
        summary
    }

    fn merge(&mut self, other: Self) {
        self.succeeded += other.succeeded;
        self.failed += other.failed;
        self.interrupted |= other.interrupted;
        self.rollback_failed |= other.rollback_failed;
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

#[derive(Default)]
struct Shared {
    state: Mutex<State>,
    changed: Condvar,
}

#[derive(Clone)]
struct Publisher {
    shared: Arc<Shared>,
    reports: Arc<Reports>,
}

#[derive(Clone)]
pub(super) struct Activity {
    publisher: Publisher,
    group: Arc<str>,
    request: Arc<str>,
    language: Language,
    report: Arc<Mutex<ReportDraft>>,
}

impl Publisher {
    fn register(&self, request: Arc<str>, language: Language) -> Activity {
        let mut state = self.shared.state.lock().unwrap();
        if state.groups.back().is_none_or(|group| group.stopping) {
            // Request IDs use the lower half of the token space. UI
            // activations use the upper half and can never hit a raw ID.
            let first = u8::from_str_radix(&request[..1], 16).expect("hex request ID");
            debug_assert!(first < 8);
            let id: Arc<str> = Arc::from(format!("{:x}{}", first | 8, &request[1..]));
            state.groups.push_back(Group {
                id,
                language,
                name: None,
                began: Instant::now(),
                visible: false,
                stopping: false,
                requests: HashMap::new(),
                totals: Totals::default(),
                summary: Summary::default(),
                report: Arc::default(),
            });
        }
        let group = state.groups.back_mut().unwrap();
        group.requests.insert(Arc::clone(&request), HashMap::new());
        Activity {
            publisher: self.clone(),
            group: Arc::clone(&group.id),
            request,
            language: group.language,
            report: Arc::clone(&group.report),
        }
    }

    fn stop_group(&self, id: &str) -> Vec<Arc<str>> {
        let mut state = self.shared.state.lock().unwrap();
        let Some(group) = state
            .groups
            .front_mut()
            .filter(|group| group.id.as_ref() == id && group.visible && !group.stopping)
        else {
            return Vec::new();
        };
        group.stopping = true;
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
        if let Some((index, group)) = state
            .groups
            .iter_mut()
            .enumerate()
            .find(|(_, group)| group.id == self.group)
        {
            if group.event(&self.request, event) && group.visible && index == 0 {
                self.publisher.mark_dirty(&mut state);
            }
        }
    }

    pub(super) fn finish(
        &self,
        result: &io::Result<Outcome>,
        cancelled: bool,
        output_cleanup_failed: bool,
    ) {
        let summary = Summary::for_result(result, cancelled, output_cleanup_failed);
        let mut state = self.publisher.shared.state.lock().unwrap();
        if state.stopping {
            return;
        }
        let Some((index, group)) = state
            .groups
            .iter_mut()
            .enumerate()
            .find(|(_, group)| group.id == self.group)
        else {
            return;
        };
        if !group.finish(&self.request, summary) || index != 0 {
            return;
        }
        while state
            .groups
            .front()
            .is_some_and(|group| group.requests.is_empty())
        {
            let group = state.groups.pop_front().unwrap();
            let summary = group.summary;
            if group.visible
                || summary.succeeded != 0
                || summary.failed != 0
                || summary.interrupted
                || summary.cleanup_failed != 0
            {
                state.completed.push_back(Completed {
                    id: group.id,
                    language: group.language,
                    elapsed: group.began.elapsed(),
                    summary,
                    report: group.report,
                });
            }
        }
        state.dirty = true;
        self.publisher.shared.changed.notify_one();
    }

    pub(super) fn record(
        &self,
        path: &Path,
        result: &io::Result<Outcome>,
        ignore_request_error: bool,
    ) {
        if self.publisher.shared.state.lock().unwrap().stopping {
            return;
        }
        let has_diagnostics = match result {
            Ok(outcome) => {
                !outcome.errors.is_empty()
                    || outcome.archives.iter().any(|archive| {
                        archive
                            .failure
                            .as_ref()
                            .is_some_and(|failure| failure.kind != FailureKind::Cancelled)
                    })
            }
            Err(_) => !ignore_request_error,
        };
        if has_diagnostics {
            if let Err(error) = self.publisher.reports.append(self, path, result) {
                eprintln!("SunPack toast failure report: {error}");
            }
        }
    }
}

struct Reports {
    directory: PathBuf,
    retention: AtomicU64,
}

#[derive(Default)]
struct ReportDraft {
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
        activity: &Activity,
        path: &Path,
        result: &io::Result<Outcome>,
    ) -> io::Result<()> {
        let language = activity.language;
        let cancel = Cancellation::default();
        let mut draft = activity.report.lock().unwrap();
        let failures = draft.failures;
        let details = draft
            .path
            .get_or_insert_with(|| self.directory.join(format!("batch-{}.tmp", activity.group)));
        let mut spool = FailureSpool {
            path: details,
            language,
            cancellation: &cancel,
            error_prefix: language.translate("toast.report.error", &[("error", "")]),
            details_prefix: language.translate("toast.report.details", &[("details", "")]),
            failures,
        };
        let written = (|| {
            match result {
                Ok(outcome) => {
                    for archive in &outcome.archives {
                        if let Some(failure) = archive
                            .failure
                            .as_ref()
                            .filter(|failure| failure.kind != FailureKind::Cancelled)
                        {
                            spool.append(&archive.path, &failure.message, failure)?;
                        }
                    }
                    for error in outcome
                        .errors
                        .iter()
                        .filter(|error| error.kind != InputErrorKind::Cleanup)
                    {
                        spool.append(&error.path, &error.message, error)?;
                    }
                    for cleanup in outcome
                        .cleanup_results
                        .iter()
                        .filter(|cleanup| cleanup.status == CleanupStatus::Failed)
                    {
                        spool.append(&cleanup.path, &cleanup.message, cleanup)?;
                    }
                }
                Err(error) => spool.append(path, &error.to_string(), &None::<String>)?,
            }
            Ok(())
        })();
        draft.failures = spool.failures;
        written
    }

    fn publish(&self, completed: &Completed, shared: &Shared) -> io::Result<Option<PathBuf>> {
        let draft = completed.report.lock().unwrap();
        if draft.failures == 0 {
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
            &[("failed", &draft.failures.to_string())],
        );
        publish_failure_report(
            draft.path.as_deref(),
            &output.with_extension("tmp"),
            &output,
            [title, "\n", &generated, "\n", &summary, "\n\n"],
            &Cancellation::default(),
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
                loop {
                    let mut state = presenter_shared.state.lock().unwrap();
                    let display = loop {
                        if state.stopping {
                            return;
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
                            state = presenter_shared
                                .changed
                                .wait_timeout(state, remaining)
                                .unwrap()
                                .0;
                        } else {
                            state = presenter_shared.changed.wait(state).unwrap();
                        }
                    };
                    drop(state);
                    let snapshot = match display {
                        Display::Progress(snapshot) => snapshot,
                        Display::Completed(completed) => {
                            let report =
                                match presenter_reports.publish(&completed, &presenter_shared) {
                                    Ok(report) => report,
                                    Err(error) => {
                                        eprintln!("SunPack toast failure report: {error}");
                                        None
                                    }
                                };
                            Snapshot::completed(completed, report)
                        }
                    };
                    sequence = sequence.wrapping_add(1);
                    let _ = presenter.show(&snapshot.encode(), sequence);
                    last_update = Some(Instant::now());
                }
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
    Progress(Snapshot),
    Completed(Completed),
}

impl Drop for Toast {
    fn drop(&mut self) {
        self.publisher.shared.state.lock().unwrap().stopping = true;
        self.publisher.shared.changed.notify_one();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::{CleanupResult, Segment};

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
        let publisher = Publisher {
            shared: Arc::default(),
            reports: Arc::new(Reports {
                directory: PathBuf::new(),
                retention: AtomicU64::new(30),
            }),
        };
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
        assert_eq!(initial.label, "3 archives");
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
        assert_eq!(snapshot.status, "1/3 finished");
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

        a.finish(&Err(io::Error::other("output deletion failed")), true, true);
        b.finish(&Ok(Outcome::default()), true, false);
        assert!(publisher.stop_group(&initial.batch).is_empty());
        assert_eq!(current(&publisher).label, "later.zip");
        let mut state = publisher.shared.state.lock().unwrap();
        let interrupted = Snapshot::completed(state.completed.pop_front().unwrap(), None);
        assert_eq!(
            interrupted.body,
            Language::En.text("interrupt.cleanup_failed")
        );
        assert!(state.completed.is_empty());
        drop(state);

        let mut outcome = Outcome::default();
        outcome.cleanup_results.push(CleanupResult {
            path: "later.zip".into(),
            mode: "delete",
            status: CleanupStatus::Failed,
            error_code: 5,
            message: "Access denied".to_owned(),
        });
        later.finish(&Ok(outcome), false, false);
        let mut state = publisher.shared.state.lock().unwrap();
        let completed = Snapshot::completed(state.completed.pop_front().unwrap(), None);
        assert!(completed.body.contains("Paths with cleanup errors: 1."));
        assert!(state.groups.is_empty());
    }
}
