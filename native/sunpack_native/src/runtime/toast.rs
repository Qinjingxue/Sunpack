use super::windows::{self, ToastLibrary};
use crate::core::i18n::Language;
use crate::failure_report::{append_failure_report, publish_failure_report, FailureRecord};
use crate::pipeline::{Cancellation, Outcome};
use std::collections::VecDeque;
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
    action: Option<(u8, String, String)>,
    report_action: Option<(u8, String, String)>,
}

impl Snapshot {
    pub(super) fn progress(
        batch: &str,
        language: Language,
        path: PathBuf,
        completed: u64,
        total: u64,
    ) -> Self {
        let progress = (total > 0).then(|| (completed as f64 / total as f64).clamp(0.0, 1.0));
        Self {
            batch: batch.to_owned(),
            kind: 1,
            title: language.text("toast.progress.title").to_owned(),
            body: String::new(),
            progress,
            label: path
                .file_name()
                .unwrap_or(path.as_os_str())
                .to_string_lossy()
                .into_owned(),
            action: Some((
                3,
                language.text("interrupt.stop").to_owned(),
                batch.to_owned(),
            )),
            report_action: None,
        }
    }

    pub(super) fn cancelled(batch: &str, language: Language) -> Self {
        Self {
            batch: batch.to_owned(),
            kind: 3,
            title: language.text("interrupt.finished").to_owned(),
            body: language.text("interrupt.cleaned").to_owned(),
            progress: None,
            label: String::new(),
            action: None,
            report_action: None,
        }
    }

    fn completed(
        batch: &str,
        language: Language,
        outcome: &Outcome,
        elapsed: Duration,
        report: Option<PathBuf>,
    ) -> Self {
        let succeeded = outcome.succeeded();
        let failed = outcome.failed();
        let (kind, suffix) = match (succeeded, failed) {
            (_, 0) => (2, "success"),
            (0, _) => (3, "failure"),
            _ => (4, "mixed"),
        };
        let seconds = elapsed.as_secs();
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
        let title = language
            .text(&format!("toast.final.{suffix}.title"))
            .to_owned();
        let body = language.translate(
            &format!("toast.final.{suffix}.body"),
            &[
                ("succeeded", &succeeded.to_string()),
                ("failed", &failed.to_string()),
                ("duration", &duration),
            ],
        );
        let action = outcome
            .archives
            .iter()
            .find_map(|archive| archive.output.as_ref())
            .map(|path| {
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
            batch: batch.to_owned(),
            kind,
            title,
            body,
            progress: None,
            label: String::new(),
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
        for field in [&self.batch, &self.title, &self.body, &self.label, "", ""] {
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
    progress: Option<Snapshot>,
    completed: VecDeque<Snapshot>,
    stopping: bool,
}

#[derive(Default)]
struct Shared {
    state: Mutex<State>,
    changed: Condvar,
}

#[derive(Clone)]
pub(super) struct Publisher {
    shared: Arc<Shared>,
    reports: Arc<Reports>,
}

impl Publisher {
    pub(super) fn publish(&self, snapshot: Snapshot) {
        let mut state = self.shared.state.lock().unwrap();
        if state.stopping {
            return;
        }
        if snapshot.kind == 1 {
            state.progress = Some(snapshot);
        } else {
            if state
                .progress
                .as_ref()
                .is_some_and(|previous| previous.batch == snapshot.batch)
            {
                state.progress = None;
            }
            state.completed.push_back(snapshot);
        }
        drop(state);
        self.shared.changed.notify_one();
    }

    pub(super) fn publish_completed(
        &self,
        batch: &str,
        language: Language,
        outcome: &Outcome,
        elapsed: Duration,
    ) {
        let report = match self.reports.publish(language, outcome) {
            Ok(path) => path,
            Err(error) => {
                eprintln!("SunPack toast failure report: {error}");
                None
            }
        };
        self.publish(Snapshot::completed(
            batch, language, outcome, elapsed, report,
        ));
    }
}

struct Reports {
    directory: PathBuf,
    retention: AtomicU64,
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
        self.failures += 1;
        let header = self.language.translate(
            "toast.report.failure",
            &[
                ("index", &self.failures.to_string()),
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
        )
    }
}

impl Reports {
    fn publish(&self, language: Language, outcome: &Outcome) -> io::Result<Option<PathBuf>> {
        if outcome.failed() == 0 && outcome.errors.is_empty() {
            return Ok(None);
        }
        let suffix = u64::from_ne_bytes(windows::random_bytes::<8>()?);
        let now = SystemTime::now();
        let seconds = now
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let output = self
            .directory
            .join(format!("failed-{seconds:020}-{suffix:016x}.txt"));
        let details = self.directory.join(format!("batch-{suffix:016x}.tmp"));
        let temp = output.with_extension("tmp");
        let cancel = Cancellation::default();
        let result = (|| {
            let mut spool = FailureSpool {
                path: &details,
                language,
                cancellation: &cancel,
                error_prefix: language.translate("toast.report.error", &[("error", "")]),
                details_prefix: language.translate("toast.report.details", &[("details", "")]),
                failures: 0,
            };
            for archive in &outcome.archives {
                if let Some(failure) = &archive.failure {
                    spool.append(&archive.path, &failure.message, failure)?;
                }
            }
            for error in &outcome.errors {
                spool.append(&error.path, &error.message, error)?;
            }
            let failures = spool.failures;
            let title = language.text("toast.report.title");
            let timestamp = report_time();
            let generated =
                language.translate("toast.report.generated", &[("timestamp", &timestamp)]);
            let summary =
                language.translate("toast.report.summary", &[("failed", &failures.to_string())]);
            publish_failure_report(
                (failures != 0).then_some(details.as_path()),
                &temp,
                &output,
                [title, "\n", &generated, "\n", &summary, "\n\n"],
                &cancel,
            )
        })();
        let _ = fs::remove_file(details);
        result?;
        self.trim(now);
        Ok(Some(output))
    }

    fn trim(&self, now: SystemTime) {
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
                    let snapshot = loop {
                        if state.stopping {
                            return;
                        }
                        if let Some(snapshot) = state.completed.pop_front() {
                            break snapshot;
                        }
                        if state.progress.is_some() {
                            let remaining = last_update.map_or(Duration::ZERO, |last| {
                                minimum_interval.saturating_sub(last.elapsed())
                            });
                            if remaining.is_zero() {
                                break state.progress.take().unwrap();
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

    pub(super) fn publisher(&self) -> Publisher {
        self.publisher.clone()
    }

    pub(super) fn set_report_retention(&self, days: u64) {
        self.publisher
            .reports
            .retention
            .store(days, Ordering::Relaxed);
    }
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
