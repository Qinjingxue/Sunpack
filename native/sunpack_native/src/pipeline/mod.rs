//! Shared archive orchestration for CLI requests and the Watch service.

mod checkpoint;
mod cleanup;
mod coordinator;
mod discovery;
mod passwords;
mod results;
pub(crate) mod scheduling;
mod shell_updates;
mod worker;
#[cfg(test)]
pub(crate) use worker::coalesced_wait_batches;

use crate::core::{config::Config, passwords::PasswordSnapshot};
use crate::io::reader::PhysicalFileGeneration;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub(crate) use crate::io::cancellation::Cancellation;
pub use checkpoint::InputCheckpoint;
pub(crate) use checkpoint::{InputRecovery, PromotedSource};
pub use coordinator::Engine;
pub(crate) use coordinator::{common_ancestor, common_output_base};
pub(crate) use discovery::scan_options;
pub(crate) use scheduling::{AsyncGate, block_on, in_control_poll, stage, Join as RequestHandle, Scheduler, MAX_PENDING_JOBS};

// Initialization failures have a distinct CLI boundary in main: closing the
// failed engine also closes its request broker, so the persistent host reports
// request failure (1), rather than usage (2) or a running-command error (3).
#[derive(Debug)]
pub(crate) struct StartupError(io::Error);

impl std::fmt::Display for StartupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
impl std::error::Error for StartupError {}

pub(crate) fn startup_error(error: io::Error) -> io::Error {
    if crate::io::cancellation::is_cancellation(&error) { error }
    else { io::Error::new(error.kind(), StartupError(error)) }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Scan,
    Extract,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    Foreground,
    Watch,
}

#[derive(Debug)]
pub struct BusyConflict {
    pub origin: Origin,
    pub paths: Vec<PathBuf>,
}

impl std::fmt::Display for BusyConflict {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(if self.origin == Origin::Watch {
            "Input is being processed by Watch"
        } else {
            "Input is already being processed"
        })
    }
}

impl std::error::Error for BusyConflict {}

#[derive(Clone)]
pub struct Request {
    pub inputs: Vec<PathBuf>,
    pub mode: Mode,
    pub origin: Origin,
    pub output_root: Option<PathBuf>,
    pub(crate) output_base: Option<PathBuf>,
    pub max_depth: usize,
    pub recursive: bool,
    pub direct: bool,
    pub deep: bool,
    pub passwords: Arc<[Arc<str>]>,
    pub password_snapshot: Option<Arc<PasswordSnapshot>>,
    pub(crate) password_scope: Option<PathBuf>,
    pub config: Arc<Config>,
    pub checkpoints: Vec<InputCheckpoint>,
    pub(crate) promoted_sources: Vec<PromotedSource>,
    pub(crate) cancel: Cancellation,
    pub(crate) discovery_scope: Option<crate::scan::scope::NativeDiscoveryScope>,
    pub(crate) watch_catalog: Option<Arc<crate::scan::directory::NativeWatchCatalog>>,
}

impl Request {
    pub fn new(inputs: Vec<PathBuf>, mode: Mode) -> Self {
        Self {
            inputs,
            mode,
            origin: Origin::Foreground,
            output_root: None,
            output_base: None,
            max_depth: 0,
            recursive: false,
            direct: false,
            deep: false,
            passwords: Arc::from([]),
            password_snapshot: None,
            password_scope: None,
            config: Arc::new(Config::default()),
            checkpoints: Vec::new(),
            promoted_sources: Vec::new(),
            cancel: Cancellation::new(),
            discovery_scope: None,
            watch_catalog: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DiscoverySource {
    Relations,
    Detection,
    Embedded,
    Direct,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    Cancelled,
    InvalidInput,
    FilesystemError,
    ProcessError,
    BackendUnavailable,
    Unsupported,
    MissingVolume,
    PasswordRequired,
    WrongPassword,
    PasswordInconclusive,
    Damaged,
    ResourceUnavailable,
    Unknown,
}

/// The creation boundary of a failure, retained for user-facing reports.
/// Native evidence remains separate: a worker phase is not the report stage.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum FailureContext {
    Discovery { discovery: DiscoverySource, reason: String, path: PathBuf, error: String },
    InputAdmission { missing_paths: Vec<PathBuf> },
    PasswordResolution,
    Extraction,
    WorkerWarning,
    OutputCreate { error: String, #[serde(default)] path: Option<PathBuf> },
    Postprocess { destination: PathBuf },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailureScope {
    pub root: String,
    pub max_depth: Option<usize>,
    pub excluded_subtrees: Vec<String>,
}

impl FailureScope {
    pub(crate) fn from_scope(scope: &crate::scan::scope::NativeDiscoveryScope) -> Self {
        let mut excluded_subtrees = scope.excluded_subtrees();
        excluded_subtrees.sort();
        Self { root: scope.root.clone(), max_depth: scope.max_depth, excluded_subtrees }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Failure {
    pub kind: FailureKind,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<Box<FailureContext>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery_scope: Option<Box<FailureScope>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) recovery: Option<Arc<checkpoint::InputRecovery>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub causes: Vec<Failure>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Box<FailureEvidence>>,
    /// Explicit classification decision, independent of fallback diagnostics.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) password_retry: bool,
}

impl Failure {
    /// Weak ZipCrypto validation does not authorize a password retry. The
    /// classifier separately marks the password-or-volume ambiguity.
    pub(crate) fn is_password_retry(&self) -> bool {
        matches!(self.kind, FailureKind::PasswordRequired | FailureKind::WrongPassword)
            || (self.kind == FailureKind::PasswordInconclusive && self.password_retry)
            || self.causes.iter().any(Self::is_password_retry)
    }

    pub(crate) fn contains(&self, kind: FailureKind) -> bool {
        self.kind == kind || self.causes.iter().any(|cause| cause.contains(kind))
    }

    pub(crate) fn with_context(mut self, context: FailureContext) -> Self {
        self.context = Some(Box::new(context));
        self
    }

    pub(crate) fn with_cause(mut self, cause: Option<Self>) -> Self {
        self.causes.extend(cause);
        self
    }

    pub(crate) fn new(kind: FailureKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            context: None,
            discovery_scope: None,
            recovery: None,
            causes: Vec::new(),
            evidence: None,
            password_retry: false,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FailureEvidence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hresult: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classification_evidence: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_crc_proven_items: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_operation_result: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub missing_volume_suspected: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub possible_missing_volume: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stderr_tail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive_read_fault: Option<ArchiveReadFault>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub missing_volume_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub missing_volume_evidence: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read: Option<FailureRead>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery: Option<RecoveryPreview>,
}

/// Field-level Rust preflight diagnostics, distinct from worker physical reads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveReadFault {
    pub code: String,
    pub operation: String,
    pub field: String,
    pub location: String,
    pub offset: u64,
    pub requested: usize,
    pub actual: usize,
    pub source_len: u64,
    pub volume_number: Option<u32>,
    pub possible_missing_volume: bool,
    pub missing_volume_hint: bool,
    pub io_kind: String,
    pub os_error: Option<i32>,
    pub detail: String,
}

impl From<&crate::io::read_fault::ReadFault> for ArchiveReadFault {
    fn from(fault: &crate::io::read_fault::ReadFault) -> Self {
        Self {
            code: fault.code.into(), operation: fault.operation.into(),
            field: fault.field.into(), location: fault.location.as_str().into(),
            offset: fault.offset, requested: fault.requested, actual: fault.actual,
            source_len: fault.source_len, volume_number: fault.volume_number,
            possible_missing_volume: fault.possible_missing_volume(),
            missing_volume_hint: fault.missing_volume_hint,
            io_kind: format!("{:?}", fault.io_kind), os_error: fault.os_error,
            detail: fault.detail.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailureRead {
    pub source_path: String,
    pub source_offset: u64,
    pub virtual_offset: u64,
    pub requested: u64,
    pub returned: u64,
    pub win32_error: i64,
    pub read_error: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RecoveryPreview {
    pub complete_files: usize,
    pub partial_files: usize,
    pub failed_files: usize,
    pub incomplete_files: usize,
    pub omitted_files: usize,
    pub files: Vec<RecoveryFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryFile {
    pub index: u32,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_path: Option<String>,
    pub status: RecoveryStatus,
    pub bytes_written: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_size: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryStatus {
    Complete,
    Partial,
    Failed,
    Incomplete,
}

#[derive(Debug, Serialize)]
pub struct InputError {
    pub path: PathBuf,
    pub message: String,
    pub kind: InputErrorKind,
    #[serde(skip)]
    pub(crate) failure: Option<Box<Failure>>,
    #[serde(rename = "operation", skip_serializing_if = "Option::is_none")]
    pub scan_operation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan_count: Option<usize>,
}

impl InputError {
    pub(crate) fn count(&self) -> usize {
        self.scan_count.unwrap_or(1)
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InputErrorKind {
    InvalidInput,
    FilesystemScan,
    EmbeddedDiscovery,
    Cleanup,
}

#[derive(Debug, Serialize)]
pub struct CleanupResult {
    pub path: PathBuf,
    pub mode: &'static str,
    pub status: CleanupStatus,
    pub error_code: i32,
    pub message: String,
}

/// An output directory could not be created; unlike a journal failure this
/// belongs to the individual archive, not the whole request.
#[derive(Debug)]
pub(crate) struct OutputCreateError(pub io::Error);

impl OutputCreateError {
    pub(crate) fn wrap(error: io::Error) -> io::Error {
        io::Error::new(error.kind(), Self(error))
    }
}

impl std::fmt::Display for OutputCreateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for OutputCreateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CleanupStatus {
    Deleted,
    Recycled,
    Kept,
    Missing,
    Failed,
}

#[derive(Debug, Serialize)]
pub struct ArchiveResult {
    #[serde(skip)]
    pub(crate) scan_layout: ScanLayout,
    pub path: PathBuf,
    pub format: String,
    pub output: Option<PathBuf>,
    pub failure: Option<Failure>,
    pub files: u64,
    pub bytes: u64,
    pub encrypted: Option<bool>,
    pub depth: usize,
    pub offset: u64,
    pub end_offset: Option<u64>,
    pub volume_completeness: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) volume_attempts: Option<Box<crate::io::archive_state::VolumeAttemptPlan>>,
    pub source_paths: Vec<PathBuf>,
    pub password: Option<String>,
    pub discovery_source: DiscoverySource,
    #[serde(skip)]
    pub(crate) damage_flags: Option<Arc<Vec<String>>>,
    pub partial: bool,
    pub retained: bool,
    pub recovered_complete_files: u64,
    pub promoted: bool,
    pub promotion_original_path: Option<PathBuf>,
}

/// Sparse presentation facts retained while the canonical input is available.
/// Extraction diagnostics keep their original completeness independently.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct ScanLayout {
    pub(crate) range: bool,
    pub(crate) volumes: bool,
}

impl ScanLayout {
    pub(crate) fn from_input(input: &crate::io::archive_state::ArchiveInput) -> Self {
        use crate::io::archive_state::{AnalysisOrigin, OpenMode};
        let extent = input.physical_extents().next();
        Self {
            range: extent.is_some_and(|extent| extent.start != 0
                || matches!(input.mode, OpenMode::FileRange | OpenMode::ConcatRanges)
                || extent.end.is_some() && input.analysis.origin == AnalysisOrigin::Embedded),
            volumes: !input.volume_style.is_empty() || input.mode.structured(),
        }
    }

    pub(crate) fn volumes<'a>(self, result: &'a ArchiveResult) -> (bool, Option<&'a str>) {
        let completeness = result.volume_completeness.as_deref();
        if result.volume_attempts.is_some() {
            return (false, Some(if completeness == Some("missing") { "missing" } else { "pending" }));
        }
        let show = self.volumes || result.source_paths.len() > 1 || completeness == Some("missing");
        (show, completeness.filter(|value| show && matches!(*value, "complete" | "missing")))
    }
}

/// Runtime disposition of one physical input. Carrier segments retain their
/// own output receipts, but retry causes belong to the carrier as a whole.
#[derive(Default)]
pub(crate) struct InputFailure<'a> {
    pub(crate) failed: bool,
    pub(crate) password: Option<&'a Failure>,
    pub(crate) missing: Option<&'a Failure>,
    pub(crate) terminal: Option<&'a Failure>,
}

impl<'a> InputFailure<'a> {
    pub(crate) fn retryable(&self) -> bool {
        self.failed && (self.password.is_some() || self.missing.is_some())
    }

    pub(crate) fn failure(&self) -> Option<&'a Failure> {
        self.failed.then(|| self.missing.or(self.password).or(self.terminal)).flatten()
    }
}

#[derive(Debug)]
pub(crate) struct ScanTaskFailure {
    pub(crate) path: PathBuf,
    pub(crate) archives: std::ops::Range<usize>,
    pub(crate) preflight: Option<Box<Failure>>,
}

#[derive(Debug, Default, Serialize)]
pub struct Outcome {
    pub archives: Vec<ArchiveResult>,
    pub errors: Vec<InputError>,
    #[serde(skip)]
    pub(crate) scan_failures: Vec<ScanTaskFailure>,
    #[serde(skip)]
    pub checkpoints: Vec<InputCheckpoint>,
    pub cleanup_results: Vec<CleanupResult>,
    #[serde(skip)]
    pub(crate) promoted_sources: Vec<PromotedSource>,
    #[serde(skip)]
    pub(crate) coalesced_from: Option<u64>,
    #[serde(skip)]
    scan_incomplete: bool,
    #[serde(skip)]
    uncommitted: bool,
}

impl Outcome {
    fn settled(&self) -> bool {
        !self.uncommitted && !self.archives.iter().any(|archive| archive.failure.as_ref()
            .is_some_and(|failure| failure.kind == FailureKind::Cancelled))
    }

    /// After the physical root's publication and relocation are finished, keep
    /// main's physical task summary rather than every successful segment. Scan
    /// and durable observers consume the detailed results before this boundary.
    fn compact_completed_extract(&mut self) {
        if !self.settled() { return; }
        // A blocked descendant needs its ancestors and successful siblings on
        // the next attempt. Release receipts only when this entire root is done.
        if !self.scan_incomplete && self.errors.is_empty()
            && self.archives.iter().all(|archive| archive.failure.is_none())
        {
            self.checkpoints = Vec::new();
            self.promoted_sources = Vec::new();
        }
        let mut groups: HashMap<(String, usize), Vec<ArchiveResult>> = HashMap::new();
        let mut order = Vec::new();
        for archive in std::mem::take(&mut self.archives) {
            let key = (crate::path_keys::path_key(&archive.path.to_string_lossy()), archive.depth);
            if !groups.contains_key(&key) { order.push(key.clone()); }
            groups.entry(key).or_default().push(archive);
        }
        for key in order {
            let mut entries = groups.remove(&key).expect("completed physical input");
            if entries.iter().all(|entry| entry.failure.is_none() && !entry.partial) {
                let output = common_ancestor(entries.iter().filter_map(|entry| entry.output.as_deref()));
                let files = entries.iter().map(|entry| entry.files).sum();
                let bytes = entries.iter().map(|entry| entry.bytes).sum();
                let mut summary = entries.remove(0);
                summary.output = output;
                summary.files = files;
                summary.bytes = bytes;
                entries = vec![summary];
            }
            for entry in &mut entries {
                // Extraction-only provenance has already been consumed by
                // cleanup, promotion and recovery receipts. Failure evidence
                // stays on the sparse result for CLI diagnostics.
                entry.source_paths = Vec::new();
                // Confirmed passwords already live in the engine's recent
                // password cache; extract reports never read this scan field.
                entry.password = None;
                entry.damage_flags = None;
                entry.volume_attempts = None;
                entry.promotion_original_path = None;
            }
            self.archives.extend(entries);
        }
    }

    pub(crate) fn input_failures(&self) -> HashMap<String, InputFailure<'_>> {
        let mut inputs: HashMap<String, InputFailure<'_>> = HashMap::new();
        for archive in &self.archives {
            let Some(failure) = archive.failure.as_ref() else { continue; };
            let input = inputs.entry(crate::path_keys::path_key(&archive.path.to_string_lossy()))
                .or_default();
            input.failed |= !archive.partial;
            match failure.kind {
                _ if failure.contains(FailureKind::MissingVolume) => { input.missing.get_or_insert(failure); }
                _ if failure.is_password_retry() => { input.password.get_or_insert(failure); }
                _ if !archive.partial => { input.terminal.get_or_insert(failure); }
                _ => {}
            }
        }
        inputs
    }

    pub fn succeeded(&self) -> usize {
        self.archives
            .iter()
            .filter(|archive| archive.failure.is_none() || archive.partial)
            .count()
    }

    pub fn failed(&self) -> usize {
        self.archives.len() - self.succeeded()
            + self
                .errors
                .iter()
                .filter(|error| error.kind != InputErrorKind::Cleanup)
                .map(InputError::count)
                .sum::<usize>()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ResourceWait {
    pub disk: bool,
    // Preserve a new wait across mailbox/report coalescing of its resume edge.
    pub disk_episode: u64,
    pub memory: bool,
    pub volume_error: Option<u64>,
}

pub type TaskId = u64;

#[derive(Debug, Clone)]
pub struct Segment {
    pub format: String,
    pub index: usize,
    pub count: usize,
    pub offset: u64,
    pub end_offset: Option<u64>,
}

/// The result needed by an in-flight display, without worker diagnostics or
/// recovery inventories. The final report uses the same status projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskStatus {
    Skipped,
    Complete,
    Partial,
    Failed,
}

impl TaskStatus {
    pub fn of(result: &ArchiveResult) -> Self {
        if result.partial { Self::Partial }
        else if result.failure.is_some() { Self::Failed }
        else { Self::Complete }
    }
}

#[derive(Debug, Clone)]
pub struct TaskCompletion {
    pub discovery: Option<DiscoverySource>,
    pub status: TaskStatus,
    pub failure: Option<Failure>,
    pub output: Option<PathBuf>,
}

impl TaskCompletion {
    pub fn from_result(result: &ArchiveResult) -> Self {
        Self {
            discovery: result.failure.as_ref().and_then(Self::discovery_source),
            status: TaskStatus::of(result),
            failure: result.failure.as_ref().map(Self::display_failure),
            output: result.output.clone(),
        }
    }

    pub(crate) fn failed(failure: &Failure) -> Self {
        Self { discovery: Self::discovery_source(failure), status: TaskStatus::Failed, failure: Some(Self::display_failure(failure)), output: None }
    }

    fn discovery_source(failure: &Failure) -> Option<DiscoverySource> {
        match failure.context.as_deref() {
            Some(FailureContext::Discovery { discovery, .. }) => Some(*discovery),
            _ => None,
        }
    }

    fn display_failure(failure: &Failure) -> Failure {
        Failure {
            kind: failure.kind,
            message: failure.message.clone(),
            context: failure.context.as_deref()
                .filter(|context| matches!(context, FailureContext::WorkerWarning))
                .map(|context| Box::new(context.clone())),
            discovery_scope: None,
            recovery: None,
            causes: failure.causes.clone(),
            password_retry: failure.password_retry,
            // Only the fields used by the common human-facing projection.
            evidence: failure.evidence.as_deref().map(|e| Box::new(FailureEvidence {
                possible_missing_volume: e.possible_missing_volume,
                archive_read_fault: e.archive_read_fault.clone(),
                native_kind: e.native_kind.clone(),
                stage: e.stage.clone(),
                ..FailureEvidence::default()
            })),
        }
    }

    pub(crate) fn relocate_output(&mut self, old: &Path, new: &Path) {
        if let Some(output) = &mut self.output {
            relocate_flatten_output(output, old, new);
        }
    }

    pub fn from_group(results: &[ArchiveResult]) -> Self {
        if results.len() == 1 { return Self::from_result(&results[0]); }
        let status = if results.iter().any(|r| TaskStatus::of(r) == TaskStatus::Failed) {
            TaskStatus::Failed
        } else if results.iter().any(|r| r.partial) { TaskStatus::Partial }
        else { TaskStatus::Complete };
        // main suppresses the ordinary INPUTS_FAILED parent detail because
        // each segment has its own row. A task-level postprocess error is not
        // that aggregate: retain its real failure for the carrier's detail.
        // Likewise a split-recovery warning wraps (rather than duplicates)
        // INPUTS_FAILED in main, and keeps its own carrier message.
        let failure = results.iter().filter_map(|result| result.failure.as_ref())
            .find(|failure| matches!(failure.context.as_deref(), Some(FailureContext::Postprocess { .. })))
            .or_else(|| results.iter().filter_map(|result| result.failure.as_ref())
                .find(|failure| failure.evidence.as_deref().is_some_and(|e| e.possible_missing_volume)))
            .map(Self::display_failure);
        Self { discovery: None, status, failure, output: common_ancestor(results.iter().filter_map(|r| r.output.as_deref())) }
    }
}

pub(crate) fn relocate_flatten_output(path: &mut PathBuf, old: &Path, new: &Path) {
    if let Ok(suffix) = path.strip_prefix(old) {
        *path = new.join(suffix);
    } else if old.starts_with(&*path) && path.starts_with(new) {
        // A carrier segment may own a wrapper above the flattened leaf.
        *path = new.to_path_buf();
    }
}

#[derive(Debug)]
pub enum Event {
    Queued {
        id: TaskId,
        parent: Option<TaskId>,
        path: PathBuf,
        depth: usize,
        segment: Option<Segment>,
    },
    Started {
        id: TaskId,
        path: PathBuf,
        depth: usize,
    },
    /// A physical retry replaces the display plan, not the execution task.
    Replanned {
        id: TaskId,
        path: PathBuf,
    },
    Waiting {
        id: TaskId,
    },
    Working {
        id: TaskId,
    },
    Extracting {
        id: TaskId,
    },
    ResolvingVolumes {
        id: TaskId,
    },
    Finalizing {
        id: TaskId,
    },
    Progress {
        id: TaskId,
        path: PathBuf,
        completed_bytes: u64,
        total_bytes: u64,
    },
    ResourceWait {
        id: TaskId,
        path: PathBuf,
        state: ResourceWait,
    },
    Finished {
        id: TaskId,
        path: PathBuf,
        depth: usize,
        result: TaskCompletion,
    },
    Skipped {
        id: TaskId,
    },
    /// Ordered display update after a task's output subtree was flattened.
    OutputsRelocated { id: TaskId, old: PathBuf, new: PathBuf },
}

/// Publication callbacks form the durable boundary for Watch. A failed callback
/// stops the corresponding filesystem operation and propagates to the request.
pub(crate) trait Observer: Send + Sync {
    fn notify(&self, event: Event);

    fn worker_updates(&self) -> WorkerUpdates {
        WorkerUpdates::All
    }

    // Publish logical roots after discovery, before any root can complete.
    // Admitted physical aliases are not necessarily independent tasks.
    fn roots_planned<'a>(&self, _paths: impl Iterator<Item = &'a str>) {}

    fn coalesced(&self) {}

    // The default keeps the caller's aggregate result. Watch transfers a
    // settled root to its ordinary completion queue without cloning receipts.
    fn root_finished(
        &self, _id: TaskId, _path: &Path, outcome: Outcome,
    ) -> impl std::future::Future<Output = io::Result<Outcome>> + Send {
        async { Ok(outcome) }
    }

    fn archive_branch(&self, _parent: &ArchiveResult, _child: &ArchiveResult) {}

    // Reporting can wait for client capacity. Transfer the existing outcome
    // vector so implementations can park the poll without copying its results.
    fn scope_finished(
        &self,
        _id: TaskId,
        archives: Vec<ArchiveResult>,
    ) -> impl std::future::Future<Output = io::Result<Vec<ArchiveResult>>> + Send {
        async { Ok(archives) }
    }

    fn claim_sources(&self, _path: &Path, _members: &[String], _depth: usize) -> io::Result<()> {
        Ok(())
    }

    fn completed_sources(
        &self,
        _generations: &HashMap<String, PhysicalFileGeneration>,
    ) -> io::Result<Option<PathBuf>> {
        Ok(None)
    }

    fn sources_processed(
        &self,
        _archives: &[ArchiveResult],
        _generations: &HashMap<String, PhysicalFileGeneration>,
        _output: Option<&Path>,
    ) -> io::Result<()> {
        Ok(())
    }

    fn promoted_source(&self, _path: &str) -> Option<PromotedSource> {
        None
    }

    fn before_output(&self, _archive: &ArchiveResult, _output: &Path) -> io::Result<()> {
        Ok(())
    }

    fn register_output(&self, archive: &ArchiveResult, output: &Path) -> io::Result<()> {
        self.before_output(archive, output)?;
        crate::scan::scope::create_output_root_exclusive(output).map_err(OutputCreateError::wrap)
    }

    /// Restart an already claimed retained output after best-effort cleanup.
    /// New output names still use exclusive registration above.
    fn reuse_output(&self, archive: &ArchiveResult, output: &Path) -> io::Result<()> {
        self.before_output(archive, output)?;
        std::fs::create_dir_all(output).map_err(OutputCreateError::wrap)
    }

    fn after_output(&self, _archive: &ArchiveResult) -> io::Result<()> {
        Ok(())
    }

    fn discard_output(&self, _archive: &ArchiveResult, _output: &Path) -> io::Result<()> {
        Ok(())
    }

    fn before_promotion(
        &self,
        _archive: &ArchiveResult,
        _moves: &[(PathBuf, PathBuf)],
    ) -> io::Result<()> {
        Ok(())
    }

    fn after_promotion(
        &self,
        _archive: &ArchiveResult,
        _moves: &[(PathBuf, PathBuf)],
        _success: bool,
        _receipts: &[PromotedSource],
    ) -> io::Result<()> {
        Ok(())
    }

    fn before_flatten(&self, _output: &Path, _work: &Path, _leaf: &Path) -> io::Result<()> {
        Ok(())
    }

    fn after_flatten(&self, _id: TaskId, _old: &Path, _output: &Path) -> io::Result<()> {
        Ok(())
    }

    fn allow_recursive_async(&self, depth: usize, pending: usize)
        -> impl std::future::Future<Output = bool> + Send {
        async move { self.allow_recursive(depth, pending) }
    }

    fn allow_recursive(&self, _depth: usize, _pending: usize) -> bool {
        true
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum WorkerUpdates {
    #[default]
    All,
    None,
}

impl<F: Fn(Event) + Send + Sync> Observer for F {
    fn notify(&self, event: Event) {
        self(event);
    }
}
