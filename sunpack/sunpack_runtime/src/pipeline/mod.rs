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
use crate::io::archive_state::VolumeCompleteness;
use crate::io::reader::PhysicalFileGeneration;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub(crate) use crate::io::cancellation::Cancellation;
pub use checkpoint::InputCheckpoint;
pub(crate) use checkpoint::{InputRecovery, GeneratedSource};
pub use coordinator::Engine;
pub(crate) use coordinator::{CommonAncestor, common_ancestor, common_output_base};
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
    pub(crate) start_depth: usize,
    pub recursive: bool,
    pub deep: bool,
    pub passwords: Arc<[Arc<str>]>,
    pub password_snapshot: Option<Arc<PasswordSnapshot>>,
    pub(crate) password_scope: Option<PathBuf>,
    pub config: Arc<Config>,
    pub checkpoints: Vec<InputCheckpoint>,
    pub(crate) generated_sources: Vec<GeneratedSource>,
    pub(crate) cleanup_boundaries: Vec<PathBuf>,
    pub(crate) cancel: Cancellation,
    pub(crate) discovery_scope: Option<crate::scan::scope::NativeDiscoveryScope>,
    pub(crate) watch_catalog: Option<Arc<crate::scan::directory::NativeWatchCatalog>>,
    pub(crate) prepared_volumes: Vec<Arc<PreparedVolume>>,
}

/// A one-shot handoff of the existing relation plan, not a second discovery.
/// Its directory snapshot is released with the submitted request.
pub(crate) struct PreparedVolume(std::sync::Mutex<Option<discovery::PreparedVolumePlan>>);

impl Request {
    #[cfg(test)]
    pub(crate) fn new(inputs: Vec<PathBuf>, mode: Mode) -> Self {
        Self::with_config(inputs, mode, Arc::new(Config::default()))
    }

    pub(crate) fn with_config(inputs: Vec<PathBuf>, mode: Mode, config: Arc<Config>) -> Self {
        Self {
            inputs,
            mode,
            origin: Origin::Foreground,
            output_root: None,
            output_base: None,
            max_depth: 0,
            start_depth: 1,
            recursive: false,
            deep: false,
            passwords: Arc::from([]),
            password_snapshot: None,
            password_scope: None,
            config,
            checkpoints: Vec::new(),
            generated_sources: Vec::new(),
            cleanup_boundaries: Vec::new(),
            cancel: Cancellation::new(),
            discovery_scope: None,
            watch_catalog: None,
            prepared_volumes: Vec::new(),
        }
    }
}

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DiscoverySource {
    Relations,
    Detection,
    #[default]
    Embedded,
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
    Discovery { discovery: DiscoverySource, reason: Cow<'static, str>, path: PathBuf },
    InputAdmission { missing_paths: Vec<PathBuf> },
    PasswordResolution,
    Extraction,
    WorkerWarning,
    OutputCreate { error: String, #[serde(default)] path: Option<PathBuf> },
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
    pub context: Option<Arc<FailureContext>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery_scope: Option<Arc<FailureScope>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) recovery: Option<Arc<checkpoint::InputRecovery>>,
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
        self.kind == FailureKind::WrongPassword
            || (self.kind == FailureKind::PasswordInconclusive && self.password_retry)
    }

    pub(crate) fn with_context(mut self, context: FailureContext) -> Self {
        self.context = Some(Arc::new(context));
        self
    }

    pub(crate) fn new(kind: FailureKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            context: None,
            discovery_scope: None,
            recovery: None,
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
    pub win32_error: i64,
    pub read_error: bool,
}

#[derive(Debug)]
pub struct InputError {
    pub path: PathBuf,
    pub message: String,
    pub kind: InputErrorKind,
    pub(crate) failure: Option<Box<Failure>>,
    pub scan_operation: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputErrorKind {
    InvalidInput,
    FilesystemScan,
    EmbeddedDiscovery,
    WatchDiscoveryIo(io::ErrorKind),
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
    Failed,
}

#[derive(Debug, Default)]
pub struct ArchiveResult {
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
    pub(crate) volume_completeness: Option<VolumeCompleteness>,
    pub(crate) volume_attempts: Option<Arc<crate::io::archive_state::VolumeAttemptPlan>>,
    pub source_paths: Vec<PathBuf>,
    pub password: Option<String>,
    pub discovery_source: DiscoverySource,
    pub partial: bool,
    pub retained: bool,
    pub recovered_complete_files: u64,
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
                || input.mode == OpenMode::FileRange
                || extent.end.is_some() && input.analysis.origin == AnalysisOrigin::Embedded),
            volumes: !input.volume_style.is_empty() || input.mode.structured(),
        }
    }

    pub(crate) fn volumes(self, result: &ArchiveResult) -> (bool, Option<&'static str>) {
        let completeness = result.volume_completeness;
        let missing = completeness == Some(VolumeCompleteness::Missing);
        if result.volume_attempts.is_some() {
            return (false, Some(if missing { VolumeCompleteness::Missing.as_str() } else { "pending" }));
        }
        let show = self.volumes || result.source_paths.len() > 1 || missing;
        (show, completeness.filter(|value| show && *value != VolumeCompleteness::Unknown)
            .map(VolumeCompleteness::as_str))
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

#[derive(Debug, Default)]
pub struct Outcome {
    pub archives: Vec<ArchiveResult>,
    pub errors: Vec<InputError>,
    pub(crate) scan_failures: Vec<ScanTaskFailure>,
    pub checkpoints: Vec<InputCheckpoint>,
    pub cleanup_results: Vec<CleanupResult>,
    pub(crate) generated_sources: Vec<GeneratedSource>,
    pub(crate) deferred_flatten: std::collections::LinkedList<PathBuf>,
    pub(crate) coalesced_from: Option<u64>,
    scan_incomplete: bool,
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
        if !self.scan_incomplete && self.errors.is_empty() && self.cleanup_results.is_empty()
            && self.archives.iter().all(|archive| archive.failure.is_none())
        {
            self.checkpoints = Vec::new();
            self.generated_sources = Vec::new();
        }
        if self.archives.len() <= 1 {
            if let Some(entry) = self.archives.first_mut() {
                if entry.failure.is_none() && !entry.partial {
                    entry.output = entry.output.as_deref().and_then(|path| std::path::absolute(path).ok());
                }
                entry.release_extract_provenance();
            }
            return;
        }
        // Most physical archives have a single result. Keep their first result
        // inline and allocate a sibling vector only for multi-segment inputs.
        let mut positions = HashMap::new();
        let mut groups: Vec<(ArchiveResult, Vec<ArchiveResult>)> = Vec::new();
        for mut archive in std::mem::take(&mut self.archives) {
            let key = (crate::path_keys::path_key(&archive.path.to_string_lossy()), archive.depth);
            archive.release_extract_provenance();
            match positions.entry(key) {
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(groups.len());
                    groups.push((archive, Vec::new()));
                }
                std::collections::hash_map::Entry::Occupied(entry) => {
                    groups[*entry.get()].1.push(archive);
                }
            }
        }
        drop(positions);
        self.archives.reserve(groups.len());
        for (mut first, siblings) in groups {
            let entries = std::iter::once(&first).chain(&siblings);
            let succeeded = entries.clone().all(|entry| entry.failure.is_none() && !entry.partial);
            if succeeded {
                first.output = common_ancestor(entries.filter_map(|entry| entry.output.as_deref()));
                for entry in siblings {
                    first.files += entry.files;
                    first.bytes += entry.bytes;
                }
                self.archives.push(first);
            } else {
                self.archives.push(first);
                self.archives.extend(siblings);
            }
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
                _ if failure.kind == FailureKind::MissingVolume => { input.missing.get_or_insert(failure); }
                _ if failure.is_password_retry() => { input.password.get_or_insert(failure); }
                _ if !archive.partial => { input.terminal.get_or_insert(failure); }
                _ => {}
            }
        }
        inputs
    }

}

impl ArchiveResult {
    fn release_extract_provenance(&mut self) {
        // Cleanup and recovery already consumed these fields.
        self.source_paths = Vec::new();
        self.password = None;
        self.volume_attempts = None;
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
    pub status: TaskStatus,
    pub failure: Option<Failure>,
    pub output: Option<PathBuf>,
}

impl TaskCompletion {
    pub fn from_result(result: &ArchiveResult) -> Self {
        Self {
            status: TaskStatus::of(result),
            failure: result.failure.as_ref().map(|failure| Self::display_failure(failure, true)),
            output: result.output.clone(),
        }
    }

    pub(crate) fn failed(failure: &Failure) -> Self {
        Self { status: TaskStatus::Failed, failure: Some(Self::display_failure(failure, true)), output: None }
    }

    fn display_failure(failure: &Failure, include_discovery: bool) -> Failure {
        Failure {
            kind: failure.kind,
            message: failure.message.clone(),
            context: match failure.context.as_deref() {
                Some(FailureContext::WorkerWarning) => failure.context.clone(),
                Some(FailureContext::Discovery { .. }) if include_discovery => failure.context.clone(),
                _ => None,
            },
            discovery_scope: None,
            recovery: None,
            password_retry: failure.password_retry,
            // Only the fields used by the common human-facing projection.
            evidence: failure.evidence.as_deref().map(|e| Box::new(FailureEvidence {
                possible_missing_volume: e.possible_missing_volume,
                archive_read_fault: e.archive_read_fault.clone(),
                native_kind: e.native_kind.clone(),
                ..FailureEvidence::default()
            })),
        }
    }

    pub(crate) fn relocate_output(&mut self, root: &Path, old: &Path, new: &Path) {
        if let Some(output) = &mut self.output {
            relocate_flatten_output(output, root, old, new);
        }
    }

    pub fn from_group(results: &[ArchiveResult]) -> Self {
        if results.len() == 1 { return Self::from_result(&results[0]); }
        let status = if results.iter().any(|r| TaskStatus::of(r) == TaskStatus::Failed) {
            TaskStatus::Failed
        } else if results.iter().any(|r| r.partial) { TaskStatus::Partial }
        else { TaskStatus::Complete };
        // Segment rows carry individual failures. Only a split-recovery
        // warning adds a separate message for the physical carrier.
        let failure = results.iter().filter_map(|result| result.failure.as_ref())
            .find(|failure| failure.evidence.as_deref().is_some_and(|e| e.possible_missing_volume))
            .map(|failure| Self::display_failure(failure, false));
        Self { status, failure, output: common_ancestor(results.iter().filter_map(|r| r.output.as_deref())) }
    }
}

pub(crate) fn relocate_flatten_output(path: &mut PathBuf, root: &Path, old: &Path, new: &Path) -> bool {
    if let Ok(suffix) = path.strip_prefix(old) {
        *path = if suffix.as_os_str().is_empty() { new.to_path_buf() } else { new.join(suffix) };
        true
    } else if old.starts_with(&*path) && path.starts_with(root) {
        *path = new.to_path_buf();
        true
    } else {
        false
    }
}

#[derive(Debug)]
pub enum Event {
    Queued {
        id: TaskId,
        parent: Option<TaskId>,
        path: PathBuf,
        segment: Option<Segment>,
    },
    Started {
        id: TaskId,
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
        result: TaskCompletion,
    },
    Skipped {
        id: TaskId,
    },
    /// Ordered display update after a task's output subtree was flattened.
    OutputsRelocated { id: TaskId, root: PathBuf, old: PathBuf, new: PathBuf },
}

/// Publication callbacks form the durable boundary for Watch. A failed callback
/// stops the corresponding filesystem operation and propagates to the request.
pub(crate) trait Observer: Send + Sync {
    const PUBLISHES_ROOTS: bool = false;

    fn notify(&self, event: Event);

    fn worker_updates(&self) -> WorkerUpdates {
        WorkerUpdates::All
    }

    // Publish logical roots after discovery, before any root can complete.
    // Admitted physical aliases are not necessarily independent tasks.
    fn roots_planned<'a>(&self, _roots: impl Iterator<Item = (&'a str, &'a [String])>) {}

    fn coalesced(&self) {}

    // Opt-in observers transfer a settled root before request completion.
    fn root_finished(
        &self, _id: TaskId, _path: &Path, outcome: Outcome, _request: u64,
    ) -> impl std::future::Future<Output = io::Result<Outcome>> + Send {
        async { Ok(outcome) }
    }

    fn scope_finished<'a>(
        &self,
        _id: TaskId,
        _archives: impl Iterator<Item = &'a ArchiveResult> + Send,
    ) -> impl std::future::Future<Output = io::Result<()>> + Send {
        async { Ok(()) }
    }

    fn claim_sources<'a>(&self, _path: &Path, _members: &[String], _depth: usize,
        _inputs: impl ExactSizeIterator<Item = &'a crate::io::archive_state::ArchiveInput>,
    ) -> io::Result<()> {
        Ok(())
    }

    fn input_admission_enabled(&self) -> bool { false }

    /// Admission after canonical discovery and physical-generation validation.
    /// Returning false retires the proposal without success, recursion or cleanup.
    /// The callback runs inside the shared blocking stage, not the control driver.
    fn admit_inputs(
        &self, _owner: &Path, _inputs: &[&crate::io::archive_state::ArchiveInput],
        _members: &[String], _depth: usize,
    ) -> io::Result<bool> {
        Ok(true)
    }

    fn completed_sources(
        &self,
        _generations: &HashMap<String, PhysicalFileGeneration>,
    ) -> io::Result<Option<PathBuf>> {
        Ok(None)
    }

    fn sources_processed(
        &self,
        _generations: HashMap<String, PhysicalFileGeneration>,
        _output: Option<&Path>,
    ) -> io::Result<()> {
        Ok(())
    }

    fn generated_source(&self, _path: &str) -> Option<GeneratedSource> {
        None
    }

    fn register_output(&self, _archive: &ArchiveResult, output: &Path) -> io::Result<()> {
        crate::scan::scope::create_output_root_exclusive(output).map_err(OutputCreateError::wrap)
    }

    /// Restart an already claimed retained output after best-effort cleanup.
    /// New output names still use exclusive registration above.
    fn reuse_output(&self, _archive: &ArchiveResult, output: &Path) -> io::Result<()> {
        std::fs::create_dir_all(output).map_err(OutputCreateError::wrap)
    }

    fn after_output(&self, _archive: &ArchiveResult) -> io::Result<()> {
        Ok(())
    }

    /// All request writers and rollback have joined. Paths are existing output
    /// reservations; observers may publish their final inventory before release.
    fn outputs_finished(&self, _paths: impl FnOnce() -> Vec<String>) -> io::Result<()> { Ok(()) }

    fn discard_output(&self, _archive: &Path, _sources: &[PathBuf], _output: &Path) -> io::Result<()> {
        Ok(())
    }

    fn before_flatten(&self, _root: &Path, _work: &Path, _leaf: &Path, _destination: &Path) -> io::Result<()> {
        Ok(())
    }

    fn after_flatten(&self, _id: TaskId, _root: &Path, _old: &Path, _output: &Path) -> io::Result<()> {
        Ok(())
    }

    fn allow_recursive_async(&self, _depth: usize, _pending: usize)
        -> impl std::future::Future<Output = bool> + Send {
        async { true }
    }

    #[cfg(test)]
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
