//! Shared archive orchestration for CLI requests and the Watch service.

mod checkpoint;
mod cleanup;
mod coordinator;
mod discovery;
mod passwords;
pub(crate) mod scheduling;
mod shell_updates;
mod worker;

use crate::core::{config::Config, passwords::PasswordSnapshot};
use crate::io::reader::PhysicalFileGeneration;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub(crate) use crate::io::cancellation::Cancellation;
pub use checkpoint::InputCheckpoint;
pub(crate) use checkpoint::PromotedSource;
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Failure {
    pub kind: FailureKind,
    pub message: String,
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
    }

    pub(crate) fn new(kind: FailureKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            evidence: None,
            password_retry: false,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FailureEvidence {
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

#[derive(Debug, Default, Serialize)]
pub struct Outcome {
    pub archives: Vec<ArchiveResult>,
    pub errors: Vec<InputError>,
    #[serde(skip)]
    pub checkpoints: Vec<InputCheckpoint>,
    pub cleanup_results: Vec<CleanupResult>,
    #[serde(skip)]
    pub(crate) promoted_sources: Vec<PromotedSource>,
    #[serde(skip)]
    pub(crate) removed_promotion_dirs: Vec<String>,
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

    pub(crate) fn input_failures(&self) -> HashMap<String, InputFailure<'_>> {
        let mut inputs: HashMap<String, InputFailure<'_>> = HashMap::new();
        for archive in &self.archives {
            let Some(failure) = archive.failure.as_ref() else { continue; };
            let input = inputs.entry(crate::path_keys::path_key(&archive.path.to_string_lossy()))
                .or_default();
            input.failed |= !archive.partial;
            match failure.kind {
                FailureKind::MissingVolume => { input.missing.get_or_insert(failure); }
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
    Waiting {
        id: TaskId,
    },
    Working {
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
        success: bool,
    },
    Skipped {
        id: TaskId,
    },
}

/// Publication callbacks form the durable boundary for Watch. A failed callback
/// stops the corresponding filesystem operation and propagates to the request.
pub(crate) trait Observer: Send + Sync {
    fn notify(&self, event: Event);

    fn worker_updates(&self) -> WorkerUpdates {
        WorkerUpdates::All
    }

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

    fn should_process_sources(
        &self,
        _path: &Path,
        _data_paths: &[&str],
        _generations: &HashMap<String, PhysicalFileGeneration>,
    ) -> io::Result<bool> {
        Ok(true)
    }

    fn sources_processed(
        &self,
        _archives: &[ArchiveResult],
        _generations: &HashMap<String, PhysicalFileGeneration>,
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

    fn after_output(&self, _archive: &ArchiveResult) -> io::Result<()> {
        Ok(())
    }

    fn checkpoint(&self, _checkpoint: &InputCheckpoint) -> io::Result<()> {
        Ok(())
    }

    fn commit_output(
        &self,
        archive: &ArchiveResult,
        checkpoint: Option<&InputCheckpoint>,
    ) -> io::Result<()> {
        self.after_output(archive)?;
        if let Some(checkpoint) = checkpoint {
            self.checkpoint(checkpoint)?;
        }
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

    fn after_flatten(&self, _output: &Path) -> io::Result<()> {
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
    Resources,
    None,
}

impl<F: Fn(Event) + Send + Sync> Observer for F {
    fn notify(&self, event: Event) {
        self(event);
    }
}
