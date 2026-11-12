//! Shared archive orchestration for CLI requests and the Watch service.

mod checkpoint;
mod cleanup;
mod coordinator;
mod discovery;
mod passwords;
mod scheduling;
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
pub(crate) use scheduling::MAX_PENDING_JOBS;

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
}

impl Failure {
    pub(crate) fn new(kind: FailureKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            evidence: None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FailureEvidence {
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

#[derive(Debug)]
pub(crate) struct OutputCleanupError {
    pub path: PathBuf,
    pub error: io::Error,
}

impl std::fmt::Display for OutputCleanupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.path.display(), self.error)
    }
}

impl std::error::Error for OutputCleanupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
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
}

impl Outcome {
    pub(crate) fn input_failures(&self) -> HashMap<String, InputFailure<'_>> {
        let mut inputs: HashMap<String, InputFailure<'_>> = HashMap::new();
        for archive in &self.archives {
            let Some(failure) = archive.failure.as_ref() else { continue; };
            let input = inputs.entry(crate::path_keys::path_key(&archive.path.to_string_lossy()))
                .or_default();
            input.failed |= !archive.partial;
            match failure.kind {
                FailureKind::MissingVolume => { input.missing.get_or_insert(failure); }
                FailureKind::PasswordRequired | FailureKind::WrongPassword
                    | FailureKind::PasswordInconclusive => { input.password.get_or_insert(failure); }
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

#[derive(Debug, Clone, Copy)]
pub struct Segment {
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
pub(crate) trait Observer: Sync {
    fn notify(&self, event: Event);

    fn worker_updates(&self) -> WorkerUpdates {
        WorkerUpdates::All
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

    fn before_cleanup(&self, _archive: &ArchiveResult) -> io::Result<()> {
        Ok(())
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

impl<F: Fn(Event) + Sync> Observer for F {
    fn notify(&self, event: Event) {
        self(event);
    }
}
