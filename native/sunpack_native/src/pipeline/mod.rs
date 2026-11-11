//! Shared archive orchestration for CLI requests and the Watch service.

mod checkpoint;
mod cleanup;
mod coordinator;
mod discovery;
mod passwords;
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

#[derive(Debug)]
pub enum Event {
    Started {
        path: PathBuf,
        depth: usize,
    },
    Progress {
        path: PathBuf,
        completed_bytes: u64,
        total_bytes: u64,
    },
    ResourceWait {
        path: PathBuf,
        state: ResourceWait,
    },
    Finished {
        path: PathBuf,
        depth: usize,
        success: bool,
    },
}

/// Publication callbacks form the durable boundary for Watch. A failed callback
/// stops the corresponding filesystem operation and propagates to the request.
pub(crate) trait Observer: Sync {
    fn notify(&self, event: Event);

    fn archive_branch(&self, _parent: &ArchiveResult, _child: &ArchiveResult) {}

    fn scope_finished(&self, _archives: &[ArchiveResult]) -> io::Result<()> {
        Ok(())
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
        crate::scan::scope::create_output_root_exclusive(output)
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

impl<F: Fn(Event) + Sync> Observer for F {
    fn notify(&self, event: Event) {
        self(event);
    }
}
