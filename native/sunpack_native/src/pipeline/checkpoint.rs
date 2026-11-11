//! Durable receipts hold physical layouts and counters, never archive file
//! tables, analysis caches, password lists, or native reader handles.

use super::{ArchiveResult, DiscoverySource, Failure, FailureKind};
use crate::io::archive_state::{ArchiveInput, InputExtent, InputPart, OpenMode};
use crate::io::reader::{
    capture_directory_identity, capture_file_generation, DirectoryIdentity,
    PersistedFileGeneration, PhysicalFileGeneration,
};
use crate::path_keys::path_key;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    io,
    path::{Path, PathBuf},
};

const SCHEMA_VERSION: u8 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InputCheckpoint {
    schema_version: u8,
    carrier: PathBuf,
    input: LogicalLayout,
    sources: Box<[SourceGeneration]>,
    output: OwnedDirectory,
    container: Option<OwnedDirectory>,
    files: u64,
    bytes: u64,
    encrypted: Option<bool>,
    discovery_source: DiscoverySource,
    children_complete: bool,
    remaining_depth: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    partial: Option<PartialReceipt>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PartialReceipt {
    failure: Failure,
    complete_files: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LogicalLayout {
    entry: PathBuf,
    mode: OpenMode,
    format: String,
    parts: Box<[InputPart]>,
    ranges: Box<[InputExtent]>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SourceGeneration {
    path: PathBuf,
    generation: PersistedFileGeneration,
}

/// A generated input moved out of a recursive output tree for a later retry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PromotedSource(SourceGeneration);

impl PromotedSource {
    pub(super) fn capture(path: &Path) -> io::Result<Self> {
        Ok(Self(SourceGeneration {
            path: path.to_path_buf(),
            generation: capture_file_generation(path)?.persisted(),
        }))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0.path
    }

    pub(super) fn matches(&self, generation: &PhysicalFileGeneration) -> bool {
        generation.persisted() == self.0.generation
    }

    pub(crate) fn is_replaced(&self) -> bool {
        capture_file_generation(self.path()).is_ok_and(|generation| !self.matches(&generation))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct OwnedDirectory {
    path: PathBuf,
    identity: DirectoryIdentity,
}

impl OwnedDirectory {
    fn capture(path: &Path) -> io::Result<Self> {
        Ok(Self {
            path: path.to_path_buf(),
            identity: capture_directory_identity(path)?,
        })
    }

    fn valid(&self) -> bool {
        capture_directory_identity(&self.path).is_ok_and(|identity| identity == self.identity)
    }
}

impl InputCheckpoint {
    pub fn entry(&self) -> &Path {
        &self.input.entry
    }
    pub fn carrier(&self) -> &Path {
        &self.carrier
    }
    pub fn output(&self) -> &Path {
        &self.output.path
    }
    pub fn source_paths(&self) -> impl Iterator<Item = &Path> {
        self.sources.iter().map(|source| source.path.as_path())
    }

    pub(super) fn key(&self) -> CheckpointKey {
        CheckpointKey::new(
            &self.input.entry.to_string_lossy(),
            self.input.mode,
            &self.input.format,
            self.input
                .parts
                .first()
                .map(|part| part.extent.start)
                .or_else(|| self.input.ranges.first().map(|range| range.start)),
        )
    }

    pub(super) fn create(
        carrier: &Path,
        input: &ArchiveInput,
        result: &ArchiveResult,
        generations: &HashMap<String, PhysicalFileGeneration>,
        container: Option<&Path>,
        children_complete: bool,
        remaining_depth: usize,
    ) -> io::Result<Option<Self>> {
        if input.volume_attempts.is_some() || (result.failure.is_some() && !result.partial) {
            return Ok(None);
        }
        let Some(output) = result.output.as_deref() else {
            return Ok(None);
        };
        let mut sources = Vec::with_capacity(result.source_paths.len());
        for path in &result.source_paths {
            let Some(generation) = generations.get(&path_key(&path.to_string_lossy())) else {
                return Ok(None);
            };
            sources.push(SourceGeneration {
                path: path.clone(),
                generation: generation.persisted(),
            });
        }
        if sources.is_empty() {
            return Ok(None);
        }
        Ok(Some(Self {
            schema_version: SCHEMA_VERSION,
            carrier: carrier.to_path_buf(),
            input: LogicalLayout {
                entry: PathBuf::from(&input.entry_path),
                mode: input.mode,
                format: input.format_hint.clone(),
                parts: input.parts.clone(),
                ranges: input.ranges.clone(),
            },
            sources: sources.into_boxed_slice(),
            output: OwnedDirectory::capture(output)?,
            container: container.map(OwnedDirectory::capture).transpose()?,
            files: result.files,
            bytes: result.bytes,
            encrypted: result.encrypted,
            discovery_source: result.discovery_source,
            children_complete,
            remaining_depth,
            partial: result.failure.as_ref().map(|failure| PartialReceipt {
                failure: failure.clone(),
                complete_files: result.recovered_complete_files,
            }),
        }))
    }

    pub(super) fn valid_for(
        &self,
        input: &ArchiveInput,
        generations: &HashMap<String, PhysicalFileGeneration>,
    ) -> bool {
        self.schema_version == SCHEMA_VERSION
            && self.input.matches(input)
            && self.sources.iter().all(|source| {
                generations
                    .get(&path_key(&source.path.to_string_lossy()))
                    .is_some_and(|generation| generation.persisted() == source.generation)
            })
            && self.output.valid()
            && self.container.as_ref().is_none_or(OwnedDirectory::valid)
    }

    pub(super) fn container(&self) -> Option<&Path> {
        self.container
            .as_ref()
            .map(|container| container.path.as_path())
    }
    pub(super) fn children_complete(&self, remaining_depth: usize) -> bool {
        self.children_complete && self.remaining_depth >= remaining_depth
    }

    pub(super) fn restore_input(&self, input: &mut ArchiveInput) {
        input.mode = self.input.mode;
        input.parts = self.input.parts.clone();
        input.ranges = self.input.ranges.clone();
        input.volume_attempts = None;
    }

    pub(super) fn relocate(&mut self, source: &Path, destination: &Path) -> bool {
        let mut changed = false;
        let mut mapped = |path: &mut PathBuf| {
            if let Ok(relative) = path.strip_prefix(source) {
                *path = destination.join(relative);
                changed = true;
            }
        };
        mapped(&mut self.carrier);
        mapped(&mut self.input.entry);
        mapped(&mut self.output.path);
        if let Some(container) = &mut self.container {
            mapped(&mut container.path);
        }
        for generation in &mut self.sources {
            mapped(&mut generation.path);
        }
        for extent in self
            .input
            .parts
            .iter_mut()
            .map(|part| &mut part.extent)
            .chain(&mut self.input.ranges)
        {
            if let Ok(relative) = Path::new(&extent.path).strip_prefix(source) {
                extent.path = destination.join(relative).to_string_lossy().into_owned();
                changed = true;
            }
        }
        changed
    }

    /// Flatten first moves the wrapper to work, then publishes the inner leaf.
    /// The wrapper itself is the only directory whose identity changes.
    pub(crate) fn rebase_flatten(
        &mut self,
        root: &Path,
        work: &Path,
        leaf: &Path,
        wrapper: Option<&DirectoryIdentity>,
        published: &DirectoryIdentity,
    ) -> bool {
        let mut changed = self.relocate(work, root);
        // Live publication can already have written a receipt at its new path.
        // An inner subtree may happen to have the old leaf's name as well.
        if changed || !self.output.path.starts_with(leaf) || !self.output.valid() {
            changed |= self.relocate(leaf, root);
        }
        for directory in std::iter::once(&mut self.output).chain(self.container.iter_mut()) {
            if directory.path == root && wrapper == Some(&directory.identity) {
                directory.identity = published.clone();
                changed = true;
            }
        }
        changed
    }

    pub(super) fn promoted(&mut self, moves: &[(PathBuf, PathBuf)]) -> io::Result<()> {
        for (source, destination) in moves {
            self.relocate(source, destination);
        }
        for source in &mut self.sources {
            source.generation = capture_file_generation(&source.path)?.persisted();
        }
        Ok(())
    }

    pub(super) fn result(&self, depth: usize) -> ArchiveResult {
        let failure = self.partial.as_ref().map(|receipt| receipt.failure.clone());
        let extent = self
            .input
            .parts
            .first()
            .map(|part| &part.extent)
            .or(self.input.ranges.first());
        ArchiveResult {
            path: self.input.entry.clone(),
            format: self.input.format.clone(),
            output: Some(self.output.path.clone()),
            volume_completeness: self.input.mode.structured().then(|| {
                if failure
                    .as_ref()
                    .is_some_and(|failure| failure.kind == FailureKind::MissingVolume)
                {
                    "missing".to_owned()
                } else {
                    "complete".to_owned()
                }
            }),
            failure,
            files: self.files,
            bytes: self.bytes,
            encrypted: self.encrypted,
            depth,
            offset: extent.map_or(0, |extent| extent.start),
            end_offset: extent.and_then(|extent| extent.end),
            volume_attempts: None,
            source_paths: self
                .sources
                .iter()
                .map(|source| source.path.clone())
                .collect(),
            password: None,
            discovery_source: self.discovery_source,
            damage_flags: None,
            partial: self.partial.is_some(),
            retained: true,
            recovered_complete_files: self
                .partial
                .as_ref()
                .map_or(0, |receipt| receipt.complete_files),
            promoted: false,
            promotion_original_path: None,
        }
    }
}

#[derive(Hash, PartialEq, Eq)]
pub(super) struct CheckpointKey {
    entry: String,
    mode: OpenMode,
    format: String,
    start: u64,
}

impl CheckpointKey {
    fn new(entry: &str, mode: OpenMode, format: &str, start: Option<u64>) -> Self {
        Self {
            entry: path_key(entry),
            mode,
            format: format.to_owned(),
            start: if mode.structured() {
                0
            } else {
                start.unwrap_or(0)
            },
        }
    }

    pub(super) fn for_input(input: &ArchiveInput) -> Self {
        Self::new(
            &input.entry_path,
            input.mode,
            &input.format_hint,
            input.physical_extents().next().map(|extent| extent.start),
        )
    }
}

impl LogicalLayout {
    fn matches(&self, input: &ArchiveInput) -> bool {
        if path_key(&self.entry.to_string_lossy()) != path_key(&input.entry_path)
            || self.mode != input.mode
            || self.format != input.format_hint
            || self.ranges != input.ranges
        {
            return false;
        }
        match &input.volume_attempts {
            Some(plan) => plan.admits_parts(&self.parts),
            None => self.parts == input.parts,
        }
    }
}
