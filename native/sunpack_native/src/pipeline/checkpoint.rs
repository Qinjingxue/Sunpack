//! Durable receipts hold physical layouts, retry facts and counters, never
//! archive file tables, analysis caches, password lists, or native reader handles.

use super::{ArchiveResult, DiscoverySource, Failure, FailureKind};
use crate::io::archive_state::{AnalysisFacts, ArchiveInput, InputExtent, InputPart, OpenMode};
use crate::io::reader::{
    capture_file_generation, PersistedFileGeneration, PhysicalFileGeneration,
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
    output: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    planned_output: Option<PathBuf>,
    container: Option<PathBuf>,
    files: u64,
    bytes: u64,
    encrypted: Option<bool>,
    discovery_source: DiscoverySource,
    children_complete: bool,
    remaining_depth: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    failure: Option<FailureReceipt>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct FailureReceipt {
    partial: bool,
    password_signature: Option<String>,
    failure: Failure,
    complete_files: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retry_facts: Option<RetryFacts>,
}

/// Retry dependencies only: no inventory, reader, or retained candidate plan.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct RetryFacts {
    logical_name: String,
    analysis: AnalysisFacts,
    plan_signature: Option<String>,
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

impl InputCheckpoint {
    /// Lightweight projection of this module's serialized recovery contract.
    pub(crate) fn serialized_output_roots(record: &serde_json::Value) -> impl Iterator<Item = &str> {
        ["output", "container"].into_iter().filter_map(move |field| record[field].as_str())
            .filter(|path| !path.is_empty())
    }

    pub fn entry(&self) -> &Path {
        &self.input.entry
    }
    pub fn carrier(&self) -> &Path {
        &self.carrier
    }
    pub fn output(&self) -> &Path {
        &self.output
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
    ) -> Option<Self> {
        if result.failure.as_ref().is_some_and(|failure| failure.kind == FailureKind::Cancelled) {
            return None;
        }
        let mut sources = Vec::with_capacity(result.source_paths.len());
        for path in &result.source_paths {
            let Some(generation) = generations.get(&path_key(&path.to_string_lossy())) else {
                return None;
            };
            sources.push(SourceGeneration {
                path: path.clone(),
                generation: generation.persisted(),
            });
        }
        if sources.is_empty() {
            return None;
        }
        Some(Self {
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
            output: result.output.clone().unwrap_or_default(),
            planned_output: None,
            container: container.map(Path::to_path_buf),
            files: result.files,
            bytes: result.bytes,
            encrypted: result.encrypted,
            discovery_source: result.discovery_source,
            children_complete,
            remaining_depth,
            failure: result.failure.as_ref().map(|failure| FailureReceipt {
                partial: result.partial,
                password_signature: None,
                failure: failure.clone(),
                complete_files: result.recovered_complete_files,
                retry_facts: Some(RetryFacts {
                    logical_name: input.logical_name.clone(),
                    analysis: input.analysis.clone(),
                    plan_signature: plan_signature(input),
                }),
            }),
        })
    }

    pub(super) fn valid_for(
        &self,
        input: &ArchiveInput,
        generations: &HashMap<String, PhysicalFileGeneration>,
    ) -> bool {
        self.schema_version == SCHEMA_VERSION
            && self.failure.as_ref().is_none_or(|partial| {
                // Failed logical inputs wake only when retry dependencies
                // change; successful outputs admit their proven volume winner.
                partial.retry_facts.as_ref().is_some_and(|facts| {
                        facts.logical_name == input.logical_name
                            && facts.analysis == input.analysis
                            && facts.plan_signature == plan_signature(input)
                    })
            })
            && (if self.failure.is_some() {
                self.input.entry == Path::new(&input.entry_path)
                    && self.input.mode == input.mode && self.input.format == input.format_hint
                    && self.input.parts == input.parts && self.input.ranges == input.ranges
            } else { self.input.matches(input) })
            && self.sources.iter().all(|source| {
                generations
                    .get(&path_key(&source.path.to_string_lossy()))
                    .is_some_and(|generation| generation.persisted() == source.generation)
            })

    }

    pub(super) fn output_slot(&self) -> Option<&Path> {
        if self.has_output() { Some(self.output()) } else { self.planned_output.as_deref() }
    }

    pub(super) fn set_planned_output(&mut self, path: Option<&Path>) {
        self.planned_output = if self.has_output() { None } else { path.map(Path::to_path_buf) };
    }

    pub(super) fn output_slot_for(&self, input: &ArchiveInput, container: &Path) -> bool {
        // Dependency generations and retry facts decide whether the result can
        // be reused, not whether the same logical segment keeps its old slot.
        let start = self.input.parts.first().map(|part| part.extent.start)
            .or_else(|| self.input.ranges.first().map(|range| range.start)).unwrap_or(0);
        self.schema_version == SCHEMA_VERSION
            && self.container() == Some(container)
            && self.output_slot().is_some_and(|output| output.strip_prefix(container)
                .is_ok_and(|relative| !relative.as_os_str().is_empty()))
            && path_key(&self.input.entry.to_string_lossy()) == path_key(&input.entry_path)
            && self.input.format == input.format_hint
            && start == input.physical_extents().next().map_or(0, |extent| extent.start)
    }

    pub(crate) fn container(&self) -> Option<&Path> {
        self.container
            .as_ref()
            .map(|container| container.as_path())
    }
    pub(crate) fn retained_container(&self) -> Option<&Path> {
        let container = self.container.as_ref()?;
        (self.has_output() && self.failure.as_ref().is_none_or(|receipt| receipt.complete_files > 0))
            .then_some(container.as_path())
    }
    pub(super) fn children_complete(&self, remaining_depth: usize) -> bool {
        self.children_complete && self.remaining_depth >= remaining_depth
    }

    pub(super) fn restore_input(&self, input: &mut ArchiveInput) {
        input.mode = self.input.mode;
        input.parts = self.input.parts.clone();
        input.ranges = self.input.ranges.clone();
        if self.failure.is_none() { input.volume_attempts = None; }
    }

    pub(super) fn relocate(&mut self, source: &Path, destination: &Path) -> bool {
        let relocate = |path: &Path| {
            let relative = path.strip_prefix(source).ok()?;
            Some(if relative.as_os_str().is_empty() {
                destination.to_path_buf()
            } else {
                destination.join(relative)
            })
        };
        let mut changed = false;
        let mut mapped = |path: &mut PathBuf| {
            if let Some(target) = relocate(path) {
                *path = target;
                changed = true;
            }
        };
        let has_output = self.has_output();
        mapped(&mut self.carrier);
        if let Some(planned) = &mut self.planned_output { mapped(planned); }
        mapped(&mut self.input.entry);
        if has_output { mapped(&mut self.output); }
        if let Some(container) = &mut self.container {
            mapped(container);
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
            if let Some(target) = relocate(Path::new(&extent.path)) {
                extent.path = target.to_string_lossy().into_owned();
                changed = true;
            }
        }
        changed
    }

    pub(super) fn relocate_flatten(&mut self, leaf: &Path, root: &Path) -> bool {
        let wrapper = self.has_output() && leaf.starts_with(&self.output) && self.output.starts_with(root);
        let changed = self.relocate(leaf, root);
        if wrapper { self.output = root.to_path_buf(); }
        changed || wrapper
    }

    /// Apply the same publication path mapping as the output transaction.
    pub(crate) fn rebase_flatten(&mut self, root: &Path, work: &Path, leaf: &Path) -> bool {
        let changed = self.relocate(work, root);
        self.relocate_flatten(leaf, root) || changed
    }

    pub(crate) fn has_output(&self) -> bool { !self.output.as_os_str().is_empty() }

    pub(crate) fn storage_key(&self) -> String {
        if self.has_output() { return self.output.to_string_lossy().into_owned(); }
        let key = self.key();
        format!("input|{}|{:?}|{}|{}", key.entry, key.mode, key.format, key.start)
    }

    pub(super) fn set_password_signature(&mut self, signature: impl FnOnce() -> String) {
        if let Some(receipt) = self.failure.as_mut().filter(|receipt| receipt.failure.is_password_retry()) {
            receipt.password_signature = Some(signature());
        }
    }

    pub(super) fn password_unchanged(&self, signature: impl FnOnce() -> String) -> bool {
        self.failure.as_ref().is_none_or(|receipt| !receipt.failure.is_password_retry()
            || receipt.password_signature.as_ref().is_some_and(|saved| *saved == signature()))
    }

    pub(super) fn promoted(&mut self, paths: &super::coordinator::PromotionPaths) -> io::Result<bool> {
        // Only physical sources are moved. Keep directory-prefix relocation in
        // relocate/rebase_flatten, where it is actually required.
        if !self.sources.iter().any(|source| paths.target(&source.path).is_some()) {
            return Ok(false);
        }
        if let Some(destination) = paths.target(&self.input.entry) {
            if let Some(facts) = self.failure.as_mut().and_then(|receipt| receipt.retry_facts.as_mut()) {
                let logical_name = crate::scan::directory::filesystem_logical_name;
                if facts.logical_name == logical_name(&self.input.entry.to_string_lossy()) {
                    facts.logical_name = logical_name(&destination.to_string_lossy());
                }
            }
        }
        paths.remap(&mut self.carrier);
        paths.remap(&mut self.input.entry);
        if let Some(receipt) = &mut self.failure { paths.remap_failure(&mut receipt.failure); }
        if let Some(planned) = &mut self.planned_output { paths.remap(planned); }
        if self.has_output() { paths.remap(&mut self.output); }
        if let Some(container) = &mut self.container { paths.remap(container); }
        for source in &mut self.sources {
            paths.remap(&mut source.path);
            source.generation = capture_file_generation(&source.path)?.persisted();
        }
        for extent in self.input.parts.iter_mut().map(|part| &mut part.extent).chain(&mut self.input.ranges) {
            if let Some(target) = paths.target(Path::new(&extent.path)) {
                extent.path = target.to_string_lossy().into_owned();
            }
        }
        Ok(true)
    }

    pub(super) fn result(&self, depth: usize) -> ArchiveResult {
        let failure = self.failure.as_ref().map(|receipt| receipt.failure.clone());
        let extent = self
            .input
            .parts
            .first()
            .map(|part| &part.extent)
            .or(self.input.ranges.first());
        ArchiveResult {
            path: self.input.entry.clone(),
            format: self.input.format.clone(),
            output: self.has_output().then(|| self.output.clone()),
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
            partial: self.failure.as_ref().is_some_and(|receipt| receipt.partial),
            retained: true,
            recovered_complete_files: self
                .failure
                .as_ref()
                .map_or(0, |receipt| receipt.complete_files),
            promoted: false,
            promotion_original_path: None,
        }
    }
}

fn plan_signature(input: &ArchiveInput) -> Option<String> {
    input.volume_attempts.as_ref().map(|plan| {
        let mut hash = crate::fast_hash_core::Hash128::new();
        hash.update(&serde_json::to_vec(plan).expect("volume plan is serializable"));
        hash.hexdigest()
    })
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

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::io::archive_state::{VolumeAttemptPlan, VolumeDomain, VolumeLayout, VolumeSlot};
    use std::{fs, sync::Arc};

    #[test]
    fn bulk_promotion_remaps_all_layout_fields_once() {
        let marker = crate::test_support::temp_file("checkpoint_bulk_promotion", b"marker");
        let root = marker.with_extension("output");
        fs::create_dir_all(&root).unwrap();
        let moves: Vec<_> = (0..256).map(|index| (
            root.join(format!("old-{index}")), root.join(format!("new-{index}")),
        )).collect();
        let mut sources = Vec::new();
        let mut parts = Vec::new();
        for (index, (source, target)) in moves.iter().enumerate() {
            fs::write(source, b"part").unwrap();
            sources.push(SourceGeneration {
                path: source.clone(), generation: capture_file_generation(source).unwrap().persisted(),
            });
            parts.push(InputPart {
                extent: InputExtent { path: source.to_string_lossy().into_owned(), start: 0, end: Some(4) },
                volume_number: Some(index as u32 + 1), canonical_name: format!("archive.7z.{:03}", index + 1),
            });
            fs::rename(source, target).unwrap();
        }
        let retained = root.join("retained-output");
        let mut checkpoint = InputCheckpoint {
            schema_version: SCHEMA_VERSION, carrier: moves[0].0.clone(),
            input: LogicalLayout {
                entry: moves[0].0.clone(), mode: OpenMode::NativeVolumes, format: "7z".into(),
                ranges: parts.iter().map(|part| part.extent.clone()).collect::<Vec<_>>().into_boxed_slice(),
                parts: parts.into_boxed_slice(),
            },
            sources: sources.into_boxed_slice(), output: retained.clone(),
            planned_output: Some(retained.clone()), container: Some(root.clone()),
            files: 1, bytes: 4, encrypted: None, discovery_source: DiscoverySource::Embedded,
            children_complete: true, remaining_depth: 0, failure: None,
        };
        let paths = super::super::coordinator::PromotionPaths::new(&moves);
        assert!(checkpoint.promoted(&paths).unwrap());
        assert_eq!(checkpoint.carrier, moves[0].1);
        assert_eq!(checkpoint.input.entry, moves[0].1);
        assert_eq!(checkpoint.output, retained);
        assert_eq!(checkpoint.planned_output.as_ref(), Some(&retained));
        assert_eq!(checkpoint.container.as_ref(), Some(&root));
        for (index, (_, target)) in moves.iter().enumerate() {
            assert_eq!(&checkpoint.sources[index].path, target);
            assert_eq!(Path::new(&checkpoint.input.parts[index].extent.path), target);
            assert_eq!(Path::new(&checkpoint.input.ranges[index].path), target);
            assert_eq!(checkpoint.sources[index].generation, capture_file_generation(target).unwrap().persisted());
        }
        assert!(!checkpoint.promoted(&paths).unwrap());
        fs::remove_dir_all(root).unwrap();
        fs::remove_file(marker).unwrap();
    }

    #[test]
    fn promoted_partial_collision_reuses_receipt_after_fresh_discovery_naming() {
        use crate::io::archive_state::archive_input_slices;
        use crate::postprocess::NativeBlockedInputPromotion;
        use crate::scan::directory::filesystem_logical_name;

        let marker = crate::test_support::temp_file("checkpoint_promotion_collision", b"marker");
        let root = marker.with_extension("output");
        for (filename, promoted_name) in [("carrier.bin", "carrier.bin"), ("carrier.zip", "carrier")] {
            let nested = root.join("nested");
            let container = nested.join("retained");
            let output = container.join("segment");
            fs::create_dir_all(&output).unwrap();
            fs::write(output.join("payload"), b"keep").unwrap();
            let source = nested.join(filename);
            fs::write(&source, b"archive!").unwrap();
            fs::write(root.join(filename), b"existing").unwrap();
            let discover = |path: &Path| {
                let path = path.to_string_lossy();
                let carrier = ArchiveInput::file(
                    path.to_string(), "zip".into(), filesystem_logical_name(&path),
                );
                archive_input_slices(&carrier, &[("zip", 0, Some(4))])
                    .unwrap().0.remove(0).unwrap()
            };
            let input = discover(&source);
            let failure = Failure::new(FailureKind::Damaged, "accepted partial");
            let mut checkpoint = InputCheckpoint {
                schema_version: SCHEMA_VERSION,
                carrier: source.clone(),
                input: LogicalLayout {
                    entry: source.clone(), mode: input.mode, format: input.format_hint.clone(),
                    parts: input.parts.clone(), ranges: input.ranges.clone(),
                },
                sources: vec![SourceGeneration {
                    path: source.clone(), generation: capture_file_generation(&source).unwrap().persisted(),
                }].into_boxed_slice(),
                output: output.clone(),
                planned_output: None,
                container: Some(container.clone()),
                files: 1, bytes: 4, encrypted: None,
                discovery_source: DiscoverySource::Embedded, children_complete: true,
                remaining_depth: 0,
                failure: Some(FailureReceipt {
                    partial: true, password_signature: None,
                    failure, complete_files: 1,
                    retry_facts: Some(RetryFacts {
                        logical_name: input.logical_name.clone(), analysis: input.analysis.clone(),
                    plan_signature: plan_signature(&input),
                    }),
                }),
            };
            let plan = NativeBlockedInputPromotion::new(
                vec![source.to_string_lossy().into_owned()], root.clone(),
            ).unwrap();
            let destination = plan.moves()[0].1.clone();
            assert_ne!(destination, root.join(filename));
            let (_, _, _, error, _) = plan.execute(|| Ok(()));
            assert!(error.is_empty(), "{error}");
            checkpoint.promoted(&super::super::coordinator::PromotionPaths::new(plan.moves())).unwrap();
            let checkpoint: InputCheckpoint = serde_json::from_value(
                serde_json::to_value(checkpoint).unwrap(),
            ).unwrap();
            let rediscovered = discover(&destination);
            assert_eq!(rediscovered.logical_name, promoted_name);
            let generations = HashMap::from([(
                path_key(&rediscovered.entry_path), capture_file_generation(&destination).unwrap(),
            )]);
            assert!(checkpoint.valid_for(&rediscovered, &generations));
            let result = checkpoint.result(1);
            assert!(result.retained && result.partial);
            assert_eq!(result.failure.unwrap().kind, FailureKind::Damaged);
            assert_eq!(result.recovered_complete_files, 1);
            assert_eq!(fs::read(output.join("payload")).unwrap(), b"keep");
            let mut changed = rediscovered;
            changed.analysis.password_required = true;
            assert!(!checkpoint.valid_for(&changed, &generations));
            fs::remove_dir_all(&root).unwrap();
        }
        fs::remove_file(marker).unwrap();
    }

    #[test]
    fn partial_retry_requires_fixed_mapping_and_facts_but_complete_admits_alternatives() {
        let source = crate::test_support::temp_file("checkpoint_retry", b"archive");
        let output = source.with_extension("output");
        fs::create_dir(&output).unwrap();
        let mut input = ArchiveInput::file(
            source.to_string_lossy().into_owned(), "7z".into(), "archive".into(),
        );
        input.mode = OpenMode::NativeVolumes;
        input.parts = vec![InputPart {
            extent: InputExtent { path: input.entry_path.clone(), start: 0, end: Some(7) },
            volume_number: Some(1),
            canonical_name: "archive.7z.001".into(),
        }].into_boxed_slice();
        let key = path_key(&input.entry_path);
        let mut generations = HashMap::from([
            (key.clone(), capture_file_generation(&source).unwrap()),
        ]);
        let complete = InputCheckpoint {
            schema_version: SCHEMA_VERSION,
            carrier: source.clone(),
            input: LogicalLayout {
                entry: source.clone(), mode: input.mode, format: input.format_hint.clone(),
                parts: input.parts.clone(), ranges: input.ranges.clone(),
            },
            sources: vec![SourceGeneration {
                path: source.clone(), generation: generations[&key].persisted(),
            }].into_boxed_slice(),
            output: output.clone(),
            planned_output: None,
            container: None, files: 1, bytes: 7, encrypted: None,
            discovery_source: DiscoverySource::Direct, children_complete: true,
            remaining_depth: 0, failure: None,
        };
        let mut result = complete.result(1);
        result.failure = Some(Failure::new(FailureKind::MissingVolume, "missing volume"));
        result.partial = true;
        result.recovered_complete_files = 1;
        let partial = InputCheckpoint::create(
            &source, &input, &result, &generations, None, true, 0,
        ).unwrap();
        // Exercise the persisted representation, not just in-memory equality.
        let partial: InputCheckpoint = serde_json::from_slice(
            &serde_json::to_vec(&partial).unwrap(),
        ).unwrap();
        assert!(partial.valid_for(&input, &generations));
        let mut changed = input.clone();
        changed.analysis.password_required = true;
        assert!(!partial.valid_for(&changed, &generations));
        changed = input.clone();
        changed.logical_name.push_str("-new");
        assert!(!partial.valid_for(&changed, &generations));

        let mut alternatives = input.clone();
        alternatives.volume_attempts = Some(Box::new(VolumeAttemptPlan {
            sources: vec![input.parts[0].extent.clone(), InputExtent {
                path: source.with_extension("alternative").to_string_lossy().into_owned(),
                start: 0, end: Some(7),
            }].into_boxed_slice(),
            layouts: vec![VolumeLayout {
                slots: vec![VolumeSlot {
                    number: 1, canonical_name: input.parts[0].canonical_name.clone(), domain: 0,
                }].into_boxed_slice(), minimum_slots: 0,
            }].into_boxed_slice(),
            domains: vec![VolumeDomain { choices: Arc::new(vec![0, 1]) }].into_boxed_slice(),
            head_size_from_total: None, minimum_size: None, tail_totals: Box::new([]),
        }));
        assert!(complete.valid_for(&alternatives, &generations));
        assert!(!partial.valid_for(&alternatives, &generations));
        assert!(InputCheckpoint::create(
            &source, &alternatives, &result, &generations, None, true, 0,
        ).is_some());

        let mut legacy = serde_json::to_value(&partial).unwrap();
        legacy["failure"].as_object_mut().unwrap().remove("retry_facts");
        let legacy: InputCheckpoint = serde_json::from_value(legacy).unwrap();
        assert!(!legacy.valid_for(&input, &generations));
        assert!(!legacy.valid_for(&alternatives, &generations));
        let legacy_complete: InputCheckpoint = serde_json::from_value(
            serde_json::to_value(&complete).unwrap(),
        ).unwrap();
        assert!(legacy_complete.valid_for(&input, &generations));
        assert!(legacy_complete.valid_for(&alternatives, &generations));
        // A failed input reserves its name without advertising recoverable
        // content. Persist and relocate that namespace independently of output.
        let mut failed = partial.clone();
        failed.output = PathBuf::new();
        let container = output.with_extension("carrier");
        let slot = container.join("segment");
        failed.container = Some(container.clone());
        failed.set_planned_output(Some(&slot));
        let mut failed: InputCheckpoint = serde_json::from_slice(
            &serde_json::to_vec(&failed).unwrap(),
        ).unwrap();
        assert!(!failed.has_output());
        assert!(failed.result(1).output.is_none());
        assert!(failed.output_slot_for(&input, &container));
        assert_eq!(failed.output_slot(), Some(slot.as_path()));
        let moved = container.with_extension("moved");
        assert!(failed.relocate(&container, &moved));
        assert_eq!(failed.output_slot(), Some(moved.join("segment").as_path()));
        assert!(!failed.has_output());
        // Length changes make this deterministic even on coarse file clocks.
        fs::write(&source, b"changed archive generation").unwrap();
        generations.insert(key, capture_file_generation(&source).unwrap());
        assert!(!partial.valid_for(&input, &generations));
        assert!(!complete.valid_for(&alternatives, &generations));
        // Promotion moves the source file itself, not only a containing
        // directory. Its rebased generation must reopen the new file path.
        let promoted = source.with_extension("promoted");
        fs::rename(&source, &promoted).unwrap();
        let mut complete = complete;
        complete.promoted(&super::super::coordinator::PromotionPaths::new(&[(source, promoted.clone())])).unwrap();
        assert_eq!(complete.entry(), promoted);
        assert_eq!(Path::new(&complete.input.parts[0].extent.path), promoted);
        fs::remove_dir(output).unwrap();
        fs::remove_file(promoted).unwrap();
    }
}
