//! Durable receipts hold physical layouts, retry facts and counters, never
//! archive file tables, analysis caches, password lists, or native reader handles.

use super::{ArchiveResult, DiscoverySource, Failure, FailureKind};
use crate::io::archive_state::ArchiveInput;
#[cfg(test)]
use crate::io::archive_state::OpenMode;
use crate::io::reader::{capture_file_generation, PhysicalFileGeneration};
use crate::path_keys::path_key;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    io,
    path::{Path, PathBuf},
    sync::Arc,
};

const SCHEMA_VERSION: u8 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InputCheckpoint {
    schema_version: u8,
    carrier: PathBuf,
    input: Arc<ArchiveInput>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    report: Option<ReportState>,
    sources: Arc<[SourceGeneration]>,
    output: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    planned_output: Option<PathBuf>,
    container: Option<PathBuf>,
    files: u64,
    bytes: u64,
    encrypted: Option<bool>,
    discovery_source: DiscoverySource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    failure: Option<Arc<FailureReceipt>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct FailureReceipt {
    partial: bool,
    password_signature: Option<String>,
    failure: Failure,
    complete_files: u64,
}

/// Facts captured before content cleanup/recursion. Execution output ownership
/// remains separate: a diagnostic output name need not name retained bytes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct ReportState {
    input_id: String,
    position: usize,
    input_count: usize,
    output: PathBuf,
    files: u64,
    bytes: u64,
    recovered_complete_files: u64,
}

/// A bounded failure report references the same input descriptors as the durable
/// receipts. It owns no handles, inventories, or additional filesystem probes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct InputRecovery {
    inputs: Vec<RecoveryReceipt>,
    output: PathBuf,
    input_count: usize,
    had_checkpoints: bool,
    retry_output: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RecoveryReceipt {
    input: Arc<ArchiveInput>,
    report: ReportState,
    sources: Arc<[SourceGeneration]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    failure: Option<Arc<FailureReceipt>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SourceGeneration {
    path: PathBuf,
    generation: PhysicalFileGeneration,
}

/// A generated source generation, retained at its original path for a later retry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct GeneratedSource(SourceGeneration);

impl GeneratedSource {
    pub(crate) fn capture(path: &Path) -> io::Result<Self> {
        Ok(Self::from_generation(path, &capture_file_generation(path)?))
    }

    pub(super) fn from_generation(path: &Path, generation: &PhysicalFileGeneration) -> Self {
        Self(SourceGeneration {
            path: path.to_path_buf(),
            generation: generation.clone(),
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0.path
    }

    pub(crate) fn matches(&self, generation: &PhysicalFileGeneration) -> bool {
        generation == &self.0.generation
    }

}

impl InputCheckpoint {

    pub fn carrier(&self) -> &Path {
        &self.carrier
    }
    pub fn output(&self) -> &Path {
        &self.output
    }
    pub fn source_paths(&self) -> impl Iterator<Item = &Path> {
        self.sources.iter().map(|source| source.path.as_path())
    }

    pub(super) fn input(&self) -> &ArchiveInput { &self.input }
    pub(super) fn failure(&self) -> Option<&Failure> { self.failure.as_ref().map(|receipt| &receipt.failure) }

    pub(super) fn key(&self) -> CheckpointKey {
        self.report.as_ref().map_or_else(|| CheckpointKey::for_input(&self.input),
            |report| CheckpointKey(report.input_id.clone()))
    }

    pub(super) fn create(
        carrier: &Path,
        input: Arc<ArchiveInput>,
        result: &ArchiveResult,
        generations: &HashMap<String, PhysicalFileGeneration>,
        container: Option<&Path>,
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
                generation: generation.clone(),
            });
        }
        if sources.is_empty() {
            return None;
        }
        Some(Self {
            schema_version: SCHEMA_VERSION,
            carrier: carrier.to_path_buf(),
            input,
            report: None,
            sources: sources.into(),
            output: result.output.clone().unwrap_or_default(),
            planned_output: None,
            container: container.map(Path::to_path_buf),
            files: result.files,
            bytes: result.bytes,
            encrypted: result.encrypted,
            discovery_source: result.discovery_source,
            failure: result.failure.as_ref().map(|failure| Arc::new(FailureReceipt {
                partial: result.partial,
                password_signature: None,
                failure: failure.clone(),
                complete_files: result.recovered_complete_files,
            })),
        })
    }

    pub(super) fn report_state(
        input: &ArchiveInput, result: &ArchiveResult, planned: Option<&Path>,
        previous: Option<&Self>, position: usize, input_count: usize,
    ) -> Option<ReportState> {
        if result.failure.as_ref().is_some_and(|failure| match failure.context.as_deref() {
            Some(super::FailureContext::InputAdmission { .. }) => true,
            // A single blocked discovery only tries to replace its volume plan.
            // If it remains blocked, the extraction state machine never ran.
            Some(super::FailureContext::Discovery { .. }) => input_count == 1,
            _ => false,
        }) {
            return None;
        }
        let old = previous.and_then(|checkpoint| checkpoint.report.as_ref());
        if result.retained {
            if let Some(old) = old {
                let mut state = old.clone(); state.input_count = input_count; return Some(state);
            }
        }
        Some(ReportState {
            input_id: old.map(|old| old.input_id.clone())
                .unwrap_or_else(|| CheckpointKey::for_input(input).0),
            position: old.map_or(position, |old| old.position), input_count,
            output: result.output.as_deref().or(planned).unwrap_or(Path::new("")).to_path_buf(),
            files: result.files, bytes: result.bytes,
            recovered_complete_files: result.recovered_complete_files,
        })
    }

    pub(super) fn settle_result(&mut self, result: &ArchiveResult) {
        self.output = result.output.clone().unwrap_or_default();
        match (&mut self.failure, &result.failure) {
            (Some(receipt), Some(failure)) => Arc::make_mut(receipt).failure = failure.clone(),
            (slot @ None, Some(failure)) => *slot = Some(Arc::new(FailureReceipt {
                partial: result.partial, password_signature: None, failure: failure.clone(),
                complete_files: result.recovered_complete_files,
            })),
            (_, None) => self.failure = None,
        }
    }

    pub(super) fn install_report(&mut self, state: Option<ReportState>) { self.report = state; }

    /// Replacement preserves the old checkpoint only when the new logical ID
    /// differs. Main's ID deliberately excludes display name and open mode.
    pub(super) fn same_report_input(&self, input: &ArchiveInput) -> bool {
        let Some(report) = &self.report else { return false; };
        report.input_id == CheckpointKey::for_input(input).0
    }

    pub(super) fn has_recovered_members(&self) -> bool {
        self.failure.as_ref().is_some_and(|failure| failure.complete_files > 0)
    }

    pub(super) fn clear_recovery_output(&mut self) {
        Self::clear_report_output(&mut self.report);
        self.output.clear();
        self.planned_output = None;
        if let Some(failure) = &mut self.failure {
            Arc::make_mut(failure).complete_files = 0;
        }
    }

    pub(super) fn report_position(&self) -> Option<usize> {
        self.report.as_ref().map(|report| report.position)
    }

    pub(super) fn report_input_count(&self) -> usize {
        self.report.as_ref().map_or(0, |report| report.input_count)
    }

    pub(super) fn clear_report_output(state: &mut Option<ReportState>) {
        if let Some(state) = state {
            state.output.clear();
            state.recovered_complete_files = 0;
        }
    }

    pub(super) fn valid_for(
        &self,
        input: &ArchiveInput,
        generations: &HashMap<String, PhysicalFileGeneration>,
    ) -> bool {
        self.schema_version == SCHEMA_VERSION
            // A worker or output device failure says nothing about this input. Keep
            // its output slot and sibling receipts, but run the input again.
            && self.failure.as_ref().is_none_or(|receipt| !receipt.failure.worker_lost() && !receipt.failure.output_filesystem_error()
                    && self.input.logical_name == input.logical_name
                    && self.input.volume_style == input.volume_style
                    && self.input.analysis == input.analysis
                    && self.input.volume_attempts == input.volume_attempts
            )
            && (if self.failure.is_some() {
                self.input.entry_path == input.entry_path
                    && self.input.mode == input.mode && self.input.format_hint == input.format_hint
                    && self.input.parts == input.parts
            } else { layout_matches(&self.input, input) })
            && self.sources.iter().all(|source| {
                generations
                    .get(&path_key(&source.path.to_string_lossy()))
                    .is_some_and(|generation| generation.matches_input(&source.generation))
            })

    }

    pub(super) fn output_slot(&self) -> Option<&Path> {
        if self.has_output() { Some(self.output()) } else { self.planned_output.as_deref() }
    }

    pub(super) fn set_planned_output(&mut self, path: Option<&Path>) {
        self.planned_output = if self.has_output() { None } else { path.map(Path::to_path_buf) };
    }

    pub(super) fn output_slot_for(&self, input: &ArchiveInput, container: &Path) -> bool {
        // The caller has selected this logical identity (including a unique
        // source-anchor match). Generation changes do not revoke its old slot.
        self.schema_version == SCHEMA_VERSION
            && self.container() == Some(container)
            && self.output_slot().is_some_and(|output| output.strip_prefix(container)
                .is_ok_and(|relative| !relative.as_os_str().is_empty()))
            && self.input.format_hint == input.format_hint
    }

    pub(crate) fn container(&self) -> Option<&Path> {
        self.container
            .as_ref()
            .map(|container| container.as_path())
    }
    pub(crate) fn retained_container(&self) -> Option<&Path> {
        let container = self.container.as_ref()?;
        self.continuable_output().then_some(container.as_path())
    }
    pub(super) fn continuable_output(&self) -> bool {
        self.has_output() && self.failure.as_ref().is_none_or(|receipt| receipt.complete_files > 0)
    }
    pub(super) fn shared_input(&self) -> Arc<ArchiveInput> {
        Arc::clone(&self.input)
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
        if let Some(report) = &mut self.report { mapped(&mut report.output); }
        if has_output { mapped(&mut self.output); }
        if let Some(container) = &mut self.container { mapped(container); }
        if self.sources.iter().any(|generation| generation.path.starts_with(source)) {
            for generation in Arc::make_mut(&mut self.sources) { mapped(&mut generation.path); }
        }
        drop(mapped);
        // Output flattening usually does not move the archive descriptor.
        // Do not copy a shared plan unless one of its physical paths changes.
        let moves_plan_source = self.input.volume_attempts.as_ref().is_some_and(|plan| {
            plan.sources.iter().any(|extent| Path::new(&extent.path).starts_with(source))
        });
        if !moves_plan_source && !Path::new(&self.input.entry_path).starts_with(source)
            && !self.input.physical_extents().any(|extent| Path::new(&extent.path).starts_with(source))
        { return changed; }
        let input = Arc::make_mut(&mut self.input);
        if let Some(target) = relocate(Path::new(&input.entry_path)) {
            input.entry_path = target.to_string_lossy().into_owned();
            changed = true;
        }
        for extent in input
            .parts
            .iter_mut()
            .map(|part| &mut part.extent)
        {
            if let Some(target) = relocate(Path::new(&extent.path)) {
                extent.path = target.to_string_lossy().into_owned();
                changed = true;
            }
        }
        if moves_plan_source {
            let plan = Arc::make_mut(input.volume_attempts.as_mut().unwrap());
            for extent in &mut plan.sources {
                if let Some(target) = relocate(Path::new(&extent.path)) {
                    extent.path = target.to_string_lossy().into_owned(); changed = true;
                }
            }
        }
        changed
    }

    pub(super) fn relocate_flatten(&mut self, root: &Path, leaf: &Path, destination: &Path) -> bool {
        // Only directory receipts can refer to wrappers that disappear entirely.
        let mut wrapper = false;
        let mut relocate_wrapper = |path: &mut PathBuf| {
            if path != leaf && leaf.starts_with(&*path) && path.starts_with(root) {
                *path = destination.to_path_buf();
                wrapper = true;
            }
        };
        if self.has_output() { relocate_wrapper(&mut self.output); }
        if let Some(planned) = &mut self.planned_output { relocate_wrapper(planned); }
        if let Some(container) = &mut self.container { relocate_wrapper(container); }
        if let Some(report) = &mut self.report {
            relocate_wrapper(&mut report.output);
        }
        self.relocate(leaf, destination) || wrapper
    }

    pub(crate) fn has_output(&self) -> bool { !self.output.as_os_str().is_empty() }

    pub(super) fn set_password_signature(&mut self, signature: impl FnOnce() -> String) {
        if let Some(receipt) = self.failure.as_mut().filter(|receipt| receipt.failure.is_password_retry()) {
            Arc::make_mut(receipt).password_signature = Some(signature());
        }
    }

    pub(super) fn password_unchanged(&self, signature: impl FnOnce() -> String) -> bool {
        self.failure.as_ref().is_none_or(|receipt| !receipt.failure.is_password_retry()
            || receipt.password_signature.as_ref().is_some_and(|saved| *saved == signature()))
    }

    pub(super) fn result(&self, depth: usize) -> ArchiveResult {
        let failure = self.failure.as_ref().map(|receipt| receipt.failure.clone());
        let extent = self
            .input
            .parts
            .first()
            .map(|part| &part.extent);
        ArchiveResult {
            path: PathBuf::from(&self.input.entry_path),
            format: self.input.format_hint.clone(),
            output: self.has_output().then(|| self.output.clone()),
            volume_completeness: self.input.mode.structured().then(|| {
                if failure
                    .as_ref()
                    .is_some_and(|failure| failure.kind == FailureKind::MissingVolume)
                {
                    super::VolumeCompleteness::Missing
                } else {
                    super::VolumeCompleteness::Complete
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
                        partial: self.failure.as_ref().is_some_and(|receipt| receipt.partial),
            retained: true,
            recovered_complete_files: self
                .failure
                .as_ref()
                .map_or(0, |receipt| receipt.complete_files),

            scan_layout: super::ScanLayout::default(),
        }
    }
}

impl InputRecovery {
    pub(super) fn capture<'a>(
        checkpoints: impl IntoIterator<Item = &'a InputCheckpoint>, carrier: &Path, relocated_carrier: Option<&Path>, output: Option<&Path>,
        input_count: usize, had_checkpoints: bool, retry_output: bool,
    ) -> Option<Arc<Self>> {
        let inputs: Vec<_> = checkpoints.into_iter()
            .filter(|checkpoint| checkpoint.carrier() == carrier || relocated_carrier == Some(checkpoint.carrier()))
            .filter_map(|checkpoint| Some(RecoveryReceipt {
                report: checkpoint.report.as_ref()?.clone(),
                input: Arc::clone(&checkpoint.input),
                sources: Arc::clone(&checkpoint.sources),
                failure: checkpoint.failure.clone(),
            }))
            .collect();
        if inputs.is_empty() { return None; }
        let cleared = inputs.iter().all(|input| input.report.output.as_os_str().is_empty());
        let output = if cleared { PathBuf::new() } else { output.map(Path::to_path_buf).unwrap_or_else(||
            inputs[0].report.output.clone()) };
        Some(Arc::new(Self { inputs, output, input_count, had_checkpoints, retry_output: retry_output && !cleared }))
    }

    pub(crate) fn aggregated(&self) -> bool { self.had_checkpoints || self.input_count > 1 }
    pub(crate) fn input_count(&self) -> usize { self.input_count }
    pub(crate) fn retry_output(&self) -> Option<&Path> {
        self.retry_output.then_some(self.output.as_path())
    }

    pub(crate) fn has_password_blocker(&self) -> bool {
        self.inputs.iter().filter_map(|input| input.failure.as_ref()).any(|receipt| receipt.failure.is_password_retry())
    }

    /// Borrow receipts until the final writer consumes them.
    pub(crate) fn report_view<'a, T: Serialize + 'a>(
        &'a self, failure: impl Fn(&'a Failure) -> T + 'a,
    ) -> impl Serialize + 'a {
        RecoveryReport { recovery: self, failure }
    }

    #[cfg(test)]
    pub(crate) fn report(&self, failure: impl Fn(&Failure) -> serde_json::Value) -> serde_json::Value {
        serde_json::to_value(self.report_view(failure)).expect("recovery report serializes")
    }

    pub(super) fn relocate_flatten(&mut self, root: &Path, leaf: &Path, destination: &Path) {
        super::relocate_flatten_output(&mut self.output, root, leaf, destination);
        for input in &mut self.inputs {
            if !input.report.output.as_os_str().is_empty() {
                super::relocate_flatten_output(&mut input.report.output, root, leaf, destination);
            }
        }
    }
}

#[derive(Hash, PartialEq, Eq)]
pub(super) struct CheckpointKey(String);

impl CheckpointKey {
    pub(super) fn for_input(input: &ArchiveInput) -> Self {
        let extent = input.physical_extents().next();
        Self(crate::io::archive_state::logical_input_id(
            &path_key(&input.entry_path), &input.format_hint, extent.map_or(0, |e| e.start),
            extent.and_then(|e| e.view.as_deref()).map(Into::into).as_ref(),
            input.analysis.zip_directory_id.as_deref(),
            extent.filter(|_| input.analysis.distinguish_end).and_then(|e| e.end),
        ))
    }
}

fn layout_matches(saved: &ArchiveInput, input: &ArchiveInput) -> bool {
        if saved.mode != input.mode
            || !saved.analysis.compatible_directory(&input.analysis)
            || saved.format_hint != input.format_hint
        {
            return false;
        }
        match &input.volume_attempts {
            Some(plan) => saved.volume_attempts.is_none() && saved.volume_style == input.volume_style && plan.admits_parts(&saved.parts),
            None => saved.parts == input.parts,
        }
    }

struct RecoveryReport<'a, F> { recovery: &'a InputRecovery, failure: F }
struct RecoveryInputs<'a, F> { recovery: &'a InputRecovery, failure: F }
struct RecoveryInput<'a, F> { receipt: &'a RecoveryReceipt, failure: F }

impl<'a, F, T> Serialize for RecoveryReport<'a, F>
where F: Fn(&'a Failure) -> T, T: Serialize {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("input_count", &self.recovery.input_count)?;
        map.serialize_entry("inputs", &RecoveryInputs { recovery: self.recovery, failure: &self.failure })?;
        map.serialize_entry("output_dir", &self.recovery.output)?;
        map.end()
    }
}
impl<'a, F, T> Serialize for RecoveryInputs<'a, F>
where F: Fn(&'a Failure) -> T, T: Serialize {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(self.recovery.inputs.len()))?;
        for receipt in &self.recovery.inputs {
            seq.serialize_element(&RecoveryInput { receipt, failure: &self.failure })?;
        }
        seq.end()
    }
}
impl<'a, F, T> Serialize for RecoveryInput<'a, F>
where F: Fn(&'a Failure) -> T, T: Serialize {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let receipt = self.receipt;
        let state = &receipt.report;
        let error = receipt.failure.as_ref().map(|receipt| &receipt.failure);
        let mut blockers = [""; 2];
        let mut count = 0;
        if let Some(error) = error {
            if error.kind == FailureKind::MissingVolume
                || receipt.input.execution_evidence().is_some()
                || receipt.input.analysis.volume_completeness == Some(crate::io::archive_state::VolumeCompleteness::Missing)
                || error.evidence.as_deref().is_some_and(|e| e.classification_evidence.as_deref() == Some("password_or_volume_inconclusive"))
            { blockers[count] = "missing_volume"; count += 1; }
            if error.is_password_retry() { blockers[count] = "password"; count += 1; }
        }
        let mut map = serializer.serialize_map(Some(11))?;
        map.serialize_entry("archive_input", &receipt.input.report())?;
        map.serialize_entry("blockers", &blockers[..count])?;
        map.serialize_entry("bytes_written", &state.bytes)?;
        map.serialize_entry("complete", &error.is_none())?;
        map.serialize_entry("failure", &error.map(&self.failure))?;
        map.serialize_entry("files_written", &state.files)?;
        map.serialize_entry("generation", &receipt.sources)?;
        map.serialize_entry("input_id", &state.input_id)?;
        map.serialize_entry("output_dir", &state.output)?;
        map.serialize_entry("position", &state.position)?;
        map.serialize_entry("recovered_complete_files", &state.recovered_complete_files)?;
        map.end()
    }
}
#[cfg(all(test, windows))]
#[path = "../../tests/unit/pipeline/checkpoint/tests.rs"]
mod tests;
