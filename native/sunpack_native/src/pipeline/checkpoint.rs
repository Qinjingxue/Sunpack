//! Durable receipts hold physical layouts, retry facts and counters, never
//! archive file tables, analysis caches, password lists, or native reader handles.

use super::{ArchiveResult, DiscoverySource, Failure, FailureKind};
use crate::io::archive_state::ArchiveInput;
#[cfg(test)]
use crate::io::archive_state::OpenMode;
use crate::io::reader::{
    capture_file_generation, PersistedFileGeneration, PhysicalFileGeneration,
};
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
    logical_name: String,
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
    inputs: Vec<InputCheckpoint>,
    output: PathBuf,
    input_count: usize,
    had_checkpoints: bool,
    retry_output: bool,
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
        Path::new(&self.input.entry_path)
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
                generation: generation.persisted(),
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
        if result.failure.as_ref().is_some_and(|failure| matches!(failure.context.as_deref(),
            Some(super::FailureContext::InputAdmission { .. }))) {
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
            logical_name: input.logical_name.clone(),
            position: old.map_or(position, |old| old.position), input_count,
            output: result.output.as_deref().or(planned).unwrap_or(Path::new("")).to_path_buf(),
            files: result.files, bytes: result.bytes,
            recovered_complete_files: result.recovered_complete_files,
        })
    }

    pub(super) fn install_report(&mut self, state: Option<ReportState>) { self.report = state; }

    /// Replacement preserves the old checkpoint only when the new logical ID
    /// differs. Main's ID deliberately excludes display name and open mode.
    pub(super) fn same_report_input(&self, input: &ArchiveInput) -> bool {
        let Some(report) = &self.report else { return false; };
        let start = input.physical_extents().next().map_or(0, |extent| extent.start);
        report.input_id == format!("{}|{}|{}", path_key(&input.entry_path), input.format_hint, start)
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
            && (self.failure.is_none() || (
                self.input.logical_name == input.logical_name
                    && self.input.volume_style == input.volume_style
                    && self.input.analysis == input.analysis
                    && self.input.volume_attempts == input.volume_attempts
            ))
            && (if self.failure.is_some() {
                self.input.entry_path == input.entry_path
                    && self.input.mode == input.mode && self.input.format_hint == input.format_hint
                    && self.input.parts == input.parts && self.input.ranges == input.ranges
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
        if !Path::new(&self.input.entry_path).starts_with(source)
            && !self.input.physical_extents().any(|extent| Path::new(&extent.path).starts_with(source))
            && !self.input.volume_attempts.as_ref().is_some_and(|plan|
                plan.sources.iter().any(|extent| Path::new(&extent.path).starts_with(source)))
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
            .chain(&mut input.ranges)
        {
            if let Some(target) = relocate(Path::new(&extent.path)) {
                extent.path = target.to_string_lossy().into_owned();
                changed = true;
            }
        }
        if let Some(plan) = &mut input.volume_attempts {
            for extent in &mut plan.sources {
                if let Some(target) = relocate(Path::new(&extent.path)) {
                    extent.path = target.to_string_lossy().into_owned(); changed = true;
                }
            }
        }
        changed
    }

    pub(super) fn relocate_flatten(&mut self, leaf: &Path, root: &Path) -> bool {
        let wrapper = self.has_output() && leaf.starts_with(&self.output) && self.output.starts_with(root);
        let changed = self.relocate(leaf, root);
        if wrapper { self.output = root.to_path_buf(); }
        if let Some(report) = &mut self.report {
            if !report.output.as_os_str().is_empty() && leaf.starts_with(&report.output) && report.output.starts_with(root) {
                report.output = root.to_path_buf();
            }
        }
        changed || wrapper
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

    pub(super) fn promoted(&mut self, paths: &super::coordinator::PromotionPaths) -> io::Result<bool> {
        // Only physical sources are moved. Keep directory-prefix relocation in
        // relocate, where it is actually required.
        if !self.sources.iter().any(|source| paths.target(&source.path).is_some()) {
            return Ok(false);
        }
        let has_output = self.has_output();
        let input = Arc::make_mut(&mut self.input);
        if let Some(destination) = paths.target(Path::new(&input.entry_path)) {
            let logical_name = crate::scan::directory::filesystem_logical_name;
            if input.logical_name == logical_name(&input.entry_path) {
                input.logical_name = logical_name(&destination.to_string_lossy());
            }
            input.entry_path = destination.to_string_lossy().into_owned();
        }
        paths.remap(&mut self.carrier);
        if let Some(planned) = &mut self.planned_output { paths.remap(planned); }
        if has_output { paths.remap(&mut self.output); }
        if let Some(report) = &mut self.report { paths.remap(&mut report.output); }
        if let Some(container) = &mut self.container { paths.remap(container); }
        for source in Arc::make_mut(&mut self.sources) {
            paths.remap(&mut source.path);
            source.generation = capture_file_generation(&source.path)?.persisted();
        }
        for extent in input.parts.iter_mut().map(|part| &mut part.extent).chain(&mut input.ranges) {
            if let Some(target) = paths.target(Path::new(&extent.path)) {
                extent.path = target.to_string_lossy().into_owned();
            }
        }
        if let Some(plan) = &mut input.volume_attempts {
            for extent in &mut plan.sources {
                if let Some(target) = paths.target(Path::new(&extent.path)) {
                    extent.path = target.to_string_lossy().into_owned();
                }
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
            path: PathBuf::from(&self.input.entry_path),
            format: self.input.format_hint.clone(),
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

impl InputRecovery {
    pub(super) fn capture<'a>(
        checkpoints: impl IntoIterator<Item = &'a InputCheckpoint>, carrier: &Path, relocated_carrier: Option<&Path>, output: Option<&Path>,
        input_count: usize, had_checkpoints: bool, retry_output: bool,
    ) -> Option<Arc<Self>> {
        let inputs: Vec<_> = checkpoints.into_iter()
            .filter(|checkpoint| (checkpoint.carrier() == carrier || relocated_carrier == Some(checkpoint.carrier())) && checkpoint.report.is_some())
            .cloned().collect();
        if inputs.is_empty() { return None; }
        let cleared = inputs.iter().all(|checkpoint| checkpoint.report.as_ref().unwrap().output.as_os_str().is_empty());
        let output = if cleared { PathBuf::new() } else { output.map(Path::to_path_buf).unwrap_or_else(||
            inputs[0].report.as_ref().unwrap().output.clone()) };
        Some(Arc::new(Self { inputs, output, input_count, had_checkpoints, retry_output: retry_output && !cleared }))
    }

    pub(crate) fn aggregated(&self) -> bool { self.had_checkpoints || self.input_count > 1 }
    pub(crate) fn input_count(&self) -> usize { self.input_count }
    pub(crate) fn retry_output(&self) -> Option<&Path> {
        self.retry_output.then_some(self.output.as_path())
    }

    pub(crate) fn report(&self, failure: impl Fn(&Failure) -> serde_json::Value) -> serde_json::Value {
        use serde_json::{json, Value};
        let inputs: Vec<_> = self.inputs.iter().map(|checkpoint| {
            let state = checkpoint.report.as_ref().expect("captured report state");
            let error = checkpoint.failure.as_ref().map(|receipt| &receipt.failure);
            let mut blockers = Vec::new();
            if let Some(error) = error {
                if error.contains(FailureKind::MissingVolume)
                    || checkpoint.input.analysis.missing_volume_evidence.is_some()
                    || checkpoint.input.analysis.volume_completeness == Some(crate::io::archive_state::VolumeCompleteness::Missing)
                    || error.evidence.as_deref().is_some_and(|e| e.classification_evidence.as_deref() == Some("password_or_volume_inconclusive"))
                { blockers.push("missing_volume"); }
                if error.is_password_retry() { blockers.push("password"); }
            }
            // Preserve the native, lossless generation representation. No stat
            // or legacy identity conversion is performed for diagnostics.
            let generation = &checkpoint.sources;
            json!({"input_id": state.input_id, "position": state.position,
                "archive_input": checkpoint.input.report_with_name(&state.logical_name), "generation": generation,
                "output_dir": state.output, "complete": error.is_none(), "blockers": blockers,
                "failure": error.map(&failure).unwrap_or(Value::Null),
                "files_written": state.files, "bytes_written": state.bytes,
                "recovered_complete_files": state.recovered_complete_files})
        }).collect();
        json!({"inputs": inputs, "output_dir": self.output, "input_count": self.input_count})
    }

    pub(super) fn relocate_flatten(&mut self, leaf: &Path, root: &Path) {
        if let Ok(relative) = self.output.strip_prefix(leaf) { self.output = root.join(relative); }
        else if leaf.starts_with(&self.output) && self.output.starts_with(root) { self.output = root.to_path_buf(); }
        for checkpoint in &mut self.inputs {
            if let Some(state) = &mut checkpoint.report {
                if !state.output.as_os_str().is_empty() {
                    super::relocate_flatten_output(&mut state.output, leaf, root);
                }
            }
        }
    }
}

#[derive(Hash, PartialEq, Eq)]
pub(super) struct CheckpointKey(String);

impl CheckpointKey {
    pub(super) fn for_input(input: &ArchiveInput) -> Self {
        Self(format!("{}|{}|{}", path_key(&input.entry_path), input.format_hint,
            input.physical_extents().next().map_or(0, |extent| extent.start)))
    }
}

fn layout_matches(saved: &ArchiveInput, input: &ArchiveInput) -> bool {
        if saved.mode != input.mode
            || saved.format_hint != input.format_hint
            || saved.ranges != input.ranges
        {
            return false;
        }
        match &input.volume_attempts {
            Some(plan) => saved.volume_attempts.is_none() && saved.volume_style == input.volume_style && plan.admits_parts(&saved.parts),
            None => saved.parts == input.parts,
        }
    }
#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::io::archive_state::{InputExtent, InputPart, VolumeAttemptPlan, VolumeDomain, VolumeLayout, VolumeSlot};
    use std::{fs, sync::Arc};

    #[test]
    fn recovery_receipts_preserve_pre_cleanup_facts_and_relocate_only_outputs() {
        let source = crate::test_support::temp_file("recovery_report", b"archive");
        let output = source.with_extension("out");
        let input = ArchiveInput::file(source.to_string_lossy().into_owned(), "zip".into(), "original".into());
        let generations = HashMap::from([(path_key(&input.entry_path), capture_file_generation(&source).unwrap())]);
        let mut result = ArchiveResult {
            path: source.clone(), format: "zip".into(), output: None, failure: None,
            files: 0, bytes: 0, encrypted: None, depth: 1, offset: 0, end_offset: None,
            volume_completeness: None, volume_attempts: None, source_paths: vec![source.clone()],
            password: None, discovery_source: DiscoverySource::Direct, damage_flags: None,
            partial: false, retained: false, recovered_complete_files: 0, promoted: false,
            promotion_original_path: None,
        };
        result.failure = Some(Failure::new(FailureKind::Damaged, "damaged").with_context(super::super::FailureContext::Extraction));
        result.output = Some(output.clone()); result.files = 3; result.bytes = 17;
        result.recovered_complete_files = 2;
        let state = InputCheckpoint::report_state(&input, &result, Some(&output), None, 4, 7);
        let shared_input = Arc::new(input.clone());
        let mut checkpoint = InputCheckpoint::create(&source, Arc::clone(&shared_input), &result, &generations, None).unwrap();
        assert!(Arc::ptr_eq(&shared_input, &checkpoint.shared_input()));
        checkpoint.install_report(state.clone());
        let checkpoint: InputCheckpoint = serde_json::from_slice(&serde_json::to_vec(&checkpoint).unwrap()).unwrap();
        let mut resumed = input.clone(); resumed.logical_name = "changed display".into();
        let state = InputCheckpoint::report_state(&resumed, &result, Some(&output), Some(&checkpoint), 1, 7).unwrap();
        assert_eq!(state.position, 4);
        assert_eq!(state.input_id, checkpoint.report.as_ref().unwrap().input_id);
        let recovery = InputRecovery::capture(&[checkpoint.clone()], &source, None, None, 7, true, true).unwrap();
        assert!(Arc::ptr_eq(&checkpoint.input, &recovery.inputs[0].input));
        assert!(Arc::ptr_eq(&checkpoint.sources, &recovery.inputs[0].sources));
        assert!(Arc::ptr_eq(checkpoint.failure.as_ref().unwrap(), recovery.inputs[0].failure.as_ref().unwrap()));
        let mut output_only = checkpoint.clone();
        output_only.relocate_flatten(&output, output.parent().unwrap());
        assert!(Arc::ptr_eq(&checkpoint.input, &output_only.input));
        assert!(Arc::ptr_eq(&checkpoint.sources, &output_only.sources));
        let render = |failure: &Failure| serde_json::json!({"kind": format!("{:?}", failure.kind)});
        let report = recovery.report(render);
        assert_eq!(report["inputs"][0]["position"], 4);
        assert_eq!(report["inputs"][0]["files_written"], 3);
        assert_eq!(report["inputs"][0]["bytes_written"], 17);
        assert_eq!(report["inputs"][0]["recovered_complete_files"], 2);
        assert_eq!(report["inputs"][0]["complete"], false);
        assert_eq!(report["inputs"][0]["archive_input"]["logical_name"], "original");
        assert_eq!(report["inputs"][0]["generation"], serde_json::to_value(&checkpoint.sources).unwrap());
        assert!(recovery.aggregated());
        // Same-request replacement keeps the first checkpoint until a result
        // with the same logical ID overwrites it. Name/mode changes alone do
        // not invent another logical input; a different format does.
        assert!(checkpoint.same_report_input(&resumed));
        let mut replacement = resumed.clone();
        replacement.format_hint = "7z".into();
        assert!(!checkpoint.same_report_input(&replacement));
        let success = ArchiveResult {
            failure: None,
            format: "7z".into(),
            recovered_complete_files: 0,
            ..result
        };
        let mut replaced = InputCheckpoint::create(&source, Arc::new(replacement.clone()), &success, &generations, None).unwrap();
        replaced.install_report(InputCheckpoint::report_state(&replacement, &success,
            Some(&output), None, 1, 1));
        let retained = checkpoint.result(1);
        assert_eq!(super::super::TaskCompletion::from_group(&[success, retained]).status,
            super::super::TaskStatus::Failed);
        let changed_id = InputRecovery::capture(&[checkpoint.clone(), replaced],
            &source, None, None, 1, true, true).unwrap();
        let changed_report = changed_id.report(render);
        assert_eq!(changed_report["input_count"], 1);
        assert_eq!(changed_report["inputs"].as_array().unwrap().len(), 2);
        assert_eq!(changed_report["inputs"][0]["complete"], false);
        assert_eq!(changed_report["inputs"][1]["complete"], true);
        assert_ne!(changed_report["inputs"][0]["input_id"], changed_report["inputs"][1]["input_id"]);
        let mut relocated = recovery.as_ref().clone();
        let parent = output.parent().unwrap();
        relocated.relocate_flatten(&output, parent);
        let relocated_report = relocated.report(render);
        let relocated_output = relocated_report["inputs"][0]["output_dir"].as_str().unwrap();
        assert_eq!(Path::new(relocated_output), parent);
        assert_eq!(relocated_report["inputs"][0]["archive_input"]["entry_path"], input.entry_path);
        // Content rejection must not revive an old partial continuation path.
        let mut cleared = checkpoint;
        InputCheckpoint::clear_report_output(&mut cleared.report);
        cleared.output.clear();
        let cleared = InputRecovery::capture(&[cleared], &source, None, Some(&output), 7, true, true).unwrap();
        assert!(cleared.retry_output().is_none());
        assert_eq!(cleared.report(render)["output_dir"], "");
        assert_eq!(cleared.report(render)["inputs"][0]["files_written"], 3);
        assert_eq!(cleared.report(render)["inputs"][0]["recovered_complete_files"], 0);
        fs::remove_file(source).unwrap();
    }

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
                role: if index == 0 { crate::io::archive_state::InputRole::First } else { crate::io::archive_state::InputRole::Member },
                extent: InputExtent { path: source.to_string_lossy().into_owned(), start: 0, end: Some(4) },
                volume_number: Some(index as u32 + 1), canonical_name: format!("archive.7z.{:03}", index + 1),
            });
            fs::rename(source, target).unwrap();
        }
        let retained = root.join("retained-output");
        let mut checkpoint = InputCheckpoint {
            schema_version: SCHEMA_VERSION, carrier: moves[0].0.clone(),
            input: Arc::new(ArchiveInput {
                mode: OpenMode::NativeVolumes,
                ranges: parts.iter().map(|part| part.extent.clone()).collect::<Vec<_>>().into_boxed_slice(),
                parts: parts.into_boxed_slice(),
                ..ArchiveInput::file(moves[0].0.to_string_lossy().into_owned(), "7z".into(), String::new())
            }), report: None,
            sources: sources.into(), output: retained.clone(),
            planned_output: Some(retained.clone()), container: Some(root.clone()),
            files: 1, bytes: 4, encrypted: None, discovery_source: DiscoverySource::Embedded,
            failure: None,
        };
        let paths = super::super::coordinator::PromotionPaths::new(&moves);
        assert!(checkpoint.promoted(&paths).unwrap());
        assert_eq!(checkpoint.carrier, moves[0].1);
        assert_eq!(Path::new(&checkpoint.input.entry_path), moves[0].1);
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
            let failure = Failure::new(FailureKind::Damaged, "accepted partial")
                .with_context(super::super::FailureContext::Discovery {
                    discovery: DiscoverySource::Embedded, path: source.clone(),
                    reason: "damaged".into(), error: "original diagnostic".into(),
                });
            let mut checkpoint = InputCheckpoint {
                schema_version: SCHEMA_VERSION,
                carrier: source.clone(),
                input: Arc::new(input.clone()), report: None,
                sources: vec![SourceGeneration {
                    path: source.clone(), generation: capture_file_generation(&source).unwrap().persisted(),
                }].into(),
                output: output.clone(),
                planned_output: None,
                container: Some(container.clone()),
                files: 1, bytes: 4, encrypted: None,
                discovery_source: DiscoverySource::Embedded, failure: Some(Arc::new(FailureReceipt {
                    partial: true, password_signature: None,
                    failure, complete_files: 1,
                })),
            };
            let plan = NativeBlockedInputPromotion::new(
                vec![source.to_string_lossy().into_owned()], root.clone(),
            ).unwrap();
            let destination = plan.moves()[0].1.clone();
            assert_ne!(destination, root.join(filename));
            let (_, _, _, error, _) = plan.execute(|| Ok(()));
            assert!(error.is_empty(), "{error}");
            let diagnostic = Arc::clone(checkpoint.failure.as_ref().unwrap());
            checkpoint.promoted(&super::super::coordinator::PromotionPaths::new(plan.moves())).unwrap();
            assert!(Arc::ptr_eq(&diagnostic, checkpoint.failure.as_ref().unwrap()));
            assert!(matches!(checkpoint.failure.as_ref().unwrap().failure.context.as_deref(),
                Some(super::super::FailureContext::Discovery { path, .. }) if path == &source));
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
            role: crate::io::archive_state::InputRole::First,
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
            input: Arc::new(input.clone()), report: None,
            sources: vec![SourceGeneration {
                path: source.clone(), generation: generations[&key].persisted(),
            }].into(),
            output: output.clone(),
            planned_output: None,
            container: None, files: 1, bytes: 7, encrypted: None,
            discovery_source: DiscoverySource::Direct, failure: None,
        };
        let mut result = complete.result(1);
        result.failure = Some(Failure::new(FailureKind::MissingVolume, "missing volume"));
        result.partial = true;
        result.recovered_complete_files = 1;
        let partial = InputCheckpoint::create(&source, Arc::new(input.clone()), &result, &generations, None).unwrap();
        // Exercise the persisted representation, not just in-memory equality.
        let partial: InputCheckpoint = serde_json::from_slice(
            &serde_json::to_vec(&partial).unwrap(),
        ).unwrap();
        assert!(partial.valid_for(&input, &generations));
        let mut metadata_only = serde_json::to_value(&partial).unwrap();
        metadata_only["sources"][0]["generation"]["created"] = serde_json::json!([false, 1, 0]);
        #[cfg(windows)]
        { metadata_only["sources"][0]["generation"]["windows"]["change_time"] = serde_json::json!(1); }
        let metadata_only: InputCheckpoint = serde_json::from_value(metadata_only).unwrap();
        assert!(metadata_only.valid_for(&input, &generations));
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
        assert!(InputCheckpoint::create(&source, Arc::new(alternatives.clone()), &result, &generations, None).is_some());

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
