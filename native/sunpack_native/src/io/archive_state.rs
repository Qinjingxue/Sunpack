//! Canonical physical layout shared by discovery, analysis, and execution.

use serde::{Deserialize, Serialize};
use serde::ser::{SerializeMap, SerializeSeq};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OpenMode {
    File,
    FileRange,
    ConcatRanges,
    NativeVolumes,
    SfxWithVolumes,
}

impl OpenMode {
    pub(crate) fn structured(self) -> bool {
        matches!(self, Self::NativeVolumes | Self::SfxWithVolumes)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub(crate) struct InputExtent {
    pub path: String,
    pub start: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct InputPart {
    #[serde(default)]
    pub role: InputRole,
    #[serde(flatten)]
    pub extent: InputExtent,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub volume_number: Option<u32>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub canonical_name: String,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum InputRole {
    #[default]
    Main,
    First,
    Member,
    Terminal,
}

impl InputPart {
    pub(crate) fn range(extent: InputExtent) -> Self {
        Self {
            extent,
            role: InputRole::Main,
            volume_number: None,
            canonical_name: String::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) enum VolumeCompleteness {
    Unknown,
    Missing,
    Complete,
}

impl VolumeCompleteness {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Missing => "missing",
            Self::Complete => "complete",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) enum AnalysisOrigin {
    #[default]
    Plain,
    Relations,
    RelationsFallback,
    Embedded,
    Planned,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AnalysisStatus { Error, Weak, Damaged, Extractable }

impl AnalysisStatus {
    pub(crate) fn from_evidence(status: &str) -> Option<Self> {
        match status {
            "error" => Some(Self::Error), "weak" => Some(Self::Weak),
            "damaged" => Some(Self::Damaged), "extractable" => Some(Self::Extractable),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct AnalysisFacts {
    #[serde(default)]
    pub origin: AnalysisOrigin,
    #[serde(default)]
    pub planning_applied: bool,
    pub status: Option<AnalysisStatus>,
    pub zip_eocd_offset: Option<u64>,
    pub volume_completeness: Option<VolumeCompleteness>,
    pub missing_volume_evidence: Option<String>,
    pub password_required: bool,
    pub structure_complete: bool,
    pub zip_spanned: bool,
    pub damage_flags: Option<Arc<Vec<String>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ArchiveInput {
    pub entry_path: String,
    pub logical_name: String,
    pub format_hint: String,
    #[serde(default)]
    pub volume_style: String,
    pub mode: OpenMode,
    pub parts: Box<[InputPart]>,
    pub ranges: Box<[InputExtent]>,
    pub volume_attempts: Option<Box<VolumeAttemptPlan>>,
    pub analysis: AnalysisFacts,
}

impl ArchiveInput {
    pub(crate) fn file(path: String, format: String, logical_name: String) -> Self {
        Self {
            entry_path: path,
            logical_name,
            format_hint: format,
            volume_style: String::new(),
            mode: OpenMode::File,
            parts: Box::new([]),
            ranges: Box::new([]),
            volume_attempts: None,
            analysis: AnalysisFacts::default(),
        }
    }

    pub(crate) fn physical_extents(&self) -> impl Iterator<Item = &InputExtent> {
        self.parts
            .iter()
            .map(|part| &part.extent)
            .chain(self.ranges.iter())
    }

    pub(crate) fn physical_paths(&self) -> impl Iterator<Item = &str> {
        let plan = self.volume_attempts.as_deref();
        let use_entry = self.parts.is_empty() && self.ranges.is_empty() && plan.is_none();
        let fixed = if plan.is_some() { &[][..] } else { &self.parts };
        fixed
            .iter()
            .map(|part| part.extent.path.as_str())
            .chain(self.ranges.iter().map(|range| range.path.as_str()))
            .chain(
                plan.into_iter()
                    .flat_map(|plan| plan.sources.iter().map(|range| range.path.as_str())),
            )
            .chain(use_entry.then_some(self.entry_path.as_str()))
    }

    pub(crate) fn execution_evidence(&self) -> Option<&str> {
        let facts = &self.analysis;
        // Relation discovery emits its confirmed missing-volume fact directly.
        // Advisory planning only exports it for a structured multi-part input;
        // a single-file internal hint is not confirmed missing-volume evidence.
        let eligible = !facts.planning_applied && facts.origin == AnalysisOrigin::Relations
            || self.mode.structured() && self.parts.len() > 1;
        eligible.then_some(facts.missing_volume_evidence.as_deref()).flatten()
    }

    pub(crate) fn worker_input(&self) -> WorkerInput<'_> {
        let attempts = self.volume_attempts.as_deref();
        WorkerInput {
            entry_path: &self.entry_path,
            open_mode: self.mode,
            format_hint: &self.format_hint,
            parts: if attempts.is_some() { &[] } else { &self.parts },
            ranges: &self.ranges,
            volume_attempts: attempts,
            analysis: self
                .execution_evidence()
                .filter(|_| attempts.is_none())
                .map(|missing_volume_evidence| WireAnalysis {
                    execution: WireExecution {
                        missing_volume_evidence,
                    },
                }),
        }
    }

    /// Validate the worker's selection against the exact domains and geometry
    /// it received. Only the selected extents become eligible for cleanup.
    pub(crate) fn select_volumes(&mut self, selection: &VolumeSelection) -> io::Result<()> {
        let plan = self
            .volume_attempts
            .as_ref()
            .ok_or_else(|| invalid("volume selection requires a plan"))?;
        let parts = plan.selected_parts(selection)?;
        self.parts = parts;
        self.volume_attempts = None;
        self.analysis.volume_completeness = Some(VolumeCompleteness::Complete);
        Ok(())
    }
}

/// Main's public archive_input receipt, distinct from the compact worker wire.
/// All values borrow the canonical input; rendering does not clone a descriptor.
pub(crate) struct ArchiveInputReport<'a> { input: &'a ArchiveInput, logical_name: &'a str }

impl ArchiveInput {
    #[cfg(test)]
    pub(crate) fn report(&self) -> ArchiveInputReport<'_> { self.report_with_name(&self.logical_name) }
    pub(crate) fn report_with_name<'a>(&'a self, logical_name: &'a str) -> ArchiveInputReport<'a> {
        ArchiveInputReport { input: self, logical_name }
    }
}

impl Serialize for ArchiveInputReport<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let input = self.input;
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("kind", "archive_input")?;
        map.serialize_entry("entry_path", &input.entry_path)?;
        map.serialize_entry("open_mode", &input.mode)?;
        if !input.format_hint.is_empty() { map.serialize_entry("format_hint", &input.format_hint)?; }
        if let Some(plan) = input.volume_attempts.as_deref() {
            map.serialize_entry("volume_attempts", &AttemptReport(plan))?;
        }
        if !input.parts.is_empty() || (input.mode == OpenMode::File && input.ranges.is_empty()) {
            map.serialize_entry("parts", &PartsReport(input))?;
        }
        if input.mode == OpenMode::ConcatRanges { map.serialize_entry("ranges", &input.ranges)?; }
        if !self.logical_name.is_empty() { map.serialize_entry("logical_name", self.logical_name)?; }
        if !input.volume_style.is_empty() { map.serialize_entry("volume_style", &input.volume_style)?; }
        let analysis = AnalysisReport(input);
        if analysis.has_fields() { map.serialize_entry("analysis", &analysis)?; }
        map.end()
    }
}

struct PartsReport<'a>(&'a ArchiveInput);
impl Serialize for PartsReport<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let implicit_file = self.0.parts.is_empty();
        let mut seq = serializer.serialize_seq(Some(if implicit_file { 1 } else { self.0.parts.len() }))?;
        if implicit_file {
            // Main's from_parts/from_source creates this canonical whole-file part.
            seq.serialize_element(&PartReport { path: &self.0.entry_path, role: InputRole::Main,
                volume_number: (self.0.analysis.origin != AnalysisOrigin::RelationsFallback).then_some(1), canonical_name: "", start: 0, end: None })?;
        } else {
            for part in &self.0.parts {
                seq.serialize_element(&PartReport { path: &part.extent.path, role: part.role,
                    volume_number: part.volume_number, canonical_name: &part.canonical_name,
                    start: part.extent.start, end: part.extent.end })?;
            }
        }
        seq.end()
    }
}

struct PartReport<'a> {
    path: &'a str, role: InputRole, volume_number: Option<u32>, canonical_name: &'a str,
    start: u64, end: Option<u64>,
}
impl Serialize for PartReport<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("path", self.path)?;
        map.serialize_entry("role", &self.role)?;
        if let Some(number) = self.volume_number { map.serialize_entry("volume_number", &number)?; }
        if !self.canonical_name.is_empty() { map.serialize_entry("canonical_name", self.canonical_name)?; }
        if self.start != 0 { map.serialize_entry("start", &self.start)?; }
        if let Some(end) = self.end { map.serialize_entry("end", &end)?; }
        map.end()
    }
}

struct AttemptReport<'a>(&'a VolumeAttemptPlan);
impl Serialize for AttemptReport<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let plan = self.0;
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("sources", &plan.sources)?;
        map.serialize_entry("domains", &plan.domains)?;
        struct Layouts<'a>(&'a [VolumeLayout]);
        impl Serialize for Layouts<'_> {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
                for layout in self.0 {
                    #[derive(Serialize)]
                    struct Layout<'a> { slots: &'a [VolumeSlot], #[serde(skip_serializing_if = "is_zero")] minimum_slots: usize }
                    fn is_zero(value: &usize) -> bool { *value == 0 }
                    seq.serialize_element(&Layout { slots: &layout.slots, minimum_slots: layout.minimum_slots })?;
                }
                seq.end()
            }
        }
        map.serialize_entry("layouts", &Layouts(&plan.layouts))?;
        if let Some(value) = plan.head_size_from_total { map.serialize_entry("head_size_from_total", &value)?; }
        if let Some(value) = plan.minimum_size { map.serialize_entry("minimum_size", &value)?; }
        if !plan.tail_totals.is_empty() { map.serialize_entry("tail_totals", &plan.tail_totals)?; }
        map.end()
    }
}

struct AnalysisReport<'a>(&'a ArchiveInput);
impl AnalysisReport<'_> {
    fn has_fields(&self) -> bool {
        let facts = &self.0.analysis;
        if facts.origin == AnalysisOrigin::RelationsFallback && !facts.planning_applied { return false; }
        facts.origin == AnalysisOrigin::Planned || facts.origin != AnalysisOrigin::Plain && facts.volume_completeness.is_some()
            || (self.0.format_hint == "lz4" && facts.structure_complete)
            || (facts.origin != AnalysisOrigin::Embedded || facts.planning_applied) && facts.zip_eocd_offset.is_some()
            || self.0.execution_evidence().is_some()
            || facts.origin == AnalysisOrigin::Embedded && facts.password_required
    }
}
impl Serialize for AnalysisReport<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let facts = &self.0.analysis;
        let mut map = serializer.serialize_map(None)?;
        if facts.origin == AnalysisOrigin::Relations && self.0.volume_attempts.is_some() && !facts.planning_applied {
            map.serialize_entry("volume_completeness", "unknown")?;
            return map.end();
        }
        if facts.origin == AnalysisOrigin::Planned {
            if let Some(status) = facts.status { map.serialize_entry("status", &status)?; }
            map.serialize_entry("damage_flags", facts.damage_flags.as_deref().map(Vec::as_slice).unwrap_or(&[]))?;
            if self.0.format_hint == "lz4" && facts.structure_complete { map.serialize_entry("structure_complete", &true)?; }
            if let Some(offset) = facts.zip_eocd_offset { map.serialize_entry("zip_eocd_offset", &offset)?; }
            if facts.password_required { map.serialize_entry("password_required", &true)?; }
        } else {
            if let Some(completeness) = facts.volume_completeness {
                // Only discovery installs this public fact; an advisory planning
                // conclusion is represented by execution.missing_volume_evidence.
                if facts.origin != AnalysisOrigin::Plain { map.serialize_entry("volume_completeness", completeness.as_str())?; }
            }
            if matches!(facts.origin, AnalysisOrigin::Relations | AnalysisOrigin::RelationsFallback) {
                if let Some(offset) = facts.zip_eocd_offset { map.serialize_entry("zip_eocd_offset", &offset)?; }
            }
            if facts.origin != AnalysisOrigin::Embedded {
                if let Some(evidence) = self.0.execution_evidence() {
                    map.serialize_entry("execution", &WireExecution { missing_volume_evidence: evidence })?;
                }
            }
            if self.0.format_hint == "lz4" && facts.structure_complete { map.serialize_entry("structure_complete", &true)?; }
            if facts.origin == AnalysisOrigin::Plain {
                if let Some(offset) = facts.zip_eocd_offset { map.serialize_entry("zip_eocd_offset", &offset)?; }
            }
            if facts.origin == AnalysisOrigin::Embedded {
                if facts.password_required { map.serialize_entry("password_required", &true)?; }
                if facts.planning_applied {
                    if let Some(offset) = facts.zip_eocd_offset { map.serialize_entry("zip_eocd_offset", &offset)?; }
                }
            }
        }
        map.end()
    }
}

#[derive(Serialize)]
pub(crate) struct WorkerInput<'a> {
    entry_path: &'a str,
    open_mode: OpenMode,
    format_hint: &'a str,
    #[serde(skip_serializing_if = "slice_empty")]
    parts: &'a [InputPart],
    #[serde(skip_serializing_if = "slice_empty")]
    ranges: &'a [InputExtent],
    #[serde(skip_serializing_if = "Option::is_none")]
    volume_attempts: Option<&'a VolumeAttemptPlan>,
    #[serde(skip_serializing_if = "Option::is_none")]
    analysis: Option<WireAnalysis<'a>>,
}

fn slice_empty<T>(value: &&[T]) -> bool {
    value.is_empty()
}

#[derive(Serialize)]
struct WireAnalysis<'a> {
    execution: WireExecution<'a>,
}

#[derive(Serialize)]
struct WireExecution<'a> {
    missing_volume_evidence: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct VolumeAttemptPlan {
    pub sources: Box<[InputExtent]>,
    pub layouts: Box<[VolumeLayout]>,
    pub domains: Box<[VolumeDomain]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_size_from_total: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minimum_size: Option<u64>,
    #[serde(default, skip_serializing_if = "<[TailTotal]>::is_empty")]
    pub tail_totals: Box<[TailTotal]>,
}

// These indexes are invocation-local: domains share Arc-backed choice lists,
// so large unnamed volume pools are indexed once, not scanned for every slot.
type DomainKey = *const Vec<usize>;
type DomainMembers = HashMap<DomainKey, HashSet<usize>>;
type ExtentKey<'a> = (&'a str, u64, Option<u64>);

enum ExtentCandidates {
    Exact(usize),
    // Record-high ends in domain order. A later shorter/equal extent can never
    // be the first admissible source, so it need not occupy the index.
    Trimmed(Vec<(u64, usize)>),
}


impl VolumeAttemptPlan {
    fn selected_parts(&self, selection: &VolumeSelection) -> io::Result<Box<[InputPart]>> {
        self.selected_parts_indexed(selection, &mut DomainMembers::new())
    }

    fn selected_parts_indexed(
        &self, selection: &VolumeSelection, domains: &mut DomainMembers,
    ) -> io::Result<Box<[InputPart]>> {
        let layout = self
            .layouts
            .get(selection.layout)
            .ok_or_else(|| invalid("unknown volume layout"))?;
        let count = selection.sources.len();
        if count != layout.slots.len()
            && (layout.minimum_slots == 0
                || count < layout.minimum_slots
                || count > layout.slots.len())
        {
            return Err(invalid("unplanned volume count"));
        }
        let mut seen = HashSet::with_capacity(count);
        let mut parts = Vec::with_capacity(count);
        for (index, (&source, slot)) in selection.sources.iter().zip(&layout.slots).enumerate() {
            let domain = if index + 1 == count {
                layout.slots.last().unwrap().domain
            } else {
                slot.domain
            };
            let choices = &self.domains[domain].choices;
            let members = domains.entry(Arc::as_ptr(choices))
                .or_insert_with(|| choices.iter().copied().collect());
            if !seen.insert(source) || !members.contains(&source) {
                return Err(invalid("worker selected an unplanned volume"));
            }
            parts.push(InputPart {
                role: if slot.number == 1 { InputRole::First } else { InputRole::Member },
                extent: self.sources.get(source)
                    .ok_or_else(|| invalid("unknown volume source"))?.clone(),
                volume_number: Some(slot.number),
                canonical_name: slot.canonical_name.clone(),
            });
        }
        let tail = *selection
            .sources
            .last()
            .ok_or_else(|| invalid("empty volume selection"))?;
        if let Some(total) = self
            .tail_totals
            .iter()
            .find(|entry| entry.source == tail)
            .map(|entry| entry.total)
            .or(self.head_size_from_total)
        {
            let length = parts[1..]
                .iter()
                .try_fold(total, |remaining, part| {
                    remaining.checked_sub(part.extent.end?.checked_sub(part.extent.start)?)
                })
                .filter(|length| *length > 0)
                .ok_or_else(|| invalid("invalid selected carrier length"))?;
            let head = &mut parts[0].extent;
            let end = head
                .start
                .checked_add(length)
                .filter(|end| head.end.is_some_and(|old| *end <= old))
                .ok_or_else(|| invalid("invalid selected carrier extent"))?;
            head.end = Some(end);
        }
        Ok(parts.into_boxed_slice())
    }

    pub(crate) fn admits_parts(&self, parts: &[InputPart]) -> bool {
        if parts.is_empty() {
            return false;
        }
        let mut members = DomainMembers::new();
        let mut domains: HashMap<(DomainKey, bool), HashMap<ExtentKey<'_>, ExtentCandidates>> = HashMap::new();
        for (index, layout) in self.layouts.iter().enumerate() {
            if parts.len() != layout.slots.len()
                && (layout.minimum_slots == 0
                    || parts.len() < layout.minimum_slots
                    || parts.len() > layout.slots.len())
            {
                continue;
            }
            let mut sources = Vec::with_capacity(parts.len());
            for (position, (part, slot)) in parts.iter().zip(&layout.slots).enumerate() {
                if part.volume_number != Some(slot.number)
                    || part.canonical_name != slot.canonical_name
                {
                    break;
                }
                let domain = if position + 1 == parts.len() {
                    layout.slots.last().unwrap().domain
                } else {
                    slot.domain
                };
                let trimmed_head = position == 0
                    && (self.head_size_from_total.is_some() || !self.tail_totals.is_empty());
                let choices = &self.domains[domain].choices;
                let extents = domains.entry((Arc::as_ptr(choices), trimmed_head))
                    .or_insert_with(|| {
                        let mut extents = HashMap::with_capacity(choices.len());
                        for &source in choices.iter() {
                            let extent = &self.sources[source];
                            let key = (extent.path.as_str(), extent.start,
                                if trimmed_head { None } else { extent.end });
                            if trimmed_head {
                                if let Some(end) = extent.end {
                                    let candidates = extents.entry(key)
                                        .or_insert_with(|| ExtentCandidates::Trimmed(Vec::new()));
                                    if let ExtentCandidates::Trimmed(ends) = candidates {
                                        if ends.last().map_or(true, |&(previous, _)| end > previous) {
                                            ends.push((end, source));
                                        }
                                    }
                                }
                            } else {
                                extents.entry(key).or_insert(ExtentCandidates::Exact(source));
                            }
                        }
                        extents
                    });
                let key = (part.extent.path.as_str(), part.extent.start,
                    if trimmed_head { None } else { part.extent.end });
                let candidate = extents.get(&key).and_then(|candidates| match candidates {
                    ExtentCandidates::Exact(source) => Some(*source),
                    ExtentCandidates::Trimmed(ends) => {
                        let end = part.extent.end?;
                        ends.get(ends.partition_point(|&(full, _)| full < end))
                            .map(|&(_, source)| source)
                    }
                });
                let Some(source) = candidate else {
                    break;
                };
                sources.push(source);
            }
            if sources.len() == parts.len()
                && self
                    .selected_parts_indexed(&VolumeSelection {
                        layout: index,
                        sources,
                    }, &mut members)
                    .is_ok_and(|selected| selected.as_ref() == parts)
            {
                return true;
            }
        }
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct VolumeLayout {
    pub slots: Box<[VolumeSlot]>,
    pub minimum_slots: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct VolumeSlot {
    pub number: u32,
    pub canonical_name: String,
    pub domain: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct VolumeDomain {
    pub choices: Arc<Vec<usize>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TailTotal {
    pub source: usize,
    pub total: u64,
}

#[derive(Deserialize)]
pub(crate) struct VolumeSelection {
    pub layout: usize,
    pub sources: Vec<usize>,
}

#[derive(Debug, Clone)]
pub(crate) enum Segment {
    Range { path: String, start: u64, len: u64 },
}

impl Segment {
    pub(crate) fn len(&self) -> u64 {
        match self {
            Self::Range { len, .. } => *len,
        }
    }
}

pub(crate) fn build_segments(source: &ArchiveInput) -> io::Result<Vec<Segment>> {
    let mut segments = source
        .physical_extents()
        .map(|extent| range_segment(&extent.path, extent.start, extent.end))
        .collect::<io::Result<Vec<_>>>()?;
    if segments.is_empty() {
        segments.push(range_segment(&source.entry_path, 0, None)?);
    }
    segments.retain(|segment| segment.len() > 0);
    Ok(segments)
}

fn range_segment(path: &str, start: u64, end: Option<u64>) -> io::Result<Segment> {
    let size = fs::metadata(path)?.len();
    let effective_end = end.unwrap_or(size).min(size);
    let len = effective_end
        .checked_sub(start)
        .ok_or_else(|| invalid("range start is beyond input end"))?;
    Ok(Segment::Range {
        path: path.to_owned(),
        start,
        len,
    })
}

/// Resolve the physical layout once for all selected analysis ranges.
pub(crate) fn archive_input_slices(
    source: &ArchiveInput,
    slices: &[(&str, u64, Option<u64>)],
) -> io::Result<(Vec<Option<ArchiveInput>>, Option<ArchiveInput>)> {
    let Some(&(first_format, first_start, first_end)) = slices.first() else {
        return Ok((Vec::new(), None));
    };
    let segments = build_segments(source)?;
    let total = segments
        .iter()
        .try_fold(0u64, |sum, part| sum.checked_add(part.len()))
        .ok_or_else(|| invalid("input size overflow"))?;
    let projected: Vec<_> = slices
        .iter()
        .map(|&(format, start, end)| {
            project_input_slice(source, &segments, total, format, start, end, false)
        })
        .collect();
    let probe = projected[0]
        .is_none()
        .then(|| {
            project_input_slice(
                source,
                &segments,
                total,
                first_format,
                first_start,
                first_end,
                true,
            )
        })
        .flatten();
    Ok((projected, probe))
}

fn project_input_slice(
    source: &ArchiveInput,
    segments: &[Segment],
    total: u64,
    format: &str,
    start: u64,
    end: Option<u64>,
    probe: bool,
) -> Option<ArchiveInput> {
    let mut end = end.or(probe.then_some(total))?;
    if start >= end || end > total {
        return None;
    }
    if format == "rar" && segments.len() > 1 {
        // RAR callbacks use independent volume containers. Preserve their
        // sequence for extraction. A password probe may use a bounded head.
        if !probe || start == 0 {
            return probe.then(|| source.clone());
        }
        end = end.min(segments[0].len());
        if start >= end {
            return None;
        }
    } else if start == 0 && end == total {
        return probe.then(|| source.clone());
    }
    let mut cursor = 0;
    let mut mapped = Vec::new();
    for Segment::Range {
        path,
        start: base,
        len,
    } in segments
    {
        let stop = cursor + len;
        let begin = start.max(cursor);
        let finish = end.min(stop);
        if begin < finish {
            mapped.push(InputExtent {
                path: path.clone(),
                start: base + (begin - cursor),
                end: Some(base + (finish - cursor)),
            });
        }
        cursor = stop;
        if cursor >= end {
            break;
        }
    }
    if mapped.is_empty() {
        return None;
    }
    let mut input = ArchiveInput::file(
        source.entry_path.clone(),
        format.to_owned(),
        source.logical_name.clone(),
    );
    if mapped.len() == 1 {
        input.mode = OpenMode::FileRange;
        input.parts = Box::new([InputPart::range(mapped.pop().unwrap())]);
    } else {
        input.mode = OpenMode::ConcatRanges;
        input.ranges = mapped.into_boxed_slice();
    }
    Some(input)
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {

    #[test]
    fn recovery_descriptor_uses_main_contract_without_worker_projection_fields() {
        let mut input = ArchiveInput::file("archive.zip".into(), "zip".into(), "archive".into());
        assert_eq!(serde_json::to_string(&input.report()).unwrap(),
            r#"{"kind":"archive_input","entry_path":"archive.zip","open_mode":"file","format_hint":"zip","parts":[{"path":"archive.zip","role":"main","volume_number":1}],"logical_name":"archive"}"#);
        input.analysis.origin = AnalysisOrigin::Embedded;
        input.analysis.volume_completeness = Some(VolumeCompleteness::Complete);
        input.analysis.password_required = true;
        // Embedded's execution-only ZIP offset does not occur in main's
        // descriptor until planning installs it into the existing analysis.
        input.analysis.zip_eocd_offset = Some(8);
        assert_eq!(serde_json::to_value(input.report()).unwrap()["analysis"],
            serde_json::json!({"volume_completeness":"complete", "password_required":true}));
        input.analysis.planning_applied = true;
        assert_eq!(serde_json::to_value(input.report()).unwrap()["analysis"]["zip_eocd_offset"], 8);
        input.analysis.origin = AnalysisOrigin::Planned;
        input.analysis.status = Some(AnalysisStatus::Damaged);
        assert!(serde_json::to_string(&input.report()).unwrap().ends_with(
            r#""analysis":{"status":"damaged","damage_flags":[],"zip_eocd_offset":8,"password_required":true}}"#));
        let persisted = serde_json::to_vec(&input).unwrap();
        let restored: ArchiveInput = serde_json::from_slice(&persisted).unwrap();
        assert_eq!(serde_json::to_string(&input.report()).unwrap(), serde_json::to_string(&restored.report()).unwrap());
    }

    #[test]
    fn recovery_descriptor_does_not_export_single_file_planning_hints() {
        let mut input = ArchiveInput::file("truncated.7z".into(), "7z".into(), "truncated".into());
        input.analysis.planning_applied = true;
        input.analysis.missing_volume_evidence = Some("seven_zip_start_header_length".into());
        assert!(serde_json::to_value(input.report()).unwrap().get("analysis").is_none());
        assert!(serde_json::to_value(input.worker_input()).unwrap().get("analysis").is_none());
        input.mode = OpenMode::NativeVolumes;
        input.parts = Box::new([InputPart::range(InputExtent { path: input.entry_path.clone(), start: 0, end: None })]);
        assert!(serde_json::to_value(input.report()).unwrap().get("analysis").is_none());
        assert!(serde_json::to_value(input.worker_input()).unwrap().get("analysis").is_none());
        input.parts = vec![input.parts[0].clone(), InputPart::range(InputExtent {
            path: "truncated.7z.002".into(), start: 0, end: None,
        })].into_boxed_slice();
        assert_eq!(serde_json::to_value(input.report()).unwrap()["analysis"]["execution"]["missing_volume_evidence"],
            "seven_zip_start_header_length");
        assert_eq!(serde_json::to_value(input.worker_input()).unwrap()["analysis"]["execution"]["missing_volume_evidence"],
            "seven_zip_start_header_length");
        // A relation conclusion is a different producer: main exports this
        // fact before planning even when only the first known volume exists.
        input.parts = Box::new([input.parts[0].clone()]);
        input.analysis.origin = AnalysisOrigin::Relations;
        input.analysis.planning_applied = false;
        input.analysis.missing_volume_evidence = Some("relation_missing_volume".into());
        assert_eq!(serde_json::to_value(input.report()).unwrap()["analysis"]["execution"]["missing_volume_evidence"],
            "relation_missing_volume");
        assert_eq!(serde_json::to_value(input.worker_input()).unwrap()["analysis"]["execution"]["missing_volume_evidence"],
            "relation_missing_volume");
    }

    #[test]
    fn recovery_volume_descriptor_preserves_style_roles_and_plan_order() {
        let mut input = ArchiveInput::file("first.zip".into(), "zip".into(), "archive".into());
        input.mode = OpenMode::NativeVolumes;
        input.volume_style = "zip_spanned".into();
        input.parts = Box::new([InputPart { role: InputRole::Terminal,
            extent: InputExtent { path: "first.zip".into(), start: 0, end: Some(12) },
            volume_number: Some(1), canonical_name: "archive.zip".into() }]);
        input.analysis.origin = AnalysisOrigin::Relations;
        input.analysis.volume_completeness = Some(VolumeCompleteness::Unknown);
        input.volume_attempts = Some(Box::new(VolumeAttemptPlan {
            sources: Box::new([input.parts[0].extent.clone()]),
            domains: Box::new([VolumeDomain { choices: Arc::new(vec![0]) }]),
            layouts: Box::new([VolumeLayout { slots: Box::new([VolumeSlot {
                number: 1, canonical_name: "archive.zip".into(), domain: 0,
            }]), minimum_slots: 0 }]),
            head_size_from_total: None, minimum_size: None, tail_totals: Box::new([]),
        }));
        let text = serde_json::to_string(&input.report()).unwrap();
        assert!(text.contains(r#""domains":[{"choices":[0]}],"layouts":[{"slots":[{"number":1,"canonical_name":"archive.zip","domain":0}]}]"#));
        assert!(!text.contains("minimum_slots"));
        assert!(text.contains(r#""role":"terminal","volume_number":1,"canonical_name":"archive.zip","end":12"#));
        let decoded: ArchiveInput = serde_json::from_slice(&serde_json::to_vec(&input).unwrap()).unwrap();
        assert_eq!(text, serde_json::to_string(&decoded.report()).unwrap());
        input.select_volumes(&VolumeSelection { layout: 0, sources: vec![0] }).unwrap();
        assert_eq!(input.parts[0].role, InputRole::First);
        assert!(input.volume_attempts.is_none());
        assert_eq!(input.volume_style, "zip_spanned");
    }
    use super::*;

    #[test]
    fn trimmed_head_admission_keeps_first_sufficient_duplicate_extent() {
        // A shorter duplicate must not hide a later sufficient carrier. Keep
        // first-match order too: a later match cannot bypass source uniqueness.
        let mut plan = VolumeAttemptPlan {
            sources: [None, Some(4), Some(12), Some(8), Some(20), Some(10)]
                .into_iter().enumerate().map(|(i, end)| InputExtent {
                    path: if i == 5 { "tail" } else { "carrier" }.into(),
                    start: 0, end,
                }).collect(),
            layouts: Box::new([VolumeLayout {
                slots: Box::new([
                    VolumeSlot { number: 1, canonical_name: String::new(), domain: 0 },
                    VolumeSlot { number: 2, canonical_name: String::new(), domain: 1 },
                ]),
                minimum_slots: 0,
            }]),
            domains: Box::new([
                VolumeDomain { choices: Arc::new(vec![0, 1, 2, 3, 4]) },
                VolumeDomain { choices: Arc::new(vec![5]) },
            ]),
            head_size_from_total: Some(20), minimum_size: None, tail_totals: Box::new([]),
        };
        let mut parts = plan.selected_parts(&VolumeSelection {
            layout: 0, sources: vec![4, 5],
        }).unwrap();
        for end in [1, 4, 5, 8, 12, 13, 20, 21] {
            plan.head_size_from_total = Some(end + 10);
            parts[0].extent.end = Some(end);
            assert_eq!(plan.admits_parts(&parts), end <= 20, "head end {end}");
        }
        parts[0].extent.end = None;
        assert!(!plan.admits_parts(&parts));

        // Source 2 is the first sufficient head, but is already the tail.
        // Source 4 also fits; choosing it instead would change old behavior.
        plan.domains[1].choices = Arc::new(vec![2]);
        plan.head_size_from_total = Some(22);
        parts[0].extent.end = Some(10);
        parts[1].extent = plan.sources[2].clone();
        assert!(!plan.admits_parts(&parts));
    }

    #[test]
    fn shared_volume_domains_are_indexed_once_and_validate_checkpoint_geometry() {
        // Same shared-pool shape used by attempts.rs for unnumbered interior
        // gaps. Both worker selection and checkpoint admission must stay valid
        // without re-scanning the pool for every slot.
        let count = 256;
        let choices = Arc::new((0..count).collect::<Vec<_>>());
        let mut plan = VolumeAttemptPlan {
            sources: (0..count).map(|i| InputExtent {
                path: format!("part-{i}"), start: 0, end: Some(10),
            }).collect(),
            layouts: Box::new([VolumeLayout {
                slots: (0..count).map(|i| VolumeSlot {
                    number: i as u32 + 1, canonical_name: String::new(), domain: i,
                }).collect(),
                minimum_slots: 0,
            }]),
            // Distinct domain records can still share the same choices Arc.
            domains: (0..count).map(|_| VolumeDomain { choices: Arc::clone(&choices) }).collect(),
            head_size_from_total: None, minimum_size: None, tail_totals: Box::new([]),
        };
        let mut indexes = DomainMembers::new();
        let mut selection = VolumeSelection { layout: 0, sources: (0..count).rev().collect() };
        let parts = plan.selected_parts_indexed(&selection, &mut indexes).unwrap();
        assert_eq!(indexes.len(), 1);
        assert_eq!(indexes.values().map(HashSet::len).sum::<usize>(), count);
        assert!(plan.admits_parts(&parts));
        selection.sources[1] = selection.sources[0];
        assert!(plan.selected_parts(&selection).is_err());
        selection.sources[1] = count;
        assert!(plan.selected_parts(&selection).is_err());
        let mut wrong = parts.clone();
        wrong[1].extent.start = 1;
        assert!(!plan.admits_parts(&wrong));
        wrong = parts.clone();
        wrong[1].canonical_name = "unplanned".into();
        assert!(!plan.admits_parts(&wrong));

        // Variable counts use the final slot's domain, and a trimmed head is
        // matched by physical start before the exact total-size formula runs.
        plan.layouts[0].minimum_slots = 2;
        plan.head_size_from_total = Some(15);
        let trimmed = plan.selected_parts(&VolumeSelection {
            layout: 0, sources: vec![0, count - 1],
        }).unwrap();
        assert_eq!(trimmed[0].extent.end, Some(5));
        assert!(plan.admits_parts(&trimmed));
        let mut wrong = trimmed;
        wrong[0].extent.end = Some(6);
        assert!(!plan.admits_parts(&wrong));
    }
}
