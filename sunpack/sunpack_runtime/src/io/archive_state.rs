//! Canonical physical layout shared by discovery, analysis, and execution.

use serde::{Deserialize, Serialize};
use serde::ser::{SerializeMap, SerializeSeq};
use super::view::{ReadView, Span};
use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OpenMode {
    File,
    FileRange,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view: Option<Arc<crate::io::view::ReadView>>,
    pub path: String,
    pub start: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end: Option<u64>,
}

#[derive(PartialEq, Eq, Hash)]
pub(crate) enum PhysicalRanges {
    Forward(u64, Option<u64>),
    Reverse(u64, u64),
    Mapped(Vec<Span>),
}

impl PhysicalRanges {
    fn contiguous(span: &Span) -> Self {
        if span.reverse { Self::Reverse(span.start, span.end) }
        else { Self::Forward(span.start, Some(span.end)) }
    }

    pub(crate) fn new(view: Option<&ReadView>, start: u64, end: Option<u64>) -> Self {
        let Some(view) = view.filter(|_| end != Some(start)) else {
            return Self::Forward(start, end);
        };
        let mut spans = Vec::new();
        let mut pending: Option<Span> = None;
        view.visit(start, end.unwrap_or_else(|| view.len()), |mut span| {
            if pending.as_mut().is_some_and(|last| last.join(&span)) {
                return Ok(());
            }
            span.normalize();
            if let Some(finished) = pending.replace(span) {
                spans.push(finished);
            }
            Ok(())
        }).expect("collecting ranges is infallible");
        if let Some(last) = pending {
            if spans.is_empty() {
                return Self::contiguous(&last);
            }
            spans.push(last);
        }
        Self::Mapped(spans)
    }
}

impl InputExtent {
    pub(crate) fn physical_ranges(&self) -> PhysicalRanges {
        PhysicalRanges::new(self.view.as_deref(), self.start, self.end)
    }
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

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
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
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct AnalysisFacts {
    #[serde(default)]
    pub origin: AnalysisOrigin,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zip_directory_id: Option<Arc<str>>,
    pub zip_eocd_offset: Option<u64>,
    pub volume_completeness: Option<VolumeCompleteness>,
    pub missing_volume_evidence: Option<String>,
    pub password_required: bool,
    pub structure_complete: bool,
    // Only applies to the physical observation being executed.
    #[serde(skip)]
    pub standalone_truncated: bool,
    pub zip_spanned: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub rar_native_volume: bool,
    /// Several validated ends share this start in the same file view.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub distinguish_end: bool,
}

impl AnalysisFacts {
    pub(crate) fn compatible_directory(&self, other: &Self) -> bool {
        self.zip_directory_id.as_ref().zip(other.zip_directory_id.as_ref())
            .is_none_or(|(a, b)| a == b)
    }
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
    pub volume_attempts: Option<Arc<VolumeAttemptPlan>>,
    pub analysis: AnalysisFacts,
}

impl ArchiveInput {
    pub(crate) fn view_tags(&self) -> Vec<ViewReport> {
        use crate::collections::SmallOrderedSet;
        let mut tags = None::<SmallOrderedSet<ViewReport>>;
        let mut plain = false;
        for extent in self.source_extents() {
            if let Some(view) = &extent.view {
                let tag = ViewReport::from(view.as_ref());
                match &mut tags {
                    Some(tags) => tags.insert(tag),
                    None => tags = Some(SmallOrderedSet::One(tag)),
                }
            } else { plain = true; }
        }
        let Some(tags) = tags else { return Vec::new() };
        let plain = plain.then_some(ViewReport { method: crate::io::view::ViewMethod::Plain, depth: 0 });
        plain.into_iter().chain(tags.iter().copied()).collect()
    }
    pub(crate) fn file(path: String, format: String, logical_name: String) -> Self {
        Self {
            entry_path: path,
            logical_name,
            format_hint: format,
            volume_style: String::new(),
            mode: OpenMode::File,
            parts: Box::new([]),
            volume_attempts: None,
            analysis: AnalysisFacts::default(),
        }
    }

    pub(crate) fn physical_extents(&self) -> impl Iterator<Item = &InputExtent> {
        self.parts.iter().map(|part| &part.extent)
    }

    pub(crate) fn source_extents(&self) -> impl Iterator<Item = &InputExtent> {
        let plan = self.volume_attempts.as_deref();
        let fixed = if plan.is_some() { &[][..] } else { &self.parts };
        fixed
            .iter()
            .map(|part| &part.extent)
            .chain(plan.into_iter().flat_map(|plan| plan.sources.iter()))
    }

    pub(crate) fn physical_paths(&self) -> impl Iterator<Item = &str> {
        let use_entry = self.parts.is_empty() && self.volume_attempts.is_none();
        self.source_extents().map(|extent| extent.path.as_str())
            .chain(use_entry.then_some(self.entry_path.as_str()))
    }

    pub(crate) fn execution_evidence(&self) -> Option<&str> {
        let facts = &self.analysis;
        // Relation discovery emits its confirmed missing-volume fact directly.
        // Other origins require a structured multi-part input; a single-file
        // hint is not confirmed missing-volume evidence.
        let eligible = facts.origin == AnalysisOrigin::Relations
            || self.mode.structured() && self.parts.len() > 1;
        eligible.then_some(facts.missing_volume_evidence.as_deref()).flatten()
    }

    pub(crate) fn uses_named_volumes(&self) -> bool {
        self.mode.structured() && (self.mode == OpenMode::SfxWithVolumes
            || self.analysis.rar_native_volume || self.analysis.zip_spanned)
    }

    pub(crate) fn worker_input(&self) -> WorkerInput<'_> {
        let attempts = self.volume_attempts.as_deref();
        WorkerInput {
            entry_path: &self.entry_path,
            open_mode: match self.mode {
                OpenMode::File => "file",
                OpenMode::FileRange => "file_range",
                OpenMode::NativeVolumes if self.uses_named_volumes() => "named_volumes",
                OpenMode::NativeVolumes => "native_volumes",
                OpenMode::SfxWithVolumes => "sfx_with_volumes",
            },
            format_hint: &self.format_hint,
            parts: if attempts.is_some() { &[] } else { &self.parts },
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

pub(crate) fn contiguous_volume_prefix(parts: &[InputPart]) -> &[InputPart] {
    let count = parts.iter().enumerate()
        .take_while(|(index, part)| part.volume_number == Some(*index as u32 + 1))
        .count();
    &parts[..count]
}

/// Main's public archive_input receipt, distinct from the compact worker wire.
/// All values borrow the canonical input; rendering does not clone a descriptor.
pub(crate) struct ArchiveInputReport<'a>(&'a ArchiveInput);

impl ArchiveInput {
    pub(crate) fn report(&self) -> ArchiveInputReport<'_> { ArchiveInputReport(self) }
}

impl Serialize for ArchiveInputReport<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let input = self.0;
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("kind", "archive_input")?;
        map.serialize_entry("entry_path", &input.entry_path)?;
        map.serialize_entry("open_mode", &input.mode)?;
        if !input.format_hint.is_empty() { map.serialize_entry("format_hint", &input.format_hint)?; }
        let views = input.view_tags();
        if !views.is_empty() {map.serialize_entry("views",&views)?;}
        if let Some(plan) = input.volume_attempts.as_deref() {
            map.serialize_entry("volume_attempts", &AttemptReport(plan))?;
        }
        if !input.parts.is_empty() || input.mode == OpenMode::File {
            map.serialize_entry("parts", &PartsReport(input))?;
        }
        if !input.logical_name.is_empty() { map.serialize_entry("logical_name", &input.logical_name)?; }
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

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ViewReport {
    pub method: crate::io::view::ViewMethod,
    #[serde(skip_serializing_if = "ViewReport::plain_depth")]
    pub depth: u32,
}

impl ViewReport {
    fn plain_depth(depth: &u32) -> bool { *depth == 0 }
}

impl std::fmt::Display for ViewReport {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "{}", self.method)?;
        if self.depth != 0 { write!(out, ":{}", self.depth)?; }
        Ok(())
    }
}

pub(crate) fn logical_input_id(path_key: &str, format: &str, start: u64, view: Option<&ViewReport>, directory: Option<&str>, distinct_end: Option<u64>) -> String {
    use std::fmt::Write;
    let mut id = format!("{path_key}|{format}|{start}");
    if let Some(view) = view { write!(id, "|{view}").unwrap(); }
    if let Some(directory) = directory { write!(id, "|zipdir:{directory}").unwrap(); }
    if let Some(end) = distinct_end { write!(id, "|end:{end}").unwrap(); }
    id
}

impl From<&crate::io::view::ReadView> for ViewReport {
    fn from(view: &crate::io::view::ReadView) -> Self {
        Self { method: view.method, depth: view.depth }
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

pub(crate) struct AttemptReport<'a>(pub &'a VolumeAttemptPlan);
struct SourceReport<'a>(&'a [InputExtent]);
impl Serialize for SourceReport<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Source<'a> {
            path: &'a str,
            start: u64,
            #[serde(skip_serializing_if = "Option::is_none")]
            end: Option<u64>,
        }
        serializer.collect_seq(self.0.iter().map(|s| Source {
            path: &s.path,
            start: s.start,
            end: s.end,
        }))
    }
}

impl Serialize for AttemptReport<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let plan = self.0;
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("sources", &SourceReport(&plan.sources))?;
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
        if facts.origin == AnalysisOrigin::RelationsFallback { return false; }
        facts.origin != AnalysisOrigin::Plain && facts.volume_completeness.is_some()
            || (self.0.format_hint == "lz4" && facts.structure_complete)
            || facts.origin != AnalysisOrigin::Embedded && facts.zip_eocd_offset.is_some()
            || self.0.execution_evidence().is_some()
            || facts.origin == AnalysisOrigin::Embedded && facts.password_required
    }
}
impl Serialize for AnalysisReport<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let facts = &self.0.analysis;
        let mut map = serializer.serialize_map(None)?;
        if facts.origin == AnalysisOrigin::Relations && self.0.volume_attempts.is_some() {
            map.serialize_entry("volume_completeness", "unknown")?;
            return map.end();
        }
        if let Some(completeness) = facts.volume_completeness {
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
        }
        map.end()
    }
}

#[derive(Serialize)]
pub(crate) struct WorkerInput<'a> {
    entry_path: &'a str,
    open_mode: &'static str,
    format_hint: &'a str,
    #[serde(skip_serializing_if = "<[InputPart]>::is_empty")]
    parts: &'a [InputPart],
    #[serde(skip_serializing_if = "Option::is_none")]
    volume_attempts: Option<&'a VolumeAttemptPlan>,
    #[serde(skip_serializing_if = "Option::is_none")]
    analysis: Option<WireAnalysis<'a>>,
}

#[derive(Serialize)]
struct WireAnalysis<'a> {
    execution: WireExecution<'a>,
}

#[derive(Serialize)]
struct WireExecution<'a> {
    missing_volume_evidence: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
#[derive(Default)]
pub(crate) struct DomainMembers(HashMap<DomainKey, HashSet<usize>>);

impl DomainMembers {
    pub(crate) fn contains(&mut self, choices: &Arc<Vec<usize>>, source: usize) -> bool {
        if choices.len() <= 8 {
            return choices.contains(&source);
        }
        self.0.entry(Arc::as_ptr(choices))
            .or_insert_with(|| choices.iter().copied().collect())
            .contains(&source)
    }
}
type ExtentKey<'a> = (&'a str, Option<&'a crate::io::view::ReadView>, u64, Option<u64>);

enum ExtentCandidates {
    Exact(usize),
    // Record-high ends in domain order. A later shorter/equal extent can never
    // be the first admissible source, so it need not occupy the index.
    Trimmed(Vec<(u64, usize)>),
}


impl VolumeAttemptPlan {
    /// A native ZIP directory fixes the disk numbers. Check whether each slot
    /// can take a distinct source, after equivalent extents have been interned.
    /// Repeated slots share a domain and its cursor. Only overlapping domains
    /// that exhaust their free choices need an augmenting path.
    pub(crate) fn prune_missing_zip_layouts(&mut self) -> bool {
        let domains = &self.domains;
        let feasible = |layout: &VolumeLayout, mut omitted: Option<&mut Vec<u32>>| {
            let mut owner = HashMap::new();
            let mut cursors = HashMap::new();
            // Preserve both disk-number anchors when projecting a partial family.
            let first = layout.slots.first();
            let remaining = layout.slots.get(1..).unwrap_or_default();
            let tail_then_members = remaining
                .split_last()
                .into_iter()
                .flat_map(|(tail, members)| std::iter::once(tail).chain(members));
            for slot in first.into_iter().chain(tail_then_members) {
                let domain = slot.domain;
                let cursor = cursors.entry(domain).or_insert(Some(0));
                // A failed augmentation proves that one more disk from this
                // domain cannot fit. Later assignments only add demands.
                if let Some(missing) = omitted.as_deref_mut() {
                    if cursor.is_none() || owner.len() == self.sources.len() {
                        missing.push(slot.number);
                        continue;
                    }
                }
                let choices = &domains[domain].choices;
                let next_choice = cursor.as_mut().expect("exhausted domains only occur in partial layouts");
                let mut free = None;
                while let Some(&source) = choices.get(*next_choice) {
                    *next_choice += 1;
                    if !owner.contains_key(&source) {
                        free = Some(source);
                        break;
                    }
                }
                if let Some(source) = free {
                    owner.insert(source, domain);
                    continue;
                }
                let mut queue = std::collections::VecDeque::from([domain]);
                let mut previous = HashMap::from([(domain, None)]);
                let replacement = 'search: loop {
                    let Some(next) = queue.pop_front() else {
                        break 'search None;
                    };
                    for &source in domains[next].choices.iter() {
                        let Some(&used) = owner.get(&source) else {
                            break 'search Some((source, next));
                        };
                        if let std::collections::hash_map::Entry::Vacant(e) = previous.entry(used) {
                            e.insert(Some((source, next)));
                            queue.push_back(used);
                        }
                    }
                };
                if replacement.is_none() {
                    if let Some(missing) = omitted.as_deref_mut() {
                        missing.push(slot.number);
                        *cursor = None;
                        continue;
                    }
                    return false;
                }
                let mut edge = replacement;
                while let Some((source, next)) = edge {
                    owner.insert(source, next);
                    edge = previous[&next];
                }
            }
            true
        };
        let mut layouts = std::mem::take(&mut self.layouts).into_vec();
        let numbered =
            |layout: &VolumeLayout| layout.slots.iter().zip(1u32..).all(|(s, n)| s.number == n);
        let mut complete = false;
        let admitted: Vec<_> = layouts
            .iter()
            .map(|layout| feasible(layout, None))
            .collect();
        if admitted.iter().all(|&ok| ok) {
            complete = layouts.iter().any(numbered);
            self.layouts = layouts.into_boxed_slice();
            return !complete;
        }
        if admitted.iter().any(|&ok| ok) {
            let mut keep = admitted.into_iter();
            layouts.retain(|_| keep.next().unwrap());
            complete = layouts.iter().any(numbered);
        } else {
            // With no feasible full layout, retain recoverable disks and their
            // original numbers for partial extraction and Watch retries.
            for layout in &mut layouts {
                let mut missing = Vec::new();
                feasible(layout, Some(&mut missing));
                missing.sort_unstable();
                let mut slots = std::mem::take(&mut layout.slots).into_vec();
                slots.retain(|slot| missing.binary_search(&slot.number).is_err());
                layout.slots = slots.into_boxed_slice();
            }
        }
        let mut remap = HashMap::new();
        let mut domains = Vec::new();
        for layout in &mut layouts {
            for slot in &mut layout.slots {
                slot.domain = *remap.entry(slot.domain).or_insert_with(|| {
                    domains.push(self.domains[slot.domain].clone());
                    domains.len() - 1
                });
            }
        }
        *self = self.with_remaining(layouts, domains);
        !complete
    }

    pub(crate) fn head_sources(&self) -> impl Iterator<Item = &InputExtent> {
        let mut seen = HashSet::new();
        self.layouts.iter().filter_map(|layout| layout.slots.first())
            .filter(move |slot| seen.insert(slot.domain))
            .flat_map(|slot| &self.domains[slot.domain].choices[..])
            .map(|&i| &self.sources[i])
    }

    pub(crate) fn sole_parts(&self) -> Option<Box<[InputPart]>> {
        let [layout] = self.layouts.as_ref() else { return None; };
        if layout.minimum_slots != 0 && layout.minimum_slots != layout.slots.len() {
            return None;
        }
        let sources = layout.slots.iter().map(|slot| match self.domains.get(slot.domain)?.choices.as_slice() {
            [source] => Some(*source),
            _ => None,
        }).collect::<Option<Vec<_>>>()?;
        let parts = self.selected_parts(&VolumeSelection { layout: 0, sources }).ok()?;
        let missing = parts.iter().fold(self.minimum_size.unwrap_or(0), |missing, part| {
            let size = part.extent.end.map_or(u64::MAX, |end| end.saturating_sub(part.extent.start));
            missing.saturating_sub(size)
        });
        (missing == 0).then_some(parts)
    }

    pub(crate) fn with_remaining(&self, layouts: Vec<VolumeLayout>, mut domains: Vec<VolumeDomain>) -> Self {
        // Drop unused source paths and remap the surviving domains once.
        let mut used = vec![false; self.sources.len()];
        for domain in &domains { for &source in domain.choices.iter() { used[source] = true; } }
        let mut remap = vec![0; used.len()];
        let mut sources = Vec::new();
        for (old, source) in self.sources.iter().enumerate() {
            if used[old] { remap[old] = sources.len(); sources.push(source.clone()); }
        }
        if sources.len() != self.sources.len() {
            for domain in &mut domains {
                for source in Arc::make_mut(&mut domain.choices) { *source = remap[*source]; }
            }
        }
        let tail_totals = self.tail_totals.iter().filter(|tail| used[tail.source]).map(|tail| {
            let mut tail = tail.clone(); tail.source = remap[tail.source]; tail
        }).collect();
        Self { layouts: layouts.into(), domains: domains.into(), sources: sources.into(), tail_totals,
            head_size_from_total: self.head_size_from_total, minimum_size: self.minimum_size }
    }

    pub(crate) fn selected_parts(&self, selection: &VolumeSelection) -> io::Result<Box<[InputPart]>> {
        self.selected_parts_indexed(selection, &mut DomainMembers::default())
    }

    pub(crate) fn visit_selection(&self, selection: &VolumeSelection, domains: &mut DomainMembers,
        mut visit: impl FnMut(&VolumeSlot, &InputExtent)) -> io::Result<()> {
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
        if count == 0 { return Err(invalid("empty volume selection")); }
        for (index, (&source, slot)) in selection.sources.iter().zip(&layout.slots).enumerate() {
            let domain = if index + 1 == count {
                layout.slots.last().unwrap().domain
            } else {
                slot.domain
            };
            let choices = &self.domains[domain].choices;
            if !seen.insert(source) || !domains.contains(choices, source) {
                return Err(invalid("worker selected an unplanned volume"));
            }
            visit(slot, self.sources.get(source).ok_or_else(|| invalid("unknown volume source"))?);
        }
        Ok(())
    }

    pub(crate) fn selected_parts_indexed(
        &self, selection: &VolumeSelection, domains: &mut DomainMembers,
    ) -> io::Result<Box<[InputPart]>> {
        let mut parts = Vec::with_capacity(selection.sources.len());
        self.visit_selection(selection, domains, |slot, extent| {
            parts.push(InputPart {
                role: if slot.number == 1 { InputRole::First } else { InputRole::Member },
                extent: extent.clone(),
                volume_number: Some(slot.number),
                canonical_name: slot.canonical_name.clone(),
            });
        })?;
        let tail = *selection.sources.last().expect("validated nonempty selection");
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
        let mut members = DomainMembers::default();
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
                            let key = (extent.path.as_str(), extent.view.as_deref(), extent.start,
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
                let key = (part.extent.path.as_str(), part.extent.view.as_deref(), part.extent.start,
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

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct VolumeLayout {
    pub slots: Box<[VolumeSlot]>,
    pub minimum_slots: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct VolumeSlot {
    pub number: u32,
    pub canonical_name: String,
    pub domain: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct VolumeDomain {
    pub choices: Arc<Vec<usize>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct TailTotal {
    pub source: usize,
    pub total: u64,
}

#[derive(Deserialize)]
pub(crate) struct VolumeSelection {
    pub layout: usize,
    pub sources: Vec<usize>,
}

#[cfg(test)]
pub(crate) use tests::archive_input_slices;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
#[path = "../../tests/unit/io/archive_state/tests.rs"]
mod tests;
