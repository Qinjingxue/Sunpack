//! Canonical physical layout shared by discovery, analysis, and execution.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct InputExtent {
    pub path: String,
    pub start: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct InputPart {
    #[serde(flatten)]
    pub extent: InputExtent,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub volume_number: Option<u32>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub canonical_name: String,
}

impl InputPart {
    pub(crate) fn range(extent: InputExtent) -> Self {
        Self {
            extent,
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

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct AnalysisFacts {
    pub zip_eocd_offset: Option<u64>,
    pub volume_completeness: Option<VolumeCompleteness>,
    pub missing_volume_evidence: Option<String>,
    pub password_required: bool,
    pub structure_complete: bool,
    pub zip_spanned: bool,
    pub damage_flags: Option<Arc<Vec<String>>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ArchiveInput {
    pub entry_path: String,
    pub logical_name: String,
    pub format_hint: String,
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
                .analysis
                .missing_volume_evidence
                .as_deref()
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct VolumeAttemptPlan {
    pub sources: Box<[InputExtent]>,
    pub layouts: Box<[VolumeLayout]>,
    pub domains: Box<[VolumeDomain]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_size_from_total: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minimum_size: Option<u64>,
    #[serde(skip_serializing_if = "<[TailTotal]>::is_empty")]
    pub tail_totals: Box<[TailTotal]>,
}

impl VolumeAttemptPlan {
    fn selected_parts(&self, selection: &VolumeSelection) -> io::Result<Box<[InputPart]>> {
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
            if !seen.insert(source) || !self.domains[domain].choices.contains(&source) {
                return Err(invalid("worker selected an unplanned volume"));
            }
            parts.push(InputPart {
                extent: self.sources[source].clone(),
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
                let candidate = self.domains[domain]
                    .choices
                    .iter()
                    .copied()
                    .find(|&source| {
                        let extent = &self.sources[source];
                        if trimmed_head {
                            extent.path == part.extent.path
                                && extent.start == part.extent.start
                                && extent
                                    .end
                                    .zip(part.extent.end)
                                    .is_some_and(|(full, end)| end <= full)
                        } else {
                            *extent == part.extent
                        }
                    });
                let Some(source) = candidate else {
                    break;
                };
                sources.push(source);
            }
            if sources.len() == parts.len()
                && self
                    .selected_parts(&VolumeSelection {
                        layout: index,
                        sources,
                    })
                    .is_ok_and(|selected| selected.as_ref() == parts)
            {
                return true;
            }
        }
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct VolumeLayout {
    pub slots: Box<[VolumeSlot]>,
    pub minimum_slots: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct VolumeSlot {
    pub number: u32,
    pub canonical_name: String,
    pub domain: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct VolumeDomain {
    pub choices: Arc<Vec<usize>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
