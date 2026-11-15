// Canonical archive analysis report.
//
// This is the only place that turns format probes into evidence,
// segment boundaries, selection, and the extraction segment plan.

use crate::analysis_native::structure::{
    has_compression_stream_header, inspect_compression_stream_reader, StreamStructure,
};
use crate::io::archive_state::AnalysisStatus::{Damaged, Extractable, Weak};
use crate::io::archive_state::{
    AnalysisFacts, AnalysisStatus, ArchiveInput, OpenMode, VolumeCompleteness,
};
use crate::io::cancellation::{CancellableOnce, Cancellation};
use crate::io::reader::FileIdentity;
use std::cmp::Reverse;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

const STREAM_STRUCTURE_CACHE_ENTRIES: usize = 512;

const ZIP_LOCAL_RECOVERY_ERRORS: &[&str] = &[
    "bad_central_directory_signature",
    "archive_offset_underflow",
    "central_directory_size_out_of_range",
];
#[derive(Clone, Copy, PartialEq, Eq)]
enum ModuleKind {
    Zip,
    Rar,
    SevenZip,
    Tar,
    Stream(&'static str),
}

impl ModuleKind {
    fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "zip" => Self::Zip,
            "rar" => Self::Rar,
            "seven_zip" => Self::SevenZip,
            "tar" => Self::Tar,
            "gzip" => Self::Stream("gzip"),
            "bzip2" => Self::Stream("bzip2"),
            "xz" => Self::Stream("xz"),
            "zstd" => Self::Stream("zstd"),
            "lz4" => Self::Stream("lz4"),
            _ => return None,
        })
    }
}

/// Parsed analysis configuration, built once per engine and shared by calls.
pub(crate) struct NativeAnalysisConfig {
    modules: Vec<ModuleKind>,
}

impl NativeAnalysisConfig {
    pub(crate) fn new<T: AsRef<str>>(modules: impl IntoIterator<Item = (T, bool)>) -> Self {
        let mut ordered = Vec::new();
        for (name, enabled) in modules {
            let Some(kind) = enabled
                .then(|| ModuleKind::from_name(name.as_ref().trim()))
                .flatten()
            else {
                continue;
            };
            if !ordered.contains(&kind) {
                ordered.push(kind);
            }
        }
        Self { modules: ordered }
    }
}

impl Default for NativeAnalysisConfig {
    fn default() -> Self {
        Self::new(
            [
                "zip",
                "rar",
                "seven_zip",
                "tar",
                "gzip",
                "bzip2",
                "xz",
                "zstd",
                "lz4",
            ]
            .into_iter()
            .map(|name| (name, true)),
        )
    }
}

fn strict_subrange(start: u64, end: Option<u64>, size: u64) -> bool {
    matches!(end, Some(end) if start < end && end <= size && (start > 0 || end < size))
}

#[derive(Clone)]
pub(crate) struct AnalysisSegment {
    pub(crate) status: AnalysisStatus,
    pub(crate) format_hint: &'static str,
    pub(crate) start: u64,
    pub(crate) end: Option<u64>,
    pub(crate) zip_eocd_offset: Option<u64>,
    pub(crate) password_required: bool,
    pub(crate) damage_flags: Vec<String>,
}

impl AnalysisSegment {
    fn range_key(&self) -> (u64, Reverse<u64>) {
        (self.start, Reverse(self.end.unwrap_or(self.start)))
    }
}

struct Evidence {
    segment: AnalysisSegment,
    structure_complete: bool,
    zip_spanned: bool,
    proven_end: Option<u64>,
}

impl Evidence {
    fn new(
        format_hint: &'static str,
        status: AnalysisStatus,
        start: u64,
        end: Option<u64>,
        damage_flags: Vec<String>,
    ) -> Self {
        Self {
            segment: AnalysisSegment {
                status,
                format_hint,
                start,
                end,
                zip_eocd_offset: None,
                password_required: false,
                damage_flags,
            },
            structure_complete: false,
            zip_spanned: false,
            proven_end: None,
        }
    }

    fn analysis_facts(&self) -> AnalysisFacts {
        let segment = &self.segment;
        AnalysisFacts {
            zip_eocd_offset: segment.zip_eocd_offset.map(|offset| segment.start + offset),
            zip_spanned: self.zip_spanned,
            password_required: segment.password_required,
            structure_complete: self.structure_complete,
            ..Default::default()
        }
    }
}

/// Probe access shared by single-file and multi-volume analysis.
struct ReportContext<'a> {
    view: &'a AnalysisBinaryView,
    disk_starts: Option<&'a [u64]>,
    signatures: LeadingSignatures,
    stream_structure: Option<Option<StreamStructure>>,
}

pub(crate) struct AnalysisReport {
    pub(crate) format_hint: &'static str,
    pub(crate) facts: AnalysisFacts,
    pub(crate) segments: Vec<AnalysisSegment>,
}

pub(crate) fn analyze_input(
    input: &ArchiveInput,
    config: &NativeAnalysisConfig,
) -> io::Result<AnalysisReport> {
    let cache_bytes = 64 * 1024 * 1024;
    if input.mode == OpenMode::File || (input.parts.is_empty() && input.ranges.is_empty()) {
        return AnalysisBinaryView::new(&input.entry_path, cache_bytes)?
            .analyze_report(config, None);
    }
    let extents = if input.mode.structured() {
        let mut parts: Vec<_> = input.parts.iter().collect();
        parts.sort_by_key(|part| part.volume_number);
        parts.into_iter().map(|part| &part.extent).collect()
    } else {
        input.physical_extents().collect::<Vec<_>>()
    };
    if extents.len() == 1 && extents[0].start == 0 && extents[0].end.is_none() {
        return AnalysisBinaryView::new(&extents[0].path, cache_bytes)?
            .analyze_report(config, None);
    }
    let (reader, starts) = ManagedReader::open_extents(
        extents.iter().map(|e| (e.path.as_str(), e.start, e.end)),
        ReaderConfig { cache_bytes },
    )?;
    let view = AnalysisBinaryView { reader };
    view.analyze_report(config, input.mode.structured().then_some(&starts))
}

impl AnalysisBinaryView {
    fn analyze_report(
        &self,
        config: &NativeAnalysisConfig,
        disk_starts: Option<&[u64]>,
    ) -> io::Result<AnalysisReport> {
        let cancellation = Cancellation::current();
        cancellation.check()?;
        let mut context = ReportContext {
            view: self,
            disk_starts,
            signatures: LeadingSignatures::read(&self.reader).map_err(reader_error)?,
            stream_structure: None,
        };
        let size = self.reader.len();
        let mut plan = SegmentPlan::default();
        for &module in &config.modules {
            cancellation.check()?;
            if let Ok(Some(evidence)) = context.run_module(module) {
                plan.consider(evidence, size);
            }
        }
        cancellation.check()?;
        Ok(plan.finish())
    }
}

impl<'a> ReportContext<'a> {
    fn run_module(&mut self, module: ModuleKind) -> std::io::Result<Option<Evidence>> {
        match module {
            ModuleKind::Zip => self.zip_module(),
            ModuleKind::Rar => self.rar_module(),
            ModuleKind::SevenZip => self.seven_zip_module(),
            ModuleKind::Tar => self.tar_module(),
            ModuleKind::Stream("lz4") => self.lz4_module(),
            ModuleKind::Stream(format) => self.stream_module(format),
        }
    }

    // ---- RAR ------------------------------------------------------------

    fn rar_module(&mut self) -> std::io::Result<Option<Evidence>> {
        let head = self.signatures.head.as_slice();
        let end = if head.starts_with(RAR5) {
            self.view.rar5_end()?
        } else if head.starts_with(RAR4) {
            self.view.rar4_end()?
        } else {
            None
        };
        Ok(end.map(|end| {
            let mut evidence = Evidence::new("rar", Extractable, 0, Some(end), Vec::new());
            evidence.structure_complete = true;
            evidence
        }))
    }

    // ---- 7z -------------------------------------------------------------

    fn seven_zip_module(&mut self) -> std::io::Result<Option<Evidence>> {
        let head = self.signatures.head.as_slice();
        if !head.starts_with(SEVEN_ZIP) {
            return Ok(None);
        }
        let raw = self.view.probe_seven_zip_native(head)?;
        Ok(seven_zip_from_native(raw))
    }

    // ---- TAR ------------------------------------------------------------

    fn tar_module(&mut self) -> std::io::Result<Option<Evidence>> {
        // Ordinary analysis owns only a TAR starting at the logical input start.
        // Nonzero TAR candidates belong to the canonical embedded scanner;
        // raw ustar hits can also be bytes inside a compression stream.
        let (end, complete) = match self.view.walk_tar()? {
            TarObservation::Unrecognized => return Ok(None),
            TarObservation::Recognized(end) => (end, false),
            TarObservation::Terminated(end) => (Some(end), true),
        };
        let mut evidence = Evidence::new("tar", Extractable, 0, end, Vec::new());
        evidence.structure_complete = complete;
        Ok(Some(evidence))
    }

    // ---- ZIP ------------------------------------------------------------

    fn zip_module(&mut self) -> std::io::Result<Option<Evidence>> {
        let Some((offset, record)) = self.signatures.zip_eocd.as_ref() else {
            return Ok(None);
        };
        let native = self
            .view
            .probe_zip_with_disk_starts(*offset, record, self.disk_starts)?;
        let local = self.signatures.zip_local;
        if native.archive_offset != 0 && local != Some(native.archive_offset) {
            // A terminal record may belong to a ZIP inside a damaged leading
            // input. A different root belongs to the existing embedded stage.
            return Ok(None);
        }
        Ok(Some(zip_from_native(native, local, self.view.reader.len())))
    }

    // ---- Compression streams -------------------------------------------

    fn stream_module(&mut self, format: &'static str) -> std::io::Result<Option<Evidence>> {
        if !matches!(self.full_stream_structure()?, Some(StreamStructure::Complete(detected)) if detected == format) {
            return Ok(None);
        }
        let end = self.view.reader.len();
        let mut evidence = Evidence::new(format, Extractable, 0, Some(end), Vec::new());
        evidence.structure_complete = true;
        Ok(Some(evidence))
    }

    /// Full-stream validation walks the complete structure, so it runs at most once
    /// per analysis and once per physical file generation across analyses.
    fn full_stream_structure(&mut self) -> io::Result<Option<StreamStructure>> {
        if let Some(structure) = self.stream_structure {
            return Ok(structure);
        }
        let reader = &self.view.reader;
        let header = self.signatures.head.as_slice();
        let structure = if has_compression_stream_header(header) {
            match reader.file_identity().ok() {
                Some(identity) => stream_structure_cached(identity, reader, header)?,
                None => inspect_compression_stream_reader(reader, header)?,
            }
        } else {
            None
        };
        self.stream_structure = Some(structure);
        Ok(structure)
    }
}

fn seven_zip_from_native(raw: SevenZipObservation) -> Option<Evidence> {
    let end = raw.declared_end?;
    let status = if raw.password_required.is_some() {
        Extractable
    } else {
        Damaged
    };
    let mut evidence = Evidence::new("7z", status, 0, Some(end), Vec::new());
    evidence.segment.password_required = raw.password_required.unwrap_or(false);
    evidence.structure_complete = raw.password_required.is_some();
    evidence.proven_end = Some(end);
    Some(evidence)
}

fn zip_from_native(native: ZipObservation, local: Option<u64>, view_size: u64) -> Evidence {
    if let Some(start) = local.filter(|_| ZIP_LOCAL_RECOVERY_ERRORS.contains(&native.error)) {
        let mut evidence = Evidence::new(
            "zip",
            Damaged,
            start,
            None,
            if start != 0 && native.password_required {
                vec![
                    "central_directory_unreliable".into(),
                    "local_header_recovery".into(),
                ]
            } else {
                Vec::new()
            },
        );
        evidence.segment.password_required = native.password_required;
        return evidence;
    }
    let archive_offset = native.archive_offset;
    let end_offset =
        (native.eocd_offset != 0).then(|| native.eocd_offset + 22 + native.comment_length);
    let status = if native.walk_ok { Extractable } else { Weak };
    let end = end_offset.map(|end| end.min(view_size));
    let mut damage_flags = Vec::new();
    if (status == Extractable && strict_subrange(archive_offset, end, view_size))
        || (archive_offset != 0 && native.password_required)
    {
        if !native.error.is_empty() {
            damage_flags.push(native.error.to_owned());
        }
        if native.content_integrity_warning {
            damage_flags.push("content_integrity_bad_or_unknown".to_owned());
        }
    }
    let mut evidence = Evidence::new("zip", status, archive_offset, end, damage_flags);
    evidence.segment.zip_eocd_offset = native.eocd_offset.checked_sub(archive_offset);
    evidence.segment.password_required = native.password_required;
    evidence.structure_complete = native.walk_ok;
    evidence.zip_spanned = native.is_multi_disk;
    evidence
}

type PrimaryEvidence = ((u64, Reverse<u64>), &'static str, AnalysisFacts);

#[derive(Default)]
struct SegmentPlan {
    primary: Option<PrimaryEvidence>,
    carved: Vec<AnalysisSegment>,
    password_segment: Option<AnalysisSegment>,
    full_range: bool,
    missing_volume: bool,
}

impl SegmentPlan {
    fn consider(&mut self, evidence: Evidence, size: u64) {
        if evidence.proven_end.is_some_and(|end| end > size) {
            self.missing_volume = true;
        }
        let segment = &evidence.segment;
        let extractable = segment.status == Extractable;
        if extractable {
            // Module order breaks ties between the same physical ranges.
            let key = segment.range_key();
            if self.primary.as_ref().is_none_or(|(best, _, _)| key < *best) {
                self.primary = Some((key, segment.format_hint, evidence.analysis_facts()));
            }
            if segment.start == 0 && segment.end == Some(size) && size != 0 {
                self.full_range = true;
            }
        }
        let segment = evidence.segment;
        let carved = extractable && strict_subrange(segment.start, segment.end, size);
        if segment.start != 0
            && segment.password_required
            && self
                .password_segment
                .as_ref()
                .is_none_or(|best| segment.start < best.start)
        {
            if !carved {
                self.password_segment = Some(segment);
                return;
            }
            self.password_segment = Some(segment.clone());
        }
        if carved {
            self.carved.push(segment);
        }
    }

    fn finish(mut self) -> AnalysisReport {
        if self.full_range {
            // Full ranges own later starts. Preserve same-start alternatives,
            // just as retain_outer_ranges does for other outer ranges.
            self.carved.retain(|segment| segment.start == 0);
        }
        self.carved.sort_by_key(AnalysisSegment::range_key);
        crate::scan::embedded::retain_outer_ranges(&mut self.carved, |segment| {
            (segment.start, segment.end.unwrap())
        });
        if self.carved.is_empty() {
            self.carved.extend(self.password_segment);
        }
        let (format_hint, mut facts) = self.primary.map_or_else(
            || ("", AnalysisFacts::default()),
            |(_, format, facts)| (format, facts),
        );
        // A CRC-valid 7z start header that extends beyond the input proves a
        // missing later volume.
        if self.missing_volume {
            facts.volume_completeness = Some(VolumeCompleteness::Missing);
            facts.missing_volume_evidence = Some("seven_zip_start_header_length".to_owned());
        }
        AnalysisReport {
            format_hint,
            facts,
            segments: self.carved,
        }
    }
}

// ---- Full-stream structure cache -----------------------------------------

type StreamStructureSlot = CancellableOnce<Result<Option<StreamStructure>, Arc<io::Error>>>;
type StreamStructureEntry = (FileIdentity, Arc<StreamStructureSlot>);

fn stream_structure_cache() -> &'static Mutex<VecDeque<StreamStructureEntry>> {
    static CACHE: OnceLock<Mutex<VecDeque<StreamStructureEntry>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(VecDeque::new()))
}

fn stream_structure_cached(
    identity: FileIdentity,
    reader: &ManagedReader,
    header: &[u8],
) -> io::Result<Option<StreamStructure>> {
    let cancellation = Cancellation::current();
    cancellation.check()?;
    let slot = loop {
        let slot = {
            let mut entries = stream_structure_cache()
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let entry = if let Some(index) = entries.iter().position(|(key, _)| *key == identity) {
                entries.remove(index).unwrap()
            } else {
                entries.retain(|(key, _)| key.path != identity.path);
                (identity.clone(), Arc::new(StreamStructureSlot::default()))
            };
            let slot = Arc::clone(&entry.1);
            entries.push_back(entry);
            slot
        };
        let ready = slot
            .get_or_init(&cancellation, || {
                let reader = reader.with_config(ReaderConfig::default());
                inspect_compression_stream_reader(&reader, header).map_err(Arc::new)
            })
            .is_some();
        if ready {
            break slot;
        }
        {
            let mut entries = stream_structure_cache()
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            entries.retain(|(key, current)| *key != identity || !Arc::ptr_eq(current, &slot));
            crate::collections::trim_deque(&mut entries);
        }
        cancellation.check()?;
    };
    let result = slot.get().expect("completed stream structure");
    let invalid = result.is_err();
    let result = cancellation.check().and_then(|()| match result {
        Ok(value) => Ok(*value),
        Err(error) => Err(io::Error::new(error.kind(), Arc::clone(error))),
    });
    let mut entries = stream_structure_cache()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if invalid {
        entries.retain(|(_, current)| !Arc::ptr_eq(current, &slot));
    }
    // Active slots stay discoverable, including under cache pressure. Once
    // their users finish, the existing bounded cache can evict them normally.
    drop(slot);
    while entries.len() > STREAM_STRUCTURE_CACHE_ENTRIES {
        let Some(index) = entries
            .iter()
            .position(|(_, slot)| Arc::strong_count(slot) == 1 && slot.get().is_some())
        else {
            break;
        };
        entries.remove(index);
    }
    crate::collections::trim_deque(&mut entries);
    result
}

pub(crate) fn clear_stream_structure_cache() {
    // Retire the whole allocation and drop results outside the cache lock.
    let retired = std::mem::take(
        &mut *stream_structure_cache()
            .lock()
            .unwrap_or_else(|error| error.into_inner()),
    );
    drop(retired);
}

pub(crate) fn release_stream_structure_cache_under_roots(roots: &[PathBuf]) {
    let mut entries = stream_structure_cache()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    entries.retain(|(key, _)| !roots.iter().any(|root| key.path.starts_with(root)));
    crate::collections::trim_deque(&mut entries);
}

#[cfg(test)]
#[path = "../../../tests/unit/analysis_native/view/report/report_tests.rs"]
mod report_tests;
