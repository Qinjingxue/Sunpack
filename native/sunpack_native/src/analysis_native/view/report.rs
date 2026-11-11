// Canonical archive analysis report.
//
// This is the only place that turns format probes into evidence,
// segment boundaries, selection, and the extraction segment plan.

use crate::analysis_native::structure::{
    has_compression_stream_header, inspect_compression_stream_reader,
};
use crate::io::archive_state::{AnalysisFacts, ArchiveInput, OpenMode, VolumeCompleteness};
use crate::io::cancellation::{CancellableOnce, Cancellation};
use crate::io::reader::FileIdentity;
use crate::scan::embedded::{EmbeddedCandidate, NativeScanResult};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

const STREAM_STRUCTURE_CACHE_ENTRIES: usize = 512;

const RAR_TRUNCATION_ERRORS: &[&str] = &[
    "rar4_block_header_out_of_range",
    "rar4_block_size_out_of_range",
    "rar4_block_payload_out_of_range",
    "rar4_block_add_size_missing",
    "rar5_block_header_out_of_range",
    "rar5_header_size_out_of_range",
    "rar5_block_payload_out_of_range",
];
const SEVEN_ZIP_BOUNDARY_ERRORS: &[&str] = &[
    "start_header_crc_mismatch",
    "next_header_out_of_range",
    "invalid_next_header_range",
];
const TAR_BENIGN_ERRORS: &[&str] = &["tar_end_zero_blocks_not_found", "analysis_resource_limit"];
const ZIP_LOCAL_RECOVERY_ERRORS: &[&str] = &[
    "bad_central_directory_signature",
    "archive_offset_underflow",
    "central_directory_size_out_of_range",
];
#[derive(Clone, Copy)]
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

    fn format(self) -> &'static str {
        match self {
            Self::Zip => "zip",
            Self::Rar => "rar",
            Self::SevenZip => "7z",
            Self::Tar => "tar",
            Self::Stream(format) => format,
        }
    }
}

#[derive(Clone)]
struct ModuleConfig {
    name: String,
    kind: ModuleKind,
}

/// Parsed analysis configuration, built once per engine and shared by calls.
pub(crate) struct NativeAnalysisConfig {
    modules: Vec<ModuleConfig>,
}

impl NativeAnalysisConfig {
    pub(crate) fn new<T: AsRef<str>>(modules: impl IntoIterator<Item = (T, bool)>) -> Self {
        let mut ordered: Vec<ModuleConfig> = Vec::new();
        for (name, enabled) in modules {
            let name = name.as_ref().trim();
            let Some(kind) = enabled.then(|| ModuleKind::from_name(name)).flatten() else {
                continue;
            };
            if !ordered.iter().any(|module| module.name == name) {
                ordered.push(ModuleConfig {
                    name: name.to_owned(),
                    kind,
                });
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
            .map(|name| (name.to_owned(), true)),
        )
    }
}

fn strict_subrange(start: u64, end: Option<u64>, size: u64) -> bool {
    matches!(end, Some(end) if start < end && end <= size && (start > 0 || end < size))
}

struct Segment {
    start: u64,
    end: Option<u64>,
    extractable: bool,
    password_required: Option<bool>,
    zip_eocd_offset: Option<u64>,
    damage_flags: Vec<String>,
}

impl Segment {
    fn new(start: u64, end: Option<u64>, damage_flags: Vec<String>) -> Self {
        Self {
            start,
            end,
            extractable: false,
            password_required: None,
            zip_eocd_offset: None,
            damage_flags,
        }
    }
}

// Keep only the evidence needed by format selection and segment planning.
enum EvidenceDetails {
    Empty,
    Fields(DiagnosticFields),
    Rar(Box<RarObservation>),
    SevenZip(Box<SevenZipObservation>),
}

impl From<DiagnosticFields> for EvidenceDetails {
    fn from(value: DiagnosticFields) -> Self {
        Self::Fields(value)
    }
}

impl EvidenceDetails {
    fn password_required(&self) -> std::io::Result<bool> {
        match self {
            Self::Rar(value) => Ok(value.password_required.unwrap_or(false)),
            Self::SevenZip(value) => Ok(value.password_required),
            Self::Fields(value) => truthy(value, "password_required"),
            Self::Empty => Ok(false),
        }
    }

    fn embedded_anchor(&self) -> std::io::Result<bool> {
        match self {
            Self::Fields(value) if str_of(value, "source")? == "embedded_scan" => {
                let kind = str_of(value, "candidate_kind")?;
                Ok(!kind.is_empty() && kind != "logical_archive")
            }
            _ => Ok(false),
        }
    }
}

pub(crate) struct Evidence {
    pub(crate) format: String,
    pub(crate) status: &'static str,
    segments: Vec<Segment>,
    details: EvidenceDetails,
}

impl Evidence {
    fn new(
        format: &str,
        status: &'static str,
        mut segments: Vec<Segment>,
        details: impl Into<EvidenceDetails>,
    ) -> Self {
        for segment in &mut segments {
            segment.extractable |= status == "extractable";
        }
        Self {
            format: format.to_string(),
            status,
            segments,
            details: details.into(),
        }
    }

    fn range_key(&self) -> (u64, std::cmp::Reverse<u64>) {
        let extractable = self.segments.iter().any(|segment| segment.extractable);
        self.segments
            .iter()
            .filter(|segment| !extractable || segment.extractable)
            .map(|segment| {
                (
                    segment.start,
                    std::cmp::Reverse(segment.end.unwrap_or(segment.start)),
                )
            })
            .min()
            .unwrap_or((u64::MAX, std::cmp::Reverse(0)))
    }

    fn not_found(format: &str) -> Self {
        Self::new(format, "not_found", Vec::new(), EvidenceDetails::Empty)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReportHitKind {
    ZipLocal,
    ZipEocd,
    ZipOther,
    Rar,
    SevenZip,
    Tar,
}

impl ReportHitKind {
    fn from_name(name: &str) -> Option<Self> {
        match name {
            "zip_local" => Some(Self::ZipLocal),
            "zip_eocd" => Some(Self::ZipEocd),
            "7z" => Some(Self::SevenZip),
            "tar_ustar" => Some(Self::Tar),
            name if name.starts_with("rar") => Some(Self::Rar),
            name if name.starts_with("zip_") => Some(Self::ZipOther),
            // Stream modules consume structural facts, not signature hits.
            _ => None,
        }
    }
}

struct ReportSignatureHit {
    kind: ReportHitKind,
    offset: u64,
}

/// Probe access shared by single-file and multi-volume analysis.
struct ReportContext<'a> {
    view: &'a AnalysisBinaryView,
    disk_starts: Option<&'a [u64]>,
    hits: Arc<[SignatureHit]>,
    embedded_scan: Option<&'a NativeScanResult>,
    stream_structure: Option<Option<Arc<DiagnosticFields>>>,
}

pub(crate) struct AnalysisSegment {
    pub(crate) format_hint: String,
    pub(crate) start: u64,
    pub(crate) end: Option<u64>,
    pub(crate) zip_eocd_offset: Option<u64>,
    pub(crate) password_required: bool,
    pub(crate) damage_flags: Option<Arc<Vec<String>>>,
}

pub(crate) struct AnalysisReport {
    pub(crate) format_hint: String,
    pub(crate) facts: AnalysisFacts,
    pub(crate) extractable_segments: Vec<AnalysisSegment>,
    pub(crate) password_segment: Option<AnalysisSegment>,
}

pub(crate) fn analyze_input(
    input: &ArchiveInput,
    config: &NativeAnalysisConfig,
    initial_prepass: Option<&NativeScanResult>,
    format_structure: bool,
) -> io::Result<AnalysisReport> {
    let cache_bytes = 64 * 1024 * 1024;
    if input.mode == OpenMode::File || (input.parts.is_empty() && input.ranges.is_empty()) {
        return AnalysisBinaryView::new(&input.entry_path, cache_bytes)?.analyze(
            config,
            initial_prepass,
            format_structure,
        );
    }
    let extents = if input.mode.structured() {
        let mut parts: Vec<_> = input.parts.iter().collect();
        parts.sort_by_key(|part| part.volume_number);
        parts.into_iter().map(|part| &part.extent).collect()
    } else {
        input.physical_extents().collect::<Vec<_>>()
    };
    if extents.len() == 1 && extents[0].start == 0 && extents[0].end.is_none() {
        return AnalysisBinaryView::new(&extents[0].path, cache_bytes)?.analyze(
            config,
            initial_prepass,
            format_structure,
        );
    }
    let (reader, starts) = ManagedReader::open_extents(
        extents.iter().map(|e| (e.path.as_str(), e.start, e.end)),
        ReaderConfig { cache_bytes },
    )?;
    let view = AnalysisBinaryView { reader };
    view.analyze_report(
        config,
        initial_prepass,
        format_structure,
        input.mode.structured().then_some(&starts),
    )
}

impl AnalysisBinaryView {
    pub(crate) fn analyze_report(
        &self,
        config: &NativeAnalysisConfig,
        initial_prepass: Option<&NativeScanResult>,
        format_structure: bool,
        disk_starts: Option<&[u64]>,
    ) -> io::Result<AnalysisReport> {
        let cancellation = Cancellation::current();
        cancellation.check()?;
        let hits = match initial_prepass {
            Some(scan) => scan
                .signature_hits()
                .filter_map(|(name, offset)| {
                    let pattern = ANALYSIS_SIGNATURES
                        .iter()
                        .position(|(item, _)| *item == name)
                        .or_else(|| {
                            name.starts_with("zip_")
                                .then_some(ANALYSIS_SIGNATURES.len() - 1)
                        })?;
                    Some(SignatureHit::new(pattern, offset))
                })
                .collect::<Vec<_>>()
                .into(),
            None => signature_prepass_native(&self.reader).map_err(reader_error)?,
        };
        let mut context = ReportContext {
            view: self,
            disk_starts,
            hits,
            embedded_scan: initial_prepass,
            stream_structure: None,
        };
        let mut evidences = Vec::new();
        if format_structure {
            for module in &config.modules {
                cancellation.check()?;
                evidences.push(match context.run_module(module) {
                    Ok(evidence) => evidence,
                    Err(error) => {
                        let message = error.to_string();
                        let mut details = DiagnosticFields::new();
                        details.put("message", &message)?;
                        if crate::io::resource_error::is_memory_error(&error) {
                            details.put("error", "out_of_memory")?;
                            details.put("failure_kind", "resource_unavailable")?;
                        }
                        Evidence::new(module.kind.format(), "error", Vec::new(), details)
                    }
                });
            }
        }
        cancellation.check()?;
        let size = self.reader.len();
        // Feasibility comes from format structure, not a cross-format score.
        let selected = evidences
            .iter()
            .enumerate()
            .filter(|(_, evidence)| evidence.segments.iter().any(|s| s.extractable))
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        // Prefer the first proven outer range. Module order only breaks ties
        // between indistinguishable ranges; independent peers remain planned.
        let best_selected = selected
            .iter()
            .copied()
            .min_by_key(|index| evidences[*index].range_key());
        let best = best_selected.or_else(|| {
            evidences
                .iter()
                .enumerate()
                .filter(|(_, e)| status_rank(e.status) != 0)
                .max_by_key(|(index, e)| (status_rank(e.status), std::cmp::Reverse(*index)))
                .map(|(i, _)| i)
        });
        let plan = SegmentPlan::build(&evidences, &selected, size)?;
        let to_segment = |(evidence, index): (usize, usize)| -> io::Result<AnalysisSegment> {
            let evidence = &evidences[evidence];
            let segment = &evidence.segments[index];
            Ok(AnalysisSegment {
                format_hint: evidence.format.clone(),
                start: segment.start,
                end: segment.end,
                zip_eocd_offset: segment.zip_eocd_offset,
                password_required: segment
                    .password_required
                    .unwrap_or(evidence.details.password_required()?),
                damage_flags: (!segment.damage_flags.is_empty())
                    .then(|| Arc::new(segment.damage_flags.clone())),
            })
        };
        let extractable_segments = plan
            .extractable
            .into_iter()
            .map(to_segment)
            .collect::<io::Result<_>>()?;
        let password_segment = plan.password_segment.map(to_segment).transpose()?;
        let primary = best.map(|index| &evidences[index]);
        let mut facts = primary
            .map(Evidence::analysis_facts)
            .transpose()?
            .unwrap_or_default();
        if !plan.missing_volume_evidence.is_empty() {
            facts.volume_completeness = Some(VolumeCompleteness::Missing);
            facts.missing_volume_evidence = Some(plan.missing_volume_evidence.to_owned());
        }
        Ok(AnalysisReport {
            format_hint: primary.map_or_else(String::new, |e| e.format.clone()),
            facts,
            extractable_segments,
            password_segment,
        })
    }
}

impl<'a> ReportContext<'a> {
    fn run_module(&mut self, module: &ModuleConfig) -> std::io::Result<Evidence> {
        match module.kind {
            ModuleKind::Zip => self.zip_module(),
            ModuleKind::Rar => self.rar_module(),
            ModuleKind::SevenZip => self.seven_zip_module(),
            ModuleKind::Tar => self.tar_module(),
            ModuleKind::Stream("lz4") => self.lz4_module(),
            ModuleKind::Stream(format) => self.stream_module(format),
        }
    }

    fn hits(&self, matches: impl Fn(ReportHitKind) -> bool) -> Vec<ReportSignatureHit> {
        self.hits
            .iter()
            .filter_map(|hit| {
                let kind = ReportHitKind::from_name(hit.name())?;
                matches(kind).then(|| ReportSignatureHit {
                    kind,
                    offset: hit.offset(),
                })
            })
            .collect()
    }

    fn embedded(&self, format: &str, logical_only: bool) -> Vec<&'a EmbeddedCandidate> {
        self.embedded_scan
            .into_iter()
            .flat_map(NativeScanResult::candidates)
            .filter(|item| {
                item.format == format && (!logical_only || item.candidate_kind == "logical_archive")
            })
            .collect()
    }

    fn preserve_multiple(&self) -> bool {
        self.embedded_scan.is_some()
    }

    // ---- RAR ------------------------------------------------------------

    fn rar_module(&mut self) -> std::io::Result<Evidence> {
        let hits = self.hits(|kind| kind == ReportHitKind::Rar);
        let embedded = self.embedded("rar", true);
        if hits.is_empty() && embedded.is_empty() {
            return Ok(Evidence::not_found("rar"));
        }
        let mut candidates = Vec::new();
        let mut exact_starts = HashSet::new();
        for item in &embedded {
            let start = item.offset;
            let end = item.end_offset;
            let Some(end) = end else { continue };
            if item.boundary_kind != "exact" || !item.extractable {
                continue;
            }
            exact_starts.insert(start);

            let mut details = DiagnosticFields::new();
            details.put("source", "embedded_scan")?;
            details.put("boundary_kind", "exact")?;
            details.put("boundary_confidence", "high")?;
            details.put("integrity_confidence", "deferred")?;
            candidates.push(Evidence::new(
                "rar",
                "extractable",
                vec![Segment::new(start, Some(end), Vec::new())],
                details,
            ));
        }
        let mut starts = embedded.iter().map(|item| item.offset).collect::<Vec<_>>();
        if starts.is_empty() {
            starts = hits.iter().map(|hit| hit.offset).collect::<Vec<_>>();
        }
        starts.sort_unstable();
        starts.dedup();
        for start in starts
            .into_iter()
            .filter(|start| !exact_starts.contains(start))
        {
            let native = (self.view.probe_rar_native(start))?;
            candidates.push(rar_from_native(native, start)?);
        }
        combine_candidates("rar", candidates, self.preserve_multiple())
    }

    // ---- 7z -------------------------------------------------------------

    fn seven_zip_module(&mut self) -> std::io::Result<Evidence> {
        let embedded = self.embedded("7z", true);
        let mut exact = Vec::new();
        for item in embedded {
            if item.boundary_kind == "exact" && item.end_offset.is_some() && item.extractable {
                exact.push(item);
            }
        }
        if !exact.is_empty() {
            let candidates = exact
                .iter()
                .map(|item| seven_zip_from_embedded(item))
                .collect::<std::io::Result<Vec<_>>>()?;
            return combine_candidates("7z", candidates, true);
        }
        let hits = self.hits(|kind| kind == ReportHitKind::SevenZip);
        if hits.is_empty() {
            return Ok(Evidence::not_found("7z"));
        }
        let mut starts = hits.iter().map(|hit| hit.offset).collect::<Vec<_>>();
        starts.sort_unstable();
        starts.dedup();
        let mut candidates = Vec::new();
        for start in starts {
            let native = (self.view.probe_seven_zip_native(start))?;
            candidates.push(seven_zip_from_native(native, start)?);
        }
        combine_candidates("7z", candidates, self.preserve_multiple())
    }

    // ---- TAR ------------------------------------------------------------

    fn tar_module(&mut self) -> std::io::Result<Evidence> {
        let embedded = self.embedded("tar", true);
        if !embedded.is_empty() {
            let mut candidates = Vec::new();
            for item in &embedded {
                let start = item.offset;
                let end = item.end_offset;
                let boundary_kind = item.boundary_kind;
                let exact = end.is_some() && boundary_kind == "exact" && item.extractable;

                let mut details = DiagnosticFields::new();
                details.put("source", "embedded_scan")?;
                details.put("boundary_kind", boundary_kind)?;
                candidates.push(Evidence::new(
                    "tar",
                    if exact { "extractable" } else { "damaged" },
                    vec![Segment::new(
                        start,
                        end,
                        if exact {
                            Vec::new()
                        } else {
                            vec!["tar_boundary_unresolved".to_string()]
                        },
                    )],
                    details,
                ));
            }
            return combine_candidates("tar", candidates, true);
        }
        // Ordinary analysis owns only a TAR starting at the logical input start.
        // Nonzero TAR candidates belong to the canonical embedded scanner;
        // raw ustar hits can also be bytes inside a compression stream.
        Ok(self
            .tar_candidate(0)?
            .unwrap_or_else(|| Evidence::not_found("tar")))
    }

    fn tar_observation(&self, start: u64) -> std::io::Result<DiagnosticFields> {
        let mut raw = self.view.walk_tar(start)?;
        set_default(&mut raw, "archive_offset", start)?;
        let detected = if truthy(&raw, "plausible")? {
            ".tar"
        } else {
            ""
        };
        set_default(&mut raw, "detected_ext", detected)?;
        let error = str_of(&raw, "error")?;
        let mut damage_flags = str_list(&raw, "damage_flags")?;
        if !error.is_empty() && !TAR_BENIGN_ERRORS.contains(&error.as_str()) {
            damage_flags.push(error);
        }
        let integrity = match raw.get("stored_checksum") {
            Some(stored) if value_truthy(stored) => match raw.get("computed_checksum") {
                Some(computed) if stored == computed => "high",
                _ => "low",
            },
            _ => "unknown",
        };
        raw.put("integrity_confidence", integrity)?;
        raw.put("damage_flags", sorted_unique(damage_flags))?;
        Ok(raw)
    }

    fn tar_candidate(&self, start: u64) -> std::io::Result<Option<Evidence>> {
        let result = self.tar_observation(start)?;
        if truthy(&result, "plausible")? {
            let segment = Segment::new(
                start,
                opt_u64_of(&result, "segment_end")?,
                read_fault_damage_flags(&result)?,
            );
            return Ok(Some(Evidence::new(
                "tar",
                "extractable",
                vec![segment],
                result.clone(),
            )));
        }
        if truthy(&result, "magic_matched")? {
            let mut damage_flags = read_fault_damage_flags(&result)?;
            if damage_flags.is_empty() {
                damage_flags.push("tar_metadata_bad".to_string());
            }
            return Ok(Some(Evidence::new(
                "tar",
                "damaged",
                vec![Segment::new(start, None, damage_flags)],
                result,
            )));
        }
        Ok(None)
    }

    // ---- ZIP ------------------------------------------------------------

    fn zip_module(&mut self) -> std::io::Result<Evidence> {
        let hits = self.hits(|kind| {
            matches!(
                kind,
                ReportHitKind::ZipLocal | ReportHitKind::ZipEocd | ReportHitKind::ZipOther
            )
        });
        let embedded = self.embedded("zip", false);
        if hits.is_empty() && embedded.is_empty() {
            return Ok(Evidence::not_found("zip"));
        }
        let mut logical = Vec::new();
        for item in &embedded {
            if item.candidate_kind == "logical_archive" {
                logical.push(zip_from_embedded(item)?);
            }
        }
        if !logical.is_empty() {
            return combine_candidates("zip", logical, true);
        }
        // Resolve only on recovery, once per analysis, including an absent local header.
        let mut earliest_local = None::<Option<u64>>;
        let mut eocd_hits = Vec::new();
        for hit in &hits {
            if hit.kind == ReportHitKind::ZipEocd {
                eocd_hits.push(hit.offset);
            }
        }
        eocd_hits.sort_unstable_by(|left, right| right.cmp(left));
        let mut evidences = Vec::new();
        for eocd_offset in eocd_hits {
            let native = self.zip_eocd_observation(eocd_offset)?;
            if native.is_empty()
                || !(truthy(&native, "magic_matched")? || truthy(&native, "plausible")?)
            {
                continue;
            }
            let archive_offset = u64_of(&native, "archive_offset")?;
            if archive_offset != 0
                && !hits
                    .iter()
                    .any(|hit| hit.kind == ReportHitKind::ZipLocal && hit.offset == archive_offset)
            {
                // A terminal record may belong to a ZIP inside a damaged
                // leading input. Reuse the parser's origin fact; discovering
                // a different root belongs to the existing embedded stage.
                continue;
            }
            evidences.push(
                match zip_local_header_recovery(&native, &hits, &mut earliest_local)? {
                    Some(recovered) => recovered,
                    None => zip_from_native(native, &hits, self.view.reader.len())?,
                },
            );
        }
        let known_starts = evidences
            .iter()
            .flat_map(|evidence| evidence.segments.iter().map(|segment| segment.start))
            .collect::<HashSet<_>>();
        for item in &embedded {
            if !item.validation.contains("local_header") {
                continue;
            }
            let start = item.offset;
            if known_starts.contains(&start) {
                continue;
            }
            let mut details = DiagnosticFields::new();
            details.put("boundary_confidence", "low")?;
            evidences.push(Evidence::new(
                "zip",
                "damaged",
                vec![Segment::new(
                    start,
                    None,
                    vec!["central_directory_unavailable".to_string()],
                )],
                details,
            ));
        }
        combine_candidates("zip", evidences, self.preserve_multiple())
    }

    fn zip_eocd_observation(&self, requested: u64) -> std::io::Result<DiagnosticFields> {
        let candidate = self.view.locate_zip_eocd_native(Some(requested))?;
        if !truthy(&candidate, "eocd_candidate_found")? {
            let mut raw = DiagnosticFields::new();
            raw.put("plausible", false)?;
            raw.put("magic_matched", false)?;
            raw.put("error", "eocd_not_found")?;
            raw.extend(candidate.clone());
            zip_observation(&mut raw)?;
            return Ok(raw);
        }
        let eocd_offset = u64_of(&candidate, "eocd_candidate_offset")?;
        let mut raw = self
            .view
            .probe_zip_with_disk_starts(eocd_offset, self.disk_starts)?;
        raw.extend(candidate.clone());
        set_default(
            &mut raw,
            "comment_length",
            i64_of(&candidate, "eocd_candidate_comment_length")?,
        )?;
        set_default(
            &mut raw,
            "declared_central_directory_offset",
            i64_of(&candidate, "eocd_candidate_cd_offset")?,
        )?;
        set_default(
            &mut raw,
            "declared_central_directory_size",
            i64_of(&candidate, "eocd_candidate_cd_size")?,
        )?;
        let total_entries = i64_of(&raw, "total_entries")?;
        set_default(&mut raw, "declared_total_entries", total_entries)?;
        let size = self.view.reader.len() as i64;
        let segment_end = match i64_of(&raw, "segment_end")? {
            0 => size,
            value => value,
        };
        set_default(
            &mut raw,
            "trailing_bytes_after_eocd",
            (size - segment_end).max(0),
        )?;
        let physical_cd = i64_of(&raw, "central_directory_offset")?;
        let declared_cd = i64_of(&raw, "declared_central_directory_offset")?;
        set_default(&mut raw, "physical_central_directory_offset", physical_cd)?;
        set_default(&mut raw, "inferred_central_directory_offset", physical_cd)?;
        let directory_size = i64_of(&raw, "central_directory_size")?;
        set_default(&mut raw, "inferred_central_directory_size", directory_size)?;
        set_default(
            &mut raw,
            "central_directory_offset_delta",
            physical_cd - declared_cd,
        )?;
        set_default(&mut raw, "central_directory_size_delta", 0)?;
        set_default(&mut raw, "entry_count_delta", 0)?;
        let links = i64_of(&raw, "local_header_links_checked")?;
        let links_ok = truthy(&raw, "local_header_links_ok")?;
        set_default(
            &mut raw,
            "local_header_links_ok_count",
            if links_ok { links } else { 0 },
        )?;
        set_default(
            &mut raw,
            "local_header_links_error_count",
            if links_ok { 0 } else { 1 },
        )?;
        zip_observation(&mut raw)?;
        Ok(raw)
    }

    // ---- Compression streams -------------------------------------------

    fn stream_module(&mut self, format: &'static str) -> std::io::Result<Evidence> {
        let embedded = self.embedded(format, true);
        if !embedded.is_empty() {
            let mut complete = true;
            let mut segments = Vec::new();
            for item in &embedded {
                let end = item.end_offset;
                let extractable =
                    end.is_some() && item.boundary_kind == "exact" && item.extractable;
                complete &= extractable;
                let mut segment = Segment::new(
                    item.offset,
                    end,
                    if end.is_some() {
                        Vec::new()
                    } else {
                        vec!["stream_boundary_inferred".to_string()]
                    },
                );
                segment.extractable = extractable;
                segments.push(segment);
            }
            let mut details = DiagnosticFields::new();
            details.put("source", "embedded_scan")?;
            details.put("boundary_confidence", if complete { "high" } else { "low" })?;
            return Ok(Evidence::new(
                format,
                if complete { "extractable" } else { "damaged" },
                segments,
                details,
            ));
        }
        let result = self.stream_observation(format)?;
        if !truthy(&result, "magic_matched")? {
            return Ok(Evidence::new(format, "not_found", Vec::new(), result));
        }
        let mut damage_flags = str_list(&result, "damage_flags")?;
        let error = str_of(&result, "error")?;
        if !error.is_empty() {
            damage_flags.push(error);
        }
        let mut damage_flags = sorted_unique(damage_flags);
        let structure_complete = truthy(&result, "structure_validation_complete")?;
        let boundary_exact = truthy(&result, "boundary_exact")?;
        let trailing = trailing_bytes(&result)?;
        let plausible = truthy(&result, "plausible")?;
        if plausible
            && structure_complete
            && boundary_exact
            && damage_flags.is_empty()
            && trailing == Some(0)
        {
            let end = match u64_of(&result, "segment_end")? {
                0 => self.view.reader.len(),
                value => value,
            };
            return Ok(Evidence::new(
                format,
                "extractable",
                vec![Segment::new(0, Some(end), Vec::new())],
                result,
            ));
        }
        if plausible {
            if !structure_complete {
                damage_flags.push("structure_validation_incomplete".to_string());
                damage_flags = sorted_unique(damage_flags);
            }

            let end = opt_u64_of(&result, "segment_end")?;
            return Ok(Evidence::new(
                format,
                "damaged",
                vec![Segment::new(0, end, damage_flags)],
                result,
            ));
        }
        if damage_flags.is_empty() {
            damage_flags.push("stream_unverified".to_string());
        }
        Ok(Evidence::new(
            format,
            if damage_flags.iter().any(|flag| flag != "stream_unverified") {
                "damaged"
            } else {
                "weak"
            },
            vec![Segment::new(0, None, damage_flags)],
            result,
        ))
    }

    fn stream_observation(&mut self, format: &str) -> std::io::Result<DiagnosticFields> {
        let raw = match self.full_stream_structure()? {
            Some(structure) if structure.get("format").and_then(Value::as_str) == Some(format) => {
                (*structure).clone()
            }
            Some(structure) => structure
                .get("format")
                .map(|actual| DiagnosticFields::from_iter([("format".to_owned(), actual.clone())]))
                .unwrap_or_default(),
            None => DiagnosticFields::new(),
        };
        stream_observation(raw, format)
    }

    /// Full-stream validation walks the complete structure, so it runs at most once
    /// per analysis and once per physical file generation across analyses.
    fn full_stream_structure(&mut self) -> io::Result<Option<Arc<DiagnosticFields>>> {
        if let Some(structure) = &self.stream_structure {
            return Ok(structure.clone());
        }
        let reader = &self.view.reader;
        let header = (reader.read_cached_at(0, 32)).ok();
        let structure =
            if let Some(header) = header.filter(|head| has_compression_stream_header(head)) {
                Some(match reader.file_identity().ok() {
                    Some(identity) => stream_structure_cached(identity, reader, &header)?,
                    None => Arc::new(inspect_compression_stream_reader(reader, &header)?),
                })
            } else {
                // No compression family can match; the requested-format mismatch
                // projection never reads the structure result.
                None
            };
        self.stream_structure = Some(structure.clone());
        Ok(structure)
    }
}

fn native_read_fault_flags(fault: &ReadFault) -> Vec<String> {
    let mut flags = vec!["read_error".into()];
    if fault.code == "unexpected_eof" {
        flags.extend(["input_truncated".into(), "probably_truncated".into()]);
    }
    if fault.possible_missing_volume() {
        flags.push("missing_volume".into());
    }
    flags
}

fn append_native_field_flag(flags: &mut Vec<String>, fault: Option<&(ReadFault, &'static str)>) {
    if let Some((fault, _)) = fault {
        let field = fault.field.trim();
        if !field.is_empty() {
            flags.push(format!("field_read_error:{field}"));
        }
    }
}

fn rar_from_native(mut raw: RarObservation, start: u64) -> std::io::Result<Evidence> {
    let mut damage_flags = raw
        .damage_flags
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>();
    if let Some((fault, legacy)) = &raw.read_fault {
        raw.error = legacy;
        damage_flags.extend(native_read_fault_flags(fault));
    }
    raw.archive_offset = if raw.archive_offset == 0 {
        start
    } else {
        raw.archive_offset
    };
    raw.plausible |= raw.header_crc_ok;
    raw.block_walk_ok |= raw.end_block_found;
    let error = raw.error;
    if !error.is_empty() {
        damage_flags.push(error.into());
    }
    if raw.blocks_checked > 0 && RAR_TRUNCATION_ERRORS.contains(&error) {
        damage_flags.push("probably_truncated".into());
    }
    damage_flags = sorted_unique(damage_flags);
    if !raw.magic_matched {
        return Ok(Evidence::new(
            "rar",
            "not_found",
            Vec::new(),
            EvidenceDetails::Rar(Box::new(raw)),
        ));
    }
    let taxonomy =
        if damage_flags.iter().any(|flag| flag == "probably_truncated") && raw.blocks_checked > 0 {
            "probably_truncated"
        } else if matches!(
            error,
            "rar5_main_header_missing" | "rar4_main_header_missing"
        ) {
            "valid_encrypted_but_unwalkable"
        } else {
            ""
        };
    let segment_end = Some(raw.segment_end).filter(|end| *end != 0);
    let (status, end) = if raw.strong_accept && segment_end.is_some() {
        ("extractable", segment_end)
    } else if taxonomy == "probably_truncated" {
        ("damaged", None)
    } else if taxonomy == "valid_encrypted_but_unwalkable" {
        ("damaged", None)
    } else if raw.plausible {
        ("damaged", None)
    } else {
        ("weak", None)
    };
    let mut segment_flags = damage_flags;
    append_native_field_flag(&mut segment_flags, raw.read_fault.as_ref());
    if !error.is_empty() {
        segment_flags.push(error.into());
    }
    if !taxonomy.is_empty() {
        segment_flags.push(taxonomy.into());
    }
    if taxonomy == "valid_encrypted_but_unwalkable" {
        raw.password_required = Some(true);
        raw.header_encrypted = Some(true);
    }
    Ok(Evidence::new(
        "rar",
        status,
        vec![Segment::new(start, end, segment_flags)],
        EvidenceDetails::Rar(Box::new(raw)),
    ))
}

fn seven_zip_from_embedded(item: &EmbeddedCandidate) -> std::io::Result<Evidence> {
    let start = item.offset;
    let end = item
        .end_offset
        .ok_or_else(|| io::Error::other("validated 7z has no end"))?;

    let validation = item.validation;
    let mut details = DiagnosticFields::new();
    details.put("source", "embedded_scan")?;
    details.put("validation", &validation)?;
    details.put("candidate_kind", "logical_archive")?;
    details.put("boundary_kind", "exact")?;
    details.put("boundary_confidence", "high")?;
    details.put("integrity_confidence", "deferred")?;
    Ok(Evidence::new(
        "7z",
        "extractable",
        vec![Segment::new(start, Some(end), Vec::new())],
        details,
    ))
}

fn seven_zip_from_native(mut raw: SevenZipObservation, start: u64) -> std::io::Result<Evidence> {
    let mut damage_flags = Vec::new();
    if let Some((fault, legacy)) = &raw.read_fault {
        raw.error = legacy;
        damage_flags.extend(native_read_fault_flags(fault));
    }
    if raw.read_fault.is_none() && !raw.error.is_empty() {
        damage_flags.push(raw.error.into());
    }
    append_native_field_flag(&mut damage_flags, raw.read_fault.as_ref());
    if !raw.error.is_empty() {
        damage_flags.push(raw.error.into());
    }
    let unreliable = SEVEN_ZIP_BOUNDARY_ERRORS.contains(&raw.error);
    if unreliable {
        damage_flags.push("boundary_unreliable".into());
    } else if raw.next_header_crc_checked && !raw.next_header_crc_ok {
        damage_flags.push("directory_integrity_bad_or_unknown".into());
    }
    if !raw.magic_matched {
        return Ok(Evidence::new(
            "7z",
            "not_found",
            Vec::new(),
            EvidenceDetails::SevenZip(Box::new(raw)),
        ));
    }
    let status = if raw.strong_accept {
        "extractable"
    } else if raw.plausible {
        "damaged"
    } else {
        "weak"
    };
    let end = if unreliable {
        None
    } else {
        Some(raw.segment_end).filter(|end| *end != 0).or_else(|| {
            (raw.next_header_size != 0).then(|| {
                start
                    .saturating_add(32)
                    .saturating_add(raw.next_header_offset)
                    .saturating_add(raw.next_header_size)
            })
        })
    };
    Ok(Evidence::new(
        "7z",
        status,
        vec![Segment::new(start, end, damage_flags)],
        EvidenceDetails::SevenZip(Box::new(raw)),
    ))
}

fn zip_observation(raw: &mut DiagnosticFields) -> std::io::Result<()> {
    let error = str_of(raw, "error")?;
    let damage_flags = sorted_unique(str_list(raw, "damage_flags")?);
    let plausible = truthy(raw, "plausible")?;
    let boundary = if plausible && error.is_empty() {
        "high"
    } else if truthy(raw, "magic_matched")? {
        "low"
    } else {
        "none"
    };
    let integrity = if truthy(raw, "content_integrity_warning")? || !damage_flags.is_empty() {
        "low"
    } else if truthy(raw, "local_header_links_ok")? || plausible {
        "medium"
    } else {
        "unknown"
    };
    set_default(raw, "boundary_confidence", boundary)?;
    set_default(raw, "integrity_confidence", integrity)?;
    set_default(raw, "damage_flags", damage_flags)?;
    Ok(())
}

fn zip_from_embedded(item: &EmbeddedCandidate) -> std::io::Result<Evidence> {
    let start = item.offset;
    let end = item.end_offset;

    let validation = item.validation;
    let boundary_kind = item.boundary_kind;
    let bounded_end = end.filter(|end| *end > start);
    let extractable = boundary_kind == "exact" && item.extractable && bounded_end.is_some();
    let exact = boundary_kind == "exact";
    let mut details = DiagnosticFields::new();
    details.put("source", "embedded_scan")?;
    details.put("validation", &validation)?;
    details.put("archive_offset", start)?;
    if let Some(offset) = item.zip_eocd_offset {
        details.put("eocd_offset", offset)?;
    }
    details.put("candidate_kind", item.candidate_kind)?;
    details.put("boundary_kind", &boundary_kind)?;
    details.put(
        "boundary_confidence",
        if exact { "high" } else { "unresolved" },
    )?;
    details.put(
        "integrity_confidence",
        if exact { "deferred" } else { "unknown" },
    )?;
    let mut segment = Segment::new(start, bounded_end, Vec::new());
    segment.zip_eocd_offset = item
        .zip_eocd_offset
        .and_then(|offset| offset.checked_sub(start));
    Ok(Evidence::new(
        "zip",
        if extractable {
            "extractable"
        } else {
            "damaged"
        },
        vec![segment],
        details,
    ))
}

fn zip_from_native(
    mut native: DiagnosticFields,
    hits: &[ReportSignatureHit],
    view_size: u64,
) -> std::io::Result<Evidence> {
    let magic_matched = truthy(&native, "magic_matched")?;
    if !magic_matched && hits.is_empty() {
        return Ok(Evidence::new("zip", "not_found", Vec::new(), native));
    }
    let archive_offset = u64_of(&native, "archive_offset")?;
    let eocd_offset = u64_of(&native, "eocd_offset")?;
    let comment_length = u64_of(&native, "comment_length")?;
    let end_offset = (eocd_offset != 0).then(|| eocd_offset + 22 + comment_length);
    let plausible = truthy(&native, "plausible")?;
    let walk_ok =
        truthy(&native, "central_directory_walk_ok")? && truthy(&native, "local_header_links_ok")?;
    let status = if plausible && walk_ok {
        "extractable"
    } else if plausible {
        "damaged"
    } else {
        "weak"
    };
    let mut damage_flags = read_fault_damage_flags(&native)?;
    let error = str_of(&native, "error")?;
    if !error.is_empty() {
        damage_flags.push(error);
    }
    let crc_warning = str_of(&native, "content_integrity_warning")?;
    if !crc_warning.is_empty() {
        damage_flags.push("content_integrity_bad_or_unknown".to_string());
        native.put("integrity_confidence", "low")?;
        native.put("content_damage_reason", &crc_warning)?;
    } else {
        set_default(
            &mut native,
            "integrity_confidence",
            if plausible { "medium" } else { "unknown" },
        )?;
    }
    set_default(
        &mut native,
        "boundary_confidence",
        if plausible && walk_ok { "high" } else { "low" },
    )?;
    let segments = if !hits.is_empty() || plausible {
        let mut segment = Segment::new(
            archive_offset,
            end_offset.map(|end| end.min(view_size)),
            damage_flags,
        );
        segment.zip_eocd_offset = opt_u64_of(&native, "eocd_offset")?
            .and_then(|offset| offset.checked_sub(archive_offset));
        vec![segment]
    } else {
        Vec::new()
    };
    Ok(Evidence::new("zip", status, segments, native))
}

fn zip_local_header_recovery(
    native: &DiagnosticFields,
    hits: &[ReportSignatureHit],
    earliest_local: &mut Option<Option<u64>>,
) -> std::io::Result<Option<Evidence>> {
    if !ZIP_LOCAL_RECOVERY_ERRORS.contains(&str_of(native, "error")?.as_str()) {
        return Ok(None);
    }
    if earliest_local.is_none() {
        let mut start = None::<u64>;
        for hit in hits {
            if hit.kind == ReportHitKind::ZipLocal {
                let offset = hit.offset;
                start = Some(start.map_or(offset, |current| current.min(offset)));
            }
        }
        *earliest_local = Some(start);
    }
    let Some(start) = (*earliest_local).flatten() else {
        return Ok(None);
    };
    let mut details = native.clone();
    details.put("boundary_confidence", "low")?;
    details.put("integrity_confidence", "unknown")?;
    details.put("directory_confidence", "low")?;
    Ok(Some(Evidence::new(
        "zip",
        "damaged",
        vec![Segment::new(
            start,
            None,
            vec![
                "central_directory_unreliable".to_string(),
                "local_header_recovery".to_string(),
            ],
        )],
        details,
    )))
}

fn stream_observation(raw: DiagnosticFields, requested: &str) -> std::io::Result<DiagnosticFields> {
    let actual = str_of(&raw, "format")?;
    let mut raw = if !requested.is_empty() && actual != requested {
        let mut replaced = DiagnosticFields::new();
        replaced.put("format", requested)?;
        replaced.put("actual_format", actual)?;
        replaced.put("magic_matched", false)?;
        replaced.put("plausible", false)?;
        replaced.put("structure_status", "invalid")?;
        replaced.put("structure_validation_complete", false)?;
        replaced.put("integrity_status", "failed")?;
        replaced.put("integrity_validation_complete", true)?;
        replaced.put("boundary_exact", false)?;
        replaced.put("error", format!("{requested}_magic_not_found"))?;
        replaced.put("damage_flags", Vec::<&str>::new())?;
        replaced.put("evidence", Vec::<&str>::new())?;
        replaced
    } else {
        raw
    };
    let structure_complete = truthy(&raw, "structure_validation_complete")?;
    let integrity_status = str_or(&raw, "integrity_status", "deferred")?;
    set_default(
        &mut raw,
        "structure_status",
        if structure_complete {
            "complete"
        } else {
            "incomplete"
        },
    )?;
    set_default(
        &mut raw,
        "structure_validation_complete",
        structure_complete,
    )?;
    set_default(&mut raw, "boundary_exact", structure_complete)?;
    set_default(&mut raw, "integrity_status", &integrity_status)?;
    set_default(
        &mut raw,
        "integrity_validation_complete",
        integrity_status == "verified" || integrity_status == "failed",
    )?;
    let trailing = trailing_bytes(&raw)?;
    let damage_flags = sorted_unique(str_list(&raw, "damage_flags")?);
    let error = str_of(&raw, "error")?;
    let (boundary, integrity) = if structure_complete
        && truthy(&raw, "boundary_exact")?
        && damage_flags.is_empty()
        && trailing == Some(0)
    {
        (
            "high",
            if integrity_status == "verified" {
                "high"
            } else {
                "unknown"
            },
        )
    } else if !damage_flags.is_empty() || !error.is_empty() {
        ("low", "low")
    } else if truthy(&raw, "plausible")? {
        ("medium", "unknown")
    } else {
        ("none", "unknown")
    };
    let file_size = i64_of(&raw, "file_size")?;
    if !raw.contains_key("segment_end") {
        match trailing {
            Some(trailing) if structure_complete && file_size >= trailing => {
                raw.put("segment_end", file_size - trailing)?
            }
            _ => raw.put("segment_end", Value::Null)?,
        }
    }
    raw.put("boundary_confidence", boundary)?;
    raw.put("integrity_confidence", integrity)?;
    set_default(&mut raw, "damage_flags", damage_flags)?;
    Ok(raw)
}

fn combine_candidates(
    format: &str,
    candidates: Vec<Evidence>,
    preserve_multiple: bool,
) -> std::io::Result<Evidence> {
    let mut usable = candidates
        .into_iter()
        .filter(|item| !item.segments.is_empty())
        .collect::<Vec<_>>();
    if usable.is_empty() {
        return Ok(Evidence::not_found(format));
    }
    if usable
        .iter()
        .any(|item| item.status == "damaged" || item.status == "extractable")
    {
        usable.retain(|item| item.status == "damaged" || item.status == "extractable");
    }
    // Prefer established format state, then the first outer physical range.
    let mut best = 0usize;
    for (index, item) in usable.iter().enumerate().skip(1) {
        let current = &usable[best];
        let rank = status_rank(item.status);
        let best_rank = status_rank(current.status);
        if rank > best_rank || (rank == best_rank && item.range_key() < current.range_key()) {
            best = index;
        }
    }
    if !preserve_multiple {
        return Ok(usable.swap_remove(best));
    }
    let mut seen = HashMap::new();
    let mut segments: Vec<Segment> = Vec::new();
    let mut details = EvidenceDetails::Empty;
    let status = usable[best].status;
    for (index, item) in usable.into_iter().enumerate() {
        let password_required = item.details.password_required()?;
        if index == best {
            details = item.details;
        }
        for mut segment in item.segments {
            // Merging evidence must not promote a damaged peer or lose an
            // encrypted peer's password requirement with the primary details.
            segment.password_required =
                Some(segment.password_required.unwrap_or(password_required));
            let key = (segment.start, segment.end);
            if let Some(&index) = seen.get(&key) {
                let previous: &mut Segment = &mut segments[index];
                let password = previous.password_required.unwrap_or(false)
                    || segment.password_required.unwrap_or(false);
                if !previous.extractable && segment.extractable {
                    *previous = segment;
                }
                previous.password_required = Some(password);
            } else {
                seen.insert(key, segments.len());
                segments.push(segment);
            }
        }
    }
    segments.sort_by_key(|segment| {
        (
            segment.start,
            segment.end.is_none(),
            segment.end.unwrap_or(0),
        )
    });
    Ok(Evidence {
        format: format.to_string(),
        status,
        segments,
        details,
    })
}

fn status_rank(status: &str) -> u8 {
    match status {
        "error" => 1,
        "weak" => 2,
        "damaged" => 3,
        "extractable" => 4,
        _ => 0,
    }
}

struct SegmentPlan {
    extractable: Vec<(usize, usize)>,
    password_segment: Option<(usize, usize)>,
    missing_volume_evidence: &'static str,
}

impl SegmentPlan {
    /// Order the canonical extractable carved segments by physical position.
    fn build(evidences: &[Evidence], selected: &[usize], size: u64) -> std::io::Result<Self> {
        let mut candidates = Vec::new();
        for &evidence_index in selected {
            let evidence = &evidences[evidence_index];
            if evidence.details.embedded_anchor()? {
                continue;
            }
            for (segment_index, segment) in evidence.segments.iter().enumerate() {
                if !segment.extractable
                    || !matches!(segment.end, Some(end) if segment.start < end && end <= size)
                {
                    continue;
                }
                candidates.push((evidence_index, segment_index));
            }
        }
        candidates.sort_by_key(|&(evidence, segment)| {
            let segment = &evidences[evidence].segments[segment];
            (segment.start, std::cmp::Reverse(segment.end.unwrap()))
        });
        crate::scan::embedded::retain_outer_ranges(&mut candidates, |&(evidence, segment)| {
            let segment = &evidences[evidence].segments[segment];
            (segment.start, segment.end.unwrap())
        });
        candidates.retain(|&(evidence, segment)| {
            let segment = &evidences[evidence].segments[segment];
            strict_subrange(segment.start, segment.end, size)
        });
        let mut password_segment = None::<(usize, usize)>;
        for (evidence_index, evidence) in evidences.iter().enumerate() {
            let password_required = evidence.details.password_required()?;
            for (segment_index, segment) in evidence.segments.iter().enumerate() {
                if segment.start == 0 || !segment.password_required.unwrap_or(password_required) {
                    continue;
                }
                let better = match password_segment {
                    None => true,
                    Some((best_evidence, best_segment)) => {
                        segment.start < evidences[best_evidence].segments[best_segment].start
                    }
                };
                if better {
                    password_segment = Some((evidence_index, segment_index));
                }
            }
        }

        // A CRC-valid 7z start header that declares an end beyond the
        // analyzed logical bytes proves a missing later volume.
        let mut missing_volume_evidence = "";
        for evidence in evidences {
            if !evidence.format.eq_ignore_ascii_case("7z") {
                continue;
            }
            let expected_end = match &evidence.details {
                EvidenceDetails::SevenZip(details) if details.start_header_crc_ok => {
                    let raw = details;
                    raw.archive_offset
                        .saturating_add(32)
                        .saturating_add(raw.next_header_offset)
                        .saturating_add(raw.next_header_size)
                }
                EvidenceDetails::Fields(details) if truthy(details, "start_header_crc_ok")? => {
                    u64_of(details, "archive_offset")?
                        .saturating_add(32)
                        .saturating_add(u64_of(details, "next_header_offset")?)
                        .saturating_add(u64_of(details, "next_header_size")?)
                }
                _ => continue,
            };
            if expected_end > size {
                missing_volume_evidence = "seven_zip_start_header_length";
                break;
            }
        }

        Ok(Self {
            extractable: candidates,
            password_segment,
            missing_volume_evidence,
        })
    }
}

impl Evidence {
    fn structure_complete(&self, details: &DiagnosticFields) -> io::Result<bool> {
        Ok(match &self.details {
            EvidenceDetails::Rar(value) => {
                value.end_block_found && value.error.is_empty() && value.read_fault.is_none()
            }
            EvidenceDetails::SevenZip(value) => {
                value.next_header_crc_ok && value.next_header_nid_valid && value.error.is_empty()
            }
            _ if self.format == "zip" => {
                truthy(&details, "central_directory_walk_ok")?
                    && truthy(&details, "local_header_links_ok")?
            }
            _ if self.format == "tar" => {
                truthy(&details, "walk_complete")? && str_of(&details, "error")?.is_empty()
            }
            _ => truthy(&details, "structure_validation_complete")?,
        })
    }

    fn analysis_facts(&self) -> io::Result<AnalysisFacts> {
        let fields = match &self.details {
            EvidenceDetails::Fields(fields) => Some(fields),
            _ => None,
        };
        let structure_complete = match &self.details {
            EvidenceDetails::Rar(value) => {
                value.end_block_found && value.error.is_empty() && value.read_fault.is_none()
            }
            EvidenceDetails::SevenZip(value) => {
                value.next_header_crc_ok && value.next_header_nid_valid && value.error.is_empty()
            }
            _ => match fields {
                Some(fields) => self.structure_complete(fields)?,
                None => false,
            },
        };
        let zip_eocd_offset = if self.format == "zip" {
            fields
                .and_then(|fields| fields.get("eocd_offset"))
                .and_then(Value::as_u64)
        } else {
            None
        };
        Ok(AnalysisFacts {
            zip_eocd_offset,
            zip_spanned: fields
                .and_then(|fields| fields.get("is_multi_disk"))
                .and_then(Value::as_bool)
                .unwrap_or(false),
            password_required: self.details.password_required()?,
            structure_complete,
            ..Default::default()
        })
    }
}

/// Trailing bytes after the last stream member. A truncated stream reports the
/// field as unavailable, which leaves the boundary unproven.
fn trailing_bytes(dict: &DiagnosticFields) -> std::io::Result<Option<i64>> {
    match dict.get("archive.trailing_data") {
        None => Ok(Some(0)),
        Some(value) if value.is_null() => Ok(Some(0)),
        Some(value) => Ok(value.as_i64()),
    }
}

fn read_fault_damage_flags(native: &DiagnosticFields) -> std::io::Result<Vec<String>> {
    let flags = str_list(native, "damage_flags")?;
    let Some(fault) = native.get("read_error") else {
        return Ok(flags);
    };
    let Some(fault) = fault.as_object() else {
        return Ok(flags);
    };
    let mut flags = flags;
    flags.push("read_error".to_string());
    if str_of(fault, "code")? == "unexpected_eof" {
        flags.push("input_truncated".to_string());
    }
    let field = str_of(fault, "field")?;
    let field = field.trim();
    if !field.is_empty() {
        flags.push(format!("field_read_error:{field}"));
    }
    if truthy(fault, "possible_missing_volume")? {
        flags.push("missing_volume".to_string());
    }
    let mut unique = Vec::with_capacity(flags.len());
    for flag in flags {
        if !flag.is_empty() && !unique.contains(&flag) {
            unique.push(flag);
        }
    }
    Ok(unique)
}

// ---- Format identity confirmation ----------------------------------------

/// Confirm a routed single-file TAR or compression stream by format identity.
pub(crate) fn confirm_format_identity_native(path: &str, format: &str) -> bool {
    match format {
        "enc" => {
            let Ok(reader) = ManagedReader::open(path) else {
                return false;
            };
            let Ok(header) = reader.read_direct_at(0, 40) else {
                return false;
            };
            sunpack_enc::Header::parse(&header, reader.len()).is_ok()
        }
        "tar" => {
            let reader = match ManagedReader::open(path) {
                Ok(reader) => reader,
                Err(_) => return false,
            };
            if reader.len() < TAR_BLOCK_SIZE as u64 {
                return false;
            }
            let Ok(header) = reader.read_direct_at(0, TAR_BLOCK_SIZE) else {
                return false;
            };
            if header.len() != TAR_BLOCK_SIZE {
                return false;
            }
            let identity = tar_header_identity(&header, 0, reader.len());
            identity.validated_size.is_ok()
                && identity.name_nonempty
                && identity.numeric_fields_valid
                && identity.typeflag_valid
                && identity.payload_in_range
        }
        "gzip" | "bzip2" | "xz" | "zstd" | "lz4" => {
            crate::analysis_native::confirm_compression_format_identity_native(path, format)
        }
        _ => false,
    }
}

// ---- Full-stream structure cache -----------------------------------------

type StreamStructureSlot = CancellableOnce<Result<Arc<DiagnosticFields>, Arc<io::Error>>>;
type StreamStructureEntry = (FileIdentity, Arc<StreamStructureSlot>);

fn stream_structure_cache() -> &'static Mutex<VecDeque<StreamStructureEntry>> {
    static CACHE: OnceLock<Mutex<VecDeque<StreamStructureEntry>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(VecDeque::new()))
}

fn stream_structure_cached(
    identity: FileIdentity,
    reader: &ManagedReader,
    header: &[u8],
) -> io::Result<Arc<DiagnosticFields>> {
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
                inspect_compression_stream_reader(&reader, header)
                    .map(Arc::new)
                    .map_err(Arc::new)
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
        Ok(value) => Ok(Arc::clone(value)),
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

pub(crate) fn clear_stream_structure_cache() -> usize {
    // Retire the whole allocation and drop results outside the cache lock.
    let retired = std::mem::take(
        &mut *stream_structure_cache()
            .lock()
            .unwrap_or_else(|error| error.into_inner()),
    );
    retired.len()
}

pub(crate) fn release_stream_structure_cache_under_roots(roots: &[PathBuf]) -> usize {
    let mut entries = stream_structure_cache()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let before = entries.len();
    entries.retain(|(key, _)| !roots.iter().any(|root| key.path.starts_with(root)));
    crate::collections::trim_deque(&mut entries);
    before - entries.len()
}

// ---- Diagnostic field access ----------------------------------------------

fn value_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|number| number != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}

fn truthy(fields: &DiagnosticFields, key: &str) -> io::Result<bool> {
    Ok(fields.get(key).is_some_and(value_truthy))
}

fn i64_of(fields: &DiagnosticFields, key: &str) -> io::Result<i64> {
    Ok(fields.get(key).and_then(Value::as_i64).unwrap_or_default())
}

fn u64_of(fields: &DiagnosticFields, key: &str) -> io::Result<u64> {
    Ok(opt_u64_of(fields, key)?.unwrap_or_default())
}

fn opt_u64_of(fields: &DiagnosticFields, key: &str) -> io::Result<Option<u64>> {
    Ok(fields.get(key).and_then(|value| {
        value
            .as_u64()
            .or_else(|| value.as_i64().map(|value| value.max(0) as u64))
    }))
}

fn str_of(fields: &DiagnosticFields, key: &str) -> io::Result<String> {
    Ok(fields
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned())
}

fn str_or(fields: &DiagnosticFields, key: &str, default: &str) -> io::Result<String> {
    Ok(fields
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .unwrap_or(default)
        .to_owned())
}

fn str_list(fields: &DiagnosticFields, key: &str) -> io::Result<Vec<String>> {
    Ok(fields
        .get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect())
}

fn set_default(
    fields: &mut DiagnosticFields,
    key: &str,
    value: impl serde::Serialize,
) -> io::Result<()> {
    if !fields.contains_key(key) {
        fields.put(key, value)?;
    }
    Ok(())
}

fn sorted_unique(mut values: Vec<String>) -> Vec<String> {
    values.retain(|value| !value.is_empty());
    values.sort();
    values.dedup();
    values
}

#[cfg(test)]
mod report_tests {
    use super::*;

    fn evidence(
        format: &str,
        status: &'static str,
        segments: &[(u64, Option<u64>)],
        details: &[(&str, &str)],
    ) -> Evidence {
        let mut dict = DiagnosticFields::new();
        for (key, value) in details {
            dict.put(*key, *value).unwrap();
        }
        Evidence::new(
            format,
            status,
            segments
                .iter()
                .map(|(start, end)| Segment::new(*start, *end, Vec::new()))
                .collect(),
            dict,
        )
    }

    fn planned(evidences: &[Evidence], plan: &SegmentPlan) -> Vec<(String, u64)> {
        plan.extractable
            .iter()
            .map(|(evidence, segment)| {
                (
                    evidences[*evidence].format.clone(),
                    evidences[*evidence].segments[*segment].start,
                )
            })
            .collect()
    }

    #[test]
    fn strict_subranges_require_exact_valid_bounds() {
        for (start, end, expected) in [
            (0, Some(100), false),
            (0, Some(50), true),
            (20, Some(100), true),
            (20, Some(50), true),
            (0, None, false),
            (20, None, false),
            (0, Some(0), false),
            (50, Some(50), false),
            (50, Some(20), false),
            (0, Some(101), false),
        ] {
            assert_eq!(
                strict_subrange(start, end, 100),
                expected,
                "{start} {end:?}"
            );
        }
    }

    #[test]
    fn plan_orders_carved_segments_including_prefix_and_skips_anchor_fragments() {
        let evidences = vec![
            evidence("rar", "extractable", &[(40, Some(60))], &[]),
            evidence("7z", "extractable", &[(4, Some(32)), (0, Some(14))], &[]),
            evidence(
                "zip",
                "extractable",
                &[(13, Some(81))],
                &[("source", "embedded_scan"), ("candidate_kind", "anchor")],
            ),
            evidence("tar", "extractable", &[(90, None)], &[]),
        ];
        let plan = SegmentPlan::build(&evidences, &[0, 1, 2, 3], 100).unwrap();
        assert_eq!(
            planned(&evidences, &plan),
            vec![("7z".into(), 0), ("rar".into(), 40)]
        );
    }

    #[test]
    fn plan_picks_first_carved_password_segment() {
        let evidences = vec![
            evidence(
                "7z",
                "damaged",
                &[(0, None)],
                &[("password_required", "yes")],
            ),
            evidence(
                "rar",
                "damaged",
                &[(90, None), (64, None)],
                &[("password_required", "yes")],
            ),
            evidence(
                "zip",
                "damaged",
                &[(10, None)],
                &[("password_required", "yes")],
            ),
        ];
        let plan = SegmentPlan::build(&evidences, &[], 200).unwrap();
        assert_eq!(plan.password_segment, Some((2, 0)));
        assert!(plan.extractable.is_empty());
    }

    #[test]
    fn plan_proves_missing_volume_from_seven_zip_declared_end() {
        let mut seven = evidence("7z", "damaged", &[(0, None)], &[]);
        let EvidenceDetails::Fields(details) = &mut seven.details else {
            unreachable!()
        };
        details.put("start_header_crc_ok", true).unwrap();
        details.put("archive_offset", 0).unwrap();
        details.put("next_header_offset", 100).unwrap();
        details.put("next_header_size", 10).unwrap();
        let evidences = vec![seven];
        assert_eq!(
            SegmentPlan::build(&evidences, &[], 50)
                .unwrap()
                .missing_volume_evidence,
            "seven_zip_start_header_length"
        );
        assert_eq!(
            SegmentPlan::build(&evidences, &[], 142)
                .unwrap()
                .missing_volume_evidence,
            ""
        );
    }

    #[test]
    fn combine_prefers_first_outer_range_and_deduplicates_segments() {
        let candidates = vec![
            evidence("rar", "weak", &[(9, None)], &[("id", "weak")]),
            evidence("rar", "extractable", &[(30, Some(50))], &[("id", "first")]),
            evidence(
                "rar",
                "extractable",
                &[(4, Some(20)), (30, Some(50))],
                &[("id", "second")],
            ),
        ];
        let combined = combine_candidates("rar", candidates, true).unwrap();
        assert_eq!(combined.status, "extractable");
        let EvidenceDetails::Fields(details) = &combined.details else {
            panic!("combined evidence did not retain its primary details");
        };
        assert_eq!(str_of(details, "id").unwrap(), "second");
        let spans = combined
            .segments
            .iter()
            .map(|segment| (segment.start, segment.end))
            .collect::<Vec<_>>();
        assert_eq!(spans, vec![(4, Some(20)), (30, Some(50))]);
    }

    #[test]
    fn merged_plan_preserves_peer_eligibility_and_password_ownership() {
        // Existing isolated-format tests cannot expose promotion of bounded
        // damaged peers, lost password facts, or a duplicate hiding a valid
        // segment. One in-memory plan covers those independent merge effects.
        let candidates = vec![
            evidence("zip", "damaged", &[(40, Some(60)), (80, Some(90))], &[]),
            evidence("zip", "extractable", &[(40, Some(60))], &[]),
            evidence(
                "zip",
                "damaged",
                &[(10, Some(20))],
                &[("password_required", "yes")],
            ),
        ];
        let combined = combine_candidates("zip", candidates, true).unwrap();
        let evidences = vec![combined];
        let plan = SegmentPlan::build(&evidences, &[0], 100).unwrap();
        assert_eq!(planned(&evidences, &plan), vec![("zip".into(), 40)]);
        assert_eq!(plan.password_segment, Some((0, 0)));
        assert_eq!(evidences[0].range_key().0, 40);

        // An encrypted primary must likewise not transfer its password
        // requirement to an earlier, unencrypted damaged peer.
        let candidates = vec![
            evidence(
                "rar",
                "extractable",
                &[(40, Some(60))],
                &[("password_required", "yes")],
            ),
            evidence("rar", "damaged", &[(10, Some(20))], &[]),
        ];
        let evidences = vec![combine_candidates("rar", candidates, true).unwrap()];
        let plan = SegmentPlan::build(&evidences, &[0], 100).unwrap();
        assert_eq!(plan.password_segment, Some((0, 1)));
    }

    #[test]
    fn read_fault_projects_field_truncation_and_missing_volume_flags() {
        let mut native = DiagnosticFields::new();
        native
            .put("damage_flags", vec!["read_error", "probably_truncated"])
            .unwrap();
        let mut fault = DiagnosticFields::new();
        fault.put("code", "unexpected_eof").unwrap();
        fault.put("field", " zip.eocd ").unwrap();
        fault.put("possible_missing_volume", true).unwrap();
        native.put("read_error", fault).unwrap();
        assert_eq!(
            read_fault_damage_flags(&native).unwrap(),
            vec![
                "read_error",
                "probably_truncated",
                "input_truncated",
                "field_read_error:zip.eocd",
                "missing_volume",
            ]
        );
        native.remove("read_error").unwrap();
        assert_eq!(
            read_fault_damage_flags(&native).unwrap(),
            vec!["read_error", "probably_truncated"]
        );
    }

    #[test]
    fn truncated_stream_trailing_size_is_unknown_not_an_error() {
        let mut raw = DiagnosticFields::new();
        raw.put("format", "gzip").unwrap();
        raw.put("magic_matched", true).unwrap();
        raw.put("plausible", false).unwrap();
        raw.put("structure_validation_complete", true).unwrap();
        raw.put("archive.trailing_data", "unavailable").unwrap();
        raw.put("file_size", 100).unwrap();
        let observed = stream_observation(raw, "gzip").unwrap();
        assert!(observed.get("segment_end").unwrap().is_null());
        assert_eq!(str_of(&observed, "boundary_confidence").unwrap(), "none");
    }
}
