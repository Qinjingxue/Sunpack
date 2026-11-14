// Canonical archive analysis report.
//
// This is the only place that turns format probes into evidence,
// segment boundaries, selection, and the extraction segment plan.

use crate::analysis_native::structure::{
    has_compression_stream_header, inspect_compression_stream_reader, StreamObservation,
};
use crate::io::archive_state::{AnalysisFacts, AnalysisStatus, ArchiveInput, OpenMode, VolumeCompleteness};
use crate::io::cancellation::{CancellableOnce, Cancellation};
use crate::io::reader::FileIdentity;
use std::collections::VecDeque;
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

// Keep only the facts consumed by selection and extraction planning.
enum EvidenceDetails {
    Empty,
    Zip(Box<ZipObservation>),
    Tar(Box<TarObservation>),
    Rar(Box<RarObservation>),
    SevenZip(Box<SevenZipObservation>),
    Stream(Arc<crate::analysis_native::structure::StreamObservation>),
}

impl EvidenceDetails {
    fn password_required(&self) -> bool {
        match self {
            Self::Rar(value) => value.password_required.unwrap_or(false),
            Self::SevenZip(value) => value.password_required,
            Self::Zip(value) => value.password_required,
            _ => false,
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

/// Probe access shared by single-file and multi-volume analysis.
struct ReportContext<'a> {
    view: &'a AnalysisBinaryView,
    disk_starts: Option<&'a [u64]>,
    signatures: LeadingSignatures,
    stream_structure: Option<Option<Arc<StreamObservation>>>,
}

pub(crate) struct AnalysisSegment {
    pub(crate) status: Option<AnalysisStatus>,
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
) -> io::Result<AnalysisReport> {
    let cache_bytes = 64 * 1024 * 1024;
    if input.mode == OpenMode::File || (input.parts.is_empty() && input.ranges.is_empty()) {
        return AnalysisBinaryView::new(&input.entry_path, cache_bytes)?.analyze_report(config, None);
    }
    let extents = if input.mode.structured() {
        let mut parts: Vec<_> = input.parts.iter().collect();
        parts.sort_by_key(|part| part.volume_number);
        parts.into_iter().map(|part| &part.extent).collect()
    } else {
        input.physical_extents().collect::<Vec<_>>()
    };
    if extents.len() == 1 && extents[0].start == 0 && extents[0].end.is_none() {
        return AnalysisBinaryView::new(&extents[0].path, cache_bytes)?.analyze_report(config, None);
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
        let mut evidences = Vec::new();
        for module in &config.modules {
            cancellation.check()?;
            evidences.push(match context.run_module(module) {
                Ok(evidence) => evidence,
                Err(_) => Evidence::new(module.kind.format(), "error", Vec::new(), EvidenceDetails::Empty),
            });
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
        let plan = SegmentPlan::build(&evidences, &selected, size);
        let to_segment = |(evidence, index): (usize, usize)| {
            let evidence = &evidences[evidence];
            let segment = &evidence.segments[index];
            AnalysisSegment {
                status: AnalysisStatus::from_evidence(evidence.status),
                format_hint: evidence.format.clone(),
                start: segment.start,
                end: segment.end,
                zip_eocd_offset: segment.zip_eocd_offset,
                password_required: segment
                    .password_required
                    .unwrap_or(evidence.details.password_required()),
                damage_flags: (!segment.damage_flags.is_empty())
                    .then(|| Arc::new(segment.damage_flags.clone())),
            }
        };
        let extractable_segments = plan
            .extractable
            .into_iter()
            .map(to_segment)
            .collect();
        let password_segment = plan.password_segment.map(to_segment);
        let primary = best_selected.map(|index| &evidences[index]);
        let mut facts = primary
            .map(Evidence::analysis_facts)
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

    // ---- RAR ------------------------------------------------------------

    fn rar_module(&mut self) -> std::io::Result<Evidence> {
        if !self.signatures.rar {
            return Ok(Evidence::not_found("rar"));
        }
        self.view.probe_rar_native(0).map(|raw| rar_from_native(raw, 0))
    }

    // ---- 7z -------------------------------------------------------------

    fn seven_zip_module(&mut self) -> std::io::Result<Evidence> {
        if !self.signatures.seven_zip {
            return Ok(Evidence::not_found("7z"));
        }
        self.view.probe_seven_zip_native(0).map(|raw| seven_zip_from_native(raw, 0))
    }

    // ---- TAR ------------------------------------------------------------

    fn tar_module(&mut self) -> std::io::Result<Evidence> {
        // Ordinary analysis owns only a TAR starting at the logical input start.
        // Nonzero TAR candidates belong to the canonical embedded scanner;
        // raw ustar hits can also be bytes inside a compression stream.
        Ok(self
            .tar_candidate(0)?
            .unwrap_or_else(|| Evidence::not_found("tar")))
    }

    fn tar_candidate(&self, start: u64) -> std::io::Result<Option<Evidence>> {
        let mut result = self.view.walk_tar(start)?;
        if let Some(fault) = &result.read_fault {
            result.damage_flags.extend(native_read_fault_flags(fault));
        }
        if !result.error.is_empty() && !TAR_BENIGN_ERRORS.contains(&result.error.as_str()) {
            result.damage_flags.push(result.error.clone());
        }
        result.damage_flags = sorted_unique(result.damage_flags);
        let mut damage_flags = result.damage_flags.clone();
        append_read_fault_field(&mut damage_flags, result.read_fault.as_ref());
        if result.plausible {
            let segment = Segment::new(start, result.segment_end, damage_flags);
            return Ok(Some(Evidence::new(
                "tar", "extractable", vec![segment], EvidenceDetails::Tar(Box::new(result)),
            )));
        }
        if result.magic_matched {
            if damage_flags.is_empty() { damage_flags.push("tar_metadata_bad".to_owned()); }
            return Ok(Some(Evidence::new(
                "tar", "damaged", vec![Segment::new(start, None, damage_flags)],
                EvidenceDetails::Tar(Box::new(result)),
            )));
        }
        Ok(None)
    }

    // ---- ZIP ------------------------------------------------------------

    fn zip_module(&mut self) -> std::io::Result<Evidence> {
        let Some((offset, record)) = self.signatures.zip_eocd.as_ref() else {
            return Ok(Evidence::not_found("zip"));
        };
        let native = self.view.probe_zip_with_disk_starts(*offset, record, self.disk_starts)?;
        let local = self.signatures.zip_local;
        if native.archive_offset != 0 && local != Some(native.archive_offset) {
            // A terminal record may belong to a ZIP inside a damaged leading
            // input. A different root belongs to the existing embedded stage.
            return Ok(Evidence::not_found("zip"));
        }
        Ok(zip_from_native(native, local, self.view.reader.len()))
    }

    // ---- Compression streams -------------------------------------------

    fn stream_module(&mut self, format: &'static str) -> std::io::Result<Evidence> {
        let Some(result) = self.full_stream_structure()? else {
            return Ok(Evidence::not_found(format));
        };
        if result.format != format {
            return Ok(Evidence::not_found(format));
        }
        if !result.magic_matched {
            return Ok(Evidence::new(format, "not_found", Vec::new(), EvidenceDetails::Stream(result)));
        }
        let mut damage_flags = result.damage_flags.clone();
        let error = result.error.clone();
        if !error.is_empty() {
            damage_flags.push(error);
        }
        let mut damage_flags = sorted_unique(damage_flags);
        let structure_complete = result.structure_complete;
        let boundary_exact = result.boundary_exact;
        let trailing = result.trailing_bytes;
        let plausible = result.plausible;
        if plausible
            && structure_complete
            && boundary_exact
            && damage_flags.is_empty()
            && trailing == Some(0)
        {
            let end = match result.segment_end.unwrap_or_default() {
                0 => self.view.reader.len(),
                value => value,
            };
            return Ok(Evidence::new(
                format,
                "extractable",
                vec![Segment::new(0, Some(end), Vec::new())],
                EvidenceDetails::Stream(result),
            ));
        }
        if plausible {
            if !structure_complete {
                damage_flags.push("structure_validation_incomplete".to_string());
                damage_flags = sorted_unique(damage_flags);
            }

            let end = result.segment_end;
            return Ok(Evidence::new(
                format,
                "damaged",
                vec![Segment::new(0, end, damage_flags)],
                EvidenceDetails::Stream(result),
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
            EvidenceDetails::Stream(result),
        ))
    }

    /// Full-stream validation walks the complete structure, so it runs at most once
    /// per analysis and once per physical file generation across analyses.
    fn full_stream_structure(&mut self) -> io::Result<Option<Arc<StreamObservation>>> {
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

fn rar_from_native(mut raw: RarObservation, start: u64) -> Evidence {
    let mut damage_flags = raw
        .damage_flags
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>();
    if let Some((fault, legacy)) = &raw.read_fault {
        raw.error = legacy;
        damage_flags.extend(native_read_fault_flags(fault));
    }
    raw.plausible |= raw.header_crc_ok;
    let error = raw.error;
    if !error.is_empty() {
        damage_flags.push(error.into());
    }
    if raw.blocks_checked > 0 && RAR_TRUNCATION_ERRORS.contains(&error) {
        damage_flags.push("probably_truncated".into());
    }
    damage_flags = sorted_unique(damage_flags);
    if !raw.magic_matched {
        return Evidence::new(
            "rar",
            "not_found",
            Vec::new(),
            EvidenceDetails::Rar(Box::new(raw)),
        );
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
    }
    Evidence::new(
        "rar",
        status,
        vec![Segment::new(start, end, segment_flags)],
        EvidenceDetails::Rar(Box::new(raw)),
    )
}

fn seven_zip_from_native(mut raw: SevenZipObservation, start: u64) -> Evidence {
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
        return Evidence::new(
            "7z",
            "not_found",
            Vec::new(),
            EvidenceDetails::SevenZip(Box::new(raw)),
        );
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
    Evidence::new(
        "7z",
        status,
        vec![Segment::new(start, end, damage_flags)],
        EvidenceDetails::SevenZip(Box::new(raw)),
    )
}

fn zip_from_native(
    native: ZipObservation,
    local: Option<u64>,
    view_size: u64,
) -> Evidence {
    if let Some(start) = local.filter(|_| ZIP_LOCAL_RECOVERY_ERRORS.contains(&native.error.as_str())) {
        return Evidence::new(
            "zip",
            "damaged",
            vec![Segment::new(
                start,
                None,
                vec!["central_directory_unreliable".into(), "local_header_recovery".into()],
            )],
            EvidenceDetails::Zip(Box::new(native)),
        );
    }
    let archive_offset = native.archive_offset;
    let end_offset = (native.eocd_offset != 0).then(|| native.eocd_offset + 22 + native.comment_length);
    let walk_ok = native.central_directory_walk_ok && native.local_header_links_ok;
    let status = if native.plausible && walk_ok { "extractable" }
        else if native.plausible { "damaged" } else { "weak" };
    let mut damage_flags = native.read_fault.as_ref().map(native_read_fault_flags).unwrap_or_default();
    append_read_fault_field(&mut damage_flags, native.read_fault.as_ref());
    if !native.error.is_empty() { damage_flags.push(native.error.clone()); }
    if !native.content_integrity_warning.is_empty() {
        damage_flags.push("content_integrity_bad_or_unknown".to_owned());
    }
    let mut segment = Segment::new(archive_offset, end_offset.map(|end| end.min(view_size)), damage_flags);
    segment.zip_eocd_offset = native.eocd_offset.checked_sub(archive_offset);
    Evidence::new("zip", status, vec![segment], EvidenceDetails::Zip(Box::new(native)))
}

struct SegmentPlan {
    extractable: Vec<(usize, usize)>,
    password_segment: Option<(usize, usize)>,
    missing_volume_evidence: &'static str,
}

impl SegmentPlan {
    /// Order the canonical extractable carved segments by physical position.
    fn build(evidences: &[Evidence], selected: &[usize], size: u64) -> Self {
        let mut candidates = Vec::new();
        for &evidence_index in selected {
            let evidence = &evidences[evidence_index];
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
            let password_required = evidence.details.password_required();
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
                _ => continue,
            };
            if expected_end > size {
                missing_volume_evidence = "seven_zip_start_header_length";
                break;
            }
        }

        Self {
            extractable: candidates,
            password_segment,
            missing_volume_evidence,
        }
    }
}

impl Evidence {
    fn analysis_facts(&self) -> AnalysisFacts {
        let structure_complete = match &self.details {
            EvidenceDetails::Rar(value) => value.end_block_found && value.error.is_empty() && value.read_fault.is_none(),
            EvidenceDetails::SevenZip(value) => value.next_header_crc_ok && value.next_header_nid_valid && value.error.is_empty(),
            EvidenceDetails::Zip(value) => value.central_directory_walk_ok && value.local_header_links_ok,
            EvidenceDetails::Tar(value) => value.walk_complete && value.error.is_empty(),
            EvidenceDetails::Stream(value) => value.structure_complete,
            _ => false,
        };
        let (zip_eocd_offset, zip_spanned) = match &self.details {
            EvidenceDetails::Zip(value) => (Some(value.eocd_offset), value.is_multi_disk),
            _ => (None, false),
        };
        AnalysisFacts { zip_eocd_offset, zip_spanned,
            password_required: self.details.password_required(), structure_complete,
            ..Default::default() }
    }
}

fn append_read_fault_field(flags: &mut Vec<String>, fault: Option<&ReadFault>) {
    if let Some(fault) = fault {
        let field = fault.field.trim();
        if !field.is_empty() { flags.push(format!("field_read_error:{field}")); }
    }
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

type StreamStructureSlot = CancellableOnce<Result<Arc<StreamObservation>, Arc<io::Error>>>;
type StreamStructureEntry = (FileIdentity, Arc<StreamStructureSlot>);

fn stream_structure_cache() -> &'static Mutex<VecDeque<StreamStructureEntry>> {
    static CACHE: OnceLock<Mutex<VecDeque<StreamStructureEntry>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(VecDeque::new()))
}

fn stream_structure_cached(
    identity: FileIdentity,
    reader: &ManagedReader,
    header: &[u8],
) -> io::Result<Arc<StreamObservation>> {
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
        password_required: bool,
    ) -> Evidence {
        let facts = EvidenceDetails::Zip(Box::new(ZipObservation { password_required, ..Default::default() }));
        Evidence::new(
            format,
            status,
            segments
                .iter()
                .map(|(start, end)| Segment::new(*start, *end, Vec::new()))
                .collect(),
            facts,
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
    fn plan_orders_outer_carved_segments_including_prefix() {
        let evidences = vec![
            evidence("rar", "extractable", &[(40, Some(60))], false),
            evidence("7z", "extractable", &[(4, Some(32)), (0, Some(14))], false),
            evidence("tar", "extractable", &[(90, None)], false),
        ];
        let plan = SegmentPlan::build(&evidences, &[0, 1, 2], 100);
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
                true,
            ),
            evidence(
                "rar",
                "damaged",
                &[(90, None), (64, None)],
                true,
            ),
            evidence(
                "zip",
                "damaged",
                &[(10, None)],
                true,
            ),
        ];
        let plan = SegmentPlan::build(&evidences, &[], 200);
        assert_eq!(plan.password_segment, Some((2, 0)));
        assert!(plan.extractable.is_empty());
    }

    #[test]
    fn plan_proves_missing_volume_from_seven_zip_declared_end() {
        let mut seven = evidence("7z", "damaged", &[(0, None)], false);
        seven.details = EvidenceDetails::SevenZip(Box::new(SevenZipObservation {
            start_header_crc_ok: true, archive_offset: 0, next_header_offset: 100, next_header_size: 10,
            ..Default::default()
        }));
        let evidences = vec![seven];
        assert_eq!(
            SegmentPlan::build(&evidences, &[], 50)
                .missing_volume_evidence,
            "seven_zip_start_header_length"
        );
        assert_eq!(
            SegmentPlan::build(&evidences, &[], 142)
                .missing_volume_evidence,
            ""
        );
    }

    #[test]
    fn typed_zip_and_tar_facts_retain_planning_boundaries() {
        // Exercise real probes and the final facts together: dictionary-field
        // conversion errors otherwise silently default password/boundary facts.
        let mut zip = vec![0u8; 30 + 46 + 22];
        zip[..4].copy_from_slice(ZIP_LOCAL);
        zip[30..34].copy_from_slice(ZIP_CENTRAL);
        zip[38..40].copy_from_slice(&1u16.to_le_bytes()); // encrypted central member
        zip[76..80].copy_from_slice(ZIP_EOCD);
        zip[84..86].copy_from_slice(&1u16.to_le_bytes());
        zip[86..88].copy_from_slice(&1u16.to_le_bytes());
        zip[88..92].copy_from_slice(&46u32.to_le_bytes());
        zip[92..96].copy_from_slice(&30u32.to_le_bytes());
        let zip_path = crate::test_support::temp_file("typed_zip_facts", &zip);
        {
            let view = AnalysisBinaryView::new(&zip_path.to_string_lossy(), 0).unwrap();
            let signatures = LeadingSignatures::read(&view.reader).unwrap();
            let (offset, record) = signatures.zip_eocd.unwrap();
            let observed = view.probe_zip_with_disk_starts(offset, &record, None).unwrap();
            assert!(observed.plausible && observed.password_required);
            let evidence = zip_from_native(observed, signatures.zip_local, zip.len() as u64);
            assert_eq!(evidence.status, "extractable");
            assert_eq!(evidence.segments[0].end, Some(zip.len() as u64));
            let facts = evidence.analysis_facts();
            assert!(facts.structure_complete && facts.password_required);
            assert_eq!(facts.zip_eocd_offset, Some(76));
        }
        let mut tar = vec![0u8; 3 * TAR_BLOCK_SIZE];
        tar[0] = b'x';
        for range in [100..108, 108..116, 116..124, 124..136, 136..148] {
            tar[range.start..range.end - 1].fill(b'0');
        }
        tar[148..156].fill(b' ');
        tar[156] = b'0';
        tar[257..263].copy_from_slice(b"ustar\0");
        let checksum = format!("{:06o}\0 ", tar_checksum(&tar[..TAR_BLOCK_SIZE]));
        tar[148..156].copy_from_slice(checksum.as_bytes());
        let tar_path = crate::test_support::temp_file("typed_tar_facts", &tar);
        {
            let view = AnalysisBinaryView::new(&tar_path.to_string_lossy(), 0).unwrap();
            let context = ReportContext { view: &view, disk_starts: None,
                signatures: LeadingSignatures::read(&view.reader).unwrap(), stream_structure: None };
            let evidence = context.tar_candidate(0).unwrap().unwrap();
            assert_eq!(evidence.status, "extractable");
            assert_eq!(evidence.segments[0].end, Some(tar.len() as u64));
            assert!(evidence.analysis_facts().structure_complete);
        }
        crate::io::reader::release_reader_resources_under_roots(vec![
            zip_path.to_string_lossy().into_owned(), tar_path.to_string_lossy().into_owned(),
        ]).unwrap();
        std::fs::remove_file(zip_path).unwrap();
        std::fs::remove_file(tar_path).unwrap();
    }

    #[test]
    fn read_fault_projects_field_truncation_and_missing_volume_flags() {
        let fault = ReadFault::short_read("read_record", 0, 22, 10, 10)
            .with_field(" zip.eocd ", FieldLocation::Tail);
        let mut flags = native_read_fault_flags(&fault);
        append_read_fault_field(&mut flags, Some(&fault));
        assert_eq!(flags, ["read_error", "input_truncated", "probably_truncated",
            "missing_volume", "field_read_error:zip.eocd"]);
    }


}
