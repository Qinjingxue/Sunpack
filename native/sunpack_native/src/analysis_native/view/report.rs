// Canonical archive analysis report.
//
// This is the only place that turns format probes into evidence, confidence,
// segment boundaries, selection, and the extraction segment plan. Python only
// projects the returned report into its task contracts.

use crate::io::reader::FileIdentity;
use pyo3::types::PyTuple;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

const DEFAULT_PREPASS_BYTES: usize = 1024 * 1024;
const DEFAULT_EXTRACTABLE_CONFIDENCE: f64 = 0.85;
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
const RAR_WALK_LIMIT_ERRORS: &[&str] = &[
    "rar4_block_walk_limit_reached",
    "rar5_block_walk_limit_reached",
];
const SEVEN_ZIP_BOUNDARY_ERRORS: &[&str] = &[
    "start_header_crc_mismatch",
    "next_header_out_of_range",
    "invalid_next_header_range",
];
const TAR_BENIGN_ERRORS: &[&str] = &["tar_end_zero_blocks_not_found", "tar_walk_budget_exhausted"];
const ZIP_LOCAL_RECOVERY_ERRORS: &[&str] = &[
    "bad_central_directory_signature",
    "archive_offset_underflow",
    "central_directory_size_out_of_range",
];
const COMPOSITE_INNER_FORMATS: &[(&str, &[&str])] = &[
    ("tar.gz", &["tar", "gzip"]),
    ("tar.bz2", &["tar", "bzip2"]),
    ("tar.xz", &["tar", "xz"]),
    ("tar.zst", &["tar", "zstd"]),
    ("tar.lz4", &["tar", "lz4"]),
];
const STREAM_CONTAINERS: &[(&str, &str)] = &[
    ("gzip", "tar.gz"),
    ("bzip2", "tar.bz2"),
    ("xz", "tar.xz"),
    ("zstd", "tar.zst"),
    ("lz4", "tar.lz4"),
];

#[derive(Clone, Copy)]
enum ModuleKind {
    Zip,
    Rar,
    SevenZip,
    Tar,
    Stream(&'static str),
    CompressedTar(&'static str, &'static str),
}

impl ModuleKind {
    fn from_name(name: &str) -> Option<(Self, &'static str, u64)> {
        // (kind, config parameter, default budget)
        Some(match name {
            "zip" => (Self::Zip, "max_cd_entries_to_walk", 64),
            "rar" => (Self::Rar, "max_blocks_to_walk", 4096),
            "seven_zip" => (Self::SevenZip, "max_next_header_check_bytes", 1024 * 1024),
            "tar" => (Self::Tar, "max_entries_to_walk", 64),
            "gzip" => (Self::Stream("gzip"), "", 0),
            "bzip2" => (Self::Stream("bzip2"), "", 0),
            "xz" => (Self::Stream("xz"), "", 0),
            "zstd" => (Self::Stream("zstd"), "", 0),
            "lz4" => (Self::Stream("lz4"), "", 0),
            "tar_gz" => (
                Self::CompressedTar("tar.gz", "gzip"),
                "max_probe_bytes",
                4 * 1024 * 1024,
            ),
            "tar_bz2" => (
                Self::CompressedTar("tar.bz2", "bzip2"),
                "max_probe_bytes",
                4 * 1024 * 1024,
            ),
            "tar_xz" => (
                Self::CompressedTar("tar.xz", "xz"),
                "max_probe_bytes",
                4 * 1024 * 1024,
            ),
            "tar_zst" => (
                Self::CompressedTar("tar.zst", "zstd"),
                "max_probe_bytes",
                4 * 1024 * 1024,
            ),
            "tar_lz4" => (
                Self::CompressedTar("tar.lz4", "lz4"),
                "max_probe_bytes",
                4 * 1024 * 1024,
            ),
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
            Self::CompressedTar(format, _) => format,
        }
    }
}

#[derive(Clone)]
struct ModuleConfig {
    name: String,
    kind: ModuleKind,
    budget: u64,
}

/// Parsed analysis configuration, built once per engine and shared by calls.
#[pyclass(frozen)]
pub(crate) struct NativeAnalysisConfig {
    prepass_enabled: bool,
    head_bytes: usize,
    tail_bytes: usize,
    extractable_confidence: f64,
    modules: Vec<ModuleConfig>,
}

#[pymethods]
impl NativeAnalysisConfig {
    #[new]
    fn new(config: &Bound<'_, PyDict>) -> PyResult<Self> {
        let prepass = dict_item(config, "prepass")?;
        let (prepass_enabled, head_bytes, tail_bytes) = match prepass {
            Some(prepass) => (
                match prepass.get_item("enabled")? {
                    Some(value) => value.is_truthy()?,
                    None => true,
                },
                positive_int_or(&prepass, "head_bytes", DEFAULT_PREPASS_BYTES as u64)? as usize,
                positive_int_or(&prepass, "tail_bytes", DEFAULT_PREPASS_BYTES as u64)? as usize,
            ),
            None => (true, DEFAULT_PREPASS_BYTES, DEFAULT_PREPASS_BYTES),
        };
        let extractable_confidence = match dict_item(config, "thresholds")? {
            Some(thresholds) => match thresholds.get_item("extractable_confidence")? {
                Some(value) if !value.is_none() => value.extract::<f64>()?,
                _ => DEFAULT_EXTRACTABLE_CONFIDENCE,
            },
            None => DEFAULT_EXTRACTABLE_CONFIDENCE,
        };
        let mut modules: Vec<ModuleConfig> = Vec::new();
        if let Some(items) = config.get_item("modules")? {
            if let Ok(items) = items.cast::<PyList>() {
                for item in items.iter() {
                    let Ok(item) = item.cast::<PyDict>() else {
                        continue;
                    };
                    let enabled = match item.get_item("enabled")? {
                        Some(value) => value.is_truthy()?,
                        None => false,
                    };
                    let name = str_of(item, "name")?.trim().to_string();
                    if !enabled || name.is_empty() {
                        continue;
                    }
                    let Some((kind, parameter, default)) = ModuleKind::from_name(&name) else {
                        continue;
                    };
                    let budget = if parameter.is_empty() {
                        0
                    } else {
                        positive_int_or(item, parameter, default)?
                    };
                    let module = ModuleConfig { name, kind, budget };
                    // A repeated name keeps its first position and last settings.
                    match modules
                        .iter_mut()
                        .find(|existing| existing.name == module.name)
                    {
                        Some(existing) => *existing = module,
                        None => modules.push(module),
                    }
                }
            }
        }
        Ok(Self {
            prepass_enabled,
            head_bytes,
            tail_bytes,
            extractable_confidence,
            modules,
        })
    }

    #[getter]
    fn module_names(&self) -> Vec<String> {
        self.modules
            .iter()
            .map(|module| module.name.clone())
            .collect()
    }
}

fn strict_subrange(start: u64, end: Option<u64>, size: u64) -> bool {
    matches!(end, Some(end) if start < end && end <= size && (start > 0 || end < size))
}

struct Segment {
    start: u64,
    end: Option<u64>,
    confidence: f64,
    damage_flags: Vec<String>,
    evidence: Vec<String>,
}

impl Segment {
    fn new(
        start: u64,
        end: Option<u64>,
        confidence: f64,
        damage_flags: Vec<String>,
        evidence: Vec<String>,
    ) -> Self {
        Self {
            start,
            end,
            confidence,
            damage_flags,
            evidence,
        }
    }
}

// Keep typed observations native until the report is exported. External
// embedded facts already arrive as Python mappings and stay borrowed.
enum EvidenceDetails<'py> {
    Empty,
    Python(Bound<'py, PyDict>),
    Rar(Box<RarReportDetails>),
    SevenZip(Box<SevenZipReportDetails>),
}

impl<'py> From<Bound<'py, PyDict>> for EvidenceDetails<'py> {
    fn from(value: Bound<'py, PyDict>) -> Self {
        Self::Python(value)
    }
}

impl<'py> EvidenceDetails<'py> {
    fn to_python(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        match self {
            Self::Empty => Ok(PyDict::new(py)),
            Self::Python(value) => Ok(value.clone()),
            Self::Rar(value) => value.to_python(py),
            Self::SevenZip(value) => value.to_python(py),
        }
    }

    fn password_required(&self) -> PyResult<bool> {
        match self {
            Self::Rar(value) => Ok(value.raw.password_required.unwrap_or(false)),
            Self::SevenZip(value) => Ok(value.raw.password_required),
            Self::Python(value) => truthy(value, "password_required"),
            Self::Empty => Ok(false),
        }
    }

    fn embedded_anchor(&self) -> PyResult<bool> {
        match self {
            Self::Python(value) if str_of(value, "source")? == "embedded_scan" => {
                let kind = str_of(value, "candidate_kind")?;
                Ok(!kind.is_empty() && kind != "logical_archive")
            }
            _ => Ok(false),
        }
    }
}

struct Evidence<'py> {
    format: String,
    confidence: f64,
    status: &'static str,
    segments: Vec<Segment>,
    warnings: Vec<String>,
    details: EvidenceDetails<'py>,
}

impl<'py> Evidence<'py> {
    fn new(
        format: &str,
        confidence: f64,
        status: &'static str,
        segments: Vec<Segment>,
        details: impl Into<EvidenceDetails<'py>>,
    ) -> Self {
        Self {
            format: format.to_string(),
            confidence,
            status,
            segments,
            warnings: Vec::new(),
            details: details.into(),
        }
    }

    fn not_found(_py: Python<'py>, format: &str) -> Self {
        Self::new(format, 0.0, "not_found", Vec::new(), EvidenceDetails::Empty)
    }

    fn with_warnings(mut self, warnings: Vec<String>) -> Self {
        self.warnings = warnings;
        self
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

fn prepass_dicts<'py>(
    prepass: &Bound<'py, PyDict>,
    key: &str,
) -> PyResult<Vec<Bound<'py, PyDict>>> {
    let Some(value) = prepass.get_item(key)? else {
        return Ok(Vec::new());
    };
    if value.is_none() {
        return Ok(Vec::new());
    }
    value
        .try_iter()?
        .map(|item| item?.cast_into::<PyDict>().map_err(Into::into))
        .collect()
}

/// Probe access shared by single-file and multi-volume analysis.
struct ReportContext<'a, 'py> {
    py: Python<'py>,
    view: &'a AnalysisBinaryView,
    disk_starts: Option<&'a [u64]>,
    // Only a physical single file receives full compression-stream structure
    // validation; a logical multi-volume stream is header-validated.
    stream_path: Option<&'a str>,
    prepass: Bound<'py, PyDict>,
    hits: Arc<[SignatureHit]>,
    embedded: HashMap<String, Vec<Bound<'py, PyDict>>>,
    stream_structure: Option<Option<Bound<'py, PyDict>>>,
}

impl AnalysisBinaryView {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn analyze_report<'py>(
        &self,
        py: Python<'py>,
        config: &NativeAnalysisConfig,
        initial_prepass: Option<&Bound<'py, PyDict>>,
        signature_prepass: bool,
        format_structure: bool,
        disk_starts: Option<&[u64]>,
        stream_path: Option<&str>,
    ) -> PyResult<Py<PyDict>> {
        self.ensure_open()?;
        let (prepass, hits) = match initial_prepass {
            Some(prepass) if !prepass.is_empty() => {
                let hits = signature_hits_from_prepass(prepass)?;
                (prepass.copy()?, hits)
            }
            _ if (signature_prepass || format_structure) && config.prepass_enabled => {
                let data = py
                    .detach(|| {
                        signature_prepass_native(&self.reader, config.head_bytes, config.tail_bytes)
                    })
                    .map_err(reader_error_to_py)?;
                let hits = Arc::clone(&data.hits);
                (signature_prepass_to_python(py, data)?.into_bound(py), hits)
            }
            _ => (PyDict::new(py), Arc::from([])),
        };
        let mut embedded: HashMap<String, Vec<Bound<'py, PyDict>>> = HashMap::new();
        for item in prepass_dicts(&prepass, "embedded_candidates")? {
            embedded
                .entry(str_of(&item, "format")?)
                .or_default()
                .push(item);
        }
        let mut context = ReportContext {
            py,
            view: self,
            disk_starts,
            stream_path,
            prepass,
            hits,
            embedded,
            stream_structure: None,
        };
        let mut evidences = Vec::new();
        if format_structure {
            for module in &config.modules {
                evidences.push(match context.run_module(module) {
                    Ok(evidence) => evidence,
                    Err(error) => {
                        let message = error.value(py).str()?.to_string();
                        Evidence::new(
                            module.kind.format(),
                            0.0,
                            "error",
                            Vec::new(),
                            PyDict::new(py),
                        )
                        .with_warnings(vec![message])
                    }
                });
            }
        }
        let size = self.reader.len();
        let selected_in_module_order = evidences
            .iter()
            .enumerate()
            .filter(|(_, evidence)| {
                evidence.status == "extractable"
                    && evidence.confidence >= config.extractable_confidence
                    && !evidence.segments.is_empty()
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        // Stable descending order keeps module order for equal confidences.
        let mut order = (0..evidences.len()).collect::<Vec<_>>();
        order.sort_by(|left, right| {
            evidences[*right]
                .confidence
                .partial_cmp(&evidences[*left].confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let mut position = vec![0usize; evidences.len()];
        for (sorted_index, original) in order.iter().enumerate() {
            position[*original] = sorted_index;
        }
        let selected = selected_in_module_order
            .iter()
            .map(|index| position[*index])
            .collect::<Vec<_>>();
        // The first selected evidence with the highest confidence names the input format.
        let mut best_selected = None::<usize>;
        for index in &selected_in_module_order {
            if best_selected
                .is_none_or(|best| evidences[*index].confidence > evidences[best].confidence)
            {
                best_selected = Some(*index);
            }
        }
        let best_selected = best_selected.map(|index| position[index]);
        let mut slots = evidences.into_iter().map(Some).collect::<Vec<_>>();
        let sorted = order
            .iter()
            .map(|index| slots[*index].take().expect("evidence moved once"))
            .collect::<Vec<_>>();

        let plan = SegmentPlan::build(&sorted, &selected, size)?;
        let stats = self.reader.stats()?;
        let report = PyDict::new(py);
        report.set_item("size", size)?;
        report.set_item("prepass", &context.prepass)?;
        report.set_item("read_bytes", stats.read_bytes)?;
        report.set_item("cache_hits", stats.cache_hits)?;
        let py_evidences = PyList::empty(py);
        for evidence in &sorted {
            py_evidences.append(evidence_to_python(py, evidence)?)?;
        }
        report.set_item("evidences", py_evidences)?;
        report.set_item("selected", selected)?;
        report.set_item("best_selected", best_selected)?;
        report.set_item("extractable_segments", plan.extractable)?;
        report.set_item("password_segment", plan.password_segment)?;
        report.set_item("missing_volume_evidence", plan.missing_volume_evidence)?;
        Ok(report.unbind())
    }
}

impl<'a, 'py> ReportContext<'a, 'py> {
    fn run_module(&mut self, module: &ModuleConfig) -> PyResult<Evidence<'py>> {
        match module.kind {
            ModuleKind::Zip => self.zip_module(module.budget as usize),
            ModuleKind::Rar => self.rar_module(module.budget as usize),
            ModuleKind::SevenZip => self.seven_zip_module(module.budget),
            ModuleKind::Tar => self.tar_module(module.budget as usize),
            ModuleKind::Stream("lz4") => self.lz4_module(false, 0),
            ModuleKind::Stream(format) => self.stream_module(format),
            ModuleKind::CompressedTar("tar.lz4", "lz4") => self.lz4_module(true, module.budget),
            ModuleKind::CompressedTar(format, stream) => {
                self.compressed_tar_module(format, stream, module.budget as usize)
            }
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

    fn embedded(&self, format: &str, logical_only: bool) -> PyResult<Vec<Bound<'py, PyDict>>> {
        let mut items = Vec::new();
        for item in self.embedded.get(format).into_iter().flatten() {
            if !logical_only || str_of(item, "candidate_kind")? == "logical_archive" {
                items.push(item.clone());
            }
        }
        Ok(items)
    }

    fn preserve_multiple(&self) -> PyResult<bool> {
        Ok(str_of(&self.prepass, "source")? == "embedded_scan")
    }

    // ---- RAR ------------------------------------------------------------

    fn rar_module(&mut self, max_blocks: usize) -> PyResult<Evidence<'py>> {
        let py = self.py;
        let hits = self.hits(|kind| kind == ReportHitKind::Rar);
        let embedded = self.embedded("rar", true)?;
        if hits.is_empty() && embedded.is_empty() {
            return Ok(Evidence::not_found(py, "rar"));
        }
        let mut candidates = Vec::new();
        let mut exact_starts = HashSet::new();
        for item in &embedded {
            let start = u64_of(item, "offset")?;
            let end = opt_u64_of(item, "end_offset")?;
            let Some(end) = end else { continue };
            if str_of(item, "boundary_kind")? != "exact" || !truthy(item, "extractable")? {
                continue;
            }
            exact_starts.insert(start);
            let confidence = f64_of(item, "confidence")?;
            let validation = str_or(item, "validation", "complete_header_walk")?;
            let details = PyDict::new(py);
            details.set_item("source", "embedded_scan")?;
            details.set_item("candidate", item)?;
            details.set_item("boundary_kind", "exact")?;
            details.set_item("boundary_confidence", "high")?;
            details.set_item("integrity_confidence", "deferred")?;
            candidates.push(Evidence::new(
                "rar",
                confidence,
                "extractable",
                vec![Segment::new(
                    start,
                    Some(end),
                    confidence,
                    Vec::new(),
                    vec![format!("rar:{validation}")],
                )],
                details,
            ));
        }
        let mut starts = embedded
            .iter()
            .map(|item| u64_of(item, "offset"))
            .collect::<PyResult<Vec<_>>>()?;
        if starts.is_empty() {
            starts = hits.iter().map(|hit| hit.offset).collect::<Vec<_>>();
        }
        starts.sort_unstable();
        starts.dedup();
        for start in starts
            .into_iter()
            .filter(|start| !exact_starts.contains(start))
        {
            let native = py.detach(|| self.view.probe_rar_native(start, max_blocks))?;
            candidates.push(rar_from_native(native, start)?);
        }
        combine_candidates(py, "rar", candidates, self.preserve_multiple()?)
    }

    // ---- 7z -------------------------------------------------------------

    fn seven_zip_module(&mut self, max_next_header: u64) -> PyResult<Evidence<'py>> {
        let py = self.py;
        let embedded = self.embedded("7z", true)?;
        let mut exact = Vec::new();
        for item in embedded {
            if str_of(&item, "boundary_kind")? == "exact"
                && opt_u64_of(&item, "end_offset")?.is_some()
                && truthy(&item, "extractable")?
            {
                exact.push(item);
            }
        }
        if !exact.is_empty() {
            let candidates = exact
                .iter()
                .map(|item| seven_zip_from_embedded(py, item))
                .collect::<PyResult<Vec<_>>>()?;
            return combine_candidates(py, "7z", candidates, true);
        }
        let hits = self.hits(|kind| kind == ReportHitKind::SevenZip);
        if hits.is_empty() {
            return Ok(Evidence::not_found(py, "7z"));
        }
        let mut starts = hits.iter().map(|hit| hit.offset).collect::<Vec<_>>();
        starts.sort_unstable();
        starts.dedup();
        let mut candidates = Vec::new();
        for start in starts {
            let native = py.detach(|| self.view.probe_seven_zip_native(start, max_next_header))?;
            candidates.push(seven_zip_from_native(native, start)?);
        }
        combine_candidates(py, "7z", candidates, self.preserve_multiple()?)
    }

    // ---- TAR ------------------------------------------------------------

    fn tar_module(&mut self, max_entries: usize) -> PyResult<Evidence<'py>> {
        let py = self.py;
        let embedded = self.embedded("tar", true)?;
        if !embedded.is_empty() {
            let mut candidates = Vec::new();
            for item in &embedded {
                let start = u64_of(item, "offset")?;
                let end = opt_u64_of(item, "end_offset")?;
                let boundary_kind = required_item(item, "boundary_kind")?;
                let exact = end.is_some()
                    && boundary_kind.str()?.to_string() == "exact"
                    && required_item(item, "extractable")?.is_truthy()?;
                let confidence = f64_of(item, "confidence")?;
                let confidence = if exact {
                    confidence
                } else {
                    confidence.min(0.80)
                };
                let validation = str_or(item, "validation", "validated_structure")?;
                let details = PyDict::new(py);
                details.set_item("source", "embedded_scan")?;
                details.set_item("candidate", item)?;
                details.set_item("boundary_kind", boundary_kind)?;
                candidates.push(Evidence::new(
                    "tar",
                    confidence,
                    if exact { "extractable" } else { "damaged" },
                    vec![Segment::new(
                        start,
                        end,
                        confidence,
                        if exact {
                            Vec::new()
                        } else {
                            vec!["tar_boundary_unresolved".to_string()]
                        },
                        vec![format!("tar:{validation}")],
                    )],
                    details,
                ));
            }
            return combine_candidates(py, "tar", candidates, true);
        }
        let mut hit_starts = self
            .hits(|kind| kind == ReportHitKind::Tar)
            .iter()
            .map(|hit| hit.offset.saturating_sub(257))
            .collect::<Vec<_>>();
        hit_starts.sort_unstable();
        hit_starts.dedup();

        // A valid archive at offset zero owns its member headers. Treating
        // every member's ustar marker as another embedded archive would turn a
        // large archive into suffix-only extraction.
        let primary = self.tar_candidate(0, max_entries)?;
        let mut evidences = Vec::new();
        if let Some(primary) = primary {
            if primary.status == "extractable" {
                return Ok(primary);
            }
            evidences.push(primary);
        }
        let mut covered_until = 0u64;
        for start in hit_starts {
            if start == 0 || start < covered_until {
                continue;
            }
            let Some(candidate) = self.tar_candidate(start, max_entries)? else {
                continue;
            };
            let end = candidate.segments.first().and_then(|segment| segment.end);
            let extractable = candidate.status == "extractable";
            evidences.push(candidate);
            if let Some(end) = end {
                covered_until = covered_until.max(end);
            } else if extractable {
                // Without a proven end, later ustar hits may be members of
                // this archive and cannot be emitted independently.
                break;
            }
        }
        combine_candidates(py, "tar", evidences, self.preserve_multiple()?)
    }

    fn tar_observation(&self, start: u64, max_entries: usize) -> PyResult<Bound<'py, PyDict>> {
        let raw = self.view.walk_tar(self.py, start, max_entries)?;
        set_default(&raw, "archive_offset", start)?;
        let detected = if truthy(&raw, "plausible")? {
            ".tar"
        } else {
            ""
        };
        set_default(&raw, "detected_ext", detected)?;
        let error = str_of(&raw, "error")?;
        let mut damage_flags = str_list(&raw, "damage_flags")?;
        if !error.is_empty() && !TAR_BENIGN_ERRORS.contains(&error.as_str()) {
            damage_flags.push(error);
        }
        let integrity = match raw.get_item("stored_checksum")? {
            Some(stored) if stored.is_truthy()? => match raw.get_item("computed_checksum")? {
                Some(computed) if stored.eq(&computed)? => "high",
                _ => "low",
            },
            _ => "unknown",
        };
        raw.set_item("integrity_confidence", integrity)?;
        raw.set_item("damage_flags", sorted_unique(damage_flags))?;
        Ok(raw)
    }

    fn tar_candidate(&self, start: u64, max_entries: usize) -> PyResult<Option<Evidence<'py>>> {
        let result = self.tar_observation(start, max_entries)?;
        if truthy(&result, "plausible")? {
            let confidence = if truthy(&result, "end_zero_blocks")? {
                0.94
            } else if truthy(&result, "walk_complete")? {
                0.90
            } else {
                0.86
            };
            let segment = Segment::new(
                start,
                opt_u64_of(&result, "segment_end")?,
                confidence,
                read_fault_damage_flags(&result)?,
                str_list(&result, "evidence")?,
            );
            return Ok(Some(Evidence::new(
                "tar",
                confidence,
                "extractable",
                vec![segment],
                result.copy()?,
            )));
        }
        if truthy(&result, "magic_matched")? {
            let mut damage_flags = read_fault_damage_flags(&result)?;
            if damage_flags.is_empty() {
                damage_flags.push("tar_metadata_bad".to_string());
            }
            let evidence = non_empty_or(str_list(&result, "evidence")?, "tar:header");
            let details = result.copy()?;
            details.set_item("route_evidence_flags", damage_flags.clone())?;
            return Ok(Some(Evidence::new(
                "tar",
                0.72,
                "damaged",
                vec![Segment::new(start, None, 0.72, damage_flags, evidence)],
                details,
            )));
        }
        Ok(None)
    }

    // ---- ZIP ------------------------------------------------------------

    fn zip_module(&mut self, max_entries: usize) -> PyResult<Evidence<'py>> {
        let py = self.py;
        let hits = self.hits(|kind| {
            matches!(
                kind,
                ReportHitKind::ZipLocal | ReportHitKind::ZipEocd | ReportHitKind::ZipOther
            )
        });
        let embedded = self.embedded("zip", false)?;
        if hits.is_empty() && embedded.is_empty() {
            return Ok(Evidence::not_found(py, "zip"));
        }
        let mut logical = Vec::new();
        for item in &embedded {
            if required_item(item, "candidate_kind")?.str()?.to_string() == "logical_archive" {
                logical.push(zip_from_embedded(py, item)?);
            }
        }
        if !logical.is_empty() {
            return combine_candidates(py, "zip", logical, true);
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
            let native = self.zip_eocd_observation(eocd_offset, max_entries)?;
            if native.is_empty()
                || !(truthy(&native, "magic_matched")? || truthy(&native, "plausible")?)
            {
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
            if !str_of(item, "validation")?.contains("local_header") {
                continue;
            }
            let start = u64_of(item, "offset")?;
            if known_starts.contains(&start) {
                continue;
            }
            let details = PyDict::new(py);
            details.set_item("boundary_confidence", "low")?;
            evidences.push(Evidence::new(
                "zip",
                0.70,
                "damaged",
                vec![Segment::new(
                    start,
                    None,
                    0.70,
                    vec!["central_directory_unavailable".to_string()],
                    vec!["zip:validated_local_header".to_string()],
                )],
                details,
            ));
        }
        combine_candidates(py, "zip", evidences, self.preserve_multiple()?)
    }

    fn zip_eocd_observation(
        &self,
        requested: u64,
        max_entries: usize,
    ) -> PyResult<Bound<'py, PyDict>> {
        let py = self.py;
        let candidate = self
            .view
            .locate_zip_eocd_native(py, Some(requested))?
            .into_bound(py);
        if !truthy(&candidate, "eocd_candidate_found")? {
            let raw = PyDict::new(py);
            raw.set_item("plausible", false)?;
            raw.set_item("magic_matched", false)?;
            raw.set_item("error", "eocd_not_found")?;
            raw.update(candidate.as_mapping())?;
            zip_observation(&raw)?;
            return Ok(raw);
        }
        let eocd_offset = u64_of(&candidate, "eocd_candidate_offset")?;
        let raw = self
            .view
            .probe_zip_with_disk_starts(py, eocd_offset, max_entries.min(256), self.disk_starts)?
            .into_bound(py);
        raw.update(candidate.as_mapping())?;
        set_default(
            &raw,
            "comment_length",
            i64_of(&candidate, "eocd_candidate_comment_length")?,
        )?;
        set_default(
            &raw,
            "declared_central_directory_offset",
            i64_of(&candidate, "eocd_candidate_cd_offset")?,
        )?;
        set_default(
            &raw,
            "declared_central_directory_size",
            i64_of(&candidate, "eocd_candidate_cd_size")?,
        )?;
        set_default(
            &raw,
            "declared_total_entries",
            i64_of(&raw, "total_entries")?,
        )?;
        let size = self.view.reader.len() as i64;
        let segment_end = match i64_of(&raw, "segment_end")? {
            0 => size,
            value => value,
        };
        set_default(
            &raw,
            "trailing_bytes_after_eocd",
            (size - segment_end).max(0),
        )?;
        let physical_cd = i64_of(&raw, "central_directory_offset")?;
        let declared_cd = i64_of(&raw, "declared_central_directory_offset")?;
        set_default(&raw, "physical_central_directory_offset", physical_cd)?;
        set_default(&raw, "inferred_central_directory_offset", physical_cd)?;
        set_default(
            &raw,
            "inferred_central_directory_size",
            i64_of(&raw, "central_directory_size")?,
        )?;
        set_default(
            &raw,
            "central_directory_offset_delta",
            physical_cd - declared_cd,
        )?;
        set_default(&raw, "central_directory_size_delta", 0)?;
        set_default(&raw, "entry_count_delta", 0)?;
        let links = i64_of(&raw, "local_header_links_checked")?;
        let links_ok = truthy(&raw, "local_header_links_ok")?;
        set_default(
            &raw,
            "local_header_links_ok_count",
            if links_ok { links } else { 0 },
        )?;
        set_default(
            &raw,
            "local_header_links_error_count",
            if links_ok { 0 } else { 1 },
        )?;
        zip_observation(&raw)?;
        Ok(raw)
    }

    // ---- Compression streams -------------------------------------------

    fn stream_module(&mut self, format: &'static str) -> PyResult<Evidence<'py>> {
        let py = self.py;
        let embedded = self.embedded(format, true)?;
        if !embedded.is_empty() {
            let mut complete = true;
            let mut confidence = f64::NEG_INFINITY;
            for item in &embedded {
                complete &= opt_u64_of(item, "end_offset")?.is_some()
                    && required_item(item, "boundary_kind")?.str()?.to_string() == "exact"
                    && required_item(item, "extractable")?.is_truthy()?;
                confidence = confidence.max(f64_of(item, "confidence")?);
            }
            let confidence = confidence.min(0.99);
            let effective = if complete {
                confidence
            } else {
                confidence.min(0.80)
            };
            let mut segments = Vec::new();
            for item in &embedded {
                let end = opt_u64_of(item, "end_offset")?;
                let validation = str_or(item, "validation", "validated_header")?;
                segments.push(Segment::new(
                    u64_of(item, "offset")?,
                    end,
                    effective,
                    if end.is_some() {
                        Vec::new()
                    } else {
                        vec!["stream_boundary_inferred".to_string()]
                    },
                    vec![format!("{format}:{validation}")],
                ));
            }
            let details = PyDict::new(py);
            details.set_item("source", "embedded_scan")?;
            details.set_item("candidates", PyList::new(py, &embedded)?)?;
            details.set_item("boundary_confidence", if complete { "high" } else { "low" })?;
            return Ok(Evidence::new(
                format,
                effective,
                if complete { "extractable" } else { "damaged" },
                segments,
                details,
            ));
        }
        let result = self.stream_observation(format)?;
        if !truthy(&result, "magic_matched")? {
            return Ok(Evidence::new(format, 0.0, "not_found", Vec::new(), result));
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
        let evidence = str_list(&result, "evidence")?;
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
                0.97,
                "extractable",
                vec![Segment::new(0, Some(end), 0.97, Vec::new(), evidence)],
                result,
            ));
        }
        if plausible {
            if !structure_complete {
                damage_flags.push("structure_validation_incomplete".to_string());
                damage_flags = sorted_unique(damage_flags);
            }
            let confidence = if damage_flags.is_empty() { 0.78 } else { 0.68 };
            let end = opt_u64_of(&result, "segment_end")?;
            let details = result.copy()?;
            details.set_item("route_evidence_flags", damage_flags.clone())?;
            return Ok(Evidence::new(
                format,
                confidence,
                "damaged",
                vec![Segment::new(0, end, confidence, damage_flags, evidence)],
                details,
            ));
        }
        if damage_flags.is_empty() {
            damage_flags.push("stream_unverified".to_string());
        }
        let details = result.copy()?;
        details.set_item("route_evidence_flags", damage_flags.clone())?;
        Ok(Evidence::new(
            format,
            0.35,
            "weak",
            vec![Segment::new(0, None, 0.35, damage_flags, evidence)],
            details,
        ))
    }

    fn stream_observation(&mut self, format: &str) -> PyResult<Bound<'py, PyDict>> {
        let py = self.py;
        let raw = match self.stream_path {
            Some(path) => match self.full_stream_structure(path)? {
                Some(structure) => structure.copy()?,
                None => PyDict::new(py),
            },
            None => {
                let raw = self.view.probe_compression(py, format)?;
                set_default(&raw, "validation_scope", "header_only")?;
                set_default(&raw, "structure_status", "incomplete")?;
                set_default(&raw, "structure_validation_complete", false)?;
                set_default(&raw, "boundary_exact", false)?;
                set_default(&raw, "integrity_status", "deferred")?;
                set_default(&raw, "integrity_validation_complete", false)?;
                set_default(&raw, "file_size", self.view.reader.len())?;
                raw
            }
        };
        stream_observation(py, raw, format)
    }

    /// Full-stream validation decodes the whole file, so it runs at most once
    /// per analysis and once per physical file generation across analyses.
    fn full_stream_structure(&mut self, path: &str) -> PyResult<Option<Bound<'py, PyDict>>> {
        if let Some(structure) = &self.stream_structure {
            return Ok(structure.clone());
        }
        let structure = if stream_family(&self.view.reader.read_at(0, 32).unwrap_or_default()) {
            let identity = self.view.reader.file_identity().ok();
            Some(match identity {
                Some(identity) => stream_structure_cached(self.py, identity, path)?,
                None => {
                    crate::analysis_native::inspect_compression_stream_structure(self.py, path)?
                        .into_bound(self.py)
                }
            })
        } else {
            // No compression family can match; the requested-format mismatch
            // projection never reads the structure result.
            None
        };
        self.stream_structure = Some(structure.clone());
        Ok(structure)
    }

    fn compressed_tar_module(
        &mut self,
        format: &str,
        stream: &str,
        max_probe_bytes: usize,
    ) -> PyResult<Evidence<'py>> {
        let py = self.py;
        let result = self
            .view
            .probe_compressed_tar(py, stream, max_probe_bytes)?
            .into_bound(py);
        if !truthy(&result, "magic_matched")? || !truthy(&result, "tar_plausible")? {
            return Ok(Evidence::new(format, 0.0, "not_found", Vec::new(), result));
        }
        let confidence = if truthy(&result, "plausible")? {
            0.93
        } else {
            0.75
        };
        let mut evidence = str_list(&result, "evidence")?;
        evidence.push("tar:inner_header".to_string());
        let details = result.copy()?;
        details.set_item("inner_format", "tar")?;
        Ok(Evidence::new(
            format,
            confidence,
            "extractable",
            vec![Segment::new(
                0,
                Some(self.view.reader.len()),
                confidence,
                Vec::new(),
                evidence,
            )],
            details,
        ))
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

struct RarReportDetails {
    raw: RarObservation,
    damage_flags: Vec<String>,
    boundary: &'static str,
    integrity: &'static str,
}

impl RarReportDetails {
    fn to_python<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let raw = &self.raw;
        let result = raw.to_python(py)?.into_bound(py);
        result.set_item("format", if raw.magic_matched { "rar" } else { "" })?;
        result.set_item("detected_ext", if raw.magic_matched { ".rar" } else { "" })?;
        result.set_item(
            "validated_prefix",
            raw.second_block_checked && raw.second_block_ok,
        )?;
        result.set_item(
            "confidence",
            if raw.header_crc_ok { "strong" } else { "none" },
        )?;
        result.set_item("boundary_confidence", self.boundary)?;
        result.set_item("integrity_confidence", self.integrity)?;
        result.set_item("damage_flags", &self.damage_flags)?;
        Ok(result)
    }
}

fn rar_from_native<'py>(mut raw: RarObservation, start: u64) -> PyResult<Evidence<'py>> {
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
    if !error.is_empty() && !RAR_WALK_LIMIT_ERRORS.contains(&error) {
        damage_flags.push(error.into());
    }
    if raw.blocks_checked > 0 && RAR_TRUNCATION_ERRORS.contains(&error) {
        damage_flags.push("probably_truncated".into());
    }
    damage_flags = sorted_unique(damage_flags);
    let boundary = if raw.end_block_found {
        "high"
    } else if raw.header_encrypted == Some(true) {
        "none"
    } else if !error.is_empty() {
        "low"
    } else if raw.second_block_checked && raw.second_block_ok {
        "medium"
    } else {
        "unknown"
    };
    let integrity = if raw.header_crc_ok {
        "high"
    } else if raw.magic_matched {
        "low"
    } else {
        "unknown"
    };
    if !raw.magic_matched {
        return Ok(Evidence::new(
            "rar",
            0.0,
            "not_found",
            Vec::new(),
            EvidenceDetails::Rar(Box::new(RarReportDetails {
                raw,
                damage_flags,
                boundary,
                integrity,
            })),
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
    let (status, confidence, end) = if raw.strong_accept && segment_end.is_some() {
        ("extractable", 0.97, segment_end)
    } else if taxonomy == "probably_truncated" {
        ("damaged", 0.82, None)
    } else if taxonomy == "valid_encrypted_but_unwalkable" {
        ("damaged", 0.72, None)
    } else if raw.plausible {
        ("damaged", 0.65, None)
    } else {
        ("weak", 0.35, None)
    };
    let mut segment_flags = damage_flags.clone();
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
    let evidence = non_empty_or(
        raw.evidence.iter().map(|s| s.to_string()).collect(),
        "rar:signature",
    );
    let warnings = if status == "extractable" {
        Vec::new()
    } else {
        vec![match taxonomy {
            "probably_truncated" => "rar block chain is incomplete; archive is probably truncated",
            "valid_encrypted_but_unwalkable" => {
                "rar header is encrypted; password is required before exact boundary resolution"
            }
            _ => "rar archive structure does not prove an exact end for this segment",
        }
        .to_string()]
    };
    Ok(Evidence::new(
        "rar",
        confidence,
        status,
        vec![Segment::new(
            start,
            end,
            confidence,
            segment_flags,
            evidence,
        )],
        EvidenceDetails::Rar(Box::new(RarReportDetails {
            raw,
            damage_flags,
            boundary,
            integrity,
        })),
    )
    .with_warnings(warnings))
}

fn seven_zip_from_embedded<'py>(
    py: Python<'py>,
    item: &Bound<'py, PyDict>,
) -> PyResult<Evidence<'py>> {
    let start = u64_of(item, "offset")?;
    let end = required_item(item, "end_offset")?.extract::<u64>()?;
    let confidence = f64_of(item, "confidence")?;
    let validation = str_or(item, "validation", "start_header_crc_and_declared_end")?;
    let details = PyDict::new(py);
    details.set_item("source", "embedded_scan")?;
    details.set_item("validation", &validation)?;
    details.set_item("candidate_kind", "logical_archive")?;
    details.set_item("boundary_kind", "exact")?;
    details.set_item("boundary_confidence", "high")?;
    details.set_item("integrity_confidence", "deferred")?;
    Ok(Evidence::new(
        "7z",
        confidence,
        "extractable",
        vec![Segment::new(
            start,
            Some(end),
            confidence,
            Vec::new(),
            vec![
                format!("7z:{validation}"),
                "embedded_scan:exact_boundary".to_string(),
            ],
        )],
        details,
    ))
}

struct SevenZipReportDetails {
    raw: SevenZipObservation,
    damage_flags: Vec<String>,
    boundary: &'static str,
    integrity: &'static str,
}

impl SevenZipReportDetails {
    fn to_python<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let raw = &self.raw;
        let result = raw.to_python(py)?.into_bound(py);
        result.set_item("detected_ext", if raw.magic_matched { ".7z" } else { "" })?;
        result.set_item(
            "next_header_semantic_ok",
            raw.next_header_crc_ok && raw.next_header_nid_valid,
        )?;
        result.set_item("confidence", if raw.plausible { "strong" } else { "none" })?;
        result.set_item("boundary_confidence", self.boundary)?;
        result.set_item("integrity_confidence", self.integrity)?;
        result.set_item("damage_flags", &self.damage_flags)?;
        Ok(result)
    }
}

fn seven_zip_from_native<'py>(mut raw: SevenZipObservation, start: u64) -> PyResult<Evidence<'py>> {
    let mut damage_flags = Vec::new();
    if let Some((fault, legacy)) = &raw.read_fault {
        raw.error = legacy;
        damage_flags.extend(native_read_fault_flags(fault));
    }
    if raw.read_fault.is_none() && !raw.error.is_empty() {
        damage_flags.push(raw.error.into());
    }
    let detail_flags = damage_flags;
    let mut damage_flags = detail_flags.clone();
    append_native_field_flag(&mut damage_flags, raw.read_fault.as_ref());
    if !raw.error.is_empty() {
        damage_flags.push(raw.error.into());
    }
    let unreliable = SEVEN_ZIP_BOUNDARY_ERRORS.contains(&raw.error);
    let mut boundary = if unreliable {
        "none"
    } else if raw.segment_end != 0 {
        if raw.strong_accept {
            "high"
        } else {
            "medium"
        }
    } else {
        "unknown"
    };
    let mut integrity = if raw.next_header_crc_checked {
        if raw.next_header_crc_ok {
            "high"
        } else {
            "low"
        }
    } else {
        "unknown"
    };
    if unreliable {
        damage_flags.push("boundary_unreliable".into());
    } else if raw.next_header_crc_checked && !raw.next_header_crc_ok {
        damage_flags.push("directory_integrity_bad_or_unknown".into());
        boundary = "medium";
        integrity = "low";
    }
    let details = SevenZipReportDetails {
        raw,
        damage_flags: detail_flags,
        boundary,
        integrity,
    };
    let raw = &details.raw;
    if !raw.magic_matched {
        return Ok(Evidence::new(
            "7z",
            0.0,
            "not_found",
            Vec::new(),
            EvidenceDetails::SevenZip(Box::new(details)),
        ));
    }
    let (status, confidence) = if raw.strong_accept {
        ("extractable", 0.97)
    } else if raw.plausible {
        ("damaged", 0.65)
    } else {
        ("weak", 0.35)
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
    let evidence = non_empty_or(
        raw.evidence.iter().map(|s| s.to_string()).collect(),
        "7z:signature",
    );
    let warnings = if end.is_some_and(|end| end != 0) {
        Vec::new()
    } else {
        vec!["7z archive structure does not prove an exact end for this segment".into()]
    };
    Ok(Evidence::new(
        "7z",
        confidence,
        status,
        vec![Segment::new(start, end, confidence, damage_flags, evidence)],
        EvidenceDetails::SevenZip(Box::new(details)),
    )
    .with_warnings(warnings))
}

fn zip_observation(raw: &Bound<'_, PyDict>) -> PyResult<()> {
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

fn zip_from_embedded<'py>(py: Python<'py>, item: &Bound<'py, PyDict>) -> PyResult<Evidence<'py>> {
    let start = u64_of(item, "offset")?;
    let end = opt_u64_of(item, "end_offset")?;
    let confidence = f64_of(item, "confidence")?;
    let validation = str_or(item, "validation", "validated_structure")?;
    let boundary_kind = required_item(item, "boundary_kind")?.str()?.to_string();
    let bounded_end = end.filter(|end| *end > start);
    let extractable = boundary_kind == "exact"
        && required_item(item, "extractable")?.is_truthy()?
        && bounded_end.is_some();
    let exact = boundary_kind == "exact";
    let details = PyDict::new(py);
    details.set_item("source", "embedded_scan")?;
    details.set_item("validation", &validation)?;
    details.set_item("archive_offset", start)?;
    if let Some(offset) = item.get_item("eocd_offset")? {
        details.set_item("eocd_offset", offset)?;
    }
    details.set_item("candidate_kind", str_of(item, "candidate_kind")?)?;
    details.set_item("boundary_kind", &boundary_kind)?;
    details.set_item(
        "boundary_confidence",
        if exact { "high" } else { "unresolved" },
    )?;
    details.set_item(
        "integrity_confidence",
        if exact { "deferred" } else { "unknown" },
    )?;
    Ok(Evidence::new(
        "zip",
        confidence,
        if confidence >= 0.85 && extractable {
            "extractable"
        } else {
            "damaged"
        },
        vec![Segment::new(
            start,
            bounded_end,
            confidence,
            Vec::new(),
            vec![
                format!("zip:{validation}"),
                "embedded_scan:validated_candidate".to_string(),
            ],
        )],
        details,
    ))
}

fn zip_from_native<'py>(
    native: Bound<'py, PyDict>,
    hits: &[ReportSignatureHit],
    view_size: u64,
) -> PyResult<Evidence<'py>> {
    let magic_matched = truthy(&native, "magic_matched")?;
    if !magic_matched && hits.is_empty() {
        return Ok(Evidence::new("zip", 0.0, "not_found", Vec::new(), native));
    }
    let archive_offset = u64_of(&native, "archive_offset")?;
    let eocd_offset = u64_of(&native, "eocd_offset")?;
    let comment_length = u64_of(&native, "comment_length")?;
    let end_offset = (eocd_offset != 0).then(|| eocd_offset + 22 + comment_length);
    let mut evidence = str_list(&native, "evidence")?;
    if truthy(&native, "central_directory_present")? {
        evidence.push("zip:central_directory".to_string());
    }
    if truthy(&native, "central_directory_walk_ok")? {
        evidence.push("zip:central_directory_walk".to_string());
    }
    if truthy(&native, "local_header_links_ok")? {
        evidence.push("zip:local_header_links".to_string());
    }
    let plausible = truthy(&native, "plausible")?;
    let walk_ok =
        truthy(&native, "central_directory_walk_ok")? && truthy(&native, "local_header_links_ok")?;
    let (status, mut confidence): (&str, f64) = if plausible && walk_ok {
        ("extractable", 0.99)
    } else if plausible {
        ("damaged", 0.65)
    } else {
        ("weak", if hits.is_empty() { 0.0 } else { 0.35 })
    };
    let mut damage_flags = read_fault_damage_flags(&native)?;
    let error = str_of(&native, "error")?;
    if !error.is_empty() {
        damage_flags.push(error);
    }
    let crc_warning = str_of(&native, "content_integrity_warning")?;
    if !crc_warning.is_empty() {
        damage_flags.push("content_integrity_bad_or_unknown".to_string());
        native.set_item("integrity_confidence", "low")?;
        native.set_item("content_damage_reason", &crc_warning)?;
        confidence = confidence.min(0.90);
    } else {
        set_default(
            &native,
            "integrity_confidence",
            if plausible { "medium" } else { "unknown" },
        )?;
    }
    set_default(
        &native,
        "boundary_confidence",
        if plausible && walk_ok { "high" } else { "low" },
    )?;
    let segments = if confidence > 0.0 {
        if evidence.is_empty() {
            evidence.push(
                if magic_matched {
                    "zip:eocd"
                } else {
                    "zip:signature"
                }
                .to_string(),
            );
        }
        vec![Segment::new(
            archive_offset,
            end_offset.map(|end| end.min(view_size)),
            confidence,
            damage_flags,
            evidence,
        )]
    } else {
        Vec::new()
    };
    Ok(Evidence::new("zip", confidence, status, segments, native))
}

fn zip_local_header_recovery<'py>(
    native: &Bound<'py, PyDict>,
    hits: &[ReportSignatureHit],
    earliest_local: &mut Option<Option<u64>>,
) -> PyResult<Option<Evidence<'py>>> {
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
    let details = native.copy()?;
    details.set_item("boundary_confidence", "low")?;
    details.set_item("integrity_confidence", "unknown")?;
    details.set_item("directory_confidence", "low")?;
    Ok(Some(
        Evidence::new(
            "zip",
            0.70,
            "damaged",
            vec![Segment::new(
                start,
                None,
                0.70,
                vec![
                    "central_directory_unreliable".to_string(),
                    "local_header_recovery".to_string(),
                ],
                vec!["zip:local_header".to_string()],
            )],
            details,
        )
        .with_warnings(vec![
            "zip central directory is damaged; recovered candidate from local headers".to_string(),
        ]),
    ))
}

fn stream_family(head: &[u8]) -> bool {
    head.starts_with(b"\x1f\x8b")
        || head.starts_with(BZIP2)
        || head.starts_with(XZ)
        || head.starts_with(ZSTD)
        || crate::formats::lz4::leading(head)
}

fn stream_observation<'py>(
    py: Python<'py>,
    raw: Bound<'py, PyDict>,
    requested: &str,
) -> PyResult<Bound<'py, PyDict>> {
    let actual = str_of(&raw, "format")?;
    let raw = if !requested.is_empty() && actual != requested {
        let replaced = PyDict::new(py);
        replaced.set_item("format", requested)?;
        replaced.set_item("actual_format", actual)?;
        replaced.set_item("magic_matched", false)?;
        replaced.set_item("plausible", false)?;
        replaced.set_item("structure_status", "invalid")?;
        replaced.set_item("structure_validation_complete", false)?;
        replaced.set_item("integrity_status", "failed")?;
        replaced.set_item("integrity_validation_complete", true)?;
        replaced.set_item("boundary_exact", false)?;
        replaced.set_item("error", format!("{requested}_magic_not_found"))?;
        replaced.set_item("damage_flags", PyList::empty(py))?;
        replaced.set_item("evidence", PyList::empty(py))?;
        replaced
    } else {
        raw
    };
    let structure_complete = truthy(&raw, "structure_validation_complete")?;
    let integrity_status = str_or(&raw, "integrity_status", "deferred")?;
    set_default(
        &raw,
        "structure_status",
        if structure_complete {
            "complete"
        } else {
            "incomplete"
        },
    )?;
    set_default(&raw, "structure_validation_complete", structure_complete)?;
    set_default(&raw, "boundary_exact", structure_complete)?;
    set_default(&raw, "integrity_status", &integrity_status)?;
    set_default(
        &raw,
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
    if !raw.contains("segment_end")? {
        match trailing {
            Some(trailing) if structure_complete && file_size >= trailing => {
                raw.set_item("segment_end", file_size - trailing)?
            }
            _ => raw.set_item("segment_end", py.None())?,
        }
    }
    raw.set_item("boundary_confidence", boundary)?;
    raw.set_item("integrity_confidence", integrity)?;
    set_default(&raw, "damage_flags", damage_flags)?;
    Ok(raw)
}

fn combine_candidates<'py>(
    py: Python<'py>,
    format: &str,
    candidates: Vec<Evidence<'py>>,
    preserve_multiple: bool,
) -> PyResult<Evidence<'py>> {
    let mut usable = candidates
        .into_iter()
        .filter(|item| item.confidence > 0.0 || !item.segments.is_empty())
        .collect::<Vec<_>>();
    if usable.is_empty() {
        return Ok(Evidence::not_found(py, format));
    }
    if usable
        .iter()
        .any(|item| item.status == "damaged" || item.status == "extractable")
    {
        usable.retain(|item| item.status == "damaged" || item.status == "extractable");
    }
    // The first maximal candidate wins, matching a stable max.
    let mut best = 0usize;
    for (index, item) in usable.iter().enumerate().skip(1) {
        let current = &usable[best];
        let rank = status_rank(item.status);
        let best_rank = status_rank(current.status);
        if rank > best_rank || (rank == best_rank && item.confidence > current.confidence) {
            best = index;
        }
    }
    if !preserve_multiple {
        return Ok(usable.swap_remove(best));
    }
    let mut seen = HashSet::new();
    let mut segments = Vec::new();
    let mut warnings = Vec::new();
    let candidate_details = PyList::empty(py);
    let mut best_details = None;
    for (index, item) in usable.iter().enumerate() {
        let projected = item.details.to_python(py)?;
        if index == best {
            best_details = Some(projected.clone());
        }
        candidate_details.append(projected)?;
        for warning in &item.warnings {
            if !warnings.contains(warning) {
                warnings.push(warning.clone());
            }
        }
    }
    let details = best_details
        .expect("best candidate was projected once")
        .copy()?;
    details.set_item("candidate_count", usable.len())?;
    details.set_item("candidate_details", candidate_details)?;
    let (confidence, status) = (usable[best].confidence, usable[best].status);
    for item in usable {
        for segment in item.segments {
            // Every candidate segment carries the primary role.
            if seen.insert((segment.start, segment.end)) {
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
        confidence,
        status,
        segments,
        warnings,
        details: details.into(),
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
    /// Order extractable carved segments, prefer specific container formats,
    /// and drop inner segments already covered by a whole-file composite.
    fn build(evidences: &[Evidence<'_>], selected: &[usize], size: u64) -> PyResult<Self> {
        let mut by_confidence = selected.to_vec();
        by_confidence.sort_by(|left, right| {
            evidences[*right]
                .confidence
                .partial_cmp(&evidences[*left].confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let mut candidates = Vec::new();
        for evidence_index in by_confidence {
            let evidence = &evidences[evidence_index];
            if evidence.details.embedded_anchor()? {
                continue;
            }
            for (segment_index, segment) in evidence.segments.iter().enumerate() {
                if !strict_subrange(segment.start, segment.end, size) {
                    continue;
                }
                candidates.push((evidence_index, segment_index, candidates.len()));
            }
        }
        candidates.sort_by(|left, right| {
            let left_segment = &evidences[left.0].segments[left.1];
            let right_segment = &evidences[right.0].segments[right.1];
            left_segment
                .start
                .cmp(&right_segment.start)
                .then_with(|| evidences[left.0].format.cmp(&evidences[right.0].format))
                .then_with(|| left.2.cmp(&right.2))
        });
        let ranges = candidates
            .iter()
            .map(|(evidence, segment, _)| {
                let segment = &evidences[*evidence].segments[*segment];
                (
                    segment.start,
                    segment.end,
                    evidences[*evidence].format.as_str(),
                )
            })
            .collect::<HashSet<_>>();
        candidates.retain(|(evidence, segment, _)| {
            let format = evidences[*evidence].format.as_str();
            let segment = &evidences[*evidence].segments[*segment];
            !STREAM_CONTAINERS.iter().any(|(stream, container)| {
                *stream == format && ranges.contains(&(segment.start, segment.end, *container))
            })
        });
        let composites = selected
            .iter()
            .filter_map(|index| {
                let evidence = &evidences[*index];
                let inner = COMPOSITE_INNER_FORMATS
                    .iter()
                    .find(|(format, _)| *format == evidence.format)?
                    .1;
                Some(
                    evidence
                        .segments
                        .iter()
                        .filter(|segment| {
                            segment.start == 0 && segment.end.is_some_and(|end| end >= size)
                        })
                        .map(move |segment| (evidence.confidence, segment.end.unwrap_or(0), inner)),
                )
            })
            .flatten()
            .collect::<Vec<_>>();
        candidates.retain(|(evidence, segment, _)| {
            let evidence = &evidences[*evidence];
            let segment = &evidence.segments[*segment];
            !composites.iter().any(|(confidence, end, inner)| {
                inner.contains(&evidence.format.as_str())
                    && evidence.confidence < *confidence
                    && segment.end.is_some_and(|segment_end| segment_end <= *end)
            })
        });

        let mut password_segment = None::<(usize, usize)>;
        for (evidence_index, evidence) in evidences.iter().enumerate() {
            if !evidence.details.password_required()? {
                continue;
            }
            for (segment_index, segment) in evidence.segments.iter().enumerate() {
                if segment.start == 0 {
                    continue;
                }
                let better = match password_segment {
                    None => true,
                    Some((best_evidence, best_segment)) => {
                        let best = &evidences[best_evidence];
                        evidence.confidence > best.confidence
                            || (evidence.confidence == best.confidence
                                && segment.start < best.segments[best_segment].start)
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
                EvidenceDetails::SevenZip(details) if details.raw.start_header_crc_ok => {
                    let raw = &details.raw;
                    raw.archive_offset
                        .saturating_add(32)
                        .saturating_add(raw.next_header_offset)
                        .saturating_add(raw.next_header_size)
                }
                EvidenceDetails::Python(details) if truthy(details, "start_header_crc_ok")? => {
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
            extractable: candidates
                .into_iter()
                .map(|(evidence, segment, _)| (evidence, segment))
                .collect(),
            password_segment,
            missing_volume_evidence,
        })
    }
}

fn evidence_to_python<'py>(
    py: Python<'py>,
    evidence: &Evidence<'py>,
) -> PyResult<Bound<'py, PyTuple>> {
    let segments = PyList::empty(py);
    for segment in &evidence.segments {
        segments.append((
            segment.start,
            segment.end,
            segment.confidence,
            segment.damage_flags.clone(),
            segment.evidence.clone(),
        ))?;
    }
    PyTuple::new(
        py,
        [
            evidence.format.clone().into_pyobject(py)?.into_any(),
            evidence.confidence.into_pyobject(py)?.into_any(),
            evidence.status.into_pyobject(py)?.into_any(),
            segments.into_any(),
            evidence.warnings.clone().into_pyobject(py)?.into_any(),
            evidence.details.to_python(py)?.into_any(),
        ],
    )
}

/// Trailing bytes after the last stream member. A truncated stream reports the
/// field as unavailable, which leaves the boundary unproven.
fn trailing_bytes(dict: &Bound<'_, PyDict>) -> PyResult<Option<i64>> {
    match dict.get_item("archive.trailing_data")? {
        None => Ok(Some(0)),
        Some(value) if value.is_none() => Ok(Some(0)),
        Some(value) => Ok(value.extract::<i64>().ok()),
    }
}

fn read_fault_damage_flags(native: &Bound<'_, PyDict>) -> PyResult<Vec<String>> {
    let flags = str_list(native, "damage_flags")?;
    let Some(fault) = native.get_item("read_error")? else {
        return Ok(flags);
    };
    let Ok(fault) = fault.cast::<PyDict>() else {
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
#[pyfunction]
pub(crate) fn confirm_format_identity(py: Python<'_>, path: &str, format: &str) -> PyResult<bool> {
    Ok(py.detach(|| confirm_format_identity_native(path, format)))
}

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
            identity.plausible
                && identity.name_nonempty
                && identity.numeric_fields_valid
                && identity.typeflag_valid
                && identity.payload_in_range
                && identity.stored_checksum == identity.computed_checksum
                && identity.error.is_empty()
        }
        "gzip" | "bzip2" | "xz" | "zstd" | "lz4" => {
            crate::analysis_native::confirm_compression_format_identity_native(path, format)
        }
        _ => false,
    }
}

// ---- Full-stream structure cache -----------------------------------------

type StreamStructureSlot = OnceLock<PyResult<Py<PyDict>>>;
type StreamStructureEntry = (FileIdentity, Arc<StreamStructureSlot>);

fn stream_structure_cache() -> &'static Mutex<VecDeque<StreamStructureEntry>> {
    static CACHE: OnceLock<Mutex<VecDeque<StreamStructureEntry>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(VecDeque::new()))
}

fn stream_structure_cached<'py>(
    py: Python<'py>,
    identity: FileIdentity,
    path: &str,
) -> PyResult<Bound<'py, PyDict>> {
    let slot = {
        let mut entries = stream_structure_cache()
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        entries.retain(|(key, _)| key.path != identity.path || *key == identity);
        let slot = entries
            .iter()
            .position(|(key, _)| *key == identity)
            .and_then(|index| entries.remove(index))
            .map(|(_, slot)| slot)
            .unwrap_or_else(|| Arc::new(OnceLock::new()));
        entries.push_back((identity.clone(), Arc::clone(&slot)));
        slot
    };
    // Waiting for another initializer must release the GIL: its final Python
    // result cannot be published until the initializer reacquires it.
    let result = py.detach(|| {
        slot.get_or_init(|| {
            Python::attach(|py| {
                crate::analysis_native::inspect_compression_stream_structure(py, path)
            })
        })
    });
    let mut entries = stream_structure_cache()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if result.is_err() {
        entries.retain(|(key, current)| *key != identity || !Arc::ptr_eq(current, &slot));
    }
    // Active slots stay discoverable, including under cache pressure. Once
    // their users finish, the existing bounded cache can evict them normally.
    while entries.len() > STREAM_STRUCTURE_CACHE_ENTRIES {
        let Some(index) = entries
            .iter()
            .position(|(_, slot)| Arc::strong_count(slot) == 1 && slot.get().is_some())
        else {
            break;
        };
        entries.remove(index);
    }
    drop(entries);
    match result {
        Ok(value) => Ok(value.clone_ref(py).into_bound(py)),
        Err(error) => Err(error.clone_ref(py)),
    }
}

pub(crate) fn clear_stream_structure_cache() -> usize {
    let mut entries = stream_structure_cache()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let count = entries.len();
    entries.clear();
    count
}

pub(crate) fn release_stream_structure_cache_under_roots(roots: &[PathBuf]) -> usize {
    let mut entries = stream_structure_cache()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let before = entries.len();
    entries.retain(|(key, _)| !roots.iter().any(|root| key.path.starts_with(root)));
    before - entries.len()
}

// ---- PyDict helpers --------------------------------------------------------

fn dict_item<'py>(dict: &Bound<'py, PyDict>, key: &str) -> PyResult<Option<Bound<'py, PyDict>>> {
    Ok(dict
        .get_item(key)?
        .and_then(|value| value.cast_into::<PyDict>().ok()))
}

fn required_item<'py>(dict: &Bound<'py, PyDict>, key: &str) -> PyResult<Bound<'py, PyAny>> {
    dict.get_item(key)?
        .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err(key.to_string()))
}

fn truthy(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<bool> {
    match dict.get_item(key)? {
        Some(value) => value.is_truthy(),
        None => Ok(false),
    }
}

fn present<'py>(dict: &Bound<'py, PyDict>, key: &str) -> PyResult<Option<Bound<'py, PyAny>>> {
    Ok(match dict.get_item(key)? {
        Some(value) if value.is_truthy()? => Some(value),
        _ => None,
    })
}

fn i64_of(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<i64> {
    match present(dict, key)? {
        Some(value) => value.extract::<i64>(),
        None => Ok(0),
    }
}

fn u64_of(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<u64> {
    Ok(i64_of(dict, key)?.max(0) as u64)
}

fn opt_u64_of(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<u64>> {
    match dict.get_item(key)? {
        Some(value) if !value.is_none() => Ok(Some(value.extract::<i64>()?.max(0) as u64)),
        _ => Ok(None),
    }
}

fn f64_of(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<f64> {
    match present(dict, key)? {
        Some(value) => value.extract::<f64>(),
        None => Ok(0.0),
    }
}

fn str_of(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<String> {
    match present(dict, key)? {
        Some(value) => Ok(value.str()?.to_string()),
        None => Ok(String::new()),
    }
}

fn str_or(dict: &Bound<'_, PyDict>, key: &str, default: &str) -> PyResult<String> {
    let value = str_of(dict, key)?;
    Ok(if value.is_empty() {
        default.to_string()
    } else {
        value
    })
}

fn str_list(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Vec<String>> {
    let Some(value) = present(dict, key)? else {
        return Ok(Vec::new());
    };
    let mut items = Vec::new();
    for item in value.try_iter()? {
        items.push(item?.str()?.to_string());
    }
    Ok(items)
}

fn positive_int_or(dict: &Bound<'_, PyDict>, key: &str, default: u64) -> PyResult<u64> {
    match present(dict, key)? {
        Some(value) => Ok(value.extract::<i64>()?.max(0) as u64),
        None => Ok(default),
    }
}

fn set_default<'py, V: IntoPyObject<'py>>(
    dict: &Bound<'py, PyDict>,
    key: &str,
    value: V,
) -> PyResult<()> {
    if !dict.contains(key)? {
        dict.set_item(key, value)?;
    }
    Ok(())
}

fn sorted_unique(mut values: Vec<String>) -> Vec<String> {
    values.retain(|value| !value.is_empty());
    values.sort();
    values.dedup();
    values
}

fn non_empty_or(values: Vec<String>, default: &str) -> Vec<String> {
    if values.is_empty() {
        vec![default.to_string()]
    } else {
        values
    }
}

#[cfg(test)]
mod report_tests {
    use super::*;

    fn evidence<'py>(
        py: Python<'py>,
        format: &str,
        confidence: f64,
        status: &'static str,
        segments: &[(u64, Option<u64>)],
        details: &[(&str, &str)],
    ) -> Evidence<'py> {
        let dict = PyDict::new(py);
        for (key, value) in details {
            dict.set_item(*key, *value).unwrap();
        }
        Evidence::new(
            format,
            confidence,
            status,
            segments
                .iter()
                .map(|(start, end)| Segment::new(*start, *end, confidence, Vec::new(), Vec::new()))
                .collect(),
            dict,
        )
    }

    fn planned(evidences: &[Evidence<'_>], plan: &SegmentPlan) -> Vec<(String, u64)> {
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
        Python::initialize();
        Python::attach(|py| {
            let evidences = vec![
                evidence(py, "rar", 0.97, "extractable", &[(40, Some(60))], &[]),
                evidence(
                    py,
                    "7z",
                    0.96,
                    "extractable",
                    &[(4, Some(32)), (0, Some(14))],
                    &[],
                ),
                evidence(
                    py,
                    "zip",
                    0.94,
                    "extractable",
                    &[(13, Some(81))],
                    &[("source", "embedded_scan"), ("candidate_kind", "anchor")],
                ),
                evidence(py, "tar", 0.90, "extractable", &[(90, None)], &[]),
            ];
            let plan = SegmentPlan::build(&evidences, &[0, 1, 2, 3], 100).unwrap();
            assert_eq!(
                planned(&evidences, &plan),
                vec![("7z".into(), 0), ("7z".into(), 4), ("rar".into(), 40)]
            );
        });
    }

    #[test]
    fn plan_prefers_compressed_tar_over_stream_for_same_range() {
        Python::initialize();
        Python::attach(|py| {
            let evidences = vec![
                evidence(py, "tar.gz", 0.93, "extractable", &[(5, Some(100))], &[]),
                evidence(py, "gzip", 0.88, "extractable", &[(5, Some(100))], &[]),
            ];
            let plan = SegmentPlan::build(&evidences, &[0, 1], 200).unwrap();
            assert_eq!(planned(&evidences, &plan), vec![("tar.gz".into(), 5)]);
        });
    }

    #[test]
    fn plan_suppresses_inner_tar_shadowed_by_whole_compressed_tar() {
        Python::initialize();
        Python::attach(|py| {
            let evidences = vec![
                evidence(py, "tar.zst", 0.93, "extractable", &[(0, Some(200))], &[]),
                evidence(py, "tar", 0.86, "extractable", &[(12, Some(180))], &[]),
                evidence(py, "zip", 0.99, "extractable", &[(20, Some(120))], &[]),
            ];
            let plan = SegmentPlan::build(&evidences, &[0, 1, 2], 200).unwrap();
            assert_eq!(planned(&evidences, &plan), vec![("zip".into(), 20)]);
        });
    }

    #[test]
    fn plan_picks_most_confident_carved_password_segment() {
        Python::initialize();
        Python::attach(|py| {
            let evidences = vec![
                evidence(
                    py,
                    "7z",
                    0.80,
                    "damaged",
                    &[(0, None)],
                    &[("password_required", "yes")],
                ),
                evidence(
                    py,
                    "rar",
                    0.72,
                    "damaged",
                    &[(90, None), (64, None)],
                    &[("password_required", "yes")],
                ),
                evidence(
                    py,
                    "zip",
                    0.60,
                    "damaged",
                    &[(10, None)],
                    &[("password_required", "yes")],
                ),
            ];
            let plan = SegmentPlan::build(&evidences, &[], 200).unwrap();
            assert_eq!(plan.password_segment, Some((1, 1)));
            assert!(plan.extractable.is_empty());
        });
    }

    #[test]
    fn plan_proves_missing_volume_from_seven_zip_declared_end() {
        Python::initialize();
        Python::attach(|py| {
            let seven = evidence(py, "7z", 0.65, "damaged", &[(0, None)], &[]);
            seven
                .details
                .to_python(py)
                .unwrap()
                .set_item("start_header_crc_ok", true)
                .unwrap();
            seven
                .details
                .to_python(py)
                .unwrap()
                .set_item("archive_offset", 0)
                .unwrap();
            seven
                .details
                .to_python(py)
                .unwrap()
                .set_item("next_header_offset", 100)
                .unwrap();
            seven
                .details
                .to_python(py)
                .unwrap()
                .set_item("next_header_size", 10)
                .unwrap();
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
        });
    }

    #[test]
    fn combine_keeps_first_best_and_deduplicates_segments() {
        Python::initialize();
        Python::attach(|py| {
            let candidates = vec![
                evidence(py, "rar", 0.35, "weak", &[(9, None)], &[("id", "weak")]),
                evidence(
                    py,
                    "rar",
                    0.97,
                    "extractable",
                    &[(30, Some(50))],
                    &[("id", "first")],
                ),
                evidence(
                    py,
                    "rar",
                    0.97,
                    "extractable",
                    &[(4, Some(20)), (30, Some(50))],
                    &[("id", "second")],
                ),
            ];
            let combined = combine_candidates(py, "rar", candidates, true).unwrap();
            assert_eq!(combined.status, "extractable");
            assert_eq!(
                str_of(&combined.details.to_python(py).unwrap(), "id").unwrap(),
                "first"
            );
            assert_eq!(
                i64_of(&combined.details.to_python(py).unwrap(), "candidate_count").unwrap(),
                2
            );
            let spans = combined
                .segments
                .iter()
                .map(|segment| (segment.start, segment.end))
                .collect::<Vec<_>>();
            assert_eq!(spans, vec![(4, Some(20)), (30, Some(50))]);
        });
    }

    #[test]
    fn read_fault_projects_field_truncation_and_missing_volume_flags() {
        Python::initialize();
        Python::attach(|py| {
            let native = PyDict::new(py);
            native
                .set_item("damage_flags", vec!["read_error", "probably_truncated"])
                .unwrap();
            let fault = PyDict::new(py);
            fault.set_item("code", "unexpected_eof").unwrap();
            fault.set_item("field", " zip.eocd ").unwrap();
            fault.set_item("possible_missing_volume", true).unwrap();
            native.set_item("read_error", fault).unwrap();
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
            native.del_item("read_error").unwrap();
            assert_eq!(
                read_fault_damage_flags(&native).unwrap(),
                vec!["read_error", "probably_truncated"]
            );
        });
    }

    #[test]
    fn truncated_stream_trailing_size_is_unknown_not_an_error() {
        Python::initialize();
        Python::attach(|py| {
            let raw = PyDict::new(py);
            raw.set_item("format", "gzip").unwrap();
            raw.set_item("magic_matched", true).unwrap();
            raw.set_item("plausible", false).unwrap();
            raw.set_item("structure_validation_complete", true).unwrap();
            raw.set_item("archive.trailing_data", "unavailable")
                .unwrap();
            raw.set_item("file_size", 100).unwrap();
            let observed = stream_observation(py, raw, "gzip").unwrap();
            assert!(observed.get_item("segment_end").unwrap().unwrap().is_none());
            assert_eq!(str_of(&observed, "boundary_confidence").unwrap(), "none");
        });
    }
}
