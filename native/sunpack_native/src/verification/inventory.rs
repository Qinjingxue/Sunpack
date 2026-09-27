use crate::io::reader::ManagedReader;
use crate::scan::directory::{
    NativeOutputInventory, OutputFileRecord, OutputInventoryVerificationSnapshot,
};
use crc32fast::Hasher as Crc32Hasher;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict, PyList};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const CRC_BUFFER_SIZE: usize = 1024 * 1024;

#[pyfunction]
#[pyo3(signature = (
    archive_files,
    inventory,
    verify_crc=false,
    basename_mode="unique",
    include_observations=false,
    detail_offset=0,
    detail_limit=128,
    max_issue_items=20
))]
pub(crate) fn match_output_inventory_coverage(
    py: Python<'_>,
    archive_files: &Bound<'_, PyAny>,
    inventory: PyRef<'_, NativeOutputInventory>,
    verify_crc: bool,
    basename_mode: &str,
    include_observations: bool,
    detail_offset: usize,
    detail_limit: usize,
    max_issue_items: usize,
) -> PyResult<Py<PyDict>> {
    let expected = archive_items_from_py(archive_files)?;
    let snapshot = inventory.verification_snapshot();
    let basename_mode = BasenameMode::parse(basename_mode)?;
    let matched = py.detach(|| {
        match_inventory(
            expected,
            snapshot,
            verify_crc,
            basename_mode,
            include_observations,
            detail_offset,
            detail_limit,
            max_issue_items,
        )
    });
    match_result_to_py(py, matched)
}

#[derive(Clone, Copy)]
enum BasenameMode {
    None,
    Unique,
    Any,
}

impl BasenameMode {
    fn parse(value: &str) -> PyResult<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "unique" => Ok(Self::Unique),
            "none" | "path" => Ok(Self::None),
            "any" | "presence" => Ok(Self::Any),
            other => Err(pyo3::exceptions::PyValueError::new_err(format!(
                "unsupported basename mode: {other}"
            ))),
        }
    }
}

#[derive(Clone)]
struct ArchiveFile {
    path: String,
    raw_path: String,
    unsafe_path: bool,
    size: Option<u64>,
    has_crc: bool,
    crc32: Option<u32>,
}

#[derive(Clone)]
struct MatchObservation {
    path: String,
    archive_path: String,
    state: &'static str,
    bytes_written: u64,
    expected_size: Option<u64>,
    progress: Option<f64>,
    crc_expected: Option<u32>,
    crc_actual: Option<u32>,
    expected_has_crc: bool,
    crc_ok: Option<bool>,
    matched_by: &'static str,
    path_blocked: bool,
    raw_archive_path: String,
    failure_kind: &'static str,
}

#[derive(Clone)]
struct Mismatch {
    path: String,
    expected_crc32: u32,
    actual_crc32: u32,
}

#[derive(Clone)]
struct MatchError {
    path: String,
    message: String,
}

#[derive(Default, Clone)]
struct Coverage {
    expected_files: usize,
    matched_files: usize,
    complete_files: usize,
    partial_files: usize,
    failed_files: usize,
    missing_files: usize,
    expected_bytes: u64,
    matched_bytes: u64,
    complete_bytes: u64,
}

struct MatchResult {
    status: &'static str,
    coverage: Coverage,
    mismatch_count: usize,
    missing_count: usize,
    mismatches: Vec<Mismatch>,
    missing: Vec<String>,
    observations: Vec<MatchObservation>,
    errors: Vec<MatchError>,
    detail_total: usize,
    detail_offset: usize,
    detail_count: usize,
    detail_truncated: bool,
    used_worker_crc: bool,
    crc_files_read: usize,
}

struct OutputIndex {
    files: Arc<Vec<OutputFileRecord>>,
    root: PathBuf,
    by_path: HashMap<String, usize>,
    by_folded_path: HashMap<String, usize>,
    by_basename: HashMap<String, usize>,
}

const AMBIGUOUS_OUTPUT: usize = usize::MAX;

fn insert_unique_output(index: &mut HashMap<String, usize>, key: String, value: usize) {
    index
        .entry(key)
        .and_modify(|entry| *entry = AMBIGUOUS_OUTPUT)
        .or_insert(value);
}

impl OutputIndex {
    fn new(snapshot: &OutputInventoryVerificationSnapshot) -> Self {
        let mut by_path = HashMap::with_capacity(snapshot.files.len());
        for (index, item) in snapshot.files.iter().enumerate() {
            let path = output_relative_path(item);
            if path.is_empty() || path.contains(".sunpack/") {
                continue;
            }
            insert_unique_output(&mut by_path, path, index);
        }
        Self {
            files: Arc::clone(&snapshot.files),
            root: PathBuf::from(&snapshot.root),
            by_path,
            by_folded_path: HashMap::new(),
            by_basename: HashMap::new(),
        }
    }

    fn match_expected(
        &mut self,
        expected: &[ArchiveFile],
        mode: BasenameMode,
    ) -> Vec<Option<(usize, &'static str)>> {
        let mut matched = vec![None; expected.len()];
        let mut used = vec![false; self.files.len()];
        let mut remaining = expected.iter().filter(|item| !item.unsafe_path).count();
        // Reserve exact matches for the entire manifest before any fallback
        // can steal another entry's output. Every output contributes once.
        for pass in 0..3 {
            if remaining == 0 || (pass == 2 && matches!(mode, BasenameMode::None)) {
                break;
            }
            if pass == 1 {
                // The common exact-path case never builds fallback indexes.
                for (output, item) in self.files.iter().enumerate() {
                    let path = output_relative_path(item);
                    if path.is_empty() || path.contains(".sunpack/") {
                        continue;
                    }
                    let folded = normalize_match_path(&path);
                    insert_unique_output(&mut self.by_folded_path, folded.clone(), output);
                    if !matches!(mode, BasenameMode::None) {
                        insert_unique_output(
                            &mut self.by_basename,
                            normalize_match_name(basename(&folded)),
                            output,
                        );
                    }
                }
            }
            for (position, item) in expected.iter().enumerate() {
                if item.unsafe_path || matched[position].is_some() {
                    continue;
                }
                let (output, by) = match pass {
                    0 => (self.by_path.get(&item.path), "path"),
                    1 => (
                        self.by_folded_path.get(&normalize_match_path(&item.path)),
                        "path",
                    ),
                    _ => (
                        self.by_basename
                            .get(&normalize_match_name(basename(&item.path))),
                        "basename",
                    ),
                };
                if let Some(&output) = output {
                    if output != AMBIGUOUS_OUTPUT && !used[output] {
                        used[output] = true;
                        matched[position] = Some((output, by));
                        remaining -= 1;
                    }
                }
            }
        }
        matched
    }

    fn crc_for(
        &self,
        item: &OutputFileRecord,
        buffer: &mut [u8],
    ) -> Result<(Option<u32>, bool), MatchError> {
        if let Some(value) = item.output_crc32 {
            return Ok((Some(value), false));
        }
        let path = output_absolute_path(&self.root, item);
        match crc32_file_with_buffer(&path, buffer) {
            Ok(value) => Ok((Some(value), true)),
            Err(error) => Err(MatchError {
                path: output_relative_path(item),
                message: error.to_string(),
            }),
        }
    }
}

fn match_inventory(
    expected: Vec<ArchiveFile>,
    snapshot: OutputInventoryVerificationSnapshot,
    verify_crc: bool,
    basename_mode: BasenameMode,
    include_observations: bool,
    detail_offset: usize,
    detail_limit: usize,
    max_issue_items: usize,
) -> MatchResult {
    if !snapshot.exists {
        return empty_status_result("missing", expected.len(), detail_offset);
    }
    if !snapshot.is_dir {
        return empty_status_result("not_directory", expected.len(), detail_offset);
    }

    let mut index = OutputIndex::new(&snapshot);
    let matches = index.match_expected(&expected, basename_mode);
    let mut coverage = Coverage::default();
    coverage.expected_files = expected.len();

    let detail_end = detail_offset.saturating_add(detail_limit);
    let mut mismatches = Vec::with_capacity(max_issue_items.min(expected.len()));
    let mut missing = Vec::with_capacity(max_issue_items.min(expected.len()));
    let mut observations = Vec::with_capacity(detail_limit.min(expected.len()));
    let mut errors = Vec::new();
    let mut mismatch_count = 0usize;
    let mut missing_count = 0usize;
    let mut crc_buffer = vec![0u8; CRC_BUFFER_SIZE];
    let mut used_worker_crc = false;
    let mut crc_files_read = 0usize;

    for (expected_index, item) in expected.iter().enumerate() {
        if let Some(expected_size) = item.size {
            coverage.expected_bytes = coverage.expected_bytes.saturating_add(expected_size);
        }
        let emit =
            include_observations && expected_index >= detail_offset && expected_index < detail_end;

        if item.unsafe_path {
            coverage.failed_files += 1;
            if emit {
                observations.push(MatchObservation {
                    path: item.path.clone(),
                    archive_path: item.path.clone(),
                    state: "failed",
                    bytes_written: 0,
                    expected_size: item.size,
                    progress: Some(0.0),
                    crc_expected: item.crc32,
                    crc_actual: None,
                    expected_has_crc: item.has_crc,
                    crc_ok: None,
                    matched_by: "",
                    path_blocked: true,
                    raw_archive_path: item.raw_path.clone(),
                    failure_kind: "output_filesystem",
                });
            }
            continue;
        }

        let Some((output_index, matched_by)) = matches[expected_index] else {
            coverage.missing_files += 1;
            missing_count += 1;
            if missing.len() < max_issue_items {
                missing.push(item.path.clone());
            }
            if emit {
                observations.push(MatchObservation {
                    path: item.path.clone(),
                    archive_path: item.path.clone(),
                    state: "missing",
                    bytes_written: 0,
                    expected_size: item.size,
                    progress: Some(0.0),
                    crc_expected: item.crc32,
                    crc_actual: None,
                    expected_has_crc: item.has_crc,
                    crc_ok: None,
                    matched_by: "",
                    path_blocked: false,
                    raw_archive_path: item.raw_path.clone(),
                    failure_kind: "",
                });
            }
            continue;
        };
        let output = &index.files[output_index];
        let actual_size = output.bytes_written;
        let write_incomplete = output.bytes_written < output.size;
        let size_incomplete = item
            .size
            .is_some_and(|expected_size| actual_size < expected_size);

        let mut actual_crc = output.output_crc32;
        if verify_crc
            && item.has_crc
            && item.crc32.is_some()
            && output.status != 2
            && !write_incomplete
        {
            if actual_crc.is_some() {
                used_worker_crc = true;
            } else {
                match index.crc_for(output, &mut crc_buffer) {
                    Ok((value, read_from_disk)) => {
                        actual_crc = value;
                        if read_from_disk {
                            crc_files_read += 1;
                        }
                    }
                    Err(error) => {
                        errors.push(error);
                        coverage.missing_files += 1;
                        missing_count += 1;
                        if missing.len() < max_issue_items {
                            missing.push(item.path.clone());
                        }
                        if emit {
                            observations.push(MatchObservation {
                                path: output_relative_path(output),
                                archive_path: item.path.clone(),
                                state: "missing",
                                bytes_written: output.bytes_written,
                                expected_size: item.size,
                                progress: Some(0.0),
                                crc_expected: item.crc32,
                                crc_actual: None,
                                expected_has_crc: item.has_crc,
                                crc_ok: None,
                                matched_by,
                                path_blocked: false,
                                raw_archive_path: item.raw_path.clone(),
                                failure_kind: "output_filesystem",
                            });
                        }
                        continue;
                    }
                }
            }
        }

        coverage.matched_files += 1;
        if let Some(expected_size) = item.size {
            coverage.matched_bytes = coverage
                .matched_bytes
                .saturating_add(actual_size.min(expected_size));
        } else {
            coverage.matched_bytes = coverage.matched_bytes.saturating_add(actual_size);
        }

        let crc_ok = if item.has_crc {
            match (item.crc32, actual_crc) {
                (Some(expected_crc), Some(actual_crc)) => Some(expected_crc == actual_crc),
                _ => None,
            }
        } else {
            None
        };
        let size_progress = size_progress(Some(actual_size), item.size);
        let (state, progress) = if output.status == 2 {
            coverage.failed_files += 1;
            ("failed", size_progress.or(Some(0.0)))
        } else if write_incomplete {
            coverage.partial_files += 1;
            ("partial", size_progress)
        } else if verify_crc && item.has_crc && crc_ok == Some(false) {
            coverage.failed_files += 1;
            mismatch_count += 1;
            if mismatches.len() < max_issue_items {
                mismatches.push(Mismatch {
                    path: item.path.clone(),
                    expected_crc32: item.crc32.unwrap_or(0),
                    actual_crc32: actual_crc.unwrap_or(0),
                });
            }
            ("failed", Some(0.0))
        } else if size_incomplete {
            coverage.partial_files += 1;
            ("partial", size_progress)
        } else if let Some(expected_size) = item.size {
            if item.has_crc && verify_crc && actual_crc.is_none() {
                ("unverified", size_progress)
            } else {
                coverage.complete_files += 1;
                coverage.complete_bytes = coverage.complete_bytes.saturating_add(expected_size);
                ("complete", size_progress)
            }
        } else if item.has_crc && verify_crc && actual_crc.is_none() {
            ("unverified", size_progress)
        } else {
            coverage.complete_files += 1;
            coverage.complete_bytes = coverage.complete_bytes.saturating_add(actual_size);
            ("complete", size_progress)
        };

        if emit {
            observations.push(MatchObservation {
                path: output_relative_path(output),
                archive_path: item.path.clone(),
                state,
                bytes_written: output.bytes_written,
                expected_size: item.size,
                progress,
                crc_expected: item.crc32,
                crc_actual: actual_crc,
                expected_has_crc: item.has_crc,
                crc_ok,
                matched_by,
                path_blocked: false,
                raw_archive_path: item.raw_path.clone(),
                failure_kind: "",
            });
        }
    }

    let detail_count = observations.len();
    let detail_total = expected.len();
    MatchResult {
        status: "ok",
        coverage,
        mismatch_count,
        missing_count,
        mismatches,
        missing,
        observations,
        errors,
        detail_total,
        detail_offset: detail_offset.min(detail_total),
        detail_count,
        detail_truncated: include_observations
            && detail_offset.saturating_add(detail_count) < detail_total,
        used_worker_crc,
        crc_files_read,
    }
}

fn empty_status_result(
    status: &'static str,
    detail_total: usize,
    detail_offset: usize,
) -> MatchResult {
    MatchResult {
        status,
        coverage: Coverage {
            expected_files: detail_total,
            ..Coverage::default()
        },
        mismatch_count: 0,
        missing_count: 0,
        mismatches: Vec::new(),
        missing: Vec::new(),
        observations: Vec::new(),
        errors: Vec::new(),
        detail_total,
        detail_offset: detail_offset.min(detail_total),
        detail_count: 0,
        detail_truncated: false,
        used_worker_crc: false,
        crc_files_read: 0,
    }
}

fn match_result_to_py(py: Python<'_>, matched: MatchResult) -> PyResult<Py<PyDict>> {
    let result = PyDict::new(py);
    result.set_item("status", matched.status)?;
    result.set_item("coverage", coverage_to_py(py, &matched.coverage)?)?;
    result.set_item("mismatch_count", matched.mismatch_count)?;
    result.set_item("missing_count", matched.missing_count)?;
    result.set_item("used_worker_crc", matched.used_worker_crc)?;
    result.set_item("crc_files_read", matched.crc_files_read)?;
    result.set_item("detail_total", matched.detail_total)?;
    result.set_item("detail_offset", matched.detail_offset)?;
    result.set_item("detail_count", matched.detail_count)?;
    result.set_item("detail_truncated", matched.detail_truncated)?;

    let mismatches = PyList::empty(py);
    for item in matched.mismatches {
        let row = PyDict::new(py);
        row.set_item("path", item.path)?;
        row.set_item("expected_crc32", item.expected_crc32)?;
        row.set_item("actual_crc32", item.actual_crc32)?;
        mismatches.append(row)?;
    }
    result.set_item("mismatches", mismatches)?;

    let missing = PyList::empty(py);
    for path in matched.missing {
        missing.append(path)?;
    }
    result.set_item("missing", missing)?;

    let observations = PyList::empty(py);
    for item in matched.observations {
        observations.append(observation_to_py(py, item)?)?;
    }
    result.set_item("observations", observations)?;

    let errors = PyList::empty(py);
    for item in matched.errors {
        let row = PyDict::new(py);
        row.set_item("path", item.path)?;
        row.set_item("message", item.message)?;
        errors.append(row)?;
    }
    result.set_item("errors", errors)?;
    result.set_item("source", "native_output_inventory")?;
    Ok(result.unbind())
}

fn coverage_to_py(py: Python<'_>, coverage: &Coverage) -> PyResult<Py<PyDict>> {
    let file_coverage = coverage.matched_files as f64 / coverage.expected_files.max(1) as f64;
    let byte_coverage = if coverage.expected_bytes > 0 {
        (coverage.matched_bytes as f64 / coverage.expected_bytes as f64).clamp(0.0, 1.0)
    } else {
        file_coverage
    };
    let mut completeness = ((file_coverage + byte_coverage) / 2.0).clamp(0.0, 1.0);
    if coverage.expected_files > 0 && coverage.failed_files > 0 {
        let non_failed = coverage
            .expected_files
            .saturating_sub(coverage.failed_files + coverage.missing_files)
            as f64;
        completeness = completeness.min((non_failed / coverage.expected_files as f64).max(0.0));
    }

    let result = PyDict::new(py);
    result.set_item("completeness", round6(completeness))?;
    result.set_item("file_coverage", round6(file_coverage))?;
    result.set_item("byte_coverage", round6(byte_coverage))?;
    result.set_item("expected_files", coverage.expected_files)?;
    result.set_item("matched_files", coverage.matched_files)?;
    result.set_item("complete_files", coverage.complete_files)?;
    result.set_item("partial_files", coverage.partial_files)?;
    result.set_item("failed_files", coverage.failed_files)?;
    result.set_item("missing_files", coverage.missing_files)?;
    result.set_item("expected_bytes", coverage.expected_bytes)?;
    result.set_item("matched_bytes", coverage.matched_bytes)?;
    result.set_item("complete_bytes", coverage.complete_bytes)?;
    Ok(result.unbind())
}

fn observation_to_py(py: Python<'_>, item: MatchObservation) -> PyResult<Py<PyDict>> {
    let row = PyDict::new(py);
    row.set_item("path", item.path)?;
    row.set_item("archive_path", item.archive_path)?;
    row.set_item("state", item.state)?;
    row.set_item("bytes_written", item.bytes_written)?;
    row.set_item("expected_size", item.expected_size)?;
    row.set_item("progress", item.progress)?;
    row.set_item("crc_expected", item.crc_expected)?;
    row.set_item("crc_actual", item.crc_actual)?;

    let details = PyDict::new(py);
    details.set_item("expected_has_crc", item.expected_has_crc)?;
    details.set_item("crc_ok", item.crc_ok)?;
    details.set_item("matched_by", item.matched_by)?;
    details.set_item("path_blocked", item.path_blocked)?;
    details.set_item("raw_archive_path", item.raw_archive_path)?;
    details.set_item("failure_kind", item.failure_kind)?;
    row.set_item("details", details)?;
    Ok(row.unbind())
}

fn archive_items_from_py(archive_files: &Bound<'_, PyAny>) -> PyResult<Vec<ArchiveFile>> {
    let mut items = Vec::new();
    for item in archive_files.try_iter()? {
        let item = item?;
        let Ok(dict) = item.cast::<PyDict>() else {
            continue;
        };
        if py_bool(dict, "shadowed")?.unwrap_or(false) {
            continue;
        }
        let projected = py_string(dict, "output_path")?
            .or_else(|| py_string(dict, "path").ok().flatten())
            .or_else(|| py_string(dict, "name").ok().flatten())
            .unwrap_or_default();
        let raw_path = py_string(dict, "raw_path")?
            .or_else(|| py_string(dict, "archive_path").ok().flatten())
            .unwrap_or_else(|| projected.clone());
        let path = windows_output_relative_path(clean_relative_archive_path(&projected));
        if path.is_empty() {
            continue;
        }
        let raw_cleaned = clean_relative_archive_path(&raw_path);
        let has_crc = py_bool(dict, "has_crc")?
            .unwrap_or_else(|| py_u32(dict, "crc32").ok().flatten().is_some());
        items.push(ArchiveFile {
            path,
            raw_path: raw_path.clone(),
            unsafe_path: unsafe_archive_path(&raw_path, &raw_cleaned),
            size: py_u64(dict, "size")?.or_else(|| py_u64(dict, "unpacked_size").ok().flatten()),
            has_crc,
            crc32: py_u32(dict, "crc32")?,
        });
    }
    Ok(items)
}

fn output_relative_path(item: &OutputFileRecord) -> String {
    clean_relative_archive_path(item.output_path.as_deref().unwrap_or(&item.path))
}

fn output_absolute_path(root: &Path, item: &OutputFileRecord) -> PathBuf {
    if let Some(path) = item.abs_path.as_deref() {
        let path = PathBuf::from(path);
        if path.is_absolute() {
            return path;
        }
    }
    root.join(item.output_path.as_deref().unwrap_or(&item.path))
}

fn crc32_file_with_buffer(path: &Path, buffer: &mut [u8]) -> std::io::Result<u32> {
    let reader = ManagedReader::open(path)?;
    let mut cursor = reader.stream_cursor();
    let mut hasher = Crc32Hasher::new();
    loop {
        let read = cursor.read(buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize())
}

fn py_string(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<String>> {
    let Some(value) = dict.get_item(key)? else {
        return Ok(None);
    };
    if value.is_none() {
        return Ok(None);
    }
    Ok(Some(value.str()?.to_string_lossy().into_owned()))
}

fn py_bool(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<bool>> {
    let Some(value) = dict.get_item(key)? else {
        return Ok(None);
    };
    if value.is_none() {
        return Ok(None);
    }
    value.extract::<bool>().map(Some)
}

fn py_u64(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<u64>> {
    let Some(value) = dict.get_item(key)? else {
        return Ok(None);
    };
    if value.is_none() {
        return Ok(None);
    }
    if let Ok(value) = value.extract::<u64>() {
        return Ok(Some(value));
    }
    if let Ok(value) = value.extract::<i64>() {
        return Ok(Some(value.max(0) as u64));
    }
    Ok(None)
}

fn py_u32(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<u32>> {
    Ok(py_u64(dict, key)?.map(|value| (value & 0xFFFF_FFFF) as u32))
}

fn clean_relative_archive_path(value: &str) -> String {
    value
        .replace('\\', "/")
        .trim()
        .trim_matches('/')
        .split('/')
        .filter(|part| !part.is_empty() && *part != "." && *part != "..")
        .collect::<Vec<_>>()
        .join("/")
}

fn normalize_match_name(value: &str) -> String {
    // Non-ASCII names must retain their actual code points. Unicode text
    // equivalence is not evidence that two filesystem entries are identical.
    value.to_ascii_lowercase()
}

fn normalize_match_path(value: &str) -> String {
    clean_relative_archive_path(value)
        .split('/')
        .filter(|part| !part.is_empty())
        .map(normalize_match_name)
        .collect::<Vec<_>>()
        .join("/")
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Names the extraction worker refuses to write (see `safe_relative_item_path`
/// in the 7z bridge): rooted paths, drive-qualified names and `..` traversal.
fn unsafe_archive_path(raw_path: &str, cleaned: &str) -> bool {
    let text = raw_path.replace('\\', "/");
    if text.is_empty() {
        return false;
    }
    if text.starts_with('/') {
        return true;
    }
    let bytes = text.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return true;
    }
    if text.split('/').any(|part| part == "..") {
        return true;
    }
    !cleaned.is_empty() && cleaned != text.trim().trim_matches('/')
}

fn is_windows_invalid_name_char(value: char) -> bool {
    (value as u32) < 0x20 || matches!(value, '<' | '>' | ':' | '"' | '|' | '?' | '*')
}

/// Mirrors `is_windows_reserved_device_name` in the 7z bridge.
fn is_windows_reserved_device_name(part: &str) -> bool {
    let bytes = part.as_bytes();
    let mut stem = part.find('.').unwrap_or(bytes.len());
    while stem > 0 && bytes[stem - 1] == b' ' {
        stem -= 1;
    }
    if stem != 3 && stem != 4 {
        return false;
    }
    let prefix = [
        bytes[0].to_ascii_lowercase(),
        bytes[1].to_ascii_lowercase(),
        bytes[2].to_ascii_lowercase(),
    ];
    if stem == 3 {
        return matches!(&prefix, b"con" | b"prn" | b"aux" | b"nul");
    }
    matches!(bytes[3], b'1'..=b'9') && matches!(&prefix, b"com" | b"lpt")
}

fn windows_output_part_needs_mapping(part: &str) -> bool {
    part.chars().any(is_windows_invalid_name_char)
        || part.ends_with(['.', ' '])
        || is_windows_reserved_device_name(part)
}

/// Mirrors `make_windows_safe_path_part` in the 7z bridge.
fn windows_output_part(part: &str) -> String {
    let mut mapped: String = part
        .chars()
        .map(|value| {
            if is_windows_invalid_name_char(value) {
                '_'
            } else {
                value
            }
        })
        .collect();
    let kept = mapped.trim_end_matches(['.', ' ']).len();
    let trailing = mapped.len() - kept;
    mapped.truncate(kept);
    mapped.extend(std::iter::repeat('_').take(trailing));
    if is_windows_reserved_device_name(&mapped) {
        mapped.insert(0, '_');
    }
    mapped
}

/// Project a cleaned archive path onto the name the worker writes on disk.
/// The mapping is idempotent, so already-projected output paths pass through.
fn windows_output_relative_path(cleaned: String) -> String {
    if !cleaned.split('/').any(windows_output_part_needs_mapping) {
        return cleaned;
    }
    cleaned
        .split('/')
        .map(windows_output_part)
        .collect::<Vec<_>>()
        .join("/")
}

fn size_progress(actual_size: Option<u64>, expected_size: Option<u64>) -> Option<f64> {
    match (actual_size, expected_size) {
        (Some(_), Some(0)) => Some(1.0),
        (Some(actual), Some(expected)) => Some((actual as f64 / expected as f64).clamp(0.0, 1.0)),
        (Some(_), None) => None,
        (None, Some(_)) => None,
        (None, None) => None,
    }
}

fn round6(value: f64) -> f64 {
    (value * 1_000_000.0).round() / 1_000_000.0
}

#[cfg(test)]
mod windows_output_name_tests {
    use super::*;

    fn bug_regression_match(
        expected: &[(&str, u32)],
        actual: &[(&str, u32)],
        mode: BasenameMode,
    ) -> MatchResult {
        let expected = expected
            .iter()
            .map(|(path, crc)| ArchiveFile {
                path: (*path).into(),
                raw_path: (*path).into(),
                unsafe_path: false,
                size: Some(1),
                has_crc: true,
                crc32: Some(*crc),
            })
            .collect();
        let files = actual
            .iter()
            .enumerate()
            .map(|(index, (path, crc))| OutputFileRecord {
                index: index as u32,
                path: (*path).into(),
                abs_path: None,
                output_path: None,
                size: 1,
                bytes_written: 1,
                crc32: Some(*crc),
                output_crc32: Some(*crc),
                crc_ok: Some(true),
                status: 1,
                mtime_ns: None,
                magic: Vec::new(),
            })
            .collect();
        match_inventory(
            expected,
            OutputInventoryVerificationSnapshot {
                root: "unused".into(),
                exists: true,
                is_dir: true,
                files: Arc::new(files),
            },
            true,
            mode,
            true,
            0,
            128,
            20,
        )
    }

    #[test]
    fn bug_regression_distinct_unicode_outputs_keep_their_own_crc() {
        let names = [("\u{e9}.txt", 100), ("e\u{301}.txt", 200)];
        let result = bug_regression_match(&names, &names, BasenameMode::None);
        assert_eq!(result.coverage.complete_files, 2);
        assert_eq!(result.mismatch_count, 0);
        assert_eq!(result.observations[1].path, "e\u{301}.txt");
    }

    #[test]
    fn bug_regression_missing_unicode_sibling_is_not_counted_twice() {
        let names = [("\u{e9}.txt", 100), ("e\u{301}.txt", 100)];
        let result = bug_regression_match(&names, &names[..1], BasenameMode::Any);
        assert_eq!(result.coverage.complete_files, 1);
        assert_eq!(result.missing_count, 1);
        assert_eq!(result.coverage.complete_bytes, 1);
    }

    #[test]
    fn bug_regression_basename_fallback_cannot_steal_later_exact_output() {
        let result = bug_regression_match(
            &[("a/readme.txt", 100), ("b/readme.txt", 200)],
            &[("b/readme.txt", 200)],
            BasenameMode::Any,
        );
        assert_eq!(result.missing, vec!["a/readme.txt"]);
        assert_eq!(result.mismatch_count, 0);
        assert_eq!(result.coverage.complete_files, 1);
    }

    #[test]
    fn bug_regression_ambiguous_basename_does_not_choose_first_output() {
        let result = bug_regression_match(
            &[("missing/readme.txt", 100)],
            &[("a/readme.txt", 100), ("b/readme.txt", 200)],
            BasenameMode::Any,
        );
        assert_eq!(result.coverage.complete_files, 0);
        assert_eq!(result.missing_count, 1);
    }

    #[test]
    fn bug_regression_ascii_fallback_preserves_exact_case_distinctions() {
        let names = [("A.txt", 100), ("a.txt", 200)];
        let result = bug_regression_match(&names, &names, BasenameMode::Unique);
        assert_eq!(result.coverage.complete_files, 2);
        assert_eq!(result.mismatch_count, 0);
        let result = bug_regression_match(
            &[("README.txt", 100)],
            &[("readme.txt", 100)],
            BasenameMode::None,
        );
        assert_eq!(result.coverage.complete_files, 1);
    }

    #[test]
    fn archive_names_project_onto_worker_output_names() {
        let cases = [
            ("docs/readme.txt", "docs/readme.txt"),
            ("logs/12:30.log", "logs/12_30.log"),
            ("a?b*c<d>e|f\"g.txt", "a_b_c_d_e_f_g.txt"),
            ("dir. /name.", "dir__/name_"),
            ("con.txt", "_con.txt"),
            ("sub/NUL", "sub/_NUL"),
            ("com1 .log", "_com1 .log"),
            ("console.txt", "console.txt"),
            ("com0.txt", "com0.txt"),
            ("ctl-\u{1}-x", "ctl-_-x"),
        ];
        for (raw, expected) in cases {
            let projected = windows_output_relative_path(clean_relative_archive_path(raw));
            assert_eq!(projected, expected, "{raw}");
            // Already-projected output paths must pass through unchanged.
            assert_eq!(windows_output_relative_path(projected.clone()), projected);
        }
    }

    #[test]
    fn only_names_the_worker_rejects_are_unsafe() {
        for raw in [
            "/abs.txt",
            "C:/abs.txt",
            "c:drive-relative.txt",
            "../escape.txt",
            "a/../b.txt",
        ] {
            assert!(
                unsafe_archive_path(raw, &clean_relative_archive_path(raw)),
                "{raw}"
            );
        }
        for raw in ["con.txt", "logs/12:30.log", "name. ", "a?b.txt"] {
            assert!(
                !unsafe_archive_path(raw, &clean_relative_archive_path(raw)),
                "{raw}"
            );
        }
    }
}
