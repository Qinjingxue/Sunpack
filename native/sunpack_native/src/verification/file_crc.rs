use crate::io::reader::ManagedReader;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict, PyList};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use unicode_normalization::UnicodeNormalization;
use crc32fast::Hasher as Crc32Hasher;

const BUFFER_SIZE: usize = 1024 * 1024;

#[pyfunction]
pub(crate) fn compute_directory_crc_manifest(
    py: Python<'_>,
    output_dir: &str,
    max_files: Option<usize>,
) -> PyResult<Py<PyDict>> {
    let root = PathBuf::from(output_dir);
    let limit = max_files.unwrap_or(usize::MAX);
    let scan = py.detach(|| scan_crc_manifest(&root, limit));
    manifest_to_py(py, scan)
}

#[pyfunction]
pub(crate) fn sample_directory_readability(
    py: Python<'_>,
    output_dir: &str,
    max_samples: Option<usize>,
    read_bytes: Option<usize>,
) -> PyResult<Py<PyDict>> {
    let root = PathBuf::from(output_dir);
    let max_samples = max_samples.unwrap_or(64).max(1);
    let read_bytes = read_bytes.unwrap_or(4096).max(1);
    let scan = py.detach(|| scan_directory_readability(&root, max_samples, read_bytes));
    readability_to_py(py, scan)
}

#[pyfunction]
pub(crate) fn match_archive_output_crc_coverage(
    py: Python<'_>,
    archive_files: &Bound<'_, PyAny>,
    output_dir: &str,
    max_files: Option<usize>,
) -> PyResult<Py<PyDict>> {
    let root = PathBuf::from(output_dir);
    let expected = archive_items_from_py(archive_files)?;
    let limit = max_files.unwrap_or(usize::MAX);
    let scan = py.detach(|| scan_crc_output_files(&root, limit));

    let result = PyDict::new(py);
    let errors = PyList::empty(py);
    result.set_item("errors", &errors)?;
    append_errors_to_py(py, &errors, &scan.errors)?;
    if scan.status != "ok" {
        result.set_item("status", scan.status)?;
        return Ok(result.unbind());
    }

    let output_index = OutputIndex::new(scan.files);
    let mismatches = PyList::empty(py);
    let missing = PyList::empty(py);
    let observations = PyList::empty(py);

    let mut coverage = CoverageAccumulator::default();
    coverage.expected_files = expected.len();

    for item in expected {
        if let Some(expected_size) = item.size {
            coverage.expected_bytes += expected_size;
        }

        if item.unsafe_path {
            coverage.failed_files += 1;
            observations.append(observation_dict(
                py,
                &item.path,
                &item.path,
                "failed",
                0,
                item.size,
                Some(0.0),
                item.crc32,
                None,
                item.has_crc,
                None,
                "",
                true,
                &item.raw_path,
                "output_filesystem",
            )?)?;
            continue;
        }

        let Some(output_item) = output_index.match_item(&item.path) else {
            coverage.missing_files += 1;
            missing.append(item.path.as_str())?;
            observations.append(observation_dict(
                py,
                &item.path,
                &item.path,
                "missing",
                0,
                item.size,
                Some(0.0),
                item.crc32,
                None,
                item.has_crc,
                None,
                "",
                false,
                &item.raw_path,
                "",
            )?)?;
            continue;
        };

        coverage.matched_files += 1;
        let size_progress = size_progress(Some(output_item.size), item.size);
        if let Some(expected_size) = item.size {
            coverage.matched_bytes += output_item.size.min(expected_size);
        } else {
            coverage.matched_bytes += output_item.size;
        }

        let crc_ok = if item.has_crc {
            item.crc32
                .map(|expected_crc| expected_crc == output_item.crc32)
        } else {
            None
        };
        let mut state = "complete";
        let mut progress = size_progress;
        let mut failed_crc = false;

        if item.has_crc && crc_ok == Some(false) {
            state = "failed";
            progress = Some(0.0);
            failed_crc = true;
            coverage.failed_files += 1;
        } else if let Some(expected_size) = item.size {
            if output_item.size < expected_size {
                state = "partial";
                coverage.partial_files += 1;
            } else {
                coverage.complete_files += 1;
                coverage.complete_bytes += expected_size;
            }
        } else {
            coverage.complete_files += 1;
            coverage.complete_bytes += output_item.size;
        }

        if failed_crc {
            let mismatch = PyDict::new(py);
            mismatch.set_item("path", item.path.as_str())?;
            mismatch.set_item("expected_crc32", item.crc32.unwrap_or(0))?;
            mismatch.set_item("actual_crc32", output_item.crc32)?;
            mismatches.append(mismatch)?;
        }

        observations.append(observation_dict(
            py,
            &output_item.path,
            &item.path,
            state,
            output_item.size,
            item.size,
            progress,
            item.crc32,
            Some(output_item.crc32),
            item.has_crc,
            crc_ok,
            output_item.matched_by,
            false,
            &item.raw_path,
            "",
        )?)?;
    }

    let coverage_dict = coverage.to_py(py)?;
    result.set_item("status", "ok")?;
    result.set_item("total_files", scan.total_files)?;
    result.set_item("scanned_files", scan.scanned_files)?;
    result.set_item("truncated", scan.scanned_files < scan.total_files)?;
    result.set_item("mismatches", mismatches)?;
    result.set_item("missing", missing)?;
    result.set_item("coverage", coverage_dict)?;
    result.set_item("observations", observations)?;
    Ok(result.unbind())
}

#[derive(Clone)]
struct FileCrcRecord {
    path: String,
    size: u64,
    crc32: u32,
}

#[derive(Clone)]
struct ScanError {
    path: String,
    message: String,
}

struct ManifestScan {
    status: &'static str,
    files: Vec<FileCrcRecord>,
    errors: Vec<ScanError>,
    total_files: usize,
    scanned_files: usize,
}

struct OutputScan {
    status: &'static str,
    files: Vec<OutputFile>,
    errors: Vec<ScanError>,
    total_files: usize,
    scanned_files: usize,
}

struct ReadabilityRecord {
    path: String,
    size: u64,
    bytes_read: u64,
}

struct ReadabilityScan {
    status: &'static str,
    samples: Vec<ReadabilityRecord>,
    errors: Vec<ScanError>,
    total_files: usize,
    readable_files: usize,
    unreadable_files: usize,
    empty_files: usize,
    bytes_read: u64,
    truncated: bool,
}

fn scan_crc_manifest(root: &Path, limit: usize) -> ManifestScan {
    if !root.exists() {
        return ManifestScan { status: "missing", files: Vec::new(), errors: Vec::new(), total_files: 0, scanned_files: 0 };
    }
    if !root.is_dir() {
        return ManifestScan { status: "not_directory", files: Vec::new(), errors: Vec::new(), total_files: 0, scanned_files: 0 };
    }
    let mut files = Vec::new();
    let mut errors = Vec::new();
    let mut total_files = 0;
    let mut scanned_files = 0;
    let mut buffer = vec![0u8; BUFFER_SIZE];
    walk_crc_manifest(root, root, limit, &mut total_files, &mut scanned_files, &mut files, &mut errors, &mut buffer);
    ManifestScan { status: "ok", files, errors, total_files, scanned_files }
}

fn walk_crc_manifest(root: &Path, current: &Path, limit: usize, total_files: &mut usize, scanned_files: &mut usize, files: &mut Vec<FileCrcRecord>, errors: &mut Vec<ScanError>, buffer: &mut [u8]) {
    let entries = match std::fs::read_dir(current) { Ok(v) => v, Err(err) => { push_scan_error(errors, current, root, err.to_string()); return; } };
    for entry in entries {
        let entry = match entry { Ok(v) => v, Err(err) => { push_scan_error(errors, current, root, err.to_string()); continue; } };
        let path = entry.path();
        let metadata = match entry.metadata() { Ok(v) => v, Err(err) => { push_scan_error(errors, &path, root, err.to_string()); continue; } };
        if metadata.is_dir() {
            walk_crc_manifest(root, &path, limit, total_files, scanned_files, files, errors, buffer);
            continue;
        }
        if !metadata.is_file() { continue; }
        *total_files += 1;
        if *scanned_files >= limit { continue; }
        match crc32_file_with_buffer(&path, buffer) {
            Ok(crc32) => { files.push(FileCrcRecord { path: relative_path(&path, root), size: metadata.len(), crc32 }); *scanned_files += 1; }
            Err(err) => push_scan_error(errors, &path, root, err.to_string()),
        }
    }
}

fn scan_crc_output_files(root: &Path, limit: usize) -> OutputScan {
    if !root.exists() { return OutputScan { status: "missing", files: Vec::new(), errors: Vec::new(), total_files: 0, scanned_files: 0 }; }
    if !root.is_dir() { return OutputScan { status: "not_directory", files: Vec::new(), errors: Vec::new(), total_files: 0, scanned_files: 0 }; }
    let mut files = Vec::new();
    let mut errors = Vec::new();
    let mut total_files = 0;
    let mut scanned_files = 0;
    let mut buffer = vec![0u8; BUFFER_SIZE];
    collect_crc_output_files(root, root, limit, &mut total_files, &mut scanned_files, &mut files, &mut errors, &mut buffer);
    OutputScan { status: "ok", files, errors, total_files, scanned_files }
}

fn collect_crc_output_files(root: &Path, current: &Path, limit: usize, total_files: &mut usize, scanned_files: &mut usize, files: &mut Vec<OutputFile>, errors: &mut Vec<ScanError>, buffer: &mut [u8]) {
    let entries = match std::fs::read_dir(current) { Ok(v) => v, Err(err) => { push_scan_error(errors, current, root, err.to_string()); return; } };
    for entry in entries {
        let entry = match entry { Ok(v) => v, Err(err) => { push_scan_error(errors, current, root, err.to_string()); continue; } };
        let path = entry.path();
        let metadata = match entry.metadata() { Ok(v) => v, Err(err) => { push_scan_error(errors, &path, root, err.to_string()); continue; } };
        if metadata.is_dir() {
            if entry.file_name().to_string_lossy().eq_ignore_ascii_case(".sunpack") { continue; }
            collect_crc_output_files(root, &path, limit, total_files, scanned_files, files, errors, buffer);
            continue;
        }
        if !metadata.is_file() { continue; }
        *total_files += 1;
        if *scanned_files >= limit { continue; }
        let rel_path = clean_relative_archive_path(&relative_path(&path, root));
        if rel_path.is_empty() { continue; }
        match crc32_file_with_buffer(&path, buffer) {
            Ok(crc32) => { files.push(OutputFile { path: rel_path, size: metadata.len(), crc32, matched_by: "" }); *scanned_files += 1; }
            Err(err) => push_scan_error(errors, &path, root, err.to_string()),
        }
    }
}

fn scan_directory_readability(root: &Path, max_samples: usize, read_bytes: usize) -> ReadabilityScan {
    if !root.exists() { return ReadabilityScan { status: "missing", samples: Vec::new(), errors: Vec::new(), total_files: 0, readable_files: 0, unreadable_files: 0, empty_files: 0, bytes_read: 0, truncated: false }; }
    if !root.is_dir() { return ReadabilityScan { status: "not_directory", samples: Vec::new(), errors: Vec::new(), total_files: 0, readable_files: 0, unreadable_files: 0, empty_files: 0, bytes_read: 0, truncated: false }; }
    let mut file_paths = Vec::new();
    let mut errors = Vec::new();
    collect_regular_files(root, root, &mut file_paths, &mut errors);
    let total_files = file_paths.len();
    let selected = select_sample_paths(&file_paths, max_samples);
    let mut samples = Vec::with_capacity(selected.len());
    let mut readable_files = 0;
    let mut unreadable_files = 0;
    let mut empty_files = 0;
    let mut bytes_read = 0;
    let mut buffer = vec![0u8; read_bytes];
    for path in selected {
        match read_sample_with_buffer(&path, &mut buffer) {
            Ok(sample) => {
                readable_files += 1;
                if sample.size == 0 { empty_files += 1; }
                bytes_read += sample.bytes_read;
                samples.push(ReadabilityRecord { path: relative_path(&path, root), size: sample.size, bytes_read: sample.bytes_read });
            }
            Err(err) => { unreadable_files += 1; push_scan_error(&mut errors, &path, root, err.to_string()); }
        }
    }
    ReadabilityScan { status: "ok", samples, errors, total_files, readable_files, unreadable_files, empty_files, bytes_read, truncated: total_files > max_samples }
}

fn collect_regular_files(root: &Path, current: &Path, paths: &mut Vec<PathBuf>, errors: &mut Vec<ScanError>) {
    let entries = match std::fs::read_dir(current) { Ok(v) => v, Err(err) => { push_scan_error(errors, current, root, err.to_string()); return; } };
    for entry in entries {
        let entry = match entry { Ok(v) => v, Err(err) => { push_scan_error(errors, current, root, err.to_string()); continue; } };
        let path = entry.path();
        let metadata = match entry.metadata() { Ok(v) => v, Err(err) => { push_scan_error(errors, &path, root, err.to_string()); continue; } };
        if metadata.is_dir() { collect_regular_files(root, &path, paths, errors); } else if metadata.is_file() { paths.push(path); }
    }
}

fn select_sample_paths(paths: &[PathBuf], max_samples: usize) -> Vec<PathBuf> {
    if paths.len() <= max_samples { return paths.to_vec(); }
    if max_samples == 1 { return vec![paths[0].clone()]; }
    let last = paths.len() - 1;
    (0..max_samples).map(|index| paths[index * last / (max_samples - 1)].clone()).collect()
}

fn push_scan_error(errors: &mut Vec<ScanError>, path: &Path, root: &Path, message: String) {
    errors.push(ScanError { path: relative_path(path, root), message });
}

fn append_errors_to_py(py: Python<'_>, errors: &Bound<'_, PyList>, scan_errors: &[ScanError]) -> PyResult<()> {
    for error in scan_errors {
        let item = PyDict::new(py);
        item.set_item("path", &error.path)?;
        item.set_item("message", &error.message)?;
        errors.append(item)?;
    }
    Ok(())
}

fn manifest_to_py(py: Python<'_>, scan: ManifestScan) -> PyResult<Py<PyDict>> {
    let result = PyDict::new(py);
    let files = PyList::empty(py);
    let errors = PyList::empty(py);
    result.set_item("files", &files)?;
    result.set_item("errors", &errors)?;
    append_errors_to_py(py, &errors, &scan.errors)?;
    result.set_item("status", scan.status)?;
    if scan.status != "ok" { return Ok(result.unbind()); }
    for record in scan.files {
        let item = PyDict::new(py);
        item.set_item("path", record.path)?;
        item.set_item("size", record.size)?;
        item.set_item("crc32", record.crc32)?;
        files.append(item)?;
    }
    result.set_item("total_files", scan.total_files)?;
    result.set_item("scanned_files", scan.scanned_files)?;
    result.set_item("truncated", scan.scanned_files < scan.total_files)?;
    Ok(result.unbind())
}

fn readability_to_py(py: Python<'_>, scan: ReadabilityScan) -> PyResult<Py<PyDict>> {
    let result = PyDict::new(py);
    let samples = PyList::empty(py);
    let errors = PyList::empty(py);
    result.set_item("samples", &samples)?;
    result.set_item("errors", &errors)?;
    append_errors_to_py(py, &errors, &scan.errors)?;
    result.set_item("status", scan.status)?;
    if scan.status != "ok" { return Ok(result.unbind()); }
    for record in scan.samples {
        let item = PyDict::new(py);
        item.set_item("path", record.path)?;
        item.set_item("size", record.size)?;
        item.set_item("bytes_read", record.bytes_read)?;
        item.set_item("empty", record.size == 0)?;
        samples.append(item)?;
    }
    result.set_item("total_files", scan.total_files)?;
    result.set_item("sampled_files", scan.readable_files + scan.unreadable_files)?;
    result.set_item("readable_files", scan.readable_files)?;
    result.set_item("unreadable_files", scan.unreadable_files)?;
    result.set_item("empty_files", scan.empty_files)?;
    result.set_item("bytes_read", scan.bytes_read)?;
    result.set_item("truncated", scan.truncated)?;
    Ok(result.unbind())
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
struct OutputFile {
    path: String,
    size: u64,
    crc32: u32,
    matched_by: &'static str,
}

struct OutputIndex {
    files: Vec<OutputFile>,
    by_path: HashMap<String, usize>,
    by_basename: HashMap<String, Vec<usize>>,
}

impl OutputIndex {
    fn new(files: Vec<OutputFile>) -> Self {
        let mut by_path = HashMap::with_capacity(files.len());
        let mut by_basename: HashMap<String, Vec<usize>> = HashMap::new();
        for (index, item) in files.iter().enumerate() {
            by_path
                .entry(normalize_match_path(&item.path))
                .or_insert(index);
            by_basename
                .entry(normalize_match_name(basename(&item.path)))
                .or_default()
                .push(index);
        }
        Self {
            files,
            by_path,
            by_basename,
        }
    }

    fn match_item(&self, expected_path: &str) -> Option<OutputFile> {
        let normalized = normalize_match_path(expected_path);
        if let Some(index) = self.by_path.get(&normalized) {
            let mut item = self.files[*index].clone();
            item.matched_by = "path";
            return Some(item);
        }
        let basename = normalize_match_name(basename(&normalized));
        let candidates = self.by_basename.get(&basename)?;
        if candidates.len() != 1 {
            return None;
        }
        let mut item = self.files[candidates[0]].clone();
        item.matched_by = "basename";
        Some(item)
    }
}

#[derive(Default)]
struct CoverageAccumulator {
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

impl CoverageAccumulator {
    fn to_py(&self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        let file_coverage = self.matched_files as f64 / self.expected_files.max(1) as f64;
        let byte_coverage = if self.expected_bytes > 0 {
            (self.matched_bytes as f64 / self.expected_bytes as f64).clamp(0.0, 1.0)
        } else {
            file_coverage
        };
        let mut completeness = ((file_coverage + byte_coverage) / 2.0).clamp(0.0, 1.0);
        if self.expected_files > 0 && self.failed_files > 0 {
            let non_failed =
                self.expected_files
                    .saturating_sub(self.failed_files + self.missing_files) as f64;
            completeness = completeness.min((non_failed / self.expected_files as f64).max(0.0));
        }

        let dict = PyDict::new(py);
        dict.set_item("completeness", round6(completeness))?;
        dict.set_item("file_coverage", round6(file_coverage))?;
        dict.set_item("byte_coverage", round6(byte_coverage))?;
        dict.set_item("expected_files", self.expected_files)?;
        dict.set_item("matched_files", self.matched_files)?;
        dict.set_item("complete_files", self.complete_files)?;
        dict.set_item("partial_files", self.partial_files)?;
        dict.set_item("failed_files", self.failed_files)?;
        dict.set_item("missing_files", self.missing_files)?;
        dict.set_item("expected_bytes", self.expected_bytes)?;
        dict.set_item("matched_bytes", self.matched_bytes)?;
        dict.set_item("complete_bytes", self.complete_bytes)?;
        Ok(dict.unbind())
    }
}

fn archive_items_from_py(archive_files: &Bound<'_, PyAny>) -> PyResult<Vec<ArchiveFile>> {
    let mut items = Vec::new();
    for item in archive_files.try_iter()? {
        let item = item?;
        let Ok(dict) = item.cast::<PyDict>() else {
            continue;
        };
        let raw_path = py_string(dict, "path")?
            .or_else(|| py_string(dict, "name").ok().flatten())
            .unwrap_or_default();
        let path = clean_relative_archive_path(&raw_path);
        if path.is_empty() {
            continue;
        }
        let has_crc = py_bool(dict, "has_crc")?
            .unwrap_or_else(|| py_u32(dict, "crc32").ok().flatten().is_some());
        items.push(ArchiveFile {
            path,
            raw_path: raw_path.clone(),
            unsafe_path: unsafe_archive_path(&raw_path, &clean_relative_archive_path(&raw_path)),
            size: py_u64(dict, "size")?.or_else(|| py_u64(dict, "unpacked_size").ok().flatten()),
            has_crc,
            crc32: py_u32(dict, "crc32")?,
        });
    }
    Ok(items)
}

fn observation_dict(
    py: Python<'_>,
    path: &str,
    archive_path: &str,
    state: &str,
    bytes_written: u64,
    expected_size: Option<u64>,
    progress: Option<f64>,
    crc_expected: Option<u32>,
    crc_actual: Option<u32>,
    expected_has_crc: bool,
    crc_ok: Option<bool>,
    matched_by: &str,
    path_blocked: bool,
    raw_archive_path: &str,
    failure_kind: &str,
) -> PyResult<Py<PyDict>> {
    let item = PyDict::new(py);
    item.set_item("path", path)?;
    item.set_item("archive_path", archive_path)?;
    item.set_item("state", state)?;
    item.set_item("bytes_written", bytes_written)?;
    item.set_item("expected_size", expected_size)?;
    item.set_item("progress", progress)?;
    item.set_item("crc_expected", crc_expected)?;
    item.set_item("crc_actual", crc_actual)?;

    let details = PyDict::new(py);
    details.set_item("expected_has_crc", expected_has_crc)?;
    details.set_item("crc_ok", crc_ok)?;
    details.set_item("matched_by", matched_by)?;
    details.set_item("path_blocked", path_blocked)?;
    details.set_item("raw_archive_path", raw_archive_path)?;
    details.set_item("failure_kind", failure_kind)?;
    item.set_item("details", details)?;
    Ok(item.unbind())
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
    value.nfc().collect::<String>().to_lowercase()
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

fn unsafe_archive_path(raw_path: &str, cleaned: &str) -> bool {
    let text = raw_path.replace('\\', "/");
    if text.is_empty() {
        return false;
    }
    if text.starts_with('/') || text.starts_with("//") {
        return true;
    }
    if text.len() >= 3 && text.as_bytes()[1] == b':' && text.as_bytes()[2] == b'/' {
        return true;
    }
    let parts: Vec<&str> = text.split('/').filter(|part| !part.is_empty()).collect();
    if parts.iter().any(|part| *part == "..") {
        return true;
    }
    if parts.iter().any(|part| windows_reserved_path_part(part)) {
        return true;
    }
    if parts.iter().any(|part| part.contains(':')) {
        return true;
    }
    !cleaned.is_empty() && cleaned != text.trim().trim_matches('/')
}

fn windows_reserved_path_part(part: &str) -> bool {
    let stem = part
        .split('.')
        .next()
        .unwrap_or("")
        .trim()
        .trim_end_matches([' ', '.'])
        .to_lowercase();
    if stem.is_empty() {
        return false;
    }
    matches!(stem.as_str(), "con" | "prn" | "aux" | "nul")
        || (stem.len() == 4
            && (stem.starts_with("com") || stem.starts_with("lpt"))
            && stem[3..].chars().all(|c| ('1'..='9').contains(&c)))
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

struct ReadSample {
    size: u64,
    bytes_read: u64,
}

fn read_sample_with_buffer(path: &Path, buffer: &mut [u8]) -> std::io::Result<ReadSample> {
    let reader = ManagedReader::open(path)?;
    let size = reader.len();
    if size == 0 {
        return Ok(ReadSample { size, bytes_read: 0 });
    }
    let head_read = reader.read_into_at(0, buffer)? as u64;
    let mut tail_read = 0u64;
    if size > buffer.len() as u64 {
        let tail_offset = size.saturating_sub(buffer.len() as u64);
        tail_read = reader.read_into_at(tail_offset, buffer)? as u64;
    }
    Ok(ReadSample { size, bytes_read: head_read + tail_read })
}

fn relative_path(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn crc32_file_with_buffer(path: &Path, buffer: &mut [u8]) -> std::io::Result<u32> {
    let reader = ManagedReader::open(path)?;
    let mut cursor = reader.stream_cursor();
    let mut hasher = Crc32Hasher::new();
    loop {
        let read = cursor.read(buffer)?;
        if read == 0 { break; }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize())
}
