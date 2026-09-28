//! Per-file extraction progress manifest owned by Rust.
//!
//! Built from the worker's native output trace (or v3 manifest rows) plus a
//! scan of the output directory. Python reads aggregates and bounded pages;
//! the optional `.sunpack/extraction_manifest.json` file is written and read
//! here as well.

use crate::io::resource_lifecycle::TrackedFile;
use crate::scan::directory::{scan_output_inventory_impl, NativeWorkerManifest, OutputFileRecord};
use crate::scan::worker_event::{NativeOutputTrace, OutputTraceItem};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;

const UNTRACED_MESSAGE: &str =
    "file was present after extraction but was not reported by worker output trace";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum FileStatus {
    Complete,
    Partial,
    Failed,
    Skipped,
    #[serde(other)]
    Unverified,
}

impl FileStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
            Self::Unverified => "unverified",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProgressFile {
    path: String,
    archive_path: String,
    status: FileStatus,
    #[serde(default)]
    source_round: u32,
    #[serde(default)]
    bytes_written: u64,
    #[serde(default)]
    expected_size: Option<u64>,
    #[serde(default)]
    crc_ok: Option<bool>,
    #[serde(default)]
    failure_stage: String,
    #[serde(default)]
    failure_kind: String,
    #[serde(default)]
    message: String,
}

impl ProgressFile {
    fn progress(&self) -> Option<f64> {
        match self.expected_size {
            Some(expected) if expected > 0 => {
                Some((self.bytes_written as f64 / expected as f64).clamp(0.0, 1.0))
            }
            _ => match self.status {
                FileStatus::Complete => Some(1.0),
                FileStatus::Failed => Some(0.0),
                FileStatus::Partial => Some(0.5),
                _ => None,
            },
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct Summary {
    complete: usize,
    partial: usize,
    failed: usize,
    skipped: usize,
    unverified: usize,
    total: usize,
}

impl Summary {
    fn of(files: &[ProgressFile]) -> Self {
        let mut summary = Self {
            total: files.len(),
            ..Self::default()
        };
        for item in files {
            match item.status {
                FileStatus::Complete => summary.complete += 1,
                FileStatus::Partial => summary.partial += 1,
                FileStatus::Failed => summary.failed += 1,
                FileStatus::Skipped => summary.skipped += 1,
                FileStatus::Unverified => summary.unverified += 1,
            }
        }
        summary
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct ManifestDocument {
    version: u32,
    archive: String,
    out_dir: String,
    partial_outputs: bool,
    failure_stage: String,
    failure_kind: String,
    worker_status: String,
    native_status: String,
    files_written: u64,
    bytes_written: u64,
    summary: Summary,
    files: Vec<ProgressFile>,
}

#[pyclass(module = "sunpack_native", frozen)]
pub(crate) struct NativeProgressManifest {
    document: Arc<ManifestDocument>,
}

#[pymethods]
impl NativeProgressManifest {
    #[getter]
    fn archive(&self) -> &str {
        &self.document.archive
    }
    #[getter]
    fn out_dir(&self) -> &str {
        &self.document.out_dir
    }
    #[getter]
    fn partial_outputs(&self) -> bool {
        self.document.partial_outputs
    }
    #[getter]
    fn failure_stage(&self) -> &str {
        &self.document.failure_stage
    }
    #[getter]
    fn failure_kind(&self) -> &str {
        &self.document.failure_kind
    }
    #[getter]
    fn worker_status(&self) -> &str {
        &self.document.worker_status
    }
    #[getter]
    fn native_status(&self) -> &str {
        &self.document.native_status
    }
    #[getter]
    fn files_written(&self) -> u64 {
        self.document.files_written
    }
    #[getter]
    fn bytes_written(&self) -> u64 {
        self.document.bytes_written
    }

    #[getter]
    fn summary<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let summary = &self.document.summary;
        let dict = PyDict::new(py);
        dict.set_item("complete", summary.complete)?;
        dict.set_item("partial", summary.partial)?;
        dict.set_item("failed", summary.failed)?;
        dict.set_item("skipped", summary.skipped)?;
        dict.set_item("unverified", summary.unverified)?;
        dict.set_item("total", summary.total)?;
        Ok(dict)
    }

    fn __len__(&self) -> usize {
        self.document.files.len()
    }

    #[pyo3(signature = (offset=0, limit=128))]
    fn file_page(&self, py: Python<'_>, offset: usize, limit: usize) -> PyResult<Vec<Py<PyDict>>> {
        let files = &self.document.files;
        if limit == 0 || offset >= files.len() {
            return Ok(Vec::new());
        }
        let end = offset.saturating_add(limit).min(files.len());
        files[offset..end]
            .iter()
            .map(|item| {
                let row = PyDict::new(py);
                row.set_item("path", &item.path)?;
                row.set_item("archive_path", &item.archive_path)?;
                row.set_item("status", item.status.as_str())?;
                row.set_item("source_round", item.source_round)?;
                row.set_item("bytes_written", item.bytes_written)?;
                row.set_item("expected_size", item.expected_size)?;
                row.set_item("crc_ok", item.crc_ok)?;
                row.set_item("failure_stage", &item.failure_stage)?;
                row.set_item("failure_kind", &item.failure_kind)?;
                row.set_item("message", &item.message)?;
                Ok(row.unbind())
            })
            .collect()
    }

    /// Mean per-file progress; 1.0 when no per-file records exist.
    fn completeness(&self) -> f64 {
        let files = &self.document.files;
        if files.is_empty() {
            return 1.0;
        }
        let total: f64 = files.iter().filter_map(ProgressFile::progress).sum();
        (total / files.len() as f64).clamp(0.0, 1.0)
    }

    /// File and byte coverage of the recorded outputs.
    fn coverage<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let files = &self.document.files;
        let mut matched_files = 0usize;
        let mut expected_bytes = 0u64;
        let mut matched_bytes = 0u64;
        let mut complete_bytes = 0u64;
        for item in files {
            if item.status != FileStatus::Failed || item.bytes_written > 0 {
                matched_files += 1;
            }
            let expected = item.expected_size.unwrap_or(0);
            expected_bytes = expected_bytes.saturating_add(expected);
            matched_bytes = matched_bytes.saturating_add(if expected > 0 {
                item.bytes_written.min(expected)
            } else {
                item.bytes_written
            });
            if item.status == FileStatus::Complete {
                complete_bytes = complete_bytes.saturating_add(if expected > 0 {
                    expected
                } else {
                    item.bytes_written
                });
            }
        }
        let summary = Summary::of(files);
        let file_coverage = matched_files as f64 / files.len().max(1) as f64;
        let byte_coverage = if expected_bytes > 0 {
            matched_bytes as f64 / expected_bytes as f64
        } else {
            file_coverage
        };
        let dict = PyDict::new(py);
        dict.set_item("file_coverage", round6(file_coverage))?;
        dict.set_item("byte_coverage", round6(byte_coverage))?;
        dict.set_item("expected_files", files.len())?;
        dict.set_item("matched_files", matched_files)?;
        dict.set_item("complete_files", summary.complete)?;
        dict.set_item("partial_files", summary.partial)?;
        dict.set_item("failed_files", summary.failed)?;
        dict.set_item("missing_files", 0)?;
        dict.set_item("unverified_files", summary.unverified)?;
        dict.set_item("expected_bytes", expected_bytes)?;
        dict.set_item("matched_bytes", matched_bytes)?;
        dict.set_item("complete_bytes", complete_bytes)?;
        Ok(dict)
    }

    /// Per-entry status and error-class counts over the recorded files.
    fn entry_outcome_counts<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let files = &self.document.files;
        let summary = Summary::of(files);
        let mut crc = 0usize;
        let mut data = 0usize;
        let mut unexpected_end = 0usize;
        let mut unsupported = 0usize;
        let mut missing_volume = 0usize;
        for item in files {
            let text = format!(
                "{} {} {}",
                item.failure_kind,
                item.message,
                item.status.as_str()
            )
            .to_lowercase();
            if item.crc_ok == Some(false) || text.contains("crc") || text.contains("checksum") {
                crc += 1;
            }
            if text.contains("data_error") || text.contains("corrupted_data") {
                data += 1;
            }
            if text.contains("unexpected_end")
                || text.contains("unexpected end")
                || text.contains("truncated")
            {
                unexpected_end += 1;
            }
            if text.contains("unsupported") {
                unsupported += 1;
            }
            if text.contains("missing_volume") || text.contains("missing volume") {
                missing_volume += 1;
            }
        }
        let dict = PyDict::new(py);
        dict.set_item("total", summary.total)?;
        dict.set_item("complete", summary.complete)?;
        dict.set_item("partial", summary.partial)?;
        dict.set_item("failed", summary.failed)?;
        dict.set_item("unverified", summary.unverified)?;
        dict.set_item("crc_error", crc)?;
        dict.set_item("data_error", data)?;
        dict.set_item("unexpected_end", unexpected_end)?;
        dict.set_item("unsupported_method", unsupported)?;
        dict.set_item("missing_volume", missing_volume)?;
        Ok(dict)
    }

    #[pyo3(signature = (path, pretty=false))]
    fn write_json(&self, py: Python<'_>, path: String, pretty: bool) -> PyResult<()> {
        let document = Arc::clone(&self.document);
        py.detach(move || -> PyResult<()> {
            let target = Path::new(&path);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let payload = if pretty {
                serde_json::to_vec_pretty(document.as_ref())
            } else {
                serde_json::to_vec(document.as_ref())
            }
            .map_err(|error| pyo3::exceptions::PyValueError::new_err(error.to_string()))?;
            let mut file = TrackedFile::open_with(target, "progress_manifest_output", |options| {
                options.write(true).create(true).truncate(true);
            })?;
            file.write_all(&payload)?;
            file.flush()?;
            Ok(())
        })
    }
}

/// Read a manifest file written by ``write_json``; ``None`` when unreadable.
#[pyfunction]
pub(crate) fn load_progress_manifest(
    py: Python<'_>,
    path: String,
) -> Option<NativeProgressManifest> {
    py.detach(move || {
        let mut file = TrackedFile::open(&path, "progress_manifest_input").ok()?;
        let mut data = Vec::new();
        file.read_to_end(&mut data).ok()?;
        let document = serde_json::from_slice::<ManifestDocument>(&data).ok()?;
        Some(NativeProgressManifest {
            document: Arc::new(document),
        })
    })
}

/// Summary-only manifest for a worker result whose complete inventory was verified.
#[pyfunction]
pub(crate) fn complete_progress_manifest(
    archive: String,
    out_dir: String,
    native_status: String,
    files_written: u64,
    bytes_written: u64,
    file_count: usize,
) -> NativeProgressManifest {
    NativeProgressManifest {
        document: Arc::new(ManifestDocument {
            version: 1,
            archive,
            out_dir,
            partial_outputs: file_count > 0,
            failure_stage: String::new(),
            failure_kind: String::new(),
            worker_status: "ok".to_string(),
            native_status,
            files_written,
            bytes_written,
            summary: Summary {
                complete: file_count,
                total: file_count,
                ..Summary::default()
            },
            files: Vec::new(),
        }),
    }
}

/// Build the per-file manifest from the worker trace (preferred) or manifest
/// rows, then add output files the worker did not report.
#[pyfunction]
#[pyo3(signature = (
    archive, out_dir, round_index, trace, rows, worker_ok,
    failure_stage, failure_kind, worker_status, native_status,
    files_written, bytes_written
))]
pub(crate) fn build_progress_manifest(
    py: Python<'_>,
    archive: String,
    out_dir: String,
    round_index: u32,
    trace: Option<PyRef<'_, NativeOutputTrace>>,
    rows: Option<PyRef<'_, NativeWorkerManifest>>,
    worker_ok: bool,
    failure_stage: String,
    failure_kind: String,
    worker_status: String,
    native_status: String,
    files_written: u64,
    bytes_written: u64,
) -> NativeProgressManifest {
    let trace = trace
        .map(|value| Arc::clone(value.items()))
        .filter(|items| !items.is_empty());
    let rows = match trace {
        Some(_) => None,
        None => rows.map(|value| Arc::clone(value.records())),
    };
    let document = py.detach(move || {
        let mut files = Vec::new();
        if let Some(items) = trace {
            files.extend(
                items
                    .iter()
                    .filter(|item| !item.is_dir)
                    .map(|item| file_from_trace(item, &out_dir, round_index)),
            );
        } else if let Some(records) = rows {
            files.extend(
                records
                    .iter()
                    .map(|item| file_from_row(item, &out_dir, round_index)),
            );
        }
        merge_untraced_files(&mut files, &out_dir, round_index, worker_ok);
        let summary = Summary::of(&files);
        let files_written = if files_written > 0 {
            files_written
        } else {
            (summary.complete + summary.partial) as u64
        };
        let bytes_written = if bytes_written > 0 {
            bytes_written
        } else {
            files.iter().map(|item| item.bytes_written).sum()
        };
        ManifestDocument {
            version: 1,
            archive,
            out_dir,
            partial_outputs: summary.partial > 0 || summary.complete > 0 || summary.failed > 0,
            failure_stage,
            failure_kind,
            worker_status,
            native_status,
            files_written,
            bytes_written,
            summary,
            files,
        }
    });
    NativeProgressManifest {
        document: Arc::new(document),
    }
}

fn file_from_trace(item: &OutputTraceItem, out_dir: &str, round_index: u32) -> ProgressFile {
    let status = match (item.failed, item.bytes_written > 0) {
        (false, _) => FileStatus::Complete,
        (true, true) => FileStatus::Partial,
        (true, false) => FileStatus::Failed,
    };
    let output = if item.output_path.is_empty() {
        &item.path
    } else {
        &item.output_path
    };
    let source = if item.path.is_empty() {
        &item.output_path
    } else {
        &item.path
    };
    ProgressFile {
        path: output_path_text(output, out_dir),
        archive_path: archive_path_text(source, out_dir),
        status,
        source_round: round_index,
        bytes_written: item.bytes_written,
        expected_size: Some(item.expected_size),
        crc_ok: None,
        failure_stage: String::new(),
        failure_kind: String::new(),
        message: String::new(),
    }
}

fn file_from_row(item: &OutputFileRecord, out_dir: &str, round_index: u32) -> ProgressFile {
    let status = match item.status {
        0 | 1 => FileStatus::Complete,
        2 => FileStatus::Failed,
        _ => FileStatus::Unverified,
    };
    ProgressFile {
        path: output_path_text(item.output_path.as_deref().unwrap_or(&item.path), out_dir),
        archive_path: archive_path_text(&item.path, out_dir),
        status,
        source_round: round_index,
        bytes_written: item.bytes_written,
        expected_size: Some(item.size),
        crc_ok: item.crc_ok,
        failure_stage: String::new(),
        failure_kind: String::new(),
        message: String::new(),
    }
}

fn merge_untraced_files(
    files: &mut Vec<ProgressFile>,
    out_dir: &str,
    round_index: u32,
    worker_ok: bool,
) {
    let seen: HashSet<String> = files
        .iter()
        .filter(|item| !item.path.is_empty())
        .map(|item| item.path.clone())
        .collect();
    let inventory = scan_output_inventory_impl(out_dir);
    for record in inventory.records().iter() {
        let path = match &record.abs_path {
            Some(path) => windows_path_text(path),
            None => output_path_text(&record.path, out_dir),
        };
        if seen.contains(&path) {
            continue;
        }
        files.push(ProgressFile {
            path,
            archive_path: record.path.clone(),
            status: if worker_ok {
                FileStatus::Complete
            } else {
                FileStatus::Unverified
            },
            source_round: round_index,
            bytes_written: record.size,
            expected_size: None,
            crc_ok: None,
            failure_stage: String::new(),
            failure_kind: String::new(),
            message: UNTRACED_MESSAGE.to_string(),
        });
    }
}

/// Absolute output path of a traced item, spelled as Windows paths are.
fn output_path_text(path: &str, out_dir: &str) -> String {
    if path.is_empty() {
        return String::new();
    }
    if Path::new(path).is_absolute() {
        return windows_path_text(path);
    }
    windows_path_text(&format!("{out_dir}\\{path}"))
}

fn archive_path_text(path: &str, out_dir: &str) -> String {
    if path.is_empty() {
        return String::new();
    }
    let candidate = Path::new(path);
    if !candidate.is_absolute() {
        return path.replace('\\', "/");
    }
    match candidate.strip_prefix(out_dir) {
        Ok(relative) => relative.to_string_lossy().replace('\\', "/"),
        Err(_) => candidate
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default(),
    }
}

/// Backslash separators, no repeated separators, no `.` parts, no trailing separator.
fn windows_path_text(path: &str) -> String {
    let unified = path.replace('/', "\\");
    let (prefix, rest) = match unified.strip_prefix("\\\\") {
        Some(rest) => ("\\\\", rest),
        None => ("", unified.as_str()),
    };
    let rooted = rest.starts_with('\\');
    let parts: Vec<&str> = rest
        .split('\\')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect();
    let mut output = String::with_capacity(unified.len());
    output.push_str(prefix);
    if rooted {
        output.push('\\');
    }
    output.push_str(&parts.join("\\"));
    if parts.len() == 1 && parts[0].ends_with(':') && !rooted {
        output.push('\\');
    }
    output
}

fn round6(value: f64) -> f64 {
    (value * 1_000_000.0).round() / 1_000_000.0
}

#[cfg(test)]
mod tests {
    use super::{archive_path_text, output_path_text, windows_path_text};

    #[test]
    fn output_paths_match_windows_pathlib_spelling() {
        assert_eq!(output_path_text("a/b.txt", "C:\\out"), "C:\\out\\a\\b.txt");
        assert_eq!(
            output_path_text("a//./b.txt", "C:\\out\\"),
            "C:\\out\\a\\b.txt"
        );
        assert_eq!(output_path_text("D:/x/y.bin", "C:\\out"), "D:\\x\\y.bin");
        assert_eq!(
            windows_path_text("\\\\server\\share\\a/b"),
            "\\\\server\\share\\a\\b"
        );
        assert_eq!(windows_path_text("C:/"), "C:\\");
    }

    #[test]
    fn archive_paths_are_relative_with_forward_slashes() {
        assert_eq!(archive_path_text("dir\\a.txt", "C:\\out"), "dir/a.txt");
        assert_eq!(
            archive_path_text("C:\\out\\dir\\a.txt", "C:\\out"),
            "dir/a.txt"
        );
        assert_eq!(archive_path_text("D:\\other\\a.txt", "C:\\out"), "a.txt");
    }
}
