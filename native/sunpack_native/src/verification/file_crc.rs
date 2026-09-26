use crate::io::reader::ManagedReader;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::io::Read;
use std::path::{Path, PathBuf};
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
