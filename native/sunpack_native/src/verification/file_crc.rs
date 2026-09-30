use crate::io::reader::ManagedReader;
use crc32fast::Hasher as Crc32Hasher;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::io::Read;
use std::path::{Path, PathBuf};

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

fn scan_crc_manifest(root: &Path, limit: usize) -> ManifestScan {
    if !root.exists() {
        return ManifestScan {
            status: "missing",
            files: Vec::new(),
            errors: Vec::new(),
            total_files: 0,
            scanned_files: 0,
        };
    }
    if !root.is_dir() {
        return ManifestScan {
            status: "not_directory",
            files: Vec::new(),
            errors: Vec::new(),
            total_files: 0,
            scanned_files: 0,
        };
    }
    let mut files = Vec::new();
    let mut errors = Vec::new();
    let mut total_files = 0;
    let mut scanned_files = 0;
    let mut buffer = vec![0u8; BUFFER_SIZE];
    walk_crc_manifest(
        root,
        root,
        limit,
        &mut total_files,
        &mut scanned_files,
        &mut files,
        &mut errors,
        &mut buffer,
    );
    ManifestScan {
        status: "ok",
        files,
        errors,
        total_files,
        scanned_files,
    }
}

fn walk_crc_manifest(
    root: &Path,
    current: &Path,
    limit: usize,
    total_files: &mut usize,
    scanned_files: &mut usize,
    files: &mut Vec<FileCrcRecord>,
    errors: &mut Vec<ScanError>,
    buffer: &mut [u8],
) {
    let entries = match std::fs::read_dir(current) {
        Ok(v) => v,
        Err(err) => {
            push_scan_error(errors, current, root, err.to_string());
            return;
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(v) => v,
            Err(err) => {
                push_scan_error(errors, current, root, err.to_string());
                continue;
            }
        };
        let path = entry.path();
        let metadata = match entry.metadata() {
            Ok(v) => v,
            Err(err) => {
                push_scan_error(errors, &path, root, err.to_string());
                continue;
            }
        };
        if metadata.is_dir() {
            walk_crc_manifest(
                root,
                &path,
                limit,
                total_files,
                scanned_files,
                files,
                errors,
                buffer,
            );
            continue;
        }
        if !metadata.is_file() {
            continue;
        }
        *total_files += 1;
        if *scanned_files >= limit {
            continue;
        }
        match crc32_file_with_buffer(&path, buffer) {
            Ok(crc32) => {
                files.push(FileCrcRecord {
                    path: relative_path(&path, root),
                    size: metadata.len(),
                    crc32,
                });
                *scanned_files += 1;
            }
            Err(err) => push_scan_error(errors, &path, root, err.to_string()),
        }
    }
}

fn push_scan_error(errors: &mut Vec<ScanError>, path: &Path, root: &Path, message: String) {
    errors.push(ScanError {
        path: relative_path(path, root),
        message,
    });
}

fn append_errors_to_py(
    py: Python<'_>,
    errors: &Bound<'_, PyList>,
    scan_errors: &[ScanError],
) -> PyResult<()> {
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
    if scan.status != "ok" {
        return Ok(result.unbind());
    }
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
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize())
}
