use crate::io::read_fault::{FieldLocation, ReadFault};
use crate::io::reader::{ManagedReader, ReaderConfig};
use crate::password::rar::{probe_header_encrypted_terminal, RarTerminalProof};
use bzip2::read::BzDecoder;
use flate2::read::GzDecoder;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use std::io::{self, Read};
use xz2::read::XzDecoder;
use zstd::stream::read::Decoder as ZstdDecoder;

include!("constants.rs");
include!("types.rs");
include!("binary.rs");
include!("multivolume.rs");
include!("impls.rs");
include!("signatures.rs");
include!("tar.rs");
include!("compression.rs");

#[pyfunction]
pub(crate) fn probe_rar_bytes(
    py: Python<'_>,
    data: &Bound<'_, PyBytes>,
    start_offset: u64,
    max_blocks_to_walk: usize,
) -> PyResult<Py<PyDict>> {
    let view = AnalysisBinaryView {
        path: "<memory>".to_string(),
        reader: ManagedReader::from_bytes(data.as_bytes().to_vec(), ReaderConfig::default()),
        closed: false,
    };
    view.probe_rar(py, start_offset, max_blocks_to_walk)
}

/// Internal relation validators reuse the canonical view parsers without
/// opening a second Python-side binary-analysis path. These helpers keep
/// path-based construction and all binary I/O inside Rust.
pub(crate) fn probe_rar_path(
    py: Python<'_>,
    path: &str,
    start_offset: u64,
    max_blocks_to_walk: usize,
) -> PyResult<Py<PyDict>> {
    let reader = ManagedReader::open(path).map_err(reader_error_to_py)?;
    AnalysisBinaryView {
        path: path.to_string(),
        reader,
        closed: false,
    }
    .probe_rar(py, start_offset, max_blocks_to_walk)
}

pub(crate) fn probe_rar_volume_paths(
    py: Python<'_>,
    paths: &[String],
    start_offset: u64,
    max_blocks_to_walk: usize,
) -> PyResult<Py<PyDict>> {
    let reader = ManagedReader::open_volumes(
        paths,
        ReaderConfig {
            cache_bytes: 64 * 1024 * 1024,
            max_read_bytes: None,
            max_concurrent_reads: 1,
        },
    )
    .map_err(reader_error_to_py)?;
    AnalysisBinaryView {
        path: paths.first().cloned().unwrap_or_default(),
        reader,
        closed: false,
    }
    .probe_rar(py, start_offset, max_blocks_to_walk)
}

pub(crate) fn probe_rar_terminal_with_password(
    paths: &[String],
    start_offset: u64,
    password: &str,
    max_blocks: usize,
) -> io::Result<Option<RarTerminalProof>> {
    let reader = if paths.len() == 1 {
        ManagedReader::open(&paths[0])?
    } else {
        ManagedReader::open_volumes(
            paths,
            ReaderConfig {
                cache_bytes: 64 * 1024 * 1024,
                max_read_bytes: None,
                max_concurrent_reads: 1,
            },
        )?
    };
    probe_header_encrypted_terminal(&reader, start_offset, password, max_blocks)
}

fn reader_error_to_py(error: std::io::Error) -> PyErr {
    if error.to_string() == "archive analysis read budget exceeded" {
        pyo3::exceptions::PyRuntimeError::new_err(error.to_string())
    } else {
        error.into()
    }
}

fn set_view_read_fault(
    result: &Bound<'_, PyDict>,
    fault: &ReadFault,
    legacy_error: &str,
) -> PyResult<()> {
    result.set_item("error", legacy_error)?;
    fault.write_python(result)?;
    let mut flags = result
        .get_item("damage_flags")?
        .and_then(|value| value.extract::<Vec<String>>().ok())
        .unwrap_or_default();
    let mut push_flag = |flag: &str| {
        if !flags.iter().any(|existing| existing == flag) {
            flags.push(flag.to_string());
        }
    };
    push_flag("read_error");
    if fault.code == "unexpected_eof" {
        push_flag("input_truncated");
        push_flag("probably_truncated");
    }
    if fault.possible_missing_volume() {
        push_flag("missing_volume");
    }
    result.set_item("damage_flags", PyList::new(result.py(), flags)?)
}
