//! Parse one sevenzip worker stdout line straight into Python objects.
//!
//! The per-item arrays of a result event (`verified_manifest.rows` and
//! `diagnostics.output_trace.items`) grow with the archive's item count, so
//! they are decoded into Rust-owned tables while the rest of the event becomes
//! an ordinary Python dict. Python never holds the raw line as parsed JSON.

use crate::scan::directory::{decode_hex_bytes, NativeWorkerManifest, OutputFileRecord};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyString};
use pyo3::IntoPyObjectExt;
use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use std::borrow::Cow;
use std::fmt;
use std::sync::Arc;

/// One `diagnostics.output_trace.items` entry, as emitted by the worker.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub(crate) struct OutputTraceItem {
    pub(crate) index: u32,
    pub(crate) path: String,
    pub(crate) output_path: String,
    pub(crate) is_dir: bool,
    pub(crate) encrypted: bool,
    pub(crate) bytes_written: u64,
    pub(crate) expected_size: u64,
    pub(crate) has_expected_size: bool,
    pub(crate) source_crc32: u32,
    pub(crate) has_source_crc32: bool,
    pub(crate) output_crc32: u32,
    pub(crate) has_output_crc32: bool,
    pub(crate) crc_verified: bool,
    pub(crate) operation_result: i64,
    pub(crate) operation_result_name: String,
    pub(crate) hresult: i64,
    pub(crate) hresult_hex: String,
    pub(crate) win32_error: i64,
    pub(crate) done: bool,
    pub(crate) failed: bool,
}

/// Rust-owned `output_trace.items` table of one worker result.
#[pyclass(module = "sunpack_native", frozen)]
pub(crate) struct NativeOutputTrace {
    items: Arc<Vec<OutputTraceItem>>,
}

impl NativeOutputTrace {
    pub(crate) fn items(&self) -> &Arc<Vec<OutputTraceItem>> {
        &self.items
    }
}

#[pymethods]
impl NativeOutputTrace {
    fn __len__(&self) -> usize {
        self.items.len()
    }

    /// True when any traced item wrote bytes or reached an unfailed path.
    fn has_progress(&self) -> bool {
        self.items
            .iter()
            .any(|item| item.bytes_written > 0 || (!item.path.is_empty() && !item.failed))
    }

    #[pyo3(signature = (offset=0, limit=128))]
    fn item_page(&self, py: Python<'_>, offset: usize, limit: usize) -> PyResult<Vec<Py<PyDict>>> {
        if limit == 0 || offset >= self.items.len() {
            return Ok(Vec::new());
        }
        let end = offset.saturating_add(limit).min(self.items.len());
        self.items[offset..end]
            .iter()
            .map(|item| {
                let row = PyDict::new(py);
                row.set_item("index", item.index)?;
                row.set_item("path", &item.path)?;
                row.set_item("output_path", &item.output_path)?;
                row.set_item("is_dir", item.is_dir)?;
                row.set_item("encrypted", item.encrypted)?;
                row.set_item("bytes_written", item.bytes_written)?;
                row.set_item("expected_size", item.expected_size)?;
                row.set_item("has_expected_size", item.has_expected_size)?;
                row.set_item("source_crc32", item.source_crc32)?;
                row.set_item("has_source_crc32", item.has_source_crc32)?;
                row.set_item("output_crc32", item.output_crc32)?;
                row.set_item("has_output_crc32", item.has_output_crc32)?;
                row.set_item("crc_verified", item.crc_verified)?;
                row.set_item("operation_result", item.operation_result)?;
                row.set_item("operation_result_name", &item.operation_result_name)?;
                row.set_item("hresult", item.hresult)?;
                row.set_item("hresult_hex", &item.hresult_hex)?;
                row.set_item("win32_error", item.win32_error)?;
                row.set_item("done", item.done)?;
                row.set_item("failed", item.failed)?;
                Ok(row.unbind())
            })
            .collect()
    }
}

/// Parse one worker line (``bytes`` or ``str``); ``None`` when it is not a JSON object event.
#[pyfunction]
pub(crate) fn parse_worker_event(
    py: Python<'_>,
    line: &Bound<'_, PyAny>,
) -> PyResult<Option<Py<PyDict>>> {
    let text: Cow<'_, str> = if let Ok(bytes) = line.cast::<PyBytes>() {
        String::from_utf8_lossy(bytes.as_bytes())
    } else {
        line.cast::<PyString>()?.to_cow()?
    };
    let text = text.trim();
    if !text.starts_with('{') {
        return Ok(None);
    }
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let Ok(value) = PySeed {
        py,
        scope: Scope::Root,
    }
    .deserialize(&mut deserializer) else {
        return Ok(None);
    };
    if deserializer.end().is_err() {
        return Ok(None);
    }
    Ok(value
        .bind(py)
        .cast::<PyDict>()
        .ok()
        .map(|dict| dict.clone().unbind()))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Scope {
    Root,
    Manifest,
    Diagnostics,
    OutputTrace,
    Plain,
}

struct PySeed<'py> {
    py: Python<'py>,
    scope: Scope,
}

fn py_error<E: de::Error>(error: PyErr) -> E {
    E::custom(error.to_string())
}

impl<'de, 'py> DeserializeSeed<'de> for PySeed<'py> {
    type Value = Py<PyAny>;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de, 'py> Visitor<'de> for PySeed<'py> {
    type Value = Py<PyAny>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
        value.into_py_any(self.py).map_err(py_error)
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
        value.into_py_any(self.py).map_err(py_error)
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
        value.into_py_any(self.py).map_err(py_error)
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
        value.into_py_any(self.py).map_err(py_error)
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(PyString::new(self.py, value).into_any().unbind())
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(self.py.None())
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(self.py.None())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let list = PyList::empty(self.py);
        while let Some(value) = seq.next_element_seed(PySeed {
            py: self.py,
            scope: Scope::Plain,
        })? {
            list.append(value).map_err(py_error)?;
        }
        Ok(list.into_any().unbind())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let py = self.py;
        let dict = PyDict::new(py);
        let mut manifest_v3 = false;
        let mut inventory = None::<[u64; 5]>;
        let mut rows = None::<Vec<OutputFileRecord>>;
        while let Some(key) = map.next_key::<String>()? {
            match (self.scope, key.as_str()) {
                (Scope::Manifest, "rows") if manifest_v3 => {
                    rows = Some(map.next_value::<WorkerRows>()?.0);
                    continue;
                }
                (Scope::Manifest, "inventory") if manifest_v3 => {
                    let columns = map.next_value::<[u64; 5]>()?;
                    let summary = PyDict::new(py);
                    let entries: [(&str, Py<PyAny>); 5] = [
                        (
                            "complete",
                            (columns[0] != 0).into_py_any(py).map_err(py_error)?,
                        ),
                        ("file_count", columns[1].into_py_any(py).map_err(py_error)?),
                        ("dir_count", columns[2].into_py_any(py).map_err(py_error)?),
                        ("total_size", columns[3].into_py_any(py).map_err(py_error)?),
                        (
                            "identity_paths",
                            (columns[4] != 0).into_py_any(py).map_err(py_error)?,
                        ),
                    ];
                    for (name, value) in entries {
                        summary.set_item(name, value).map_err(py_error)?;
                    }
                    dict.set_item("inventory", summary).map_err(py_error)?;
                    inventory = Some(columns);
                    continue;
                }
                (Scope::OutputTrace, "items") => {
                    let items = map.next_value::<Vec<OutputTraceItem>>()?;
                    let native = Py::new(
                        py,
                        NativeOutputTrace {
                            items: Arc::new(items),
                        },
                    )
                    .map_err(py_error)?;
                    dict.set_item("native_items", native).map_err(py_error)?;
                    continue;
                }
                _ => {}
            }
            let child = match (self.scope, key.as_str()) {
                (Scope::Root, "verified_manifest") => Scope::Manifest,
                (Scope::Root, "diagnostics") => Scope::Diagnostics,
                (Scope::Diagnostics, "output_trace") => Scope::OutputTrace,
                _ => Scope::Plain,
            };
            let value = map.next_value_seed(PySeed { py, scope: child })?;
            if self.scope == Scope::Manifest && key == "version" {
                manifest_v3 = value.bind(py).extract::<i64>().ok() == Some(3);
            }
            dict.set_item(key, value).map_err(py_error)?;
        }
        if let Some(files) = rows.filter(|files| !files.is_empty()) {
            let columns = inventory.unwrap_or([0, files.len() as u64, 0, 0, 0]);
            let manifest = NativeWorkerManifest::from_parts(files, columns).map_err(py_error)?;
            dict.set_item("native_rows", Py::new(py, manifest).map_err(py_error)?)
                .map_err(py_error)?;
        }
        Ok(dict.into_any().unbind())
    }
}

/// `verified_manifest.rows` v3: one fixed 14-column array per regular file.
struct WorkerRows(Vec<OutputFileRecord>);

type WorkerRow = (
    u32,
    String,
    String,
    u64,
    u64,
    u8,
    u32,
    u8,
    u32,
    u8,
    u8,
    u8,
    u64,
    String,
);

impl<'de> Deserialize<'de> for WorkerRows {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct RowsVisitor;

        impl<'de> Visitor<'de> for RowsVisitor {
            type Value = WorkerRows;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("worker manifest v3 rows")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<WorkerRows, A::Error> {
                let mut files = Vec::with_capacity(seq.size_hint().unwrap_or(0));
                while let Some(row) = seq.next_element::<WorkerRow>()? {
                    let (
                        index,
                        path,
                        raw_output_path,
                        size,
                        bytes_written,
                        has_crc,
                        source_crc32,
                        has_output_crc,
                        output_crc32,
                        crc_ok,
                        status,
                        has_mtime,
                        mtime_ns,
                        magic_hex,
                    ) = row;
                    files.push(OutputFileRecord {
                        index,
                        output_path: (!raw_output_path.is_empty() && raw_output_path != path)
                            .then_some(raw_output_path),
                        path,
                        abs_path: None,
                        size,
                        bytes_written,
                        crc32: (has_crc != 0).then_some(source_crc32),
                        output_crc32: (has_output_crc != 0).then_some(output_crc32),
                        crc_ok: Some(crc_ok != 0),
                        status,
                        mtime_ns: (has_mtime != 0).then_some(mtime_ns),
                        magic: decode_hex_bytes(&magic_hex).map_err(py_error)?,
                    });
                }
                Ok(WorkerRows(files))
            }
        }

        deserializer.deserialize_seq(RowsVisitor)
    }
}
