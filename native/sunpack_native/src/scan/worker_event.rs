//! Parse one sevenzip worker stdout line straight into Python objects.
//!
//! Per-item manifest and trace chunks are decoded directly into Rust-owned
//! tables. A job accumulator moves them into the final native_rows/native_items
//! objects while only event envelopes and result summaries become Python dicts.

use crate::scan::directory::{decode_hex_bytes, NativeWorkerManifest, OutputFileRecord};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyString};
use pyo3::IntoPyObjectExt;
use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use std::borrow::Cow;
use std::fmt;
use std::sync::Arc;

/// One `diagnostics.output_trace.items` entry, as emitted by the worker.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
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
        let mut inventory = None::<[u64; 5]>;
        let mut rows = None::<Vec<OutputFileRecord>>;
        while let Some(key) = map.next_key::<String>()? {
            match (self.scope, key.as_str()) {
                (Scope::Manifest, "rows") => {
                    rows = Some(map.next_value::<WorkerRows>()?.0);
                    continue;
                }
                (Scope::Manifest, "inventory") => {
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
                (Scope::Root, "rows") => {
                    let chunk = WorkerChunk {
                        data: Some(ChunkData::Manifest(map.next_value::<WorkerRows>()?.0)),
                    };
                    dict.set_item("native_chunk", Py::new(py, chunk).map_err(py_error)?)
                        .map_err(py_error)?;
                    continue;
                }
                (Scope::Root, "items") => {
                    let chunk = WorkerChunk {
                        data: Some(ChunkData::Trace(map.next_value::<Vec<OutputTraceItem>>()?)),
                    };
                    dict.set_item("native_chunk", Py::new(py, chunk).map_err(py_error)?)
                        .map_err(py_error)?;
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
            dict.set_item(key, value).map_err(py_error)?;
        }
        if let Some(files) = rows {
            let columns = inventory.ok_or_else(|| de::Error::missing_field("inventory"))?;
            let manifest = NativeWorkerManifest::from_parts(files, columns).map_err(py_error)?;
            dict.set_item("native_rows", Py::new(py, manifest).map_err(py_error)?)
                .map_err(py_error)?;
        }
        Ok(dict.into_any().unbind())
    }
}

enum ChunkData {
    Manifest(Vec<OutputFileRecord>),
    Trace(Vec<OutputTraceItem>),
}

#[pyclass]
struct WorkerChunk {
    data: Option<ChunkData>,
}

/// Transport-only storage. Chunk vectors are moved into the job's tables;
/// finalization moves those tables into the existing immutable native objects.
#[pyclass(module = "sunpack_native")]
pub(crate) struct NativeWorkerResultAccumulator {
    job_id: String,
    manifest_seq: usize,
    trace_seq: usize,
    files: Vec<OutputFileRecord>,
    items: Vec<OutputTraceItem>,
    finished: bool,
}

#[pymethods]
impl NativeWorkerResultAccumulator {
    #[new]
    fn new(job_id: String) -> Self {
        Self {
            job_id,
            manifest_seq: 0,
            trace_seq: 0,
            files: Vec::new(),
            items: Vec::new(),
            finished: false,
        }
    }

    /// True for a consumed chunk; result events are finalized in place.
    fn accept(&mut self, py: Python<'_>, payload: &Bound<'_, PyDict>) -> PyResult<bool> {
        let kind = payload
            .get_item("type")?
            .ok_or_else(|| PyValueError::new_err("worker event type missing"))?
            .extract::<String>()?;
        if !matches!(kind.as_str(), "manifest_chunk" | "trace_chunk" | "result") {
            return Ok(false);
        }
        if self.finished {
            return Err(PyValueError::new_err("worker data received after result"));
        }
        let job_id = payload
            .get_item("job_id")?
            .ok_or_else(|| PyValueError::new_err("worker job_id missing"))?
            .extract::<String>()?;
        if job_id != self.job_id {
            return Err(PyValueError::new_err("worker chunk belongs to another job"));
        }
        if kind != "result" {
            let seq = payload
                .get_item("seq")?
                .ok_or_else(|| PyValueError::new_err("worker chunk sequence missing"))?
                .extract::<usize>()?;
            let expected = if kind == "manifest_chunk" {
                self.manifest_seq
            } else {
                self.trace_seq
            };
            if seq != expected {
                return Err(PyValueError::new_err(format!(
                    "{kind} sequence {seq}, expected {expected}"
                )));
            }
            let chunk = payload
                .get_item("native_chunk")?
                .ok_or_else(|| PyValueError::new_err("worker chunk data missing"))?;
            let mut chunk = chunk.extract::<PyRefMut<'_, WorkerChunk>>()?;
            match chunk.data.take() {
                Some(ChunkData::Manifest(mut files)) if kind == "manifest_chunk" => {
                    self.files.append(&mut files);
                    self.manifest_seq += 1;
                }
                Some(ChunkData::Trace(mut items)) if kind == "trace_chunk" => {
                    self.items.append(&mut items);
                    self.trace_seq += 1;
                }
                _ => return Err(PyValueError::new_err("worker chunk data type mismatch")),
            }
            return Ok(true);
        }

        let manifest = payload.get_item("verified_manifest")?;
        let trace = payload
            .get_item("diagnostics")?
            .map(|value| value.cast_into::<PyDict>())
            .transpose()?
            .map(|dict| dict.get_item("output_trace"))
            .transpose()?
            .flatten();
        if let Some(manifest) = &manifest {
            let manifest = manifest.cast::<PyDict>()?;
            check_chunk_summary(manifest, self.manifest_seq, self.files.len(), "file_count")?;
        } else if self.manifest_seq != 0 {
            return Err(PyValueError::new_err(
                "manifest chunks have no result summary",
            ));
        }
        if let Some(trace) = &trace {
            check_chunk_summary(
                trace.cast::<PyDict>()?,
                self.trace_seq,
                self.items.len(),
                "item_count",
            )?;
        } else if self.trace_seq != 0 {
            return Err(PyValueError::new_err("trace chunks have no result summary"));
        }

        if let Some(manifest) = manifest {
            let manifest = manifest.cast::<PyDict>()?;
            let inventory = manifest
                .get_item("inventory")?
                .ok_or_else(|| PyValueError::new_err("manifest inventory missing"))?;
            let inventory = inventory.cast::<PyDict>()?;
            let field = |key: &str| {
                inventory.get_item(key)?.ok_or_else(|| {
                    PyValueError::new_err(format!("manifest inventory {key} missing"))
                })
            };
            let columns = [
                u64::from(field("complete")?.is_truthy()?),
                field("file_count")?.extract::<u64>()?,
                field("dir_count")?.extract::<u64>()?,
                field("total_size")?.extract::<u64>()?,
                u64::from(field("identity_paths")?.is_truthy()?),
            ];
            let native =
                NativeWorkerManifest::from_parts(std::mem::take(&mut self.files), columns)?;
            manifest.set_item("native_rows", Py::new(py, native)?)?;
            manifest.del_item("chunk_count")?;
        }
        if let Some(trace) = trace {
            let trace = trace.cast::<PyDict>()?;
            trace.set_item(
                "native_items",
                Py::new(
                    py,
                    NativeOutputTrace {
                        items: Arc::new(std::mem::take(&mut self.items)),
                    },
                )?,
            )?;
            trace.del_item("chunk_count")?;
            trace.del_item("item_count")?;
        }
        self.finished = true;
        Ok(false)
    }
}

fn check_chunk_summary(
    dict: &Bound<'_, PyDict>,
    chunks: usize,
    rows: usize,
    count_key: &str,
) -> PyResult<()> {
    let count = |key: &str| -> PyResult<usize> {
        dict.get_item(key)?
            .ok_or_else(|| PyValueError::new_err(format!("worker summary {key} missing")))?
            .extract()
    };
    if count("chunk_count")? != chunks || count(count_key)? != rows {
        return Err(PyValueError::new_err("worker chunk summary count mismatch"));
    }
    Ok(())
}

/// The normal parser is single-pass. On a malformed event only, recover the
/// top-level routing prefix without parsing the damaged per-item body again.
#[pyfunction]
pub(crate) fn parse_worker_transport_event(
    py: Python<'_>,
    line: &Bound<'_, PyAny>,
) -> PyResult<Py<PyDict>> {
    if let Some(payload) = parse_worker_event(py, line)? {
        return Ok(payload);
    }
    let text = if let Ok(bytes) = line.cast::<PyBytes>() {
        String::from_utf8_lossy(bytes.as_bytes())
    } else {
        line.cast::<PyString>()?.to_cow()?
    };
    let job_id = recover_job_id(&text)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| PyValueError::new_err("unattributable worker protocol error"))?;
    let payload = PyDict::new(py);
    payload.set_item("type", "protocol_error")?;
    payload.set_item("job_id", job_id)?;
    payload.set_item("message", "malformed worker event")?;
    Ok(payload.unbind())
}

fn recover_job_id(text: &str) -> Option<String> {
    let mut rest = text.trim_start().strip_prefix('{')?.trim_start();
    loop {
        let mut key = serde_json::Deserializer::from_str(rest).into_iter::<String>();
        let name = key.next()?.ok()?;
        rest = rest[key.byte_offset()..]
            .trim_start()
            .strip_prefix(':')?
            .trim_start();
        if name == "job_id" {
            return serde_json::Deserializer::from_str(rest)
                .into_iter::<String>()
                .next()?
                .ok();
        }
        let mut value = serde_json::Deserializer::from_str(rest).into_iter::<de::IgnoredAny>();
        value.next()?.ok()?;
        rest = rest[value.byte_offset()..]
            .trim_start()
            .strip_prefix(',')?
            .trim_start();
    }
}

/// One fixed 14-column array per regular file in the worker manifest.
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
                formatter.write_str("worker manifest rows")
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
