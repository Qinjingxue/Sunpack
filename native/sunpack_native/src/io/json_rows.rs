//! Immutable, lossless JSON arrays. Storage spills by bytes, never by row count.
//! Reports copy encoded chunks directly; Python decodes a row only on explicit access.
use super::cancellation::Cancellation;
use super::scratch::{Blob, Spool};
use pyo3::exceptions::PyIndexError;
use pyo3::prelude::*;
use serde::Serialize;
use std::io::{self, Write};

#[derive(Default)]
pub(crate) struct JsonArrayBuilder {
    data: Spool,
    offsets: Spool,
    count: usize,
}

impl JsonArrayBuilder {
    pub(crate) fn push<T: Serialize>(&mut self, value: &T) -> io::Result<()> {
        self.data.write_all(if self.count == 0 { b"[" } else { b"," })?;
        let start = self.data.len()?;
        serde_json::to_writer(&mut self.data, value).map_err(io::Error::other)?;
        self.offsets.write_all(&start.to_le_bytes())?;
        self.offsets.write_all(&self.data.len()?.to_le_bytes())?;
        self.count += 1;
        Ok(())
    }

    pub(crate) fn finish(mut self) -> io::Result<NativeJsonArray> {
        self.data.write_all(if self.count == 0 { b"[]" } else { b"]" })?;
        Ok(NativeJsonArray {
            data: self.data.finish()?,
            offsets: self.offsets.finish()?,
            count: self.count,
        })
    }
}

#[pyclass(module = "sunpack_native", frozen)]
pub(crate) struct NativeJsonArray {
    data: Blob,
    offsets: Blob,
    count: usize,
}

impl NativeJsonArray {
    pub(crate) fn write_json(&self, out: &mut impl Write, cancel: &Cancellation) -> io::Result<()> {
        let mut start = 0;
        while start < self.data.len() {
            cancel.check_io()?;
            let mut end = (start + 64 * 1024).min(self.data.len());
            // File sinks accept arbitrary bytes; text sinks need whole UTF-8.
            while end < self.data.len() && self.data[end] & 0xc0 == 0x80 { end -= 1; }
            out.write_all(&self.data[start..end])?;
            start = end;
        }
        Ok(())
    }
}

#[pymethods]
impl NativeJsonArray {
    fn __len__(&self) -> usize {
        self.count
    }

    fn __getitem__(&self, py: Python<'_>, index: isize) -> PyResult<Py<PyAny>> {
        let index = if index < 0 { self.count as isize + index } else { index };
        if index < 0 || index as usize >= self.count {
            return Err(PyIndexError::new_err("JSON row index out of range"));
        }
        let offset = index as usize * 16;
        let start = u64::from_le_bytes(self.offsets[offset..offset + 8].try_into().unwrap()) as usize;
        let end = u64::from_le_bytes(self.offsets[offset + 8..offset + 16].try_into().unwrap()) as usize;
        // Explicit UI/test row access, outside the report-writing hot path.
        let text = std::str::from_utf8(&self.data[start..end]).map_err(io::Error::other)?;
        Ok(py.import("json")?.call_method1("loads", (text,))?.unbind())
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.data.as_ref() == other.data.as_ref()
    }

    #[getter]
    fn spilled(&self) -> bool {
        matches!(self.data, Blob::Mapped(_))
    }

    #[getter]
    fn json_bytes(&self) -> usize {
        self.data.len()
    }
}
