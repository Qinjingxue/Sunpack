use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::sync::Arc;

/// One regular-file entry of a source-side archive walk.
///
/// `path` is the projected output name; `raw_path` is only stored when the
/// projection differs from the name recorded in the archive (TAR duplicates).
#[derive(Clone)]
pub(crate) struct ManifestEntry {
    pub(crate) path: String,
    pub(crate) raw_path: Option<String>,
    pub(crate) size: u64,
    pub(crate) crc32: Option<u32>,
}

/// Summary plus a Rust-owned entry table for one archive-input manifest.
///
/// Python only sees aggregate fields and bounded views; the per-entry table
/// never becomes Python objects on the verification path.
#[pyclass(module = "sunpack_native", frozen)]
pub(crate) struct NativeArchiveManifest {
    pub(crate) status: i64,
    pub(crate) is_archive: bool,
    pub(crate) damaged: bool,
    pub(crate) checksum_error: bool,
    pub(crate) item_count: usize,
    pub(crate) file_count: usize,
    pub(crate) total_unpacked_size: u64,
    pub(crate) message: String,
    pub(crate) archive_type: String,
    pub(crate) source: String,
    pub(crate) archive_walk_complete: bool,
    pub(crate) verified_item_count: usize,
    pub(crate) failure_kind: String,
    pub(crate) entries: Arc<Vec<ManifestEntry>>,
}

impl NativeArchiveManifest {
    pub(crate) fn entries_view(&self, limit: Option<usize>) -> &[ManifestEntry] {
        let end = limit.unwrap_or(self.entries.len()).min(self.entries.len());
        &self.entries[..end]
    }
}

#[pymethods]
impl NativeArchiveManifest {
    #[getter]
    fn status(&self) -> i64 {
        self.status
    }
    #[getter]
    fn is_archive(&self) -> bool {
        self.is_archive
    }
    #[getter]
    fn damaged(&self) -> bool {
        self.damaged
    }
    #[getter]
    fn checksum_error(&self) -> bool {
        self.checksum_error
    }
    #[getter]
    fn item_count(&self) -> usize {
        self.item_count
    }
    #[getter]
    fn file_count(&self) -> usize {
        self.file_count
    }
    #[getter]
    fn total_unpacked_size(&self) -> u64 {
        self.total_unpacked_size
    }
    #[getter]
    fn message(&self) -> &str {
        &self.message
    }
    #[getter]
    fn archive_type(&self) -> &str {
        &self.archive_type
    }
    #[getter]
    fn source(&self) -> &str {
        &self.source
    }
    #[getter]
    fn archive_walk_complete(&self) -> bool {
        self.archive_walk_complete
    }
    #[getter]
    fn verified_item_count(&self) -> usize {
        self.verified_item_count
    }
    #[getter]
    fn failure_kind(&self) -> &str {
        &self.failure_kind
    }

    fn __len__(&self) -> usize {
        self.entries.len()
    }

    /// Projected entry names among the first `limit` retained entries.
    #[pyo3(signature = (limit=None))]
    fn expected_names(&self, limit: Option<usize>) -> Vec<String> {
        self.entries_view(limit)
            .iter()
            .filter(|item| !item.path.is_empty())
            .map(|item| item.path.clone())
            .collect()
    }

    #[pyo3(signature = (offset=0, limit=128))]
    fn entry_page(&self, py: Python<'_>, offset: usize, limit: usize) -> PyResult<Vec<Py<PyDict>>> {
        if limit == 0 || offset >= self.entries.len() {
            return Ok(Vec::new());
        }
        let end = offset.saturating_add(limit).min(self.entries.len());
        self.entries[offset..end]
            .iter()
            .map(|item| {
                let row = PyDict::new(py);
                row.set_item("path", &item.path)?;
                row.set_item("archive_path", item.raw_path.as_ref().unwrap_or(&item.path))?;
                row.set_item("size", item.size)?;
                row.set_item("has_crc", item.crc32.is_some())?;
                if let Some(crc32) = item.crc32 {
                    row.set_item("crc32", crc32)?;
                }
                Ok(row.unbind())
            })
            .collect()
    }
}
