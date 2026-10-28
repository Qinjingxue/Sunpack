use crate::fast_hash_core::{hash_reader, Xxh64};
use crate::io::resource_lifecycle::TrackedFile;
use pyo3::exceptions::PyOSError;
use pyo3::prelude::*;
use std::io;
use std::path::Path;

#[pyfunction]
pub(crate) fn runtime_binary_build_id(py: Python<'_>, path: String) -> PyResult<String> {
    py.detach(move || hash_runtime_binary(Path::new(&path)))
        .map(|hash| format!("{hash:016x}"))
        .map_err(|error| PyOSError::new_err(error.to_string()))
}

fn hash_runtime_binary(path: &Path) -> io::Result<u64> {
    let file = TrackedFile::open_reader(path, "runtime_binary_build_id")?;
    let mut hash = Xxh64::new(0);
    hash_reader(file, |data| hash.update(data))?;
    Ok(hash.digest())
}
