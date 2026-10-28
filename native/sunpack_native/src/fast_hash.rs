//! Stable non-cryptographic identities using the already bundled XXH64.
pub(crate) use crate::fast_hash_core::xxh64;
use crate::fast_hash_core::{hash_reader, Hash128};
use crate::io::resource_lifecycle::TrackedFile;
use pyo3::prelude::*;
use std::path::PathBuf;

#[pyfunction]
pub(crate) fn fast_hash64(py: Python<'_>, data: &[u8]) -> String {
    py.detach(|| format!("{:016x}", xxh64(data, 0)))
}

#[pyfunction]
pub(crate) fn fast_hash128(py: Python<'_>, data: &[u8]) -> String {
    py.detach(|| format!("{:016x}{:016x}", xxh64(data, 0), xxh64(data, 1)))
}

#[pyclass(module = "sunpack_native")]
pub(crate) struct FastHash128(Hash128);

#[pymethods]
impl FastHash128 {
    #[new]
    fn new() -> Self {
        Self(Hash128::new())
    }

    fn update(&mut self, py: Python<'_>, data: &[u8]) {
        py.detach(|| self.0.update(data));
    }

    fn hexdigest(&self) -> String {
        self.0.hexdigest()
    }
}

#[pyfunction]
pub(crate) fn fast_hash128_file(py: Python<'_>, path: PathBuf) -> PyResult<String> {
    py.detach(move || {
        let file = TrackedFile::open_reader(path, "fast_hash128_file")?;
        let mut digest = Hash128::new();
        hash_reader(file, |data| digest.update(data))?;
        Ok(digest.hexdigest())
    })
}

#[cfg(test)]
mod tests {
    use super::xxh64;

    #[test]
    fn bundled_xxh64_vectors() {
        assert_eq!(xxh64(b"", 0), 0xef46db3751d8e999);
        assert_eq!(xxh64(b"a", 0), 0xd24ec4f1a98c6e5b);
        assert_ne!(xxh64(b"", 0), xxh64(b"", 1));
    }
}
