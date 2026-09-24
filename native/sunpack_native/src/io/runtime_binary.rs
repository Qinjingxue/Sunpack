use crate::io::resource_lifecycle::TrackedFile;
use pyo3::exceptions::PyOSError;
use pyo3::prelude::*;
use std::io::{self, Read};
use std::path::Path;

const FNV_OFFSET_BASIS: u64 = 0xCBF2_9CE4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01B3;
const READ_BUFFER_SIZE: usize = 1024 * 1024;

#[pyfunction]
pub(crate) fn runtime_binary_build_id(py: Python<'_>, path: String) -> PyResult<String> {
    py.detach(move || hash_runtime_binary(Path::new(&path)))
        .map(|hash| format!("{hash:016x}"))
        .map_err(|error| PyOSError::new_err(error.to_string()))
}

fn hash_runtime_binary(path: &Path) -> io::Result<u64> {
    let mut file = TrackedFile::open_reader(path, "runtime_binary_build_id")?;
    let mut buffer = vec![0u8; READ_BUFFER_SIZE];
    let mut hash = FNV_OFFSET_BASIS;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        for byte in &buffer[..count] {
            hash = (hash ^ u64::from(*byte)).wrapping_mul(FNV_PRIME);
        }
    }
    Ok(hash)
}
