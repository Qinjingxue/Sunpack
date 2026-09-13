use crate::io::reader::ManagedReader;
use pyo3::prelude::*;

pub(crate) const STREAM_CHUNK_SIZE: usize = 1024 * 1024;

pub(crate) fn read_range(path: &str, start: u64, len: u64) -> PyResult<Vec<u8>> {
    let reader = ManagedReader::open(path)?;
    Ok(reader.read_exact_at(start, len as usize)?)
}
