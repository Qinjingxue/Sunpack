use flate2::{Decompress, FlushDecompress, Status};
use memchr::memmem;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

const LFH_SIG: &[u8] = b"PK\x03\x04";
const DD_SIG: &[u8] = b"PK\x07\x08";
const CD_SIG: &[u8] = b"PK\x01\x02";
const EOCD_SIG: &[u8] = b"PK\x05\x06";
const ZIP64_EOCD_SIG: &[u8] = b"PK\x06\x06";
const ZIP64_LOCATOR_SIG: &[u8] = b"PK\x06\x07";
const LOCAL_HEADER_LEN: usize = 30;
const COPY_CHUNK_SIZE: usize = 1024 * 1024;

