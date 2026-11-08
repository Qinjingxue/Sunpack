use crate::io::reader::ManagedReader;
use crc32fast::hash as crc32;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::io::Read;

include!("constants.rs");
include!("api.rs");
include!("common.rs");
include!("compression.rs");
include!("util.rs");
