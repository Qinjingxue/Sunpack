use crate::io::read_fault::{read_exact_field, seek_field, FieldLocation, ReadFault};
use crate::io::reader::{ManagedReader, SourceCursor};
use crate::scan::magic::rfind_subslice;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::io::Read;

include!("constants.rs");
include!("api.rs");
include!("common.rs");
include!("seven_zip.rs");
include!("rar.rs");
include!("tar.rs");
include!("compression.rs");
include!("util.rs");
