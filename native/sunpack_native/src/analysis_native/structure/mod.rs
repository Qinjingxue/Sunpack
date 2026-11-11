use super::diagnostic::{lz4_diagnostic, DiagnosticFields, DiagnosticFieldsExt};
use crate::io::reader::ManagedReader;
use crc32fast::hash as crc32;
use std::io::Read;

include!("constants.rs");
include!("api.rs");
include!("common.rs");
include!("compression.rs");
include!("util.rs");
