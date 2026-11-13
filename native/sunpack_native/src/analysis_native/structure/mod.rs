use crate::io::reader::ManagedReader;
use crc32fast::hash as crc32;
use std::io::Read;

include!("constants.rs");
include!("api.rs");
include!("compression.rs");
include!("util.rs");
