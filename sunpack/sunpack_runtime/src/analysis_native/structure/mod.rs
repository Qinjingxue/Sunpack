use crc32fast::hash as crc32;
use std::io;
use crate::scan::compression_stream::{gzip_payload_offset_from_slice, validate_bzip2_identity, validate_xz_identity};

include!("constants.rs");
include!("api.rs");
include!("compression.rs");
