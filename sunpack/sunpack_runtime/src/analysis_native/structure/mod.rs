use crate::scan::compression_stream::{
    validate_bzip2_identity, validate_gzip_identity, validate_xz_identity,
};
use std::io;

include!("constants.rs");
include!("api.rs");
include!("compression.rs");
