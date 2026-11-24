use crate::scan::compression_stream::{
    validate_bzip2_identity, validate_gzip_identity, validate_xz_identity,
    xz_has_terminal_footer, zstd_head_extent, StreamReadiness,
};
use std::borrow::Cow;
use std::io;

include!("constants.rs");
include!("api.rs");
include!("compression.rs");
