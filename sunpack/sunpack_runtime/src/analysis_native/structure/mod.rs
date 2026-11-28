use crate::scan::compression_stream::{
    bzip2_may_end_at, gzip_head_extent, validate_bzip2_identity, validate_xz_identity,
    xz_has_terminal_footer, StreamReadiness,
};
use std::borrow::Cow;
use std::io;

include!("constants.rs");
include!("api.rs");
include!("compression.rs");
