//! Named fields used by detailed format diagnostics and scan output.
use serde::Serialize;
use serde_json::{Map, Value};
use std::io;

pub(super) type DiagnosticFields = Map<String, Value>;

pub(super) trait DiagnosticFieldsExt {
    fn put(&mut self, name: &str, value: impl Serialize) -> io::Result<()>;
}

impl DiagnosticFieldsExt for DiagnosticFields {
    fn put(&mut self, name: &str, value: impl Serialize) -> io::Result<()> {
        self.insert(name.to_owned(), serde_json::to_value(value)?);
        Ok(())
    }
}

pub(super) fn lz4_diagnostic(
    index: &crate::formats::lz4::Index,
    file_size: u64,
) -> DiagnosticFields {
    use serde_json::json;
    let Value::Object(fields) = json!({
        "format": "lz4",
        "ext": ".lz4",
        "file_size": file_size,
        "magic_matched": index.magic_matched(),
        "plausible": index.frames > 0,
        "error": index.error,
        "damage_flags": index.error.is_empty().then_some(Vec::<&str>::new()).unwrap_or_else(|| vec![index.error]),
        "evidence": ["lz4:frame_structure"],
        "structure_status": if index.complete { "complete" } else { "incomplete" },
        "structure_validation_complete": index.complete,
        "boundary_exact": index.complete,
        "segment_end": index.complete.then_some(index.end),
        "archive.trailing_data": file_size.saturating_sub(index.end),
        "integrity_status": if index.checksum_present() { "deferred" } else { "not_present" },
        "integrity_validation_complete": false,
        "checksum_present": index.checksum_present(),
        "structure.stream_count": index.frames,
        "structure.block_count": index.blocks,
        "structure.decoded_size": index.decoded_size,
    }) else {
        unreachable!()
    };
    fields
}
