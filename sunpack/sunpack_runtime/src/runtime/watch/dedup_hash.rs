//! Watch-only content fingerprints. Scheduling and logical-input descriptions
//! belong to the caller; this module never discovers or extracts archives.
use std::io;
use std::path::Path;
use xxhash_rust::xxh3::Xxh3;

pub(super) struct HashRange<'a> {
    pub(super) path: &'a Path,
    pub(super) offset: u64,
    pub(super) len: u64,
}

/// Hash the exact logical byte stream in caller-specified order. Read-ahead is
/// bounded independently of source size. The caller must run under the shared
/// Watch work budget and revalidate its discovery/USN generation before admission.
pub(super) fn hash_ranges(ranges: &[HashRange<'_>]) -> io::Result<[u8; 16]> {
    let mut state = Xxh3::new();
    for range in ranges {
        crate::io::iocp::read_range_ordered(range.path, range.offset, range.len, |bytes| {
            state.update(bytes);
            Ok(())
        })?;
    }
    Ok(state.digest128().to_le_bytes())
}

#[cfg(test)]
#[path = "../../../tests/unit/runtime/watch/dedup_hash_tests.rs"]
mod tests;
