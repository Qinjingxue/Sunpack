//! Watch-only content fingerprints. Scheduling and logical-input descriptions
//! belong to the caller; this module never discovers or extracts archives.
use crate::io::reader::PhysicalFileGeneration;
use std::io;
use std::path::Path;
use xxhash_rust::xxh3::Xxh3;

/// Hash an ordered logical byte stream under the shared Watch work budget.
/// The caller revalidates the path and USN before publishing the digest.
pub(super) struct StreamHash(Xxh3);

impl StreamHash {
    pub(super) fn new() -> Self {
        #[cfg(test)]
        metrics::call();
        Self(Xxh3::new())
    }

    pub(super) fn read(
        &mut self,
        path: &Path,
        offset: u64,
        len: u64,
        reversed: bool,
        validate_generation: impl FnOnce(&PhysicalFileGeneration) -> io::Result<()>,
    ) -> io::Result<()> {
        crate::io::iocp::read_range_ordered(
            path,
            offset,
            len,
            reversed,
            validate_generation,
            |bytes| {
                #[cfg(test)]
                metrics::consume(bytes.len());
                self.0.update(bytes);
                Ok(())
            },
        )
    }

    pub(super) fn finish(self) -> [u8; 16] {
        self.0.digest128().to_le_bytes()
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/runtime/watch/dedup_hash_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "../../../tests/unit/runtime/watch/dedup_hash_metrics.rs"]
pub(super) mod metrics;
