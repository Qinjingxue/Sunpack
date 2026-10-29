pub(crate) mod archive_state;
pub(crate) mod atomic_file;
#[cfg(windows)]
pub(crate) mod config_changes;
pub(crate) mod directory_errors;
pub(crate) mod display_store;
pub(crate) mod display_wake;
#[cfg(windows)]
pub(crate) mod file_generation;
#[cfg(windows)]
pub(crate) mod iocp;
pub(crate) mod read_fault;
pub(crate) mod reader;
pub(crate) mod resource_error;
pub(crate) mod resource_lifecycle;
pub(crate) mod runtime_binary;
pub(crate) mod scratch;
pub(crate) mod util;

// The payload owns its representation and any shared coordinate context;
// IOCP forwards it without expanding compact records into absolute objects.
pub(crate) struct ScanBatch<T> {
    pub(crate) results: T,
    pub(crate) discarded_results: usize,
}

impl<T: Default> Default for ScanBatch<T> {
    fn default() -> Self {
        Self {
            results: T::default(),
            discarded_results: 0,
        }
    }
}
