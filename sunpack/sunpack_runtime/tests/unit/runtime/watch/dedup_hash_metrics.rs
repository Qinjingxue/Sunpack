//! Process totals for the opt-in deduplication benchmark.
use std::sync::atomic::{AtomicU64, Ordering};
pub(crate) static CALLS: AtomicU64 = AtomicU64::new(0);
pub(crate) static BYTES: AtomicU64 = AtomicU64::new(0);
pub(crate) fn call() {
    CALLS.fetch_add(1, Ordering::Relaxed);
}
pub(crate) fn consume(n: usize) {
    BYTES.fetch_add(n as u64, Ordering::Relaxed);
}
