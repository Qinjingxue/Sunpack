//! Test-only process totals for benchmarks and per-caller counters for parallel unit tests.
use std::sync::atomic::{AtomicU64, Ordering};
use std::cell::Cell;
pub(crate) static CALLS: AtomicU64 = AtomicU64::new(0);
pub(crate) static BYTES: AtomicU64 = AtomicU64::new(0);
thread_local! { static LOCAL: Cell<(u64, u64)> = const { Cell::new((0, 0)) }; }
pub(crate) fn call() {
    CALLS.fetch_add(1, Ordering::Relaxed);
    LOCAL.with(|v| { let (calls, bytes) = v.get(); v.set((calls + 1, bytes)); });
}
pub(crate) fn consume(n: usize) {
    BYTES.fetch_add(n as u64, Ordering::Relaxed);
    LOCAL.with(|v| { let (calls, bytes) = v.get(); v.set((calls, bytes + n as u64)); });
}
pub(crate) fn snapshot() -> (u64, u64) { LOCAL.with(Cell::get) }
