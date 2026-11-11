#![allow(dead_code)]
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
struct Meter;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
unsafe impl GlobalAlloc for Meter {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = System.alloc(l);
        if !p.is_null() {
            let v = LIVE.fetch_add(l.size(), Ordering::Relaxed) + l.size();
            PEAK.fetch_max(v, Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size(), Ordering::Relaxed);
        System.dealloc(p, l)
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        let q = System.realloc(p, l, n);
        if !q.is_null() {
            let v = if n >= l.size() {
                LIVE.fetch_add(n - l.size(), Ordering::Relaxed) + n - l.size()
            } else {
                LIVE.fetch_sub(l.size() - n, Ordering::Relaxed) - (l.size() - n)
            };
            PEAK.fetch_max(v, Ordering::Relaxed);
        }
        q
    }
}
#[cfg(feature = "allocation-meter")]
#[global_allocator]
static ALLOC: Meter = Meter;
#[path = "COLLECTIONS"]
mod collections;
#[path = "FAST_HASH_CORE"]
mod fast_hash_core;
#[path = "PATH_KEYS"]
mod path_keys;
mod fast_hash {
    pub(crate) use crate::fast_hash_core::xxh64;
}
mod io {
    #[path = "RESOURCE_LIFECYCLE"]
    pub(crate) mod resource_lifecycle;
    #[path = "SCRATCH"]
    pub(crate) mod scratch;
}
mod scan {
    // BENCHMARK_PRODUCTION_TYPES
    mod hit_storage;
}
