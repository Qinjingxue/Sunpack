//! Explicit opt-in microbenchmark of the real Watch admission index, not discovery.
use super::*;
use std::time::Instant;

#[repr(C)]
#[derive(Default)]
struct MemoryCounters {
    cb: u32,
    faults: u32,
    peak_working_set: usize,
    working_set: usize,
    peak_paged: usize,
    paged: usize,
    peak_nonpaged: usize,
    nonpaged: usize,
    pagefile: usize,
    peak_pagefile: usize,
    private: usize,
}
fn memory() -> MemoryCounters {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> *mut std::ffi::c_void;
    }
    #[link(name = "psapi")]
    unsafe extern "system" {
        fn GetProcessMemoryInfo(
            process: *mut std::ffi::c_void,
            counters: *mut MemoryCounters,
            size: u32,
        ) -> i32;
    }
    let mut value = MemoryCounters::default();
    value.cb = std::mem::size_of::<MemoryCounters>() as u32;
    let size = value.cb;
    assert_ne!(
        unsafe { GetProcessMemoryInfo(GetCurrentProcess(), &mut value, size) },
        0
    );
    value
}

#[test]
#[ignore = "explicit benchmark: python -m benchmarks watch dedup-index"]
fn measure_watch_dedup_index() {
    let root = PathBuf::from(std::env::var_os("SUNPACK_DEDUP_BENCH_ROOT").expect("benchmark root"));
    let count: usize = std::env::var("SUNPACK_DEDUP_BENCH_COUNT")
        .unwrap()
        .parse()
        .unwrap();
    let mode_name = std::env::var("SUNPACK_DEDUP_BENCH_MODE").unwrap();
    let mode = match mode_name.as_str() {
        "none" => WatchDeduplication::None,
        "file_id" => WatchDeduplication::FileId,
        "hash" => WatchDeduplication::Hash,
        _ => panic!("unknown benchmark mode"),
    };
    let baseline = std::env::var("SUNPACK_DEDUP_BENCH_PHASE").unwrap() == "baseline";
    let folder = PathBuf::from(std::env::var_os("SUNPACK_DEDUP_BENCH_INDEX").unwrap());
    let mut index = Index::open(&folder, mode, WatchDeduplicationScope::Root).unwrap();
    index
        .reconcile_journals(&[("benchmark-scope".into(), "benchmark-volume".into(), 1)])
        .unwrap();
    let mut times = Vec::with_capacity(count);
    let before = memory();
    let start = Instant::now();
    let mut duplicates = 0;
    for i in 0..count {
        let path = root.join(format!("{:03}/{i:05}.zip", i / 512));
        let input = ArchiveInput::file(
            path.to_string_lossy().into_owned(),
            "zip".into(),
            format!("{i:05}.zip"),
        );
        let start = Instant::now();
        if let Some(mut prepared) = index
            .prepare(&input.entry_path, "benchmark-scope", &[&input], baseline)
            .unwrap()
        {
            loop {
                prepared.hash().unwrap();
                if !index.refresh(&mut prepared) {
                    duplicates += usize::from(index.commit(prepared).unwrap());
                    break;
                }
            }
        }
        times.push(start.elapsed().as_nanos() as u64);
    }
    let admit_ns = start.elapsed().as_nanos() as u64;
    let flush = Instant::now();
    index.finish_rebuild().unwrap();
    let flush_ns = flush.elapsed().as_nanos() as u64;
    let after = memory();
    let wal_bytes = fs::metadata(folder.join("dedup.wal.bin")).map_or(0, |m| m.len());
    let hashed = index
        .records
        .values()
        .filter(|r| r.digest.is_some())
        .count();
    let record_count = index.records.len();
    // Move exactly one 512-file subtree away from the recorded paths. Keep
    // directory IO out of the invalidation timer and restore fixtures afterward.
    let subtree = root.join("000");
    let moved = root.join("__benchmark_removed");
    let move_start = Instant::now();
    fs::rename(&subtree, &moved).unwrap();
    let move_ns = move_start.elapsed().as_nanos() as u64;
    let invalidate_start = Instant::now();
    index.invalidate_tree(&subtree.to_string_lossy()).unwrap();
    let invalidate_ns = invalidate_start.elapsed().as_nanos() as u64;
    let remaining_records = index.records.len();
    fs::rename(&moved, &subtree).unwrap();
    times.sort_unstable();
    let percentile = |p: usize| times[(times.len().saturating_sub(1) * p) / 100];
    println!(
        "SUNPACK_DEDUP_BENCH {}",
        serde_json::json!({
            "count":count, "mode":mode_name, "baseline":baseline, "duplicates":duplicates,
            "records":record_count, "hashed_records":hashed,
            "admission_ns":admit_ns, "durable_finish_ns":flush_ns,
            "inputs_per_second":count as f64 / (admit_ns as f64 / 1e9),
            "latency_median_ns":percentile(50), "latency_p95_ns":percentile(95),
            "latency_p99_ns":percentile(99), "latency_max_ns":times.last(),
            "private_delta_bytes":after.private as i64 - before.private as i64,
            "working_set_delta_bytes":after.working_set as i64 - before.working_set as i64,
            "peak_working_set_bytes":after.peak_working_set,
            "wal_bytes":wal_bytes, "directory_move_ns":move_ns,
        "invalidate_subtree_ns":invalidate_ns, "invalidated_paths":count.min(512), "remaining_records":remaining_records,
        })
    );
}
