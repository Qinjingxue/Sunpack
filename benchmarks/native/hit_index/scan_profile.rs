//! Benchmark-only instrumentation. Never compiled into the installed extension.
use super::hit_storage::HitStorage;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

static NS: [AtomicU64; 13] = [const { AtomicU64::new(0) }; 13];
static CALLS: [AtomicU64; 13] = [const { AtomicU64::new(0) }; 13];
static FINE: AtomicBool = AtomicBool::new(false);
static SPACE: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];
const NAMES: [&str; 13] = ["match_and_stream_encode", "prepare", "builder_push", "builder_finish",
    "partition", "encode_leaf", "flush_leaf", "fallback_encode", "validate",
    "zip64", "zip_eocd", "validate_remaining", "roots"];
pub(super) struct Span { start: Option<Instant>, stage: usize }
impl Span {
    pub(super) fn new(stage: usize) -> Self {
        let enabled = !(4..=7).contains(&stage) || FINE.load(Ordering::Relaxed);
        Self { start: enabled.then(Instant::now), stage }
    }
}
impl Drop for Span {
    fn drop(&mut self) {
        let Some(start) = self.start else { return; };
        let ns = start.elapsed().as_nanos() as u64;
        NS[self.stage].fetch_add(ns, Ordering::Relaxed);
        CALLS[self.stage].fetch_add(1, Ordering::Relaxed);
    }
}
pub(super) fn reset() {
    FINE.store(std::env::var_os("SUNPACK_BENCH_PROFILE_FINE").is_some(), Ordering::Relaxed);
    for i in 0..13 { NS[i].store(0, Ordering::Relaxed); CALLS[i].store(0, Ordering::Relaxed); }
    for value in &SPACE { value.store(0, Ordering::Relaxed); }
}
pub(super) fn space(stage: usize, bytes: usize) { SPACE[stage].fetch_add(bytes as u64, Ordering::Relaxed); }
pub(super) fn space_snapshot() -> [usize; 3] { std::array::from_fn(|i| SPACE[i].load(Ordering::Relaxed) as usize) }
pub(super) fn write(storage: &HitStorage, size: u64, read_bytes: u64, pipeline_ns: u64,
    io_match_ns: u64, roots: usize, roots_capacity: usize, candidates: usize,
    candidates_capacity: usize) -> std::io::Result<()> {
    // Snapshot counters BEFORE diagnostic decoding/entropy/compression. Nested
    // worker times overlap; these are inclusive service times, not percentages.
    let stages = NAMES.iter().enumerate().map(|(i, name)| ((*name).to_string(),
        serde_json::json!({"ns": NS[i].load(Ordering::Relaxed), "calls": CALLS[i].load(Ordering::Relaxed)})))
        .collect::<serde_json::Map<String, serde_json::Value>>();
    let analysis_start = Instant::now();
    let storage = storage.benchmark_storage_profile(size)?;
    let value = serde_json::json!({"fine": FINE.load(Ordering::Relaxed), "file_bytes": size, "read_bytes": read_bytes,
        "pipeline_ns": pipeline_ns, "io_match_wall_ns": io_match_ns, "stages": stages,
        "storage": storage, "diagnostic_ns": analysis_start.elapsed().as_nanos() as u64,
        "retained": {"roots": roots, "roots_capacity_bytes": roots_capacity,
            "candidates": candidates, "candidates_capacity_bytes": candidates_capacity,
            "raw_hit_bytes": std::mem::size_of::<super::RawHit>(),
            "candidate_bytes": std::mem::size_of::<super::EmbeddedCandidate>(),
            "result_inline_bytes": std::mem::size_of::<super::NativeScanResult>()}});
    let path = std::env::var_os("SUNPACK_BENCH_PROFILE").ok_or_else(|| std::io::Error::other("missing profile path"))?;
    serde_json::to_writer(std::fs::File::create(path)?, &value)?;
    Ok(())
}
