"""Exact, fail-closed hooks applied only to an isolated production source copy."""
from .build import NATIVE


def replace_once(source, old, new):
    if source.count(old) != 1:
        raise RuntimeError(f"Production profiling hook changed: {old!r}")
    return source.replace(old, new)


def span(source, signature, stage, namespace="super::benchmark_profile"):
    start = source.index(signature)
    if source.count(signature) != 1:
        raise RuntimeError(f"Ambiguous profile function: {signature}")
    opening = source.index("{", start)
    return source[:opening + 1] + f"\n    let _profile_span = {namespace}::Span::new({stage});\n" + source[opening + 1:]


def instrument(root):
    path = root / "scan/hit_storage.rs"
    source = path.read_text(encoding="utf-8")
    for signature, stage in [("fn partition(", 4), ("fn encode_leaf(", 5),
                             ("fn flush_leaf(", 6), ("fn encode(", 7),
                             ("pub(super) fn prepare(", 1),
                             ("pub(super) fn push(&mut self, batch: Prepared)", 2),
                             ("pub(super) fn finish(mut self) -> io::Result<HitStorage>", 3)]:
        source = span(source, signature, stage)
    source = replace_once(source, "let start = end.next_multiple_of(8);", "let start = end.next_multiple_of(8);\n        super::benchmark_profile::space(0, (start - end) as usize);")
    source = replace_once(source, "self.arena.write_all(&segment.bytes())?;", "self.arena.write_all(&segment.bytes())?;\n                super::benchmark_profile::space(1, SEG_BYTES);")
    source = replace_once(source, "self.arena.write_all(&base.to_ne_bytes())?;", "super::benchmark_profile::space(2, 16 + hits.len() * 4);\n        self.arena.write_all(&base.to_ne_bytes())?;")
    source += "\n" + (NATIVE / "storage_profile.rs").read_text(encoding="utf-8")
    path.write_text(source, encoding="utf-8")
    path = root / "scan/embedded.rs"
    source = path.read_text(encoding="utf-8")
    source = span(source, "fn scan_sample_batch(", 0, "benchmark_profile")
    source = span(source, "fn validate_raw_hits(", 8, "benchmark_profile")
    source = replace_once(source, "let matching_window = if", "benchmark_profile::reset();\n    let profile_start = std::time::Instant::now();\n    let matching_window = if")
    source = replace_once(source, "let output = {\n        #[cfg(windows)]", "let profile_io = std::time::Instant::now();\n    let output = {\n        #[cfg(windows)]")
    source = replace_once(source, "let storage = builder.finish()?;", "let profile_io_ns = profile_io.elapsed().as_nanos() as u64;\n    let storage = builder.finish()?;")
    source = replace_once(source, "    candidates.sort_by_key(|candidate|", "    let profile_roots = benchmark_profile::Span::new(12);\n    candidates.sort_by_key(|candidate|")
    source = replace_once(source, "    Ok(NativeScanResult {\n        file_size,", """    drop(profile_roots);
    let profile_pipeline_ns = profile_start.elapsed().as_nanos() as u64;
    benchmark_profile::write(&storage, file_size, output.read_bytes, profile_pipeline_ns,
        profile_io_ns, raw_hits.len(), raw_hits.capacity() * std::mem::size_of::<RawHit>(),
        candidates.len(), candidates.capacity() * std::mem::size_of::<EmbeddedCandidate>())?;
    Ok(NativeScanResult {
        file_size,""")
    source = replace_once(source, "    let mut zip64_records = BTreeMap::new();", "    let profile_zip64 = benchmark_profile::Span::new(9);\n    let mut zip64_records = BTreeMap::new();")
    source = replace_once(source, "    let mut candidates = raw_hits\n        .par_iter_mask", "    drop(profile_zip64);\n    let profile_eocd = benchmark_profile::Span::new(10);\n    let mut candidates = raw_hits\n        .par_iter_mask")
    source = replace_once(source, "    let mut seeded_ranges = candidates", "    drop(profile_eocd);\n    let _profile_remaining = benchmark_profile::Span::new(11);\n    let mut seeded_ranges = candidates")
    source += f'\n#[path = "{(NATIVE / "scan_profile.rs").as_posix()}"]\nmod benchmark_profile;\n'
    path.write_text(source, encoding="utf-8")
