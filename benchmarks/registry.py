from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Scenario:
    group: str
    name: str
    module: str
    description: str


_ROWS = [
    ("scheduling", "event-log", "benchmarks.scenarios.event_log", "State-log submission, deletion storms, compaction and short restart retention."),
    ("reader", "password-fast-path", "benchmarks.scenarios.reader_password_fast_path", "Password candidate fast paths."),
    ("reader", "embedded-scan", "benchmarks.scenarios.reader_embedded_scan", "Native and CLI embedded scanning."),
    ("memory", "residual-rss", "benchmarks.scenarios.memory_residual_rss", "Residual RSS and Python allocations."),
    ("memory", "password-store", "benchmarks.scenarios.password_store", "Password snapshot memory and unrelated-scope query scaling."),
    ("memory", "many-tasks", "benchmarks.scenarios.memory_many_tasks", "Python and native worker memory growth across formats."),
    ("scan", "directory", "benchmarks.scenarios.scan_directory", "Directory scanner comparison."),
    ("scan", "watch-catalog", "benchmarks.scenarios.watch_catalog", "Native Watch catalog, bucket lookup, protected output pruning and state lifetime."),
    ("scan", "hotspots", "benchmarks.scenarios.scan_hotspots", "Full scan hotspot instrumentation."),
    ("scan", "hit-index", "benchmarks.scenarios.hit_index", "Pinned integer-index baselines, exact typed-hit conformance, real traces and production Builder lifecycle."),
    ("scan", "synthetic-pressure", "benchmarks.scenarios.scan_synthetic_pressure", "Synthetic mixed-corpus scan."),
    ("watch", "catalog-recovery", "benchmarks.scenarios.watch_catalog_recovery", "Per-directory versus batched USN catalog recovery on one journal interval."),
    ("watch", "real-file", "benchmarks.scenarios.watch_real_file", "End-to-end watch arrival, extraction, and completion for one supplied file."),
    ("watch", "format-matrix", "benchmarks.scenarios.watch_format_matrix", "Per-format watch internal stage timings across formats and input shapes."),
    ("watch", "cli-format-matrix", "benchmarks.scenarios.watch_cli_format_matrix", "End-to-end watch matrix for ZIPX, LZ4 and ENC on the fixed 300 MiB corpus."),
    ("watch", "arrival-matrix", "benchmarks.scenarios.watch_arrival_matrix", "Watch arrival/move methods versus quiet-window policies."),
    ("watch", "split-arrival", "benchmarks.scenarios.watch_split_arrival", "Split-volume order and slow-arrival watch benchmark."),
    ("watch", "state-persistence", "benchmarks.scenarios.watch_state_persistence", "Incremental watch-state latency versus retained state size."),
    ("extraction", "format-matrix", "benchmarks.scenarios.extraction_format_matrix", "Format and workload matrix."),
    ("extraction", "cli-format-matrix", "benchmarks.scenarios.extraction_cli_format_matrix", "Full CLI 300 MiB format matrix, including ZIPX, LZ4 and ENC, with coarse internal phase timings and worker-prefetch control."),
    ("extraction", "real-archive", "benchmarks.scenarios.extraction_real_archive", "Fresh-process real archive baseline."),
    ("extraction", "large-archive-profile", "benchmarks.scenarios.extraction_large_archive", "Large archive pipeline profile."),
    ("extraction", "sevenzip-worker-matrix", "benchmarks.scenarios.sevenzip_worker_matrix", "Direct native 7z.dll worker format and size matrix."),
    ("extraction", "worker-vs-7z-300m", "benchmarks.scenarios.worker_vs_7z_300m", "Reproducible 300 MiB native worker versus 7z.exe matrix with timing, peak RSS, archive, and machine metadata."),
    ("extraction", "worker-concurrency-300m", "benchmarks.scenarios.worker_concurrency_300m", "Single persistent worker versus concurrent 7z processes on the 300 MiB full format matrix."),
    ("extraction", "split-pressure", "benchmarks.scenarios.extraction_split_pressure", "Split and carrier archive matrix."),
]

SCENARIOS = {
    (group, name): Scenario(
        group,
        name,
        module,
        description,
    )
    for group, name, module, description in _ROWS
}
