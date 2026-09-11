from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Scenario:
    group: str
    name: str
    module: str
    description: str


_ROWS = [
    ("reader", "password-fast-path", "benchmarks.scenarios.reader_password_fast_path", "Password candidate fast paths."),
    ("reader", "password-size-scaling", "benchmarks.scenarios.reader_password_size_scaling", "Password cost versus payload size."),
    ("reader", "seven-zip-password", "benchmarks.scenarios.reader_seven_zip_password", "7z password probe optimization."),
    ("reader", "embedded-scan", "benchmarks.scenarios.reader_embedded_scan", "Native and CLI embedded scanning."),
    ("reader", "volume-anchor", "benchmarks.scenarios.reader_volume_anchor", "Bounded native volume-anchor probing."),
    ("memory", "residual-rss", "benchmarks.scenarios.memory_residual_rss", "Residual RSS and Python allocations."),
    ("memory", "worker-manifest", "benchmarks.scenarios.memory_worker_manifest", "Native manifest materialization."),
    ("memory", "many-tasks", "benchmarks.scenarios.memory_many_tasks", "Python and native worker memory growth across formats."),
    ("scan", "directory", "benchmarks.scenarios.scan_directory", "Directory scanner comparison."),
    ("scan", "hotspots", "benchmarks.scenarios.scan_hotspots", "Full scan hotspot instrumentation."),
    ("scan", "synthetic-pressure", "benchmarks.scenarios.scan_synthetic_pressure", "Synthetic mixed-corpus scan."),
    ("watch", "real-file", "benchmarks.scenarios.watch_real_file", "End-to-end watch arrival, extraction, and promotion."),
    ("watch", "arrival-matrix", "benchmarks.scenarios.watch_arrival_matrix", "Watch arrival/move methods versus quiet-window policies."),
    ("watch", "split-arrival", "benchmarks.scenarios.watch_split_arrival", "Split-volume order and slow-arrival watch benchmark."),
    ("watch", "state-persistence", "benchmarks.scenarios.watch_state_persistence", "Incremental watch-state latency versus retained state size."),
    ("extraction", "format-matrix", "benchmarks.scenarios.extraction_format_matrix", "Format and workload matrix."),
    ("extraction", "real-archive", "benchmarks.scenarios.extraction_real_archive", "Fresh-process real archive baseline."),
    ("extraction", "large-archive-profile", "benchmarks.scenarios.extraction_large_archive", "Large archive pipeline profile."),
    ("extraction", "sevenzip-worker-matrix", "benchmarks.scenarios.sevenzip_worker_matrix", "Direct native 7z.dll worker format and size matrix."),
    ("extraction", "worker-read-blocking", "benchmarks.scenarios.worker_read_blocking", "ReadFile wall-time share for a single 1 GiB archive through IInStream::Read."),
    ("extraction", "worker-read-patterns", "benchmarks.scenarios.worker_read_patterns", "Configurable native-worker IInStream seek/read pattern profile, with solid-mode variants and prefetch comparison."),
    ("extraction", "worker-small-file-scheduling", "benchmarks.scenarios.worker_small_file_scheduling", "Native worker parallelism and fairness under many small archive jobs."),
    ("extraction", "worker-initial-concurrency-matrix", "benchmarks.scenarios.worker_initial_concurrency_matrix", "Initial native-worker concurrency across ZIP, 7z, RAR, solid, and non-solid archives."),
    ("extraction", "worker-single-file-write", "benchmarks.scenarios.worker_single_file_write", "Before/after native worker throughput for one large output file."),
    ("extraction", "worker-multi-volume-write", "benchmarks.scenarios.worker_multi_volume_write", "Per-volume writer scheduling across two real physical disks."),
    ("extraction", "worker-volume-writer-scheduling", "benchmarks.scenarios.worker_volume_writer_scheduling", "Cross-volume versus same-volume writer scheduling with a paired control."),
    ("extraction", "worker-resource-pressure", "benchmarks.scenarios.worker_resource_pressure", "Real 7z CPU, IO, and decoder-memory contention."),
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
