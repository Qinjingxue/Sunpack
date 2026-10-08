# Performance benchmarks

Performance measurements and diagnostic profiles live here; behavioural assertions live under `tests/`.

ENC v4 Rust probes live in `native/enc_ctr.rs` (pure CTR) and `native/enc_decrypt.rs`
(authenticated streaming to a null sink). Run them with `cargo run --manifest-path
native/Cargo.toml --release -p sunpack-enc --features parallel-decrypt --example throughput --
256 3 5` or the `decrypt` example. Thread counts are benchmark budgets; the product worker
acquires remaining CPU credits anew for each batch. Measurements and reproduction commands
are in [ENC v4 optimization](../docs/zh-CN/benchmark_enc_v4_optimization.md).

List the supported scenarios:

```powershell
uv run --locked python -m benchmarks --list
```

Run a scenario by group and name. Arguments after the scenario are passed to that scenario:

The `watch` group automatically builds and installs a uniquely named ephemeral
Watch Broker test service, launches the benchmark with an ordinary user token,
and removes only that service afterward. It never reuses, stops, or deletes an
installed release `SunPackWatchBroker` service. CI must already run with an
elevated account; interactive UAC is deliberately disabled there. Watch reports
include the test service/pipe identity, Broker binary SHA-256, and connection state.

```powershell
uv run --locked python -m benchmarks reader password-fast-path --rounds 5
uv run --no-sync python -m benchmarks reader enc-password-fast-path --path native/sunpack_enc/tests/data/algorithm_0.mov --path C:\path\to\large.enc --wrong-passwords 64 --rounds 3 --jobs 1
uv run --locked python -m benchmarks reader volume-anchor --files 128 --logical-mib 64 --rounds 5
uv run --locked python -m benchmarks reader embedded-scan --generate-gib 10 --rounds 3 --skip-cli `
  --iocp-chunk-mib 2 --iocp-buffers 8 --iocp-workers 2
uv run --locked python -m benchmarks reader embedded-scan --generate-plan5-mib 500 --rounds 3 --skip-cli `
  --baseline-report benchmarks/results/reader.embedded-scan/<baseline-run>/report.json `
  --max-regression-percent 5
uv run --locked python -m benchmarks scan hotspots . --mode full --json-out benchmarks/results/scan-hotspots.json
uv run --locked python -m benchmarks extraction format-matrix --runs 5 --json-out benchmarks/results/extraction-benchmark.json
uv run --locked python -m benchmarks extraction cli-format-matrix --runs 3 --prefetch on --json-out benchmarks/results/cli-format-matrix-prefetch-on.json
uv run --locked python -m benchmarks extraction cli-format-matrix --format zipx --format lz4 --runs 3 --prefetch on --json-out benchmarks/results/cli-zipx-lz4-prefetch-on.json
uv run --locked python -m benchmarks extraction cli-format-matrix --format zipx --format lz4 --runs 3 --prefetch off --json-out benchmarks/results/cli-zipx-lz4-prefetch-off.json
cmake --build native/sevenzip_bridge/build-probe --config Release --target sunpack_sevenzip_worker
uv run --locked python -m benchmarks extraction sevenzip-worker-matrix --runs 3 --warmups 1 --json-out benchmarks/results/sevenzip-worker-baseline.json
uv run --locked python -m benchmarks extraction worker-vs-7z-300m `
  --sunpack-version v0.7.0 --worker-source-commit c3eaec11 `
  --worker native/sevenzip_bridge/build-x64/Release/sunpack_sevenzip_worker.exe `
  --small-files 8 --large-files 2 --large-file-mib 150 --runs 5 --warmups 0 `
  --json-out benchmarks/results/worker-vs-7z-300m-v0.7.0-c3eaec11-rss.json
uv run --locked python -m benchmarks extraction worker-read-blocking --runs 1 --payload-gib 1 --json-out benchmarks/results/worker-read-blocking.json
uv run --locked python -m benchmarks extraction worker-concurrency-300m --concurrency 8 --runs 2 --json-out benchmarks/results/worker-concurrency-300m.json
uv run --locked python -m benchmarks extraction worker-read-patterns --runs 1 --json-out benchmarks/results/worker-read-patterns.json
# Enable the production format-aware prefetch policy while tuning its defaults (512 KiB x 2).
uv run --locked python -m benchmarks extraction worker-read-patterns --runs 2 --prefetch on --prefetch-window-kib 512 --prefetch-depth 2
# Compare production-policy prefetch on/off in alternating order. Two 512 MiB members retain a meaningful solid-7z case.
uv run --locked python -m benchmarks extraction worker-read-patterns --format tar --format rar-split --format 7z --7z-variant solid --large-files 2 --large-file-mib 512 --large-content random --runs 5 --prefetch compare
uv run --locked python -m benchmarks extraction worker-small-file-scheduling --jobs 256 --clients 4 --capacities 1,2,4,8 --runs 3
uv run --locked python -m benchmarks extraction worker-single-file-write --baseline-worker-path C:\path\to\before\sunpack_sevenzip_worker.exe --candidate-worker-path C:\path\to\after\sunpack_sevenzip_worker.exe --payload-gib 1 --writer-threads 4 --runs 3 --warmups 1
uv run --locked python -m benchmarks extraction worker-resource-pressure --modes cpu,io --capacities 1,2,4 --jobs 4
uv run --locked python -m benchmarks watch real-file C:\path\to\sample.jpg --wrong-password-count 100 --password '⑨' --json-out benchmarks/results/watch-real-file.json
uv run --locked python -m benchmarks watch arrival-matrix C:\path\to\sample.jpg --quiet-values 0,1.25 --runs 2 --wrong-password-count 100 --password '⑨' --json-out benchmarks/results/watch-arrival-matrix.json
uv run --locked python -m benchmarks watch split-arrival C:\path\to\archive.7z.001 C:\path\to\archive.7z.002 C:\path\to\archive.7z.003 C:\path\to\archive.7z.004 --quiet-values 0,1.25 --chunk-mib 4 --chunk-delay-ms 50 --json-out benchmarks/results/watch-split-arrival.json
uv run --locked python -m benchmarks watch format-matrix --runs 3 --warmups 1 --json-out benchmarks/results/watch-format-matrix.json
uv run --locked python -m benchmarks watch format-matrix --formats 7z,zip,rar --variants plain,encrypted --workloads many_small --runs 3
# A/B the post-extract flatten stage (post_extract.flatten_single_directory) on real outputs
uv run --locked python -m benchmarks watch format-matrix --formats zip,rar,tar,7z --flatten-modes on,off --runs 1
uv run --locked python -m benchmarks extraction split-pressure --profile acceptance --strict
uv run --locked python -m benchmarks memory residual-rss
uv run --locked python -m benchmarks memory many-tasks --python-rounds 5 --worker-rounds 3 --json-out benchmarks/results/memory-growth.json
uv run --no-sync python -m benchmarks scheduling broker-queue --baseline-ref <before-commit> --runs 5 --warmups 1
uv run --no-sync python -m benchmarks scheduling watch-source-claims --baseline-ref <before-commit> --runs 7 --warmups 1
uv run --no-sync python -m benchmarks memory watch-source-indexes --paths 4096 --batches 12 --warmups 2
```

`scheduling watch-source-claims` compares watch claim, release, and state
retirement against the committed scheduler. The lifecycle case includes pending
index maintenance, metadata updates, dirty events, partial ownership transfer,
and release. Each sample verifies identical ownership and ordered event replay.
It uses metadata fixtures and production locks without requiring a Broker
service; archive IO and log/state persistence are outside the measurement.
Additional index allocations are measured separately with tracemalloc.

`memory watch-source-indexes` repeatedly inserts unique candidates, claims
sources, transfers dirty paths, and releases owners. It checks collection through
weak references, empty index table capacity, and destruction of a populated
scheduler. Scheduler allocations and RSS are reported separately; allocator
reserves can keep RSS elevated after the indexed objects have been freed.

`scheduling broker-queue` loads the exact broker source from `--baseline-ref` and
compares it with the working tree in alternating A/B order. It verifies identical
selection order/results and reports single-selection latency, enqueue-plus-drain
cost, and actual broker submit-to-completion time at the same thread capacity.
The default queue sizes range from 1 to 4096, with homogeneous and mixed stages;
broker workloads include one request and mixed watch/foreground requests. Reports
record both source hashes and all raw wall/CPU samples. These are scheduling
measurements without archive decoding or filesystem IO.

## Run timeout

`reader enc-password-fast-path` measures the production Rust quick-block
verifier on independently generated ENC v4 files. Compare different payload
sizes with repeated `--path`, and concurrent batches with `--jobs`. In a separate
process, set `RAYON_NUM_THREADS=1` for the serial baseline. Reports include
logical reader bytes, wall/CPU samples, peak RSS and residual RSS; Argon2 memory
depends on the file's KDF parameter, not its payload size or candidate count.

Every scenario runs in a child process under a hard wall-clock deadline, so a
stale scenario that calls a removed API and blocks forever is killed instead
of hanging the whole benchmark run. The global limit defaults to 3600 seconds
and can be overridden before the scenario name, or via
`SUNPACK_BENCH_TIMEOUT`:

```powershell
uv run --locked python -m benchmarks --timeout 600 extraction format-matrix --runs 3
```

A killed scenario exits with code 124. Scenario-internal subprocesses (7-Zip,
the CLI client, native workers, worker children) all carry their own timeouts
too; they honour `SUNPACK_BENCH_SUBPROCESS_TIMEOUT` (default 600s) where
applicable.

## Real archive workspace lifecycle

Scenarios that generate real archives use `BenchmarkWorkspace` and share this lifecycle:

1. Create corpus, work, and extraction-output directories under `benchmarks/.work/`.
2. Generate archives through the existing `ArchiveFixtureFactory` or scenario corpus builder.
3. Always write `report.json` and `manifest.json` under
   `benchmarks/results/<scenario>/<UTC timestamp>-<run id>/`.
4. Remove the complete temporary work directory when the scenario exits, including on failure.

Use `--results-root PATH` to put durable results elsewhere. By default, durable benchmark
results are stored under `benchmarks/results/`. Use `--keep-workdir` only when
debugging a generated archive; the retained path is recorded in `manifest.json`. Temporary
archives are never copied to the durable result directory implicitly, so large corpora do not
accumulate. A scenario may explicitly preserve a small diagnostic artifact with the workspace API.

Remove regenerable benchmark data without touching versioned reports:

```powershell
uv run --locked python -m benchmarks clean --cache --work
```

`extraction format-matrix` builds ZIP, 7z, split 7z, RAR, split RAR, TAR, gzip,
bzip2, xz, zstd and the conventional compressed-TAR aliases. It uses the bundled
binaries under `tools/`. Each archive is placed in an isolated scanner input directory,
then both SunPack's complete detection/extraction flow and raw 7-Zip are timed. Only
cases where both extractors exit successfully contribute to the comparison ratio;
payload-content correctness is covered by dedicated correctness tests, so the matrix
does not re-hash extracted files.
The matrix starts extractor commands strictly one at a time, while leaving SunPack's internal scheduler at its program-controlled
default and using unlimited recursive extraction. Generated scanner entry files are
rejected when they fall below the project's 1 MiB recognition floor.

The format matrix now uses an adaptive host-pressure gate before every extractor launch.
Tune it with `--max-cpu-percent`, `--min-available-memory-percent`, and
`--pressure-max-wait-seconds`; `--case-cooldown-seconds` is an optional extra fixed delay.
Generated corpora are content-addressed under `benchmarks/.cache/` and can be refreshed
with `--rebuild-corpus-cache` or disabled with `--no-corpus-cache`. Use repeated `--format`
options for a focused run. One diagnostic extraction per case reuses the large-archive
runtime profiler and writes phase medians and per-format aggregates into the report; use
`--no-phase-profile` when only end-to-end timing is needed. For stable internal medians,
set `--phase-profile-warmups 1 --phase-profile-runs 3`.

The format matrix reports live progress by default: timestamped lines on stderr show the
current phase (`corpus`, `detection`, `extraction_matrix`, `phase_profiles`, `report`),
the case/run/label being executed, and each operation's wall time. The cumulative phase
breakdown is recorded in the report's `phase_timing_seconds` and printed to stderr at the
end. Disable this with `--no-progress`. Progress always goes to stderr, so the
detection-worker subprocess keeps its stdout JSON contract intact; the parent forwards the
worker's stderr so per-archive scan progress is visible live.

The reusable harness in `benchmarks/harness` defines the common wall/CPU clocks,
RSS/Private Bytes process-tree memory sampling, real-archive workspace lifecycle, and
versioned JSON report envelope. New scenarios must use those components instead of
adding another local timer, memory sampler, or temporary-directory policy.

`watch format-matrix` measures the internal stages of the production watch path
(`WatchScheduler` -> `PipelineEngine`) for every generated archive format. It reuses the
format-matrix corpus builder, so ZIP, 7z, split 7z, RAR, split RAR, TAR, gzip, bzip2, xz,
zstd and the compressed-TAR aliases all arrive through the same watched directory, and it
instruments every submitted request with the same `RequestRuntimeProfiler` that
`extraction large-archive-profile` uses. Variants reproduce the input shapes the product
must handle: `plain`, `disguised` (`.jpg` extension), `carrier`
(`[garbage][archive][garbage]`), `encrypted` (real encryption with wrong password
candidates first, so password resolution is measured), and `nested` (an archive inside an
archive, so the recursive pass runs inside one watch request). Split formats only run
`plain`, because renaming or re-wrapping individual volumes changes the volume chain
itself; every skipped case is recorded with its reason.

Per case the report keeps the wall-clock arrival view (`feed`, `feed_to_first_processing`,
`post_feed_to_completion`, `case_wall`), the terminal outcome, and the full per-stage
breakdown (`stage_seconds`, `stage_seconds_by_request`) plus a `headline_seconds` rollup
whose columns are printed as a table: pipeline run, planning, batch execute, extract,
verify, output scan, and native worker time. `aggregates` holds the median of every stage
per `workload:format:variant` case. A successful request clears its watch-state entry, so
the terminal outcome is taken from the completed pipeline reply and the durable state
statuses are reported separately as informational `state_statuses`/`blocked_statuses`.
`--flatten-modes on,off` repeats every case with `post_extract.flatten_single_directory`
forced on or off, which isolates the post-extract flatten stage from extraction itself.
Rounds alternate case order to avoid thermal and ordering bias, `--warmups` samples are
recorded but excluded from `aggregates`, and every case has its own `--timeout` so one
stuck format cannot consume the whole scenario budget.

`extraction sevenzip-worker-matrix` measures the native persistent
`sunpack_sevenzip_worker.exe` directly. It reuses the format-matrix corpus builder,
generates tiny/small/medium/large profiles by default, and records per-run worker wall time,
worker CPU time, child-process RSS peak, output statistics, native status, and failures.
Use repeated or comma-separated `--profile` values and repeated `--format` values to
focus the matrix. Durable results contain both `report.json` and `results.csv`.

`extraction worker-vs-7z-300m` is the standalone reproduction of the documented
300 MiB end-to-end comparison. It builds the deterministic `few_large` corpus
(one repeated-text 150 MiB member plus one fixed-seed random 150 MiB member),
adds explicit 7z/RAR5/RAR4 solid and non-solid variants, and covers 7z split,
RAR split, ZIP, TAR, Gzip, BZip2, XZ, Zstandard, and their compressed-TAR
aliases. Each case reuses one persistent native worker for its measured runs;
each reference run starts a new `7z.exe` process. Both process trees' RSS is
sampled every 20 ms and each measured run records its peak. The result records the exact
archive volume sizes, archive-listing method/solid fields, payload-to-archive
ratio, CPU/memory/disk inventory, active power scheme, tool hashes, all raw
samples, and per-case time/RSS medians. `--metadata-only` generates only the corpus
catalog. The full interpretation, machine identity, and recorded v0.7.0 result
are documented in [English](../docs/benchmark_worker_vs_7z_300m.md) and
[简体中文](../docs/zh-CN/benchmark_worker_vs_7z_300m.md).

`extraction cli-format-matrix` includes ZIPX (ZIP using LZMA compression) and
LZ4 in its fixed 300 MiB full-format corpus. ZIPX is rebuilt from the existing
payload members; LZ4 is one frame containing the concatenated 300 MiB raw
members, so both cases produce exactly 300 MiB of output. The LZ4 corpus writer
is part of `sunpack_sevenzip_lz4`; build it with
`cmake --build native/sevenzip_bridge/build-x64 --config Release --target sunpack_sevenzip_lz4`
when it is missing. `--prefetch on|off` controls the native worker's input
prefetch setting before the persistent worker starts. Run the ZIPX/LZ4 command
once per setting in separate benchmark processes for an apples-to-apples A/B.
The worker disables prefetch by default when the request's `format_hint` is
`lz4` or `tar.lz4`; an explicit `SUNPACK_SEVENZIP_PREFETCH=1` still enables it
for comparison runs.

`extraction worker-small-file-scheduling` measures the worker-internal thread
scheduler under a deliberately adversarial many-small-file workload. It creates
one small ZIP per job and submits each request's full burst before the next
request, then sweeps `--capacities` (native thread counts). Per run it records
throughput, observed active-job peak, time-weighted thread-capacity utilization,
queue/service latency percentiles, queued-but-underutilized thread time,
worker CPU/RSS/read/write utilization, early- and overall-admission Jain fairness,
the spread to each request's first admission, and the longest same-request admission
run. The early index detects short-term monopolization; the overall index detects
whether requests receive equal admission counts by the end of the batch.

`extraction worker-concurrency-300m` compares one persistent native worker with
concurrent fresh `7z.exe` processes on all 18 generated 300 MiB format/variant
cases. It reuses the format builder with payloads written by a standalone Rust
fixture generator (requires `rustc`), caches fixtures, passes the real output
volume identity, and validates output counts and sizes outside the timer.
Each homogeneous burst contains as many jobs as the requested concurrency;
the mixed batch contains two rounds of all cases at every concurrency. Reports
include paired trials with alternating engine order, throughput, sampled RSS,
process CPU time, and worker start/finish timelines. `--resume` continues completed
batches after checking binary and configuration fingerprints. For diagnosis,
`--dry-run` compares decode/verify against `7z t`, `--writer-threads` changes the
per-volume writer width, and `--profile` enables available native diagnostics.
`--format` and `--no-mixed` restrict diagnostic runs. These direct worker tests
exclude CLI/watch planning, recursive extraction, and post-extract verification.
Compressed TAR codecs are measured as one outer stream layer for both engines.

`extraction worker-fair-timing` is the like-for-like wall-clock comparison. The worker's
completion means "bytes are on the device", while `7z.exe` returns as soon as the bytes
are in the page cache, so timing only the return is not comparable. It measures each run
twice — extraction wall as reported by `worker-concurrency-300m`, then a Rust `sync_all`
over the produced tree — and treats `wall + flush` as the decisive number. A "wait until
the host disk goes quiet" probe was tried and removed: unrelated background writeback
keeps the disk busy for about a second here regardless of workload size, so it measured
the machine rather than the extraction.
`worker-window-sweep` and `worker-paired-ab` are benchmark-only reproduction helpers
used by the analysis below: the sweep rewrites the single residency-window constant in
`sevenzip_async_output.hpp`, rebuilds the probe worker once per value, runs every value in
alternating order per trial, and restores the original header on exit; the paired A/B
compares two worker binaries on the same cached corpus with alternating order, and can
apply per-engine environment overrides such as
`SUNPACK_ASYNC_WRITER_FILE_INFLIGHT_MIB` (only effective on a build that reads it).
Run them as scripts (`python benchmarks/scenarios/worker_window_sweep.py --help`)
because the sweep mutates source.
`extraction worker-concurrency-ablation` decomposes the parallel worker deficit into
single-variable ablations on the same cached 300 MiB corpus: per-volume writer width,
shared buffer count, volume space gate, native CPU budget, and input prefetch, each
optionally paired with concurrent `7z.exe` and with `--dry` (worker `dry_run` against
`7z t`) to separate decode cost from output-write cost. It reports wall time, process
CPU split, and per-job decoder credit grants.
`extraction worker-writer-ablation` reuses the probe-instrumented worker to break the
output path into phases (dispatch, WriteFile, producer, capacity wait, copy, queue) and
reports write-completion depth (`inflight_peak`, `queue_depth_peak`) and per-write
latency. Its `memory` and `memory-nocopy` sink modes write nothing, so decode-only cost
can be compared against the real write path; the probe phases overlap across threads and
must not be summed as batch wall time. Both scenarios accept a probe binary built with
`-DSUP7Z_ENABLE_WRITER_PROBE=ON -DSUP7Z_ENABLE_PIPELINE_TIMING=ON`; the product worker
build does not carry that instrumentation. The measured root causes are written up in
[简体中文](../docs/zh-CN/benchmark_worker_concurrency_gap_analysis.md), together with the
fixes that measurement rejected (deeper per-volume IOCP writer threads, releasing the
residency window at submission instead of at IO completion, enlarging the residency
window or the buffer pool) and the two harness bugs found while fixing the timing
(7z.exe output directories were not cleared before `-aoa`, and one scenario recorded only
the last `--format`).

`memory many-tasks` measures memory _growth_ (not peak) of the two long-lived
components under a large task count across every format: the Python pipeline and
the native 7z worker. One mixed-format corpus is built with the format-matrix
builder (archives kept above the 1 MiB scanner floor, e.g.
`--small-files 1100 --large-files 2 --large-file-mib 1`), then:

- phase `python` re-runs the whole corpus through the persistent-runtime
  `extract` pipeline once per round (`--python-rounds`, default 5) and samples
  the Python process RSS/private/tracemalloc/native reader cache after every
  round, plus the residual after the engine closes;
- phase `worker` feeds every archive through one persistent
  `sunpack_sevenzip_worker.exe` (`--worker-rounds`, default 3) and samples the
  worker process RSS after every job, so per-format and cumulative growth come
  straight out of the trajectory.

Use `--format` to restrict formats, `--skip-python` / `--skip-worker` to run a
single phase, and `--json-out` for a durable copy.

`reader embedded-scan --generate-gib 10 --rounds 1 --skip-cli` creates a streamed
ZIP64 fixture under the benchmark workspace, measures native embedded-scan wall/CPU
time and process memory peaks, and writes the report to the durable `benchmarks/results`
directory. The generated archive is removed automatically unless `--keep-workdir` is
supplied. The 10 GiB member is stored (not highly compressed), so generation is not
part of the measured scan operation and the run exercises a large-file scan directly.
The embedded scanner uses the bounded `ReadFile(OVERLAPPED)`/IOCP pipeline by
default. IOCP uses a separate scan-local handle and reports `scan_read_bytes` and
`scan_read_operations`; tune it
with `--iocp-chunk-mib`, `--iocp-buffers`, and `--iocp-workers` without changing
the normal reader cache or `read_at()` behavior. `iocp-buffers` controls the
bounded in-flight read depth; `iocp-workers` controls parallel signature
scanning independently.

`reader embedded-scan --generate-plan5-mib 500 --rounds 3 --skip-cli` creates a
500 MiB carrier around the real Plan 5 embedded-archive matrix. The matrix has
128 independently generated archives and covers ZIP, 7z, RAR4/5, TAR, gzip,
bzip2, xz, and zstd plus their container/codec variants. The scenario verifies
every expected format/offset on every measured run, so throughput results cannot
hide candidate-validation regressions or missed archives.

`extraction real-archive` measures the current architecture: `sunpack extract`
delegates to the long-lived persistent server process, so RSS accounting
includes the CLI client's process tree plus the persistent server and its
native 7-Zip worker (baseline service RSS is subtracted as idle overhead).
Each run has a per-run timeout (`--timeout`, default 600s); a timed-out run is
reported with exit code -124 and the server is shut down so the next run
starts from a clean baseline.

`extraction split-pressure` and `extraction large-archive-profile` drive the
async `PipelineEngine` (one event loop per submission) and instrument the
per-request runtime through the private runtime-factory seam. Timing columns
reflect the current pipeline stages: `pipeline_scan`, `input_planning`,
`batch_prepare`/`batch_execute`/`batch_collect_result`, `output_scan`,
`password_resolve`, `verify`, and `extract_ms` (the pipeline wall
minus every measured stage, since native extraction runs asynchronously
through the worker). Stages removed by the refactor report 0.0.

The following obsolete probes were intentionally removed during consolidation:

- cache saturation and idle-thread scripts that inspected `_ENGINE`, `_runtime`, and `_SESSIONS`;
- the standalone scan-layer probe, subsumed by `scan hotspots --mode ...`;
- the hard-coded nested-authorization microbenchmark;
- the PowerShell memory stress script;
- the separate SunPack-versus-7-Zip runner, subsumed by the format matrix baseline.

Use pytest only for stable product contracts. Opt-in timing/resource assertions are
marked `performance` and run with `pytest --run-performance`; multi-GB large-archive
tests additionally require `--run-large-archive-performance`.

ENC comparisons can also run directly as modules:

```powershell
uv run python -m benchmarks.scenarios.worker_enc_batch_ab --worker before=PATH_TO_BASELINE_WORKER --worker after=PATH_TO_CURRENT_WORKER --path PATH_TO_LARGE_ENC --concurrency 1,8 --capacity 4 --rounds 11 --json-out benchmarks/results/enc-worker-ab.json
uv run python -m benchmarks.scenarios.reader_enc_single_candidate_ab --baseline BASELINE_GIT_REVISION --path native/sunpack_enc/tests/data/algorithm_0.mov --rounds 11 --json-out benchmarks/results/enc-single-candidate-ab.json
```

The worker comparison expects an independently generated `large.expected` beside
each `large.enc`, validates native size/CRC outside the timer, and includes final
KDF, authentication and real output writes. Pass several `LABEL=PATH` workers to
compare prebuilt stream policies. `--affinity 0,2,4,6` optionally holds the
benchmark workers to the same logical CPUs; production scheduling is unaffected.

For ENC writer copy diagnosis, build the worker with
`SUP7Z_ENABLE_WRITER_PROBE=ON` and pass the same binary as `memory=PATH` and
`nocopy=PATH`, adding `--writer-mode memory=memory --writer-mode nocopy=memory-nocopy`.
These diagnostic sinks retain decoder/MAC/KDF and writer queueing but create no
output files; `memory-nocopy` additionally skips the staging memcpy. They cannot
validate output CRC and are explicitly marked as diagnostics. A `real=PATH`
worker with `--writer-mode real=real` provides the validated write reference.
Compare alternating repeated trials under both natural scheduling and affinity;
profile phase sums overlap across jobs and cannot be added to wall time.

The scheduler comparison loads only the old scheduler from the specified local
Git revision; both sides use the installed native extension and current worker.
Use `--origin watch` for the watch submission path. Pure AES diagnostics use the
existing Rust `throughput` example with `-- 32 9 1 0 raw-aes`; this excludes CTR,
KDF, authentication and I/O.
