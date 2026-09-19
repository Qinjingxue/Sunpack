# Performance benchmarks

Performance measurements and diagnostic profiles live here; behavioural assertions live under `tests/`.

List the supported scenarios:

```powershell
python -m benchmarks --list
```

Run a scenario by group and name. Arguments after the scenario are passed to that scenario:

The `watch` group automatically builds and installs a uniquely named ephemeral
Watch Broker test service, launches the benchmark with an ordinary user token,
and removes only that service afterward. It never reuses, stops, or deletes an
installed release `SunPackWatchBroker` service. CI must already run with an
elevated account; interactive UAC is deliberately disabled there. Watch reports
include the test service/pipe identity, Broker binary SHA-256, and connection state.

```powershell
python -m benchmarks reader password-fast-path --rounds 5
python -m benchmarks reader volume-anchor --files 128 --logical-mib 64 --rounds 5
python -m benchmarks reader embedded-scan --generate-gib 10 --rounds 3 --skip-cli `
  --iocp-chunk-mib 2 --iocp-buffers 8 --iocp-workers 2
python -m benchmarks reader embedded-scan --generate-plan5-mib 500 --rounds 3 --skip-cli `
  --baseline-report benchmarks/results/reader.embedded-scan/<baseline-run>/report.json `
  --max-regression-percent 5
python -m benchmarks scan hotspots . --mode full --json-out benchmarks/results/scan-hotspots.json
python -m benchmarks extraction format-matrix --runs 5 --json-out benchmarks/results/extraction-benchmark.json
python -m benchmarks extraction sevenzip-worker-matrix --runs 3 --warmups 1 --json-out benchmarks/results/sevenzip-worker-baseline.json
python -m benchmarks extraction worker-read-blocking --runs 1 --payload-gib 1 --json-out benchmarks/results/worker-read-blocking.json
python -m benchmarks extraction worker-read-patterns --runs 1 --json-out benchmarks/results/worker-read-patterns.json
# Enable prefetch uniformly across formats while tuning its defaults (512 KiB x 2).
python -m benchmarks extraction worker-read-patterns --runs 2 --prefetch on --prefetch-window-kib 512 --prefetch-depth 2
# Compare uniform prefetch on/off in alternating order. Two 512 MiB members retain a meaningful solid-7z case.
python -m benchmarks extraction worker-read-patterns --format tar --format rar-split --format 7z --7z-variant solid --large-files 2 --large-file-mib 512 --large-content random --runs 5 --prefetch compare
python -m benchmarks extraction worker-small-file-scheduling --jobs 256 --clients 4 --capacities 1,2,4,8 --runs 3
python -m benchmarks extraction worker-single-file-write --baseline-worker-path C:\path\to\before\sunpack_sevenzip_worker.exe --candidate-worker-path C:\path\to\after\sunpack_sevenzip_worker.exe --payload-gib 1 --writer-threads 4 --runs 3 --warmups 1
python -m benchmarks extraction worker-resource-pressure --modes cpu,io,memory --controllers adaptive,fixed --capacities 1,2,4 --jobs 4
python -m benchmarks watch real-file C:\path\to\sample.jpg --wrong-password-count 100 --password '⑨' --json-out benchmarks/results/watch-real-file.json
python -m benchmarks watch arrival-matrix C:\path\to\sample.jpg --quiet-values 0,1.25 --runs 2 --wrong-password-count 100 --password '⑨' --json-out benchmarks/results/watch-arrival-matrix.json
python -m benchmarks watch split-arrival C:\path\to\archive.7z.001 C:\path\to\archive.7z.002 C:\path\to\archive.7z.003 C:\path\to\archive.7z.004 --quiet-values 0,1.25 --chunk-mib 4 --chunk-delay-ms 50 --json-out benchmarks/results/watch-split-arrival.json
python -m benchmarks watch format-matrix --runs 3 --warmups 1 --json-out benchmarks/results/watch-format-matrix.json
python -m benchmarks watch format-matrix --formats 7z,zip,rar --variants plain,encrypted --workloads many_small --runs 3
# A/B the post-extract flatten stage (post_extract.flatten_single_directory) on real outputs
python -m benchmarks watch format-matrix --formats zip,rar,tar,7z --flatten-modes on,off --runs 1
python -m benchmarks extraction split-pressure --profile acceptance --strict
python -m benchmarks memory residual-rss
python -m benchmarks memory many-tasks --python-rounds 5 --worker-rounds 3 --json-out benchmarks/results/memory-growth.json
```

## Run timeout

Every scenario runs in a child process under a hard wall-clock deadline, so a
stale scenario that calls a removed API and blocks forever is killed instead
of hanging the whole benchmark run.  The global limit defaults to 3600 seconds
and can be overridden before the scenario name, or via
`SUNPACK_BENCH_TIMEOUT`:

```powershell
python -m benchmarks --timeout 600 extraction format-matrix --runs 3
```

A killed scenario exits with code 124.  Scenario-internal subprocesses (7-Zip,
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
python -m benchmarks clean --cache --work
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

`extraction worker-initial-concurrency-matrix` calibrates the startup admission
limit against real ZIP stored/deflate, 7z solid/non-solid, and RAR solid/non-solid
archives. It sweeps `--initial-active-jobs` while holding the detected CPU/RAM
capacity constant, and reports median throughput, p95 queue latency, peak active
jobs, worker RSS, and normalized cross-format recommendations with and without
solid formats. Candidate order is alternated between rounds to reduce thermal and
ordering bias. Production uses one CPU token per job; `--cpu-weight-mode legacy`
replays the former format-dependent CPU weights for A/B comparison. Solid and
large-dictionary cases remain bounded by memory admission without a separate global mutex.

`extraction worker-resource-pressure` uses real 7z archives and the native worker
to measure resource contention rather than synthetic weights. `cpu` uses highly
compressible LZMA2 data with a large dictionary to stress decoding; `io` uses
random data with `-mx=0` to stress archive reads and output writes; `memory` uses
LZMA2 decoder dictionaries with a deliberately small worker memory budget. It
compares the adaptive controller with a fixed active-job limit and records worker
CPU, host CPU, read throughput, worker RSS, admitted jobs, reservation totals,
timeouts, and result failures. Repeat the memory case with `--dictionary-hint` and
`--no-dictionary-hint` to distinguish accurate decoder reservations from
underestimated reservations. These are pressure probes, not a hard RSS limit or a
proof that arbitrary archives cannot exhaust system memory.

`memory many-tasks` measures memory *growth* (not peak) of the two long-lived
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
`password_resolve`, `verify`, `resource`, and `extract_ms` (the pipeline wall
minus every measured stage, since native extraction runs asynchronously
through the worker). Stages removed by the refactor report 0.0.

The following obsolete probes were intentionally removed during consolidation:

- cache saturation and idle-thread scripts that inspected `_ENGINE`, `_runtime`, and `_SESSIONS`;
- the standalone scan-layer probe, subsumed by `scan hotspots --mode ...`;
- the hard-coded nested-authorization microbenchmark;
- the PowerShell memory stress script;
- the separate SunPack-versus-7-Zip runner, subsumed by the format matrix baseline.

Use pytest only for stable product contracts. Opt-in timing/resource assertions are
marked `performance` and run with `pytest --run-performance`; multi-GB resource-guard
tests additionally require `--run-large-archive-performance`.
