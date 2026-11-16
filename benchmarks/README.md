# Native performance workloads

Benchmarks invoke the real Windows launcher, resident Rust runtime and native
worker. Python only generates fixtures, samples process metadata and writes
reports. No application Python package or PyO3 extension is imported.
Correctness regressions belong in `tests/`; these workloads measure coarse
latency, throughput and memory rather than duplicate implementation tests.

Build the native release artifacts first (`scripts/setup_windows_dev.ps1 -BuildProfile release`), or
pass `--profile ci` for existing CI artifacts. `--launcher C:\package\sunpack.exe`
uses a complete unpacked package, including its sibling runtime and tools.
Each run stages a unique installation and ProgramData directory and shuts its
own persistent runtime down on exit. It does not attach to an installed runtime.

```powershell
uv run --locked --extra test python -m benchmarks --list
uv run --locked --extra test python -m benchmarks scan directory --runs 5 --ordinary-files 100000
uv run --locked --extra test python -m benchmarks scan directory --shape carrier --formats zip,7z
uv run --locked --extra test python -m benchmarks extraction format-matrix --runs 5
uv run --locked --extra test python -m benchmarks extraction format-matrix --shape disguised
uv run --locked --extra test python -m benchmarks extraction format-matrix --shape carrier --formats zip,7z
uv run --locked --extra test python -m benchmarks extraction real-archive --archive C:\archives\sample.7z --password secret
uv run --locked --extra test python -m benchmarks extraction cli-vs-7z --formats zip,7z,xz
uv run --locked --extra test python -m benchmarks memory residual-rss --runs 20
uv run --locked --extra test python -m benchmarks memory many-tasks --copies 16 --runs 10
uv run --locked --extra test python -m benchmarks memory password-store --password-entries 100000 --runs 10
uv run --locked --extra test python -m benchmarks watch state-persistence --copies 100 --runs 5
uv run --locked --extra test python -m benchmarks --timeout 900 watch live-arrival --runs 120 --arrival-interval-ms 1000
uv run --locked --extra test python -m benchmarks password probe-matrix --candidates 1000
uv run --locked --extra test python -m benchmarks scan embedded --size-mib 1024 --segments 128
uv run --locked --extra test python -m benchmarks scan hit-index
uv run --locked --extra test python -m benchmarks extraction e2e-300m
uv run --locked --extra test python -m benchmarks watch e2e-300m
uv run --locked --extra test python -m benchmarks worker format-matrix
uv run --locked --extra test python -m benchmarks scan game-tree --directory D:\game
uv run --locked --extra test python -m benchmarks watch quiet-corpus --seeds 2 --splits development --channels immediate --widths 1,4
```

`password probe-matrix` puts the matching password after the requested number
of wrong candidates and measures the Rust verifier on a reused reader with
1 MiB stored payloads. It reports the first round, warm median and Windows
peak memory for encrypted 7z, ZIP, RAR and standalone ENC v4. The ENC run
uses the published test vector. CLI scan is measured
separately and can be skipped with `--skip-cli`.

`scan embedded` measures the Rust scanner directly and reports CLI discovery
separately. It defaults to a generated 1 GiB ZIP carrier. Use `--mixed` for the
historical Plan 5 mixed-format carrier, including ZIPX, 7z-Zstandard, 7z-LZ4
and LZ4 frames. Use `--stored-zip` for a large stored ZIP
(including ZIP64 when needed), or `--file` for an existing input.
`scan hit-index` defaults to real matcher hits captured from a mixed carrier.
It times index construction, iteration and seeks, with a separate allocation
pass. Use `--file` to capture a different input, `--trace` to replay a saved
`hits.bin`, or `--hits` for the synthetic equal-gap workload. Capture I/O and
report serialization are outside the index measurements.

The Worker, CLI and Watch 300 MiB matrices share one format list. Cases use
two reproducible 150 MiB payload files by default, or one stream of the same
total size. They include ZIPX (LZMA and Zstandard), split ZIP, 7z-Zstandard,
7z-LZ4, independent compression streams, compressed TAR variants and ENC.
ENC v4 uses standalone discovery in the CLI and Watch matrices. Carrier runs
exclude ENC because its header does not publish the archive length.
Set `--large-file-mib 1 --runs 1` for a smoke run. ENC generation needs
Java and the reference JAR. Missing optional generators are reported as skipped, and
`--sample FORMAT=PATH` accepts external formats. Watch requires permission to
create its isolated temporary Broker service. The direct worker matrix measures
the persistent worker separately, with explicit solid and non-solid 7z, RAR5
and RAR4 variants. Use `--compare-7z` to run stock 7z.exe on supported cases.
ENC and formats whose handler or codec is missing in stock 7z are skipped.
Compressed TAR cases measure the first decompression layer. Process memory
peaks are sampled lower bounds.

`scan game-tree --directory` scans immediate child directories as separate
recursive output scopes. Add `--single-root` to scan the supplied directory as
one scope, including files directly in it. The benchmark reads the directory
tree in place and uses the checkout's configuration, ignoring
`SUNPACK_CONFIG_OVERRIDES`. Each run records directory preparation time,
discovery and authorization time together, Windows peak working set and commit,
and the allowed paths. Runs use fresh processes and retain the filesystem cache.
Use `--archive` for the separate CLI extraction measurement on an existing archive.

`watch quiet-corpus` replays the historical 28 writer families through the
Rust Watch scheduler. The default design covers three seed splits, four
notification channels, concurrency widths and both timer/observation tie
orders, for 7,296 traces and 76,224 physical files. It keeps per-seed and
family/channel/width/tie summaries, confidence intervals, completion-to-proposal
latency for logical inputs, censored inputs and invalid proposal bursts.

The test build substitutes virtual metadata, handle readability and a virtual
clock, with immediate retirement at admission. Replay elapsed time and
scheduler-thread CPU time exclude corpus generation, process startup and
report writing. Busy retries under unchanged snapshots are coalesced. Use
the Watch end-to-end benchmarks for actual Broker, pipeline and OS timing.

The command saves the exact corpus, proposal timelines and evaluator source.
Use `--corpus` to replay saved traces and `--compare` to report paired seed
deltas with the same evaluator, trace corpus and tie orders.

```powershell
# Freeze one report before changing the Rust policy.
uv run --locked --extra test python -m benchmarks watch quiet-corpus --pin-report .cache/quiet-before.json
# Replay the saved traces with the changed implementation and the same evaluator.
uv run --locked --extra test python -m benchmarks watch quiet-corpus --corpus PATH/TO/traces.jsonl.gz --compare .cache/quiet-before.json
```

Generated fixtures reuse the deterministic many-small-file and few-large-file
corpora. ZIP, 7z, RAR, TAR, gzip, bzip2, XZ, Zstandard and available split variants
are supported; missing optional generators are recorded as skipped. ZIPX, LZ4,
ENC, nested and other real archives can be supplied through `--archive` without
any test helper dependency. Extraction uses recursive discovery by default.
The external archive is preserved; known numbered/RAR volume siblings are copied
into the isolated input directory. Supply `--archive-format` for composite-stream
7-Zip comparisons where the filename alone is insufficient.

Generation and package staging are outside measurements. The fixture cache is
keyed by settings and tool metadata. `--cache-root`, `--rebuild-corpus`,
`--small-files`, `--large-files` and `--large-file-mib` control it. No output-content
hashing is performed. Reports include native command responses and output file
counts/bytes as workload metadata. Raw 7-Zip comparison includes the second TAR
extraction for compressed TAR formats; it measures the original archive rather
than a carrier wrapper.

Each request records wall time, sampled native process-tree peak RSS/private
memory, and resident RSS/private memory, handles and threads. The sampled peak
is a lower bound. Watch reports include the dedicated Broker and its descendants
in the total, and expose Broker RSS and private memory separately in each sample.
The benchmark interpreter is excluded. Keep the runtime warm across requests by default, or use `--cold`
for process-start costs. `memory password-store` probes a header-encrypted archive
with one matching scope and many unrelated scopes; later rounds reuse the real
password and reader caches.

Watch runs install a uniquely named temporary Broker service using the existing
service-management script, and remove it afterward. They do not reuse or alter
the installed release service. `watch state-persistence` measures startup, admission,
and graceful stop of Watch, which finishes submitted work and flushes completed
state. Later rounds restart the runtime with the retained archives and completed
state. `--copies` controls the number of retained archives.

`watch live-arrival` starts continuous Watch on an empty root and publishes fully
written files by same-volume rename. Each latency ends when Watch removes the
isolated input after extraction and post-processing. Split volumes are published
together under a new directory and complete when all source members are gone.
`--copies` makes each wave larger; `--runs` and `--arrival-interval-ms` control
repeated arrival and idle periods without restarting Watch. The report contains
individual arrival latencies and a single service memory timeline spanning all
waves, including between-wave idle samples. Use successful inputs and supply an
operator `--timeout` when benchmarking unfamiliar archives.

Results and metadata are written under `benchmarks/results/native-<mode>/`.
`--results-root` changes that location; `--keep-workdir` retains generated inputs
and outputs. `python -m benchmarks clean --cache --work` removes regenerable
artifacts. No implicit timeout is imposed; an operator can supply a whole-run
budget with `--timeout` before the group name or `SUNPACK_BENCH_TIMEOUT`.

The previous Python allocation, extension object, scheduler monkeypatch and
extension-capture scenarios were removed with their implementation. Their results
cannot be compared directly to the native process metrics. The new direct-worker
scenario uses the current worker protocol. Historical
index experiment material remains in `hit_index/`; its independent C ABI probe
and native algorithm comparison build tools require no Python extension. The
[GUI benchmark](gui/README.md) remains a native executable.
