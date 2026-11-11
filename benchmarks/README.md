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
is a lower bound. The benchmark interpreter and isolated Watch Broker service
are excluded. Keep the runtime warm across requests by default, or use `--cold`
for process-start costs. `memory password-store` probes a header-encrypted archive
with one matching scope and many unrelated scopes; later rounds reuse the real
password and reader caches.

Watch runs install a uniquely named temporary Broker service using the existing
service-management script, and remove it afterward. They do not reuse or alter
the installed release service. The first `watch start --once` measures bootstrap
and extraction; later rounds restart the persistent runtime and measure recovery
of completed state. This is a restart workload, not a live arrival latency metric.
`--copies` controls the number of independently retained archive entries.

Results and metadata are written under `benchmarks/results/native-<mode>/`.
`--results-root` changes that location; `--keep-workdir` retains generated inputs
and outputs. `python -m benchmarks clean --cache --work` removes regenerable
artifacts. No implicit timeout is imposed; an operator can supply a whole-run
budget with `--timeout` before the group name or `SUNPACK_BENCH_TIMEOUT`.

The previous Python allocation, extension object, scheduler monkeypatch, private
worker-wire and extension-capture scenarios were removed with their implementation.
Their results cannot be compared directly to the native process metrics. Historical
index experiment material remains in `hit_index/`; its independent C ABI probe
and native algorithm comparison build tools require no Python extension. The
[GUI benchmark](gui/README.md) remains a native executable.
