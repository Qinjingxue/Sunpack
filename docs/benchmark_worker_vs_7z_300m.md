# Reproducible 300 MiB worker versus 7-Zip benchmark

This document contains the detailed protocol behind the short result table in
the root README. The benchmark compares the SunPack native worker with the
bundled command-line `7z.exe` across the supported generated formats.

## Software and machine

Recorded software identity:

| Component | Value |
| --- | --- |
| SunPack | v0.7.0 |
| Worker source | tag `v0.7.0`, commit `e37c1769` |
| BZip2 decoder cap | 12 parallel block workers |
| Worker binary | `native/sevenzip_bridge/build-x64/Release/sunpack_sevenzip_worker.exe` |
| 7-Zip CLI | 7-Zip 26.03 (x64), `tools/7z.exe` |
| 7-Zip SHA-256 | `6ee3c0ed0b27663c1b948ae85a7c0bb073aed1498983182f3f0df1f6a8c30b2f` |
| Worker SHA-256 | `15d3f14f2102f501fa3351c63294c80fb3b359d93ceb9a477166dec321cae8ee` |
| Run date / JSON | 2026-09-25; `benchmarks/results/worker-vs-7z-300m-v0.7.0-rss.json` |

Recorded host:

| Property | Value |
| --- | --- |
| OS | Windows 11 Pro for Workstations, x64, build 26100 |
| Computer | MSI Vector GP78HX 13VI |
| CPU | 13th Gen Intel Core i9-13980HX, 24 physical cores / 32 logical processors |
| Memory | 31.77 GiB |
| Benchmark volume | `C:` NTFS, Samsung NVMe MZVL21T0HCLR-00B00, 934.47 GiB total and approximately 192.42 GiB free at capture time |

The reproduction script records the host inventory, active power scheme, binary
hashes, and 7-Zip version in the JSON result as well.

## Corpus and archive properties

The measured workload is the `few_large` corpus, with an uncompressed payload of
314,572,800 bytes (300 MiB) and exactly two members:

- one deterministic 150 MiB file made from repeated `sunpack-benchmark\n` text;
- one deterministic 150 MiB random file generated with seed `20260729`.

The payload is therefore half highly compressible and half incompressible. It
contains no encryption, carrier data, nested archive, or missing volume. The
corpus builder is invoked with `small_files=8`, `large_files=2`, and
`large_file_mib=150`; the `few_large` archives contain only the two large
members.

| Case | Method and construction | Solid / volume layout | Archive size and ratio |
| --- | --- | --- | --- |
| 7z split | LZMA2, 7-Zip default | default solid behavior, `-v16m` | 10 volumes; 157,320,671 bytes total |
| 7z solid | LZMA2, `-ms=on` | solid, single volume | 157,320,671 bytes; 50.01% of payload; 2.00x payload/archive |
| 7z non-solid | LZMA2, `-ms=off` | non-solid, single volume | 157,319,996 bytes; 50.01%; 2.00x |
| ZIP | Deflate, 7-Zip default | single ZIP volume | 157,703,555 bytes; 50.13%; 1.99x |
| RAR5 split | RAR5 default method | default solid behavior, `-v16m` | 10 volumes; 157,594,577 bytes total |
| RAR5 solid | RAR5 default method, `-s` | solid, single volume | 157,592,751 bytes; 50.10%; 2.00x |
| RAR5 non-solid | RAR5 default method, `-s-` | non-solid, single volume | 157,295,918 bytes; 50.00%; 2.00x |
| RAR4 solid | RAR4 default method, `-ma4 -s` | solid, single volume | 157,769,630 bytes; 50.15%; 1.99x |
| RAR4 non-solid | RAR4 default method, `-ma4 -s-` | non-solid, single volume | 157,365,992 bytes; 50.03%; 2.00x |
| TAR | no compression | single TAR | 314,575,360 bytes; TAR metadata/padding adds 2,560 bytes |
| Gzip / TGZ | Deflate over TAR | same compressed stream bytes | 157,773,338 bytes; 50.15%; 1.99x |
| BZip2 / TBZ2 | BZip2 over TAR | same compressed stream bytes | 158,006,008 bytes; 50.23%; 1.99x |
| XZ / TXZ | LZMA2 over TAR | same compressed stream bytes | 157,321,248 bytes; 50.01%; 2.00x |
| Zstandard / TZST | Zstandard level 3 over TAR | same compressed stream bytes | 157,305,943 bytes; 50.01%; 2.00x |

The percentage is `archive bytes / 300 MiB payload`; the second ratio is
`payload bytes / archive bytes`. The old timing result stored only the first
volume for split cases, so `archive_catalog.archive_bytes_total` from a new run
is authoritative for split archive totals.

7-Zip creates the 7z, ZIP, TAR, and TAR-codec fixtures; `Rar.exe` creates RAR4
and RAR5; `zstd.exe -3` creates Zstandard. The aliases (`tgz`, `tbz2`, `txz`,
and `tzst`) are byte-identical copies of their corresponding compressed TAR
archives.

## Measurement protocol

- Five measured runs per case, zero warmups.
- One persistent native worker process per case, reused for its five runs.
- One fresh `7z.exe x` process per reference run; process startup is included.
- Worker diagnostics and prefetch disabled.
- Same generated archive used for both implementations.
- Reported time values are per-case wall-time medians in milliseconds.
- The benchmark samples the native worker and `7z.exe` process trees' resident set
  size (RSS) every 20 ms. Each run records the sampled peak; tables show the
  median of those per-run peaks in MiB. The Python benchmark harness is excluded.
  Spikes shorter than the sampling interval may not be captured.

The comparison is end-to-end, not a pure decoder microbenchmark. This preserves
the actual product execution model, but means the reference includes CLI process
startup overhead. For compressed TAR aliases, a successful `7z.exe` return code
and valid TAR output are the correctness criteria; the TAR metadata explains the
2,560-byte difference from the two raw members.

## Result

### Wall time (median ms)

| Format / variant | SunPack worker | `7z.exe` | worker / 7-Zip |
| --- | ---: | ---: | ---: |
| 7z split | 152.428 | 212.774 | 0.716 |
| 7z non-solid | 191.658 | 249.196 | 0.769 |
| 7z solid | 152.874 | 208.849 | 0.732 |
| BZip2 | 2,903.218 | 3,018.483 | 0.962 |
| Gzip | 85.065 | 210.524 | 0.404 |
| RAR5 split | 225.367 | 774.706 | 0.291 |
| RAR4 non-solid | 167.379 | 189.960 | 0.881 |
| RAR4 solid | 646.962 | 663.775 | 0.975 |
| RAR5 non-solid | 133.381 | 185.708 | 0.718 |
| RAR5 solid | 205.989 | 764.585 | 0.269 |
| TAR | 86.117 | 139.751 | 0.616 |
| TBZ2 | 2,795.495 | 2,952.648 | 0.947 |
| TGZ | 83.694 | 199.684 | 0.419 |
| TXZ | 176.999 | 179.940 | 0.984 |
| TZST | 90.564 | 167.695 | 0.540 |
| XZ | 172.809 | 180.811 | 0.956 |
| ZIP | 96.212 | 202.997 | 0.474 |
| ZST | 88.075 | 154.881 | 0.569 |

### Peak RSS (median MiB)

| Format / variant | SunPack worker | `7z.exe` | worker / 7-Zip |
| --- | ---: | ---: | ---: |
| 7z split | 474.410 | 458.383 | 1.035 |
| 7z non-solid | 323.938 | 308.055 | 1.052 |
| 7z solid | 474.148 | 458.312 | 1.035 |
| BZip2 | 146.871 | 12.637 | 11.622 |
| Gzip | 25.055 | 8.219 | 3.048 |
| RAR5 split | 52.145 | 40.516 | 1.287 |
| RAR4 non-solid | 24.320 | 11.613 | 2.094 |
| RAR4 solid | 25.027 | 12.359 | 2.025 |
| RAR5 non-solid | 52.008 | 39.613 | 1.313 |
| RAR5 solid | 53.043 | 40.480 | 1.310 |
| TAR | 24.074 | 7.305 | 3.296 |
| TBZ2 | 146.953 | 12.641 | 11.625 |
| TGZ | 25.051 | 8.227 | 3.045 |
| TXZ | 474.520 | 458.531 | 1.035 |
| TZST | 21.871 | 9.801 | 2.232 |
| XZ | 474.484 | 458.527 | 1.035 |
| ZIP | 23.090 | 7.992 | 2.889 |
| ZST | 21.500 | 9.793 | 2.195 |

The sum of independent per-case time medians is 8,454.286 ms for the worker and
10,656.967 ms for `7z.exe`: worker/7-Zip is **0.793x**, approximately 20.7%
lower. The worker has a lower median time in all 18 cases. These times are
independent case medians summed for a compact comparison, not one serial run.

Peak memory is format-dependent. The worker / 7-Zip ratio is below 1 when the
worker uses less RSS and above 1 when `7z.exe` uses less. For example,
BZip2/TBZ2 use about 147 MiB in the worker versus about 13 MiB in `7z.exe`,
while solid 7z/XZ cases are about 474 MiB versus 459 MiB. RSS values are
per-case medians of sampled run peaks; they are not added across formats.

## Reproduction

```powershell
uv sync --locked --extra dev
cmake --build native/sevenzip_bridge/build-x64 --config Release --target sunpack_sevenzip_worker --parallel
uv run python -m benchmarks extraction worker-vs-7z-300m `
  --sunpack-version v0.7.0 `
  --worker-source-commit e37c1769 `
  --worker native/sevenzip_bridge/build-x64/Release/sunpack_sevenzip_worker.exe `
  --small-files 8 --large-files 2 --large-file-mib 150 `
  --runs 5 --warmups 0 `
  --json-out benchmarks/results/worker-vs-7z-300m-v0.7.0-rss.json
```

The direct script entry point is:

```powershell
uv run python benchmarks/scenarios/worker_vs_7z_300m.py `
  --sunpack-version v0.7.0 --worker-source-commit e37c1769 `
  --worker native/sevenzip_bridge/build-x64/Release/sunpack_sevenzip_worker.exe `
  --small-files 8 --large-files 2 `
  --large-file-mib 150 --runs 5 --warmups 0 `
  --json-out benchmarks/results/worker-vs-7z-300m-v0.7.0-rss.json
```

Use `--metadata-only` to generate the corpus and catalog without extraction, or
`--format zip --runs 1` for a quick smoke test. The script records raw samples,
archive `7z -slt` properties, volume sizes, compression ratios, host metadata,
and derived time/RSS medians in JSON. RSS is sampled from process descendants
at 20 ms intervals; the JSON retains each measured run's raw peak.
