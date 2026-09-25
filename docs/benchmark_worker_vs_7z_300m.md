# Reproducible 300 MiB worker versus 7-Zip benchmark

This document contains the detailed protocol behind the short result table in
the root README. The benchmark compares the SunPack native worker with the
bundled command-line `7z.exe` across the supported generated formats.

## Software and machine

Recorded software identity:

| Component            | Value                                                                        |
| -------------------- | ---------------------------------------------------------------------------- |
| SunPack              | v0.7.0                                                                       |
| Repository HEAD      | `c3eaec11`                                                                   |
| Worker source        | commit `c3eaec11` (`perf(bzip2): stream full blocks through one input pass`) |
| BZip2 parallel width | Up to four lanes: the caller plus up to three worker threads                 |
| Worker binary        | `native/sevenzip_bridge/build-x64/Release/sunpack_sevenzip_worker.exe`       |
| 7-Zip CLI            | 7-Zip 26.03 (x64), `tools/7z.exe`                                            |
| 7-Zip SHA-256        | `6ee3c0ed0b27663c1b948ae85a7c0bb073aed1498983182f3f0df1f6a8c30b2f`           |
| Worker SHA-256       | `8f1a0b1c5ff50b79206101112682b429d2e6349f9a47a630968ecfce5e6fee32`           |
| Run date / JSON      | 2026-09-25; `benchmarks/results/worker-vs-7z-300m-v0.7.0-c3eaec11-rss.json`  |

Recorded host:

| Property         | Value                                                                                                          |
| ---------------- | -------------------------------------------------------------------------------------------------------------- |
| OS               | Windows 11 Pro for Workstations, x64, build 26100                                                              |
| Computer         | MSI Vector GP78HX 13VI                                                                                         |
| CPU              | 13th Gen Intel Core i9-13980HX, 24 physical cores / 32 logical processors                                      |
| Memory           | 31.77 GiB                                                                                                      |
| Benchmark volume | `C:` NTFS, Samsung NVMe MZVL21T0HCLR-00B00, 934.47 GiB total and approximately 197.80 GiB free at capture time |

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

| Case             | Method and construction         | Solid / volume layout           | Archive size and ratio                                      |
| ---------------- | ------------------------------- | ------------------------------- | ----------------------------------------------------------- |
| 7z split         | LZMA2, 7-Zip default            | default solid behavior, `-v16m` | 10 volumes; 157,320,674 bytes total                         |
| 7z solid         | LZMA2, `-ms=on`                 | solid, single volume            | 157,320,674 bytes; 50.01% of payload; 2.00x payload/archive |
| 7z non-solid     | LZMA2, `-ms=off`                | non-solid, single volume        | 157,319,999 bytes; 50.01%; 2.00x                            |
| ZIP              | Deflate, 7-Zip default          | single ZIP volume               | 157,703,555 bytes; 50.13%; 1.99x                            |
| RAR5 split       | RAR5 default method             | default solid behavior, `-v16m` | 10 volumes; 157,594,577 bytes total                         |
| RAR5 solid       | RAR5 default method, `-s`       | solid, single volume            | 157,592,751 bytes; 50.10%; 2.00x                            |
| RAR5 non-solid   | RAR5 default method, `-s-`      | non-solid, single volume        | 157,295,918 bytes; 50.00%; 2.00x                            |
| RAR4 solid       | RAR4 default method, `-ma4 -s`  | solid, single volume            | 157,769,630 bytes; 50.15%; 1.99x                            |
| RAR4 non-solid   | RAR4 default method, `-ma4 -s-` | non-solid, single volume        | 157,365,992 bytes; 50.03%; 2.00x                            |
| TAR              | no compression                  | single TAR                      | 314,575,360 bytes; TAR metadata/padding adds 2,560 bytes    |
| Gzip / TGZ       | Deflate over TAR                | same compressed stream bytes    | 157,773,338 bytes; 50.15%; 1.99x                            |
| BZip2 / TBZ2     | BZip2 over TAR                  | same compressed stream bytes    | 158,006,051 bytes; 50.23%; 1.99x                            |
| XZ / TXZ         | LZMA2 over TAR                  | same compressed stream bytes    | 157,321,248 bytes; 50.01%; 2.00x                            |
| Zstandard / TZST | Zstandard level 3 over TAR      | same compressed stream bytes    | 157,305,941 bytes; 50.01%; 2.00x                            |

The percentage is `archive bytes / 300 MiB payload`; the second ratio is
`payload bytes / archive bytes`. Split archive totals use the sum of all volume
sizes recorded in `archive_catalog.archive_bytes_total`.

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

The BZip2 worker in this build streams full blocks in one input pass and uses up
to four parallel lanes. These are end-to-end measurements, not pure decoder
microbenchmarks, so they preserve the product execution model; the reference
also includes CLI process startup overhead. For compressed TAR aliases, a
successful `7z.exe` return code and valid TAR output are the correctness
criteria; the TAR metadata explains the 2,560-byte difference from the two raw
members.

## Result

### Time and peak RSS (per-case medians)

Worker measurements are grouped first (time, then RSS), followed by the same
measurements for `7z.exe`. Time ratio and RSS ratio are each worker divided by
7-Zip; a ratio below 1 favors the worker for that metric.

| Format / variant | Worker time (ms) | `7z.exe` time (ms) | Time ratio | Worker peak RSS (MiB) | `7z.exe` peak RSS (MiB) | RSS ratio |
| ---------------- | ---------------: | -----------------: | ---------: | --------------------: | ----------------------: | --------: |
| 7z split         |          151.347 |            209.220 |      0.723 |               469.258 |                 458.383 |     1.024 |
| 7z non-solid     |          192.130 |            249.181 |      0.771 |               319.113 |                 308.051 |     1.036 |
| 7z solid         |          148.431 |            206.594 |      0.718 |               469.215 |                 458.309 |     1.024 |
| BZip2            |        1,752.476 |          2,947.405 |      0.595 |                43.137 |                  12.637 |     3.414 |
| Gzip             |           67.378 |            195.667 |      0.344 |                24.992 |                   8.219 |     3.041 |
| RAR5 split       |          224.977 |            780.676 |      0.288 |                52.066 |                  40.504 |     1.285 |
| RAR4 non-solid   |          170.297 |            181.628 |      0.938 |                24.281 |                  11.605 |     2.092 |
| RAR4 solid       |          630.189 |            655.308 |      0.962 |                25.020 |                  12.352 |     2.026 |
| RAR5 non-solid   |          126.030 |            180.823 |      0.697 |                52.008 |                  39.609 |     1.313 |
| RAR5 solid       |          192.755 |            756.119 |      0.255 |                53.059 |                  40.473 |     1.311 |
| TAR              |           72.315 |            118.175 |      0.612 |                25.000 |                   7.301 |     3.424 |
| TBZ2             |        1,769.768 |          2,972.193 |      0.595 |                44.023 |                  12.629 |     3.486 |
| TGZ              |           71.309 |            202.180 |      0.353 |                25.016 |                   8.211 |     3.047 |
| TXZ              |          169.861 |            183.313 |      0.927 |               474.453 |                 458.520 |     1.035 |
| TZST             |           93.847 |            152.214 |      0.617 |                21.473 |                   9.801 |     2.191 |
| XZ               |          165.727 |            182.915 |      0.906 |               474.484 |                 458.520 |     1.035 |
| ZIP              |           93.797 |            197.793 |      0.474 |                20.379 |                   7.988 |     2.551 |
| ZST              |           95.207 |            156.096 |      0.610 |                21.414 |                   9.801 |     2.185 |

All 18 worker cases and all 18 `7z.exe` cases succeeded. The sum of independent
per-case time medians is 6,187.841 ms for the worker and 10,527.500 ms for
`7z.exe` (0.588x, about 41.2% lower). This is a compact sum of independent case
medians, not one serial run. BZip2/TBZ2 use about 43–44 MiB in the worker versus
about 12.6 MiB in `7z.exe`; solid 7z/XZ cases use about 469–474 MiB versus about
458 MiB. RSS values are per-case medians of sampled run peaks and are not summed
across formats.

## Reproduction

```powershell
uv sync --locked --extra dev
cmake --build native/sevenzip_bridge/build-x64 --config Release --target sunpack_sevenzip_worker --parallel
uv run python -m benchmarks extraction worker-vs-7z-300m `
  --sunpack-version v0.7.0 `
  --worker-source-commit c3eaec11 `
  --worker native/sevenzip_bridge/build-x64/Release/sunpack_sevenzip_worker.exe `
  --small-files 8 --large-files 2 --large-file-mib 150 `
  --runs 5 --warmups 0 `
  --json-out benchmarks/results/worker-vs-7z-300m-v0.7.0-c3eaec11-rss.json
```

The direct script entry point is:

```powershell
uv run python benchmarks/scenarios/worker_vs_7z_300m.py `
  --sunpack-version v0.7.0 --worker-source-commit c3eaec11 `
  --worker native/sevenzip_bridge/build-x64/Release/sunpack_sevenzip_worker.exe `
  --small-files 8 --large-files 2 `
  --large-file-mib 150 --runs 5 --warmups 0 `
  --json-out benchmarks/results/worker-vs-7z-300m-v0.7.0-c3eaec11-rss.json
```

Use `--metadata-only` to generate the corpus and catalog without extraction, or
`--format zip --runs 1` for a quick smoke test. The script records raw samples,
archive `7z -slt` properties, volume sizes, compression ratios, host metadata,
and derived time/RSS medians in JSON. RSS is sampled from process descendants
at 20 ms intervals; the JSON retains each measured run's raw peak.
