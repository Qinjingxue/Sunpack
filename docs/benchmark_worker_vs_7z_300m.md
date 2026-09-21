# Reproducible 300 MiB worker versus 7-Zip benchmark

This document contains the detailed protocol behind the short result table in
the root README. The benchmark compares the SunPack native worker with the
bundled command-line `7z.exe` across the supported generated formats.

## Software and machine

Recorded software identity:

| Component | Value |
| --- | --- |
| SunPack | v0.6.2 |
| Worker source | commit `86587874` |
| Worker binary | `native/sevenzip_bridge/build-x64/Release/sunpack_sevenzip_worker.exe` |
| 7-Zip CLI | 7-Zip 26.03 (x64), `tools/7z.exe` |
| 7-Zip SHA-256 | `6ee3c0ed0b27663c1b948ae85a7c0bb073aed1498983182f3f0df1f6a8c30b2f` |
| Worker SHA-256 | `38c48d83d3e8d57445192d820334c08d548caf41e9a9a659537102c28af90adb` |

Recorded host:

| Property | Value |
| --- | --- |
| OS | Windows 11 Pro for Workstations, x64, build 26100 |
| Computer | MSI Vector GP78HX 13VI |
| CPU | 13th Gen Intel Core i9-13980HX, 24 physical cores / 32 logical processors |
| Memory | 31.77 GiB |
| Benchmark volume | `C:` NTFS, Samsung NVMe MZVL21T0HCLR-00B00, 934.47 GiB total and approximately 240.01 GiB free at capture time |

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
| 7z split | LZMA2, 7-Zip default | default solid behavior, `-v16m` | 16 MiB volumes; total is recorded by `archive_catalog` |
| 7z solid | LZMA2, `-ms=on` | solid, single volume | 157,320,673 bytes; 50.01% of payload; 2.00x payload/archive |
| 7z non-solid | LZMA2, `-ms=off` | non-solid, single volume | 157,319,998 bytes; 50.01%; 2.00x |
| ZIP | Deflate, 7-Zip default | single ZIP volume | 157,703,555 bytes; 50.13%; 1.99x |
| RAR5 split | RAR5 default method | default solid behavior, `-v16m` | 16 MiB volumes; total is recorded by `archive_catalog` |
| RAR5 solid | RAR5 default method, `-s` | solid, single volume | 157,592,751 bytes; 50.10%; 2.00x |
| RAR5 non-solid | RAR5 default method, `-s-` | non-solid, single volume | 157,295,918 bytes; 50.00%; 2.00x |
| RAR4 solid | RAR4 default method, `-ma4 -s` | solid, single volume | 157,769,630 bytes; 50.15%; 1.99x |
| RAR4 non-solid | RAR4 default method, `-ma4 -s-` | non-solid, single volume | 157,365,992 bytes; 50.03%; 2.00x |
| TAR | no compression | single TAR | 314,575,360 bytes; TAR metadata/padding adds 2,560 bytes |
| Gzip / TGZ | Deflate over TAR | same compressed stream bytes | 157,773,336 bytes; 50.15%; 1.99x |
| BZip2 / TBZ2 | BZip2 over TAR | same compressed stream bytes | 158,006,043 bytes; 50.23%; 1.99x |
| XZ / TXZ | LZMA2 over TAR | same compressed stream bytes | 157,321,248 bytes; 50.01%; 2.00x |
| Zstandard / TZST | Zstandard level 3 over TAR | same compressed stream bytes | 157,305,941 bytes; 50.01%; 2.00x |

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
- Reported values are per-case wall-time medians in milliseconds.

The comparison is end-to-end, not a pure decoder microbenchmark. This preserves
the actual product execution model, but means the reference includes CLI process
startup overhead. For compressed TAR aliases, a successful `7z.exe` return code
and valid TAR output are the correctness criteria; the TAR metadata explains the
2,560-byte difference from the two raw members.

## Result

| Format / variant | SunPack worker | `7z.exe` | worker / `7z.exe` |
| --- | ---: | ---: | ---: |
| 7z split | 152.350 | 209.230 | 0.728 |
| 7z non-solid | 207.955 | 252.429 | 0.824 |
| 7z solid | 161.992 | 207.314 | 0.781 |
| BZip2 | 2661.051 | 2992.485 | 0.889 |
| Gzip | 84.008 | 204.110 | 0.412 |
| RAR5 split | 231.310 | 780.304 | 0.296 |
| RAR4 non-solid | 170.658 | 183.902 | 0.928 |
| RAR4 solid | 645.206 | 659.011 | 0.979 |
| RAR5 non-solid | 126.918 | 184.521 | 0.688 |
| RAR5 solid | 212.166 | 759.690 | 0.279 |
| TAR | 86.768 | 123.733 | 0.701 |
| TBZ2 | 2533.095 | 2975.355 | 0.851 |
| TGZ | 84.924 | 201.506 | 0.421 |
| TXZ | 177.336 | 179.254 | 0.989 |
| TZST | 89.280 | 154.064 | 0.579 |
| XZ | 178.589 | 182.980 | 0.976 |
| ZIP | 94.941 | 197.796 | 0.480 |
| ZST | 96.481 | 155.547 | 0.620 |

The sum of independent per-case medians is 7,995.028 ms for the worker and
10,603.231 ms for `7z.exe`: worker/7z is **0.754x**, approximately 24.6% lower.
The worker is faster in all 18 cases. The largest gains are RAR5 solid, RAR5
split, Gzip/TGZ, and ZIP; RAR4 is close to parity and XZ/TXZ are effectively
tied.

## Reproduction

```powershell
uv sync --locked --extra dev
uv run python -m benchmarks extraction worker-vs-7z-300m `
  --sunpack-version v0.6.2 `
  --worker-source-commit 86587874 `
  --small-files 8 --large-files 2 --large-file-mib 150 `
  --runs 5 --warmups 0 `
  --json-out benchmarks/results/worker-vs-7z-300m-reproduced.json
```

The direct script entry point is:

```powershell
uv run python benchmarks/scenarios/worker_vs_7z_300m.py `
  --worker-source-commit 86587874 --small-files 8 --large-files 2 `
  --large-file-mib 150 --runs 5 --warmups 0 `
  --json-out benchmarks/results/worker-vs-7z-300m-reproduced.json
```

Use `--metadata-only` to generate the corpus and catalog without extraction, or
`--format zip --runs 1` for a quick smoke test. The script records raw samples,
archive `7z -slt` properties, volume sizes, compression ratios, host metadata,
and derived medians in JSON.
