# Reproducible 300 MiB worker versus 7-Zip benchmark

This document contains the detailed protocol behind the short result table in
the root README. The benchmark compares the SunPack native worker with the
bundled command-line `7z.exe` across the supported generated formats.

## Software and machine

Recorded software identity:

| Component            | Value                                                                        |
| -------------------- | ---------------------------------------------------------------------------- |
| SunPack              | v0.7.9                                                                       |
| Repository HEAD      | `b9fdfa6d`                                                                   |
| Worker source        | commit `b9fdfa6d` |
| BZip2 parallel width | Up to four lanes: the caller plus up to three worker threads                 |
| Worker binary        | `native/sevenzip_bridge/build-x64/Release/sunpack_sevenzip_worker.exe`       |
| 7-Zip CLI            | 7-Zip 26.03 (x64), `tools/7z.exe`                                            |
| 7-Zip SHA-256        | `6ee3c0ed0b27663c1b948ae85a7c0bb073aed1498983182f3f0df1f6a8c30b2f`           |
| Worker SHA-256       | `03b96534876d1e847abf9f00dd73b120880a39a7959889964943e0bec6b56bc4`           |
| Run date / JSON      | 2026-10-03; `benchmarks/results/worker-vs-7z-300m-v0.7.9-b9fdfa6-rss-20261003.json` |

Recorded host:

| Property         | Value                                                                                                          |
| ---------------- | -------------------------------------------------------------------------------------------------------------- |
| OS               | Windows 11, x64, build 26200                                                              |
| Computer         | MSI Vector GP78HX 13VI                                                                                         |
| CPU              | 13th Gen Intel Core i9-13980HX, 24 physical cores / 32 logical processors                                      |
| Memory           | 31.77 GiB                                                                                                      |
| Benchmark volume | `C:` NTFS, Samsung NVMe MZVL21T0HCLR-00B00, 934.47 GiB total and approximately 271.36 GiB free at capture time |

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
| 7z split         | LZMA2, 7-Zip default            | default solid behavior, `-v16m` | 10 volumes; 157,320,673 bytes total                         |
| 7z solid         | LZMA2, `-ms=on`                 | solid, single volume            | 157,320,673 bytes; 50.01% of payload; 2.00x payload/archive |
| 7z non-solid     | LZMA2, `-ms=off`                | non-solid, single volume        | 157,319,998 bytes; 50.01%; 2.00x                            |
| ZIP              | Deflate, 7-Zip default          | single ZIP volume               | 157,703,555 bytes; 50.13%; 1.99x                            |
| RAR5 split       | RAR5 default method             | default solid behavior, `-v16m` | 10 volumes; 157,594,577 bytes total                         |
| RAR5 solid       | RAR5 default method, `-s`       | solid, single volume            | 157,592,751 bytes; 50.10%; 2.00x                            |
| RAR5 non-solid   | RAR5 default method, `-s-`      | non-solid, single volume        | 157,295,918 bytes; 50.00%; 2.00x                            |
| RAR4 solid       | RAR4 default method, `-ma4 -s`  | solid, single volume            | 157,769,630 bytes; 50.15%; 1.99x                            |
| RAR4 non-solid   | RAR4 default method, `-ma4 -s-` | non-solid, single volume        | 157,365,992 bytes; 50.03%; 2.00x                            |
| TAR              | no compression                  | single TAR                      | 314,575,360 bytes; TAR metadata/padding adds 2,560 bytes    |
| Gzip / TGZ       | Deflate over TAR                | same compressed stream bytes    | 157,773,338 bytes; 50.15%; 1.99x                            |
| BZip2 / TBZ2     | BZip2 over TAR                  | same compressed stream bytes    | 158,006,027 bytes; 50.23%; 1.99x                            |
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

These are end-to-end measurements, not pure decoder microbenchmarks: they
preserve the product execution model, and the reference includes CLI process
startup overhead. Every case produced the expected output, and both implementations
succeeded in all 18 cases. For TBZ2, the full-matrix worker runs were bimodal
(1,560 to 6,405 ms), so its table row uses the separate paired five-run
confirmation report at
`benchmarks/results/worker-vs-7z-300m-v0.7.9-b9fdfa6-tbz2-confirm-20261003.json`.
RSS remains a per-case median and is not summed across formats. The TAR metadata
explains the 2,560-byte difference from the two raw members.

## Result

### Time and peak RSS (per-case medians)

Worker measurements are grouped first (time, then RSS), followed by the same
measurements for `7z.exe`. Time ratio and RSS ratio are each worker divided by
7-Zip; a ratio below 1 favors the worker for that metric.

| Format / variant | Worker time (ms) | `7z.exe` time (ms) | Time ratio | Worker peak RSS (MiB) | `7z.exe` peak RSS (MiB) | RSS ratio |
| ---------------- | :--------------- | :----------------- | :--------- | :-------------------- | :---------------------- | :-------- |
| 7z split         | 141.886          | 203.605            | 0.697      | 476.199               | 458.379                 | 1.039     |
| 7z non-solid     | 188.029          | 250.020            | 0.752      | 324.137               | 308.047                 | 1.052     |
| 7z solid         | 142.802          | 204.641            | 0.698      | 475.652               | 458.309                 | 1.038     |
| BZip2            | 1,670.859        | 2,914.191          | 0.573      | 43.289                | 12.625                  | 3.429     |
| Gzip             | 81.731           | 209.743            | 0.390      | 25.188                | 8.215                   | 3.066     |
| RAR5 split       | 172.453          | 768.066            | 0.225      | 54.242                | 40.516                  | 1.339     |
| RAR4 non-solid   | 80.926           | 185.464            | 0.436      | 27.488                | 11.598                  | 2.370     |
| RAR4 solid       | 539.789          | 652.330            | 0.827      | 28.211                | 12.348                  | 2.285     |
| RAR5 non-solid   | 95.293           | 186.992            | 0.510      | 56.250                | 39.605                  | 1.420     |
| RAR5 solid       | 168.938          | 745.597            | 0.227      | 57.289                | 40.477                  | 1.415     |
| TAR              | 76.350           | 120.331            | 0.634      | 24.031                | 7.297                   | 3.293     |
| TBZ2             | 1,663.736        | 2,890.008          | 0.576      | 44.141                | 12.625                  | 3.496     |
| TGZ              | 84.974           | 213.233            | 0.399      | 25.215                | 8.219                   | 3.068     |
| TXZ              | 156.893          | 181.328            | 0.865      | 474.617               | 458.523                 | 1.035     |
| TZST             | 100.259          | 188.752            | 0.531      | 23.012                | 9.789                   | 2.351     |
| XZ               | 169.011          | 183.459            | 0.921      | 474.621               | 458.520                 | 1.035     |
| ZIP              | 76.254           | 198.892            | 0.383      | 25.289                | 7.984                   | 3.167     |
| ZST              | 104.599          | 181.936            | 0.575      | 23.039                | 9.789                   | 2.354     |

Using the separate TBZ2 confirmation with the other 17 full-matrix cases, the
sum of per-case medians is 5,714.782 ms for the worker and 10,478.588 ms for
`7z.exe` (0.545x). This is not a single serial run. BZip2/TBZ2 use about 43–44 MiB
in the worker versus about 12.6 MiB in `7z.exe`; solid 7z/XZ cases use about
475 MiB versus about 458 MiB. RSS values are per-case medians of sampled run
peaks and are not summed across formats.

## Reproduction

```powershell
uv sync --locked --extra dev
cmake --build native/sevenzip_bridge/build-x64 --config Release --target sunpack_sevenzip_worker --parallel
uv run python -m benchmarks extraction worker-vs-7z-300m `
  --sunpack-version v0.7.9 `
  --worker-source-commit b9fdfa6d `
  --worker native/sevenzip_bridge/build-x64/Release/sunpack_sevenzip_worker.exe `
  --small-files 8 --large-files 2 --large-file-mib 150 `
  --runs 5 --warmups 0 `
  --json-out benchmarks/results/worker-vs-7z-300m-v0.7.9-b9fdfa6-rss-20261003.json
```

The direct script entry point is:

```powershell
uv run python benchmarks/scenarios/worker_vs_7z_300m.py `
  --sunpack-version v0.7.9 --worker-source-commit b9fdfa6d `
  --worker native/sevenzip_bridge/build-x64/Release/sunpack_sevenzip_worker.exe `
  --small-files 8 --large-files 2 `
  --large-file-mib 150 --runs 5 --warmups 0 `
  --json-out benchmarks/results/worker-vs-7z-300m-v0.7.9-b9fdfa6-rss-20261003.json
```

Use `--metadata-only` to generate the corpus and catalog without extraction, or
`--format zip --runs 1` for a quick smoke test. The script records raw samples,
archive `7z -slt` properties, volume sizes, compression ratios, host metadata,
and derived time/RSS medians in JSON. RSS is sampled from process descendants
at 20 ms intervals; the JSON retains each measured run's raw peak.
