# sevenzip_bridge

Windows C++ component containing SunPack's embedded 7-Zip extraction worker.

The product runtime uses `sunpack_sevenzip_worker.exe`. The former in-process
`sunpack_sevenzip.dll` resource-analysis ABI has been removed.

## Responsibilities

- worker-internal bounded password candidate confirmation
- extraction from files, volume sets, file ranges, concatenated ranges and patch-plan inputs
- embedded 7-Zip decode backends and SunPack's optimized writer/runtime control

Format, structure, encryption, and password analysis belong to Rust. The worker
reports decode and output-finalization facts; the coordinator uses the final
execution result without rereading source archives or output files.

## Requirements

- Windows
- CMake 3.25 or newer
- Visual Studio Build Tools 2022 or another C++17 MSVC-compatible toolchain
- ARM64 optimized builds additionally require `clang-cl` (Visual Studio C++ Clang tools for Windows)

## Build

```powershell
.\.venv\Scripts\cmake.exe -S sunpack\sevenzip_bridge -B .cache\native\x64\release\sevenzip_bridge -A x64
.\.venv\Scripts\cmake.exe --build .cache\native\x64\release\sevenzip_bridge --config Release
.\.venv\Scripts\ctest.exe --test-dir .cache\native\x64\release\sevenzip_bridge -C Release --output-on-failure
```

On x64 the build assembles the upstream 7-Zip hot paths
(`Asm/x86/{LzmaDecOpt,7zCrcOpt,XzCrc64Opt,AesOpt,Sha1Opt,Sha256Opt}.asm`) with
`ml64.exe`. Those replace the matching C fallbacks. `Sort.asm` and
`LzFindOpt.asm` are compression-side and stay disabled.

On ARM64, upstream 7-Zip uses `Asm/arm64/LzmaDecOpt.S` for the optimized LZMA
decoder core. CMake invokes `clang-cl --target=arm64-pc-windows-msvc` for that
single assembly file; CRC/AES/SHA remain on upstream C/intrinsics.

For local diagnostics, configure with `-DSUP7Z_DEBUG=ON` and build with
`--config Release`. This keeps compiler optimizations and the architecture's
assembly paths, skips final LTO, selects Cargo's `ci` profile for ENC, and
includes worker pipeline timing. Set `SUNPACK_SEVENZIP_PROFILE_PIPELINE=1`
before launching that worker to collect timing. `setup_windows_dev.ps1 -BuildProfile ci` selects this mode automatically.

Release runtime output:

```text
.cache\native\x64\release\sevenzip_bridge\Release\sunpack_sevenzip_worker.exe
```

Development and release scripts copy it to:

```text
tools\sunpack_sevenzip_worker.exe
```

## Runtime contract

`sunpack_sevenzip_worker.exe` must be available in the SunPack tool directory.
Do not add a `7z.exe x` fallback to the product extraction path; failures remain
explicit and structured.

Every job supplies the canonical `archive_input` descriptor and may carry an
`input_id` for reporting. Format, ordered parts, canonical volume names, and
byte extents belong to that descriptor. The worker does not infer input shape
from root-level path, format, or offset aliases. File, named-volume, and range
stream adapters remain specialized below this shared protocol.

## Binary pipe frames

Both directions use `SPBF` (four bytes), a little-endian 32-bit length, and
binary typed values. On stdin the high bit marks a continuation. Requests up
to 512 KiB use one frame. Larger requests carry the same object across
successive frames of at most 512 KiB, with the high bit clear on the final
frame. An empty continuation discards the unfinished request. The worker
parses fields and collection items directly into the request and admits it
only after the complete object ends at the final frame boundary. Deploy the
worker and Rust runtime together. Stderr remains diagnostic text.

The codecs are `src/internal/worker_wire.hpp` and
`../sunpack_runtime/src/scan/worker_wire.rs`. Manifest rows and trace items
stay in Rust throughout assembly, progress reporting, and recursive discovery.

| Tag | Value |
| --- | --- |
| 0 | Container end |
| 1 | Null |
| 2 / 3 | False / true |
| 4 / 5 / 6 | Little-endian u64 / i64 / IEEE-754 f64 |
| 7 / 8 | u32 byte length followed by UTF-8 text / raw bytes |
| 9 | Array of typed values, terminated by tag 0 |
| 10 | Object of text keys and typed values, terminated by tag 0 |
| 11 / 12 | u8 / little-endian u32 |

Nonnegative integers use the smallest supported width. Objects carry optional
control/result fields without a second pass to count or size them. Per-file
manifest rows have 14 positional columns (`WorkerRow` in `worker_event.rs`),
with raw magic bytes and an empty output path when it equals the archive path.
Trace rows use the 20 fields of `OutputTraceItem` in declaration order.

Chunks target 512 KiB and retain job IDs, sequence numbers, and final count
validation. A larger individual row gets its own frame. Chunking does not cap
the total result. Output locking covers the complete frame, including its
header; paired lifecycle events share that lock. Input buffers grow only as
bytes arrive and are released after parsing. Readers accept split/coalesced
frames and reject incomplete EOF. Malformed bodies with a recoverable job ID
cancel only that job; invalid framing aborts the shared worker before failing
its pending jobs. Graceful shutdown still drains admitted work.
