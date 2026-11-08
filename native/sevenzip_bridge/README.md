# sevenzip_bridge

Windows C++ component containing SunPack's embedded 7-Zip extraction worker.

The product runtime uses `sunpack_sevenzip_worker.exe`. The former in-process
`sunpack_sevenzip.dll` resource-analysis ABI has been removed.

## Responsibilities

- worker-internal bounded password candidate confirmation
- extraction from files, volume sets, file ranges, concatenated ranges and patch-plan inputs
- embedded 7-Zip decode backends and SunPack's optimized writer/runtime control

Format, structure, encryption, and verification analysis stay in the Python/Rust
pipeline. The worker reports structured extraction facts and operation results.

## Requirements

- Windows
- CMake 3.25 or newer
- Visual Studio Build Tools 2022 or another C++17 MSVC-compatible toolchain
- ARM64 optimized builds additionally require `clang-cl` (Visual Studio C++ Clang tools for Windows)

## Build

```powershell
cmake -S native\sevenzip_bridge -B native\sevenzip_bridge\build-x64 -A x64
cmake --build native\sevenzip_bridge\build-x64 --config Release
ctest --test-dir native\sevenzip_bridge\build-x64 -C Release --output-on-failure
```

On x64 the build assembles the upstream 7-Zip hot paths
(`Asm/x86/{LzmaDecOpt,7zCrcOpt,XzCrc64Opt,AesOpt,Sha1Opt,Sha256Opt}.asm`) with
`ml64.exe`. Those replace the matching C fallbacks. `Sort.asm` and
`LzFindOpt.asm` are compression-side and stay disabled.

On ARM64, upstream 7-Zip uses `Asm/arm64/LzmaDecOpt.S` for the optimized LZMA
decoder core. CMake invokes `clang-cl --target=arm64-pc-windows-msvc` for that
single assembly file; CRC/AES/SHA remain on upstream C/intrinsics.

`SUP7Z_USE_X64_ASM` and `SUP7Z_USE_ARM64_ASM` default to `ON` and remain
benchmark/rollback switches. `SUP7Z_ENABLE_PIPELINE_TIMING` is benchmark-only.

Release runtime output:

```text
native\sevenzip_bridge\build-x64\Release\sunpack_sevenzip_worker.exe
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

Both stdin and stdout use `SPBF` (four bytes), a little-endian `u32` payload
length, and one typed object. There is no newline delimiter, JSON parser,
protocol negotiation, or fallback. Deploy the worker and Rust extension together.
Stderr remains diagnostic text.

The codecs are `src/internal/worker_wire.hpp` and
`../sunpack_native/src/scan/worker_wire.rs`. Python forwards bytes and receives
decoded event envelopes; manifest rows and trace items stay in Rust throughout
assembly and verification.

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
