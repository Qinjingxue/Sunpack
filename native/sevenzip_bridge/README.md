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
