# sevenzip_bridge

Windows C++ bridge around the bundled `7z.dll`.

It provides SunPack's in-process archive inspection ABI and the out-of-process extraction worker. Product code calls the bridge through `sunpack.support.sevenzip_bridge`; extraction jobs are executed by `sunpack_sevenzip_worker.exe`.

## Responsibilities

- archive probe and test
- password array attempts
- open-only archive probing and resource analysis
- extraction from files, volume sets, file ranges, concatenated ranges and patch-plan inputs

Business decisions remain in Python. The bridge reports structured facts and operation results.

## Requirements

- Windows
- CMake 3.25 or newer
- Visual Studio Build Tools 2022 or another C++17 MSVC-compatible toolchain
- ARM64 optimized builds additionally require `clang-cl` (Visual Studio C++ Clang tools for Windows)
- repository `tools\7z.dll`

## Build

```powershell
cmake -S native\sevenzip_bridge -B native\sevenzip_bridge\build-x64 -A x64
cmake --build native\sevenzip_bridge\build-x64 --config Release
ctest --test-dir native\sevenzip_bridge\build-x64 -C Release --output-on-failure
```

On x64 the build assembles the upstream 7-Zip hot paths
(`Asm/x86/{LzmaDecOpt,7zCrcOpt,XzCrc64Opt,AesOpt,Sha1Opt,Sha256Opt}.asm`) with
`ml64.exe`. Those replace the matching C fallbacks, so the x64 build compiles
**223 C/C++ translation units + 6 MASM** instead of 228 C/C++.
`Sort.asm` and `LzFindOpt.asm` are compression-side and stay disabled.

On ARM64, upstream 7-Zip uses a different model: only
`Asm/arm64/LzmaDecOpt.S` replaces the LZMA decoder core. CMake invokes
`clang-cl --target=arm64-pc-windows-msvc` for that single GNU-style
preprocessed assembly file and links the resulting ARM64 COFF object into the
otherwise normal MSVC build. CRC/AES/SHA continue to use upstream
C/intrinsics, so ARM64 remains **228 C/C++ translation units + 1 assembly
object**.

`SUP7Z_USE_X64_ASM` and `SUP7Z_USE_ARM64_ASM` (both default `ON`) are
benchmark/rollback switches, not user settings:

```powershell
cmake -S native\sevenzip_bridge -B native\sevenzip_bridge\build-c-only -A x64 -DSUP7Z_USE_X64_ASM=OFF
cmake -S native\sevenzip_bridge -B native\sevenzip_bridge\build-arm64-c-only -A ARM64 -DSUP7Z_USE_ARM64_ASM=OFF
```

Give each setting its own build directory. CMake records the effective x64 and
ARM64 assembly selections separately and refuses to flip either architecture's
optimized path inside one build directory, keeping A/B comparisons free of
stale intermediate objects.
Builds are incremental and Release-only (`/O2 /Oi /Ot /Gy /Gw /GF` + `/GL` /
`/LTCG /OPT:REF /OPT:ICF`); the MASM objects carry no C/C++ optimization flags
by design, since `ml64.exe` has none.

Release outputs:

```text
native\sevenzip_bridge\build-x64\Release\sunpack_sevenzip.dll
native\sevenzip_bridge\build-x64\Release\sunpack_sevenzip_worker.exe
```

Development and release scripts copy them to:

```text
tools\sunpack_sevenzip.dll
tools\sunpack_sevenzip_worker.exe
```

## C API

The DLL exports a narrow C ABI for archive resource analysis and manifest queries. Password candidate confirmation is an internal worker capability, not a public Python/DLL probe API.

The Python binding owns library loading, typed result conversion and caches for those resource queries. The worker owns extraction, bounded confirmation of weak password candidates, process isolation, JSON job handling and progress output.

## Runtime Contract

`sunpack_sevenzip.dll`, `sunpack_sevenzip_worker.exe` must be available in the same SunPack tool directory. Do not add a `7z.exe x` fallback to the product extraction path; failures must remain explicit and structured.
