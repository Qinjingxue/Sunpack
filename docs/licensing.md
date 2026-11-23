# Licensing and third-party compliance

**English** | [简体中文](zh-CN/licensing.md) | [繁體中文](zh-TW/licensing.md) | [日本語](ja/licensing.md) | [한국어](ko/licensing.md)

This document summarizes how licenses are scoped in the SunPack repository and
what must be preserved when distributing SunPack. The original license texts
control if this summary differs from them.

## SunPack-original code

Independently written SunPack source code is licensed under the root
[MIT License](../LICENSE), including original application code in the Worker
and Rust Runtime. Third-party code and modifications to it are distributed
under the applicable terms described in
[THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md). Modified LGPL-covered
7-Zip files are distributed under the LGPL with any applicable upstream terms.

## Vendored 7-Zip 26.05 source

The vendored tree is a trimmed, locally modified subset of
[7-Zip 26.05](https://github.com/ip7z/7zip/releases/tag/26.05). The tree also
retains unchanged files from earlier upstream releases.

The repository keeps its 7-Zip 26.05 runtime subset at the historical path:

`sunpack/sevenzip_bridge/7z2604-src/`

The upstream 7-Zip source license governs the vendored files. The source tree
includes the upstream license at

`sunpack/sevenzip_bridge/7z2604-src/DOC/License.txt`

A convenience copy is also kept at:

`licenses/7zip-source-license.txt`

The upstream license identifies these file-specific terms:

- `CPP/7zip/Compress/Rar*`: GNU LGPL plus the unRAR license restriction.
- `CPP/7zip/Compress/LzfseDecoder.cpp`: BSD 3-Clause.
- `C/ZstdDec.c`: BSD 3-Clause.
- `C/Xxh64.c`: BSD 2-Clause.
- Files explicitly marked public domain retain that status.
- Other 7-Zip source files are under the GNU LGPL, version 2.1 or later.

The complete GNU LGPL 2.1 text is stored at
`licenses/LGPL-2.1.txt`.

### Modifying vendored 7-Zip files

Changes to files governed by the LGPL must continue to satisfy the LGPL.
In particular, when an LGPL-covered file is modified, preserve upstream
copyright/license notices and add the change notices required by the LGPL,
including that the file was changed and the date of the change.

The unRAR-restricted RAR decompression sources must also retain the upstream
restriction: they may not be used to recreate the proprietary RAR compression
algorithm. See the upstream 7-Zip license text for the exact terms.

Prefer keeping SunPack-specific integration code outside the vendored
`7z2604-src/` tree where practical. This keeps upstream provenance and license
boundaries easy to audit and reduces merge friction when updating 7-Zip.

## Vendored zlib-ng 2.3.3 source

The native ZIP Deflate fast path vendors the required zlib-ng 2.3.3 build
sources at:

`sunpack/sevenzip_bridge/zlib-ng-2.3.3/`

Those files are pinned to upstream commit
`12731092979c6d07f42da27da673a9f6c7b13586` and remain under the upstream
zlib license. The release copy is stored at:

`licenses/zlib-ng-license.txt`

Keep the upstream copyright and permission notice with redistributed source and
binary packages.

## 7-Zip development assets

Development setup stages `7z.exe`, `7z.dll`, and `7zCon.sfx` for generating
test fixtures. Those binaries remain subject to the 7-Zip binary distribution
terms summarized in `licenses/7zip-license.txt`.

## Release packaging requirements

The Windows installer displays and installs `THIRD_PARTY_LICENSES.txt`. The
file identifies `tools/sunpack_sevenzip_worker.exe`, which embeds the modified
7-Zip backend, and `sunpack-runtime.exe`, which embeds 7-Zip's Deflate64
decoder. It includes the applicable license texts and the source URL for the
exact commit used by the official release workflow. The GitHub Release also
links to this archive alongside the installers.

When redistributing a local build, provide its complete corresponding source,
including local changes and build scripts, alongside the binary distribution
or by another method allowed by the LGPL. You can pass
`-CorrespondingSourceUrl` to `scripts/build_windows.ps1` to include the
download URL in the installer. Recipients may modify the linked executables
for their own use and reverse engineer them to debug those modifications
under [LGPL 2.1 section 6](https://www.gnu.org/licenses/old-licenses/lgpl-2.1.en.html).

### Rebuild the Worker and Runtime

Extract the corresponding source archive from the release notice. On Windows,
install the [development prerequisites](development_setup.md), including the
MSVC tools for the target architecture and the corresponding Rust target.
Run these commands from the extracted source root to rebuild x64 after
modifying the 7-Zip source under `sunpack/sevenzip_bridge/7z2604-src/`.

```powershell
.\scripts\setup_windows_dev.ps1 -Arch x64 -BootstrapOnly
$cmake = '.\.venv\Scripts\cmake.exe'
& $cmake -S sunpack/sevenzip_bridge -B .cache/relink-worker-x64 -A x64 -DSUP7Z_DEBUG=OFF
& $cmake --build .cache/relink-worker-x64 --config Release --target sunpack_sevenzip_worker
cargo build --locked --release --manifest-path sunpack/Cargo.toml --target x86_64-pc-windows-msvc -p sunpack-runtime --bin sunpack-runtime
```

For ARM64, use `-Arch arm64`, `-A ARM64`, a separate CMake build directory,
and the Rust target `aarch64-pc-windows-msvc`. The optimized ARM64 Worker also
requires the Visual Studio C++ Clang tools. The Worker EXE is in the CMake
build directory's `Release` folder. The Runtime EXE is in
`.cache/rust-target/<rust-target>/release/`. Replace the corresponding
executables together with their matching release's remaining files when
testing a modified build. The full installer can also be rebuilt with
`scripts/build_windows.ps1 -Arch x64 -SkipTests -NoPause` (use `arm64` for
the ARM64 installer).

## Updating 7-Zip

When updating the vendored 7-Zip version:

1. Import the upstream license file together with the source.
2. Refresh `licenses/7zip-source-license.txt` from that exact upstream version.
3. Review upstream license changes, especially the RAR, BSD, and public-domain
   exceptions.
4. Update `THIRD_PARTY_NOTICES.md` and this document if paths, versions, or
   license terms change.
5. Keep release-package tests verifying that the consolidated document preserves
   all required license texts and attributions.

