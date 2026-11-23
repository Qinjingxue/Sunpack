# 许可证与分发

[English](../licensing.md) | **简体中文** | [繁體中文](../zh-TW/licensing.md) | [日本語](../ja/licensing.md) | [한국어](../ko/licensing.md)

本文说明 SunPack 仓库中各许可证的适用范围，以及分发时需要保留的材料。如本文与许可证原文有出入，以原文为准。

## SunPack 原创代码

SunPack 独立编写的源代码采用仓库根目录的 [MIT 许可证](../../LICENSE)，包括 Worker 和 Rust Runtime 的原创应用代码。第三方代码及其修改按 [第三方声明](../../THIRD_PARTY_NOTICES.md) 中列出的适用条款分发。修改过的 7-Zip 文件如果受 LGPL 约束，分发时须遵守 LGPL 及其他适用的上游条款。

## 随附的 7-Zip 26.05 源码

SunPack 对 [7-Zip 26.05](https://github.com/ip7z/7zip/releases/tag/26.05) 的部分运行时代码做了裁剪和修改，同时保留了部分早期上游版本的原样文件。源码沿用 `sunpack/sevenzip_bridge/7z2604-src/` 路径。

随附的文件适用上游 7-Zip 许可证。原文位于 [DOC/License.txt](../../sunpack/sevenzip_bridge/7z2604-src/DOC/License.txt)，发行用副本位于 [licenses/7zip-source-license.txt](../../licenses/7zip-source-license.txt)。

- `CPP/7zip/Compress/Rar*` 适用 GNU LGPL 和 unRAR 许可限制。
- `CPP/7zip/Compress/LzfseDecoder.cpp` 和 `C/ZstdDec.c` 适用 BSD 三条款许可证。
- `C/Xxh64.c` 适用 BSD 两条款许可证。
- 明确标注为公有领域的文件保留该状态。
- 其余 7-Zip 源码适用 GNU LGPL 2.1 或更高版本。仓库附有 [GNU LGPL 2.1 全文](../../licenses/LGPL-2.1.txt)。

### 修改随附的 7-Zip 文件

修改受 LGPL 约束的文件时，须保留上游的版权和许可声明，并在修改过的文件中显著注明修改及日期。

受 unRAR 限制的 RAR 解压源码须保留上游限制，包括不得用来重建专有的 RAR 压缩算法。具体条款见上游许可证原文。

在可行的情况下，将 SunPack 专用的集成代码放在 `7z2604-src/` 之外，便于核对代码来源和许可范围，也能减少合并上游更新时的冲突。

## 随附的 zlib-ng 2.3.3 源码

ZIP Deflate 快速路径所需的 zlib-ng 2.3.3 构建源码位于 `sunpack/sevenzip_bridge/zlib-ng-2.3.3/`，固定到上游提交 `12731092979c6d07f42da27da673a9f6c7b13586`，适用上游 zlib 许可证。再分发源码或二进制时须保留上游版权和许可声明。发行用副本位于 [licenses/zlib-ng-license.txt](../../licenses/zlib-ng-license.txt)。

## 7-Zip 开发工具

开发环境准备的 `7z.exe`、`7z.dll` 和 `7zCon.sfx` 用于生成测试样本。这些二进制文件适用 [7-Zip 二进制分发条款](../../licenses/7zip-license.txt)。

## 发行包要求

Windows 安装器会显示并安装 `THIRD_PARTY_LICENSES.txt`。该文件列明内置修改版 7-Zip 后端的 `tools/sunpack_sevenzip_worker.exe`，以及内置 7-Zip Deflate64 解码器的 `sunpack-runtime.exe`。文件附有适用的许可证全文和官方构建所用提交的源码下载链接。GitHub Release 也会在安装器旁提供同一源码归档的链接。

再分发本地构建时，应随二进制提供完整的对应源码，包括本地修改和构建脚本，或采用 LGPL 允许的其他方式提供。调用 `scripts/build_windows.ps1` 时可以传入 `-CorrespondingSourceUrl`，把下载链接写入安装包。根据 [LGPL 2.1 第 6 条](https://www.gnu.org/licenses/old-licenses/lgpl-2.1.en.html)，接收者可以为自用修改链接后的可执行文件，也可以为调试这些修改而进行逆向工程。

### 重建 Worker 和 Runtime

从发行说明下载并解压对应源码。在 Windows 上安装[开发环境所需工具](development_setup.md)，包括目标架构的 MSVC 工具链和 Rust 目标。修改 `sunpack/sevenzip_bridge/7z2604-src/` 下的 7-Zip 源码后，在解压后的源码根目录运行以下命令重建 x64 版本。

```powershell
.\scripts\setup_windows_dev.ps1 -Arch x64 -BootstrapOnly
$cmake = '.\.venv\Scripts\cmake.exe'
& $cmake -S sunpack/sevenzip_bridge -B .cache/relink-worker-x64 -A x64 -DSUP7Z_DEBUG=OFF
& $cmake --build .cache/relink-worker-x64 --config Release --target sunpack_sevenzip_worker
cargo build --locked --release --manifest-path sunpack/Cargo.toml --target x86_64-pc-windows-msvc -p sunpack-runtime --bin sunpack-runtime
```

构建 ARM64 版本时，改用 `-Arch arm64`、`-A ARM64`、单独的 CMake 构建目录及 Rust 目标 `aarch64-pc-windows-msvc`。启用优化的 ARM64 Worker 还需要 Visual Studio 的 C++ Clang 工具。

Worker 的 EXE 位于 CMake 构建目录的 `Release` 文件夹中。Runtime 的 EXE 位于 `.cache/rust-target/<rust-target>/release/`。测试修改后的版本时，用重建的可执行文件替换对应文件，并搭配同一发行版本的其余文件运行。要重建完整安装器，可以运行 `scripts/build_windows.ps1 -Arch x64 -SkipTests -NoPause`，ARM64 安装器则用 `-Arch arm64`。

## 更新 7-Zip

1. 导入上游源码时一并导入许可证文件。
2. 用相同上游版本的原文更新 `licenses/7zip-source-license.txt`。
3. 核查上游许可变化，特别是 RAR、BSD 和公有领域例外。
4. 路径、版本或许可条款变化时，更新 `THIRD_PARTY_NOTICES.md` 和本文。
5. 保留发行包测试，验证合并后的许可文件包含所需的许可原文和出处声明。
