# 开发环境和构建说明

[English](../development_setup.md) | **简体中文**

SunPack 是 Windows-only 项目。Python 依赖统一声明在根目录 `pyproject.toml`，由 `uv.lock` 锁定；Rust、C++ 和 Windows 服务使用同一条构建链路。

## 环境要求

- Windows 10/11
- PowerShell 5.1 或更新版本
- Python 3.10 或更新版本，架构必须与目标发行包一致
- `uv` 0.12 或更新版本
- Rust MSVC toolchain，提供 `cargo`
- Visual Studio Build Tools 2022，包含 C++17 编译器
- ARM64 优化构建还需要 Visual Studio **C++ Clang tools for Windows** 组件（`clang-cl`），仅用于上游 7-Zip `LzmaDecOpt.S`
- 首次安装依赖和准备 7-Zip 测试文件所需的网络连接

项目主要目录：

```text
sunpack/                    产品运行时代码
native/sunpack_native/      Rust/PyO3 扩展
native/sunpack_usn_core/    NTFS/USN 共用 Rust 核心
native/sunpack_watch_broker/Windows Watch Broker 服务
native/sevenzip_bridge/     Windows 7z.dll bridge 与 worker
native/toast_host/          Windows toast DLL
tools/                      x64 外部工具和原生构建产物
tools-arm64/                ARM64 外部工具和原生构建产物
```

## Python 依赖

可安装的 extra：

| Extra | 用途 |
| --- | --- |
| 默认 | SunPack 运行依赖 |
| `test` | pytest 与测试数据生成依赖 |
| `build` | Nuitka、maturin、CMake |
| `dev` | build 与 test 的并集 |

常用安装方式：

```powershell
uv sync --locked
uv sync --locked --extra test
uv sync --locked --extra dev
```

开发环境目录为 `.venv`。如果该环境启用了全局 site-packages，准备脚本会重建它，避免全局包影响依赖解析。

## 一键准备开发环境

```powershell
.\scripts\setup_windows_dev.ps1
```

脚本会：

1. 用 `uv sync --locked --extra dev` 准备隔离的 `.venv`
2. 构建并安装当前架构的 Rust/PyO3 wheel
3. 构建 `sunpack-watch-broker.exe`
4. 准备对应架构的 `7z.exe`、`7z.dll` 和 license
5. 构建 `sunpack_sevenzip.dll`、`sunpack_sevenzip_worker.exe` 和 `sunpack_toast.dll`
6. 把原生产物复制到工具目录
7. 运行 Python、Rust、C++ 和 CLI smoke checks

选项：

```powershell
.\scripts\setup_windows_dev.ps1 -Clean
.\scripts\setup_windows_dev.ps1 -Arch arm64
.\scripts\setup_windows_dev.ps1 -SkipAcceptanceTestTools
```

目标架构必须与当前 Python 进程架构一致。

## USN Watch Broker

watch 使用 NTFS USN Journal 判断文件内容变化和文件是否已经跨过写入边界。需要访问卷级 Journal 的操作集中在 `native/sunpack_usn_core` 和 `native/sunpack_watch_broker`，Python 只消费文件观察结果和 watch 状态。

### 组件和生命周期

- `native/sunpack_usn_core` 是 Windows-only Rust crate，包含卷标识、Journal 探测、有限范围的 USN reason 读取以及命名管道客户端协议。
- `native/sunpack_watch_broker` 编译为 `sunpack-watch-broker.exe`，以 Windows service 运行，持有卷级 Journal 访问能力。
- watch 启动时先取得一个进程级 lease。第一个 lease 负责按需启动服务并建立本地 named pipe 连接；同一进程中的后续 lease 复用连接；最后一个 lease 释放时向服务发送释放请求。
- 服务按需启动。第一个客户端在 5 秒内未连接时服务退出；最后一个 lease 释放后等待 1 秒再退出。每个服务最多保留 64 个客户端和 64 个卷上下文。

标准身份为：

```text
Service: SunPackWatchBroker
Pipe:    \\.\pipe\SunPack.WatchBroker.v1
```

服务只接受本机 named pipe 客户端。安装服务需要管理员权限；已安装服务由普通 watch 运行实例通过客户端协议使用。

### USN 读取边界

文件观察由 Rust 读取文件元数据和当前 USN。当前 USN 大于上次记录时，客户端请求 broker 读取：

```text
previous_usn < usn <= current_usn
```

每次观察最多读取 1 MiB 的 reason 数据，支持 USN record version 2、3、4，并区分全部 reason 与去除 `CLOSE` 后的 reason。覆盖、扩展、截断等内容变化会进入 watch 的内容变更路径；仅元数据变化不会被当作内容写入。

watch 根启动前会验证路径位于 NTFS 卷且 Journal 可读。Journal 不可用、卷标识无效或 broker 不可连接时，watch 启动失败并报告原因。

### 本地手动构建

x64：

```powershell
cargo build --locked --manifest-path native\sunpack_watch_broker\Cargo.toml --release --target x86_64-pc-windows-msvc --target-dir .cache\rust-target\x64
```

ARM64 将目标三元组和目标目录替换为 `aarch64-pc-windows-msvc` 与 `.cache\rust-target\arm64`。输出文件为：

```text
.cache\rust-target\x64\x86_64-pc-windows-msvc\release\sunpack-watch-broker.exe
```

开发测试服务必须使用测试身份前缀：

```text
Service: SunPackWatchBrokerTest_<id>
Pipe:    \\.\pipe\SunPack.WatchBroker.Test.<id>
```

可以用仓库脚本安装或卸载临时服务；脚本会拒绝标准服务身份，避免测试覆盖开发机上的发布服务：

```powershell
.\scripts\manage_test_watch_service.ps1 -Action Install `
  -ServiceName SunPackWatchBrokerTest_dev `
  -PipeName '\\.\pipe\SunPack.WatchBroker.Test.dev' `
  -BrokerPath '.cache\rust-target\x64\x86_64-pc-windows-msvc\release\sunpack-watch-broker.exe'

.\scripts\manage_test_watch_service.ps1 -Action Uninstall `
  -ServiceName SunPackWatchBrokerTest_dev `
  -PipeName '\\.\pipe\SunPack.WatchBroker.Test.dev'
```

## 手动构建原生组件

### Rust/PyO3

```powershell
uv sync --locked --extra build
.\.venv\Scripts\maturin.exe build --manifest-path native\sunpack_native\Cargo.toml --release --target-dir .cache\rust-target\x64 --out build\native-wheels-dev
$wheel = Get-ChildItem build\native-wheels-dev\sunpack_native-*.whl |
    Sort-Object LastWriteTimeUtc -Descending |
    Select-Object -First 1 -ExpandProperty FullName
uv pip uninstall --python .\.venv\Scripts\python.exe sunpack-native
uv pip install --python .\.venv\Scripts\python.exe --reinstall $wheel
```

### C++ 7-Zip bridge

```powershell
cmake -S native\sevenzip_bridge -B native\sevenzip_bridge\build-x64 -A x64
cmake --build native\sevenzip_bridge\build-x64 --config Release
ctest --test-dir native\sevenzip_bridge\build-x64 -C Release --output-on-failure
Copy-Item native\sevenzip_bridge\build-x64\Release\sunpack_sevenzip.dll tools\sunpack_sevenzip.dll -Force
Copy-Item native\sevenzip_bridge\build-x64\Release\sunpack_sevenzip_worker.exe tools\sunpack_sevenzip_worker.exe -Force
```

bridge 运行时还需要同一工具目录中的 `7z.dll`。

### Windows toast

```powershell
cmake -S native\toast_host -B native\toast_host\build-x64 -A x64
cmake --build native\toast_host\build-x64 --config Release
ctest --test-dir native\toast_host\build-x64 -C Release --output-on-failure
Copy-Item native\toast_host\build-x64\Release\sunpack_toast.dll tools\sunpack_toast.dll -Force
```

持续运行的 watch 按 `watch.toast_enabled` 创建 Windows 通知能力，并按配置发送进度、完成和失败通知。普通 CLI 请求以及 `watch start --once` 不创建通知能力。通知失败报告写入 `watch.state_dir` 管理的状态目录。

## Smoke Checks

```powershell
.\.venv\Scripts\python.exe -c "import sunpack_native as n; print(n.native_available(), n.scanner_version())"
.\.venv\Scripts\python.exe -c "from sunpack.support.sevenzip_bridge import get_native_sevenzip_bridge; print(get_native_sevenzip_bridge().available())"
.\.venv\Scripts\python.exe -m pytest tests\unit\test_config_loader.py
```

前两个命令分别验证 Rust 扩展和 C++ bridge；第三个命令验证配置加载。

## 测试

普通 pytest：

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

直接运行 pytest 时，需要 Windows NTFS Watch Broker 的用例会被跳过。完整验收通过 `run_acceptance_tests.ps1` 准备隔离测试服务，运行单元、功能、集成、真实场景、磁盘空间和 CLI smoke tests，结束后自动卸载测试服务：

```powershell
.\run_acceptance_tests.ps1 -NoWait
```

验收服务使用随机的测试服务名、named pipe 和临时环境变量，不会覆盖已安装的发布服务。CI 环境未提权时，服务安装会立即失败，避免等待交互式 UAC。

项目 CI 风格测试：

```powershell
.\scripts\run_ci_tests.ps1
```

## Windows 发行构建

正式构建入口：

```powershell
.\scripts\build_windows.ps1
```

常用参数：

```powershell
.\scripts\build_windows.ps1 -Arch x64
.\scripts\build_windows.ps1 -Clean
.\scripts\build_windows.ps1 -SkipTests
.\scripts\build_windows.ps1 -Version 1.2.3
```

发布产物为 Windows 安装器。构建环境必须安装 Inno Setup 6；缺少 `ISCC.exe` 时会在构建开始前失败，也可以通过 `-InnoCompilerPath` 指定编译器路径。构建会运行 packaged smoke checks，并使用真实 Inno Setup 编译器生成最终安装器；安装器行为通过静态 contract tests 校验，不再运行依赖机器状态的安装/升级/卸载 E2E。`-SkipTests` 只跳过 acceptance suite。

构建过程：

1. 创建或复用 `.venv`（`-Clean` 时清理重建）
2. 安装项目 `dev` extra
3. 构建并安装 Rust wheel
4. 构建 Watch Broker
5. 构建和测试 C++ bridge/worker 与 toast DLL
6. 可选运行 acceptance tests
7. 构建无控制台 runtime 和 CLI launcher
8. 复制配置、密码表、工具、Watch Broker、第三方许可证文件和声明
9. 校验关键 PE 文件架构
10. 运行 packaged CLI、bridge 和 worker smoke checks
11. 用 Inno Setup 创建 Windows 安装器

输出：

```text
dist\sunpack-<arch>\
dist\sunpack-<arch>\service\sunpack-watch-broker.exe
dist\sunpack-<arch>\licenses\SunPack-MIT.txt
dist\sunpack-<arch>\licenses\7zip-license.txt
dist\sunpack-<arch>\licenses\7zip-source-license.txt
dist\sunpack-<arch>\licenses\LGPL-2.1.txt
dist\sunpack-<arch>\THIRD_PARTY_NOTICES.md
release\sunpack-windows-<arch>-<version>-setup.exe
```

ARM64 必须在 ARM64 Windows 和 ARM64 Python 环境中构建。已有目录可独立校验：

```powershell
.\scripts\verify_windows_package_arch.ps1 -PackageRoot dist\sunpack-x64 -Arch x64
```

## 运行时原生文件

x64 开发环境默认使用：

```text
tools\7z.exe
tools\7z.dll
tools\sunpack_sevenzip.dll
tools\sunpack_sevenzip_worker.exe
tools\sunpack_toast.dll
```

安装包还包含：

```text
service\sunpack-watch-broker.exe
```

`sunpack_sevenzip.dll` 提供 probe、test、密码尝试、健康检查、资源分析和 manifest C ABI。`sunpack_sevenzip_worker.exe` 读取 JSON job，通过 `7z.dll` 解压文件、分卷和虚拟输入。`7z.exe` 用于开发 fixture、手工诊断、文件来源和发布资源准备。
