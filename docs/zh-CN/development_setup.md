# 开发环境和构建说明

**简体中文** | [English](../development_setup.md) | [繁體中文](../zh-TW/development_setup.md) | [日本語](../ja/development_setup.md) | [한국어](../ko/development_setup.md)

SunPack 是 Windows-only 项目。Cargo 构建 Rust 运行时和 Watch Broker，CMake 构建原生 worker、启动器、GUI 与通知 DLL。Python 测试依赖由 `uv.lock` 锁定。

## 目录和构建产物

运行开发脚本所需的工具链见 [README 的开发环境要求](../../README.zh-CN.md#开发相关)。

项目主要目录：

```text
sunpack/sunpack_runtime/      Rust 调度与计算核心、CLI 和 Watch
sunpack/sunpack_usn_core/     NTFS/ReFS USN 共用 Rust 核心
sunpack/sunpack_watch_broker/ Windows Watch Broker 服务
sunpack/sevenzip_bridge/      CLI 启动器与内嵌 7-Zip worker
sunpack/toast_host/           Windows toast DLL
tools/                        共享的外部归档工具
tools/arm64/                  ARM64 版 7-Zip 测试工具
.cache/rust-target/            共用的 Cargo 构建目录
.cache/native/                 启动器、worker 和 Toast 的 CMake 构建目录
.cache/gui-x64/                x64 GUI 的 CMake 构建目录
```

开发、发布和 CI 入口共用这些目录。Cargo 按目标三元组和 profile 保存产物。原生 CMake 使用 `.cache/native/<架构>/<profile>/<组件>/`，让诊断用的 `ci` 和启用 LTO 的 `release` 构建并存。源码启动器和测试直接使用所选构建产物。

## Python 依赖

可安装的 extra：

| Extra | 用途 |
| --- | --- |
| `test` | pytest 与测试数据生成依赖 |
| `build` | CMake |
| `dev` | build 与 test 的并集 |

常用安装方式：

```powershell
uv sync --locked
uv sync --locked --extra test
uv sync --locked --extra dev
```

首次创建 `.venv` 时，脚本通过 uv 选择 Python，x64 主机使用 3.11，ARM64 主机使用 3.12。uv 可以按需下载解释器。已有 `.venv` 会保留其解释器并同步锁定的依赖。如果该环境启用了全局 site-packages，脚本会关闭该选项。

## 一键准备开发环境

```powershell
.\scripts\setup_windows_dev.ps1
```

脚本会：

1. 用 rustup 补齐所选架构的 Rust MSVC target，并用 `uv sync --locked --extra dev` 同步 `.venv`。
2. 准备并检查验收归档生成器。
3. 构建 Rust runtime、Watch Broker、测试数据生成器、CLI 启动器、worker 和 Toast DLL，产物留在 `.cache`。
4. 使用 `ci` profile 且构建架构与当前 PowerShell 进程架构相同时，运行 worker 与 Toast 的 CTest 用例。

选项：

```powershell
.\scripts\setup_windows_dev.ps1 -Clean
.\scripts\setup_windows_dev.ps1 -Arch arm64
.\scripts\setup_windows_dev.ps1 -SkipAcceptanceTestTools
.\scripts\setup_windows_dev.ps1 -Arch arm64 -SkipAcceptanceTestTools
```

x64 和 ARM64 都会准备对应架构的 7-Zip 测试工具，首次下载使用 26.04，只保留 `7z.exe`、`7z.dll` 和 `7zCon.sfx`。完整验收另外使用 `tools/` 下共享的 WinRAR 6.22、zstd 1.5.7 和 [7-Zip-Zstandard 25.01 / Zstandard 1.5.7 Release 4](https://github.com/mcmilk/7-Zip-zstd/releases/tag/v25.01-v1.5.7-R4)。WinRAR 只提取两个生成器、RAR SFX 模块和许可证，7-Zip-Zstandard 保留 LZ4 生成器及配套 DLL 和许可证。这些工具都只供开发和测试使用。

在 Windows 11 ARM64 上运行 `.\run_acceptance_tests.ps1 -Arch arm64 -NoWait`。共享的 x64 生成器由 Windows 仿真运行。`-SkipAcceptanceTestTools` 跳过共享生成器的准备和检查，适用于仅构建或在 x64 主机上交叉构建 ARM64。

## USN Watch Broker

watch 使用 NTFS/ReFS USN Journal 判断文件内容变化和文件是否已经跨过写入边界。需要访问卷级 Journal 的操作集中在 `sunpack/sunpack_usn_core` 和 `sunpack/sunpack_watch_broker`，Watch 直接消费 Rust 文件观察结果和状态。

### 组件和生命周期

- `sunpack/sunpack_usn_core` 是 Windows-only Rust crate，包含卷标识、Journal 探测、有限范围的 USN reason 读取以及命名管道客户端协议。
- `sunpack/sunpack_watch_broker` 编译为 `sunpack-watch-broker.exe`，以 Windows service 运行，持有卷级 Journal 访问能力。
- watch 启动时先取得一个进程级 lease。第一个 lease 负责按需启动服务并建立本地 named pipe 连接，同一进程中的后续 lease 复用连接，最后一个 lease 释放时关闭连接。
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

watch 根启动前会验证路径位于 NTFS 或 ReFS 卷且 Journal 可读。Journal 不存在时，先由 Broker 自动创建，再观察文件身份；创建或读取失败、卷标识无效或 broker 不可连接时，watch 启动失败并报告原因。

### 本地手动构建

x64：

```powershell
cargo build --locked --manifest-path sunpack\sunpack_watch_broker\Cargo.toml --release `
  --target x86_64-pc-windows-msvc --target-dir .cache\rust-target\watch-broker
```

ARM64 使用目标三元组 `aarch64-pc-windows-msvc`。x64 输出文件如下。

```text
.cache\rust-target\watch-broker\x86_64-pc-windows-msvc\release\sunpack-watch-broker.exe
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
  -BrokerPath '.cache\rust-target\watch-broker\x86_64-pc-windows-msvc\release\sunpack-watch-broker.exe'

.\scripts\manage_test_watch_service.ps1 -Action Uninstall `
  -ServiceName SunPackWatchBrokerTest_dev `
  -PipeName '\\.\pipe\SunPack.WatchBroker.Test.dev'
```

## 手动构建原生组件

### Rust 运行时

```powershell
cargo build --locked --manifest-path sunpack\Cargo.toml -p sunpack-runtime --bin sunpack-runtime --release --target x86_64-pc-windows-msvc
```

### C++ 内嵌 7-Zip worker

```powershell
.\.venv\Scripts\cmake.exe -S sunpack\sevenzip_bridge -B .cache\native\x64\release\sevenzip_bridge -A x64
.\.venv\Scripts\cmake.exe --build .cache\native\x64\release\sevenzip_bridge --config Release
.\.venv\Scripts\ctest.exe --test-dir .cache\native\x64\release\sevenzip_bridge -C Release --output-on-failure
```

产品 worker 内嵌保留的 7-Zip 源码，运行时不加载 `7z.dll`。

### Windows toast

```powershell
.\.venv\Scripts\cmake.exe -S sunpack\toast_host -B .cache\native\x64\release\toast_host -A x64
.\.venv\Scripts\cmake.exe --build .cache\native\x64\release\toast_host --config Release
.\.venv\Scripts\ctest.exe --test-dir .cache\native\x64\release\toast_host -C Release --output-on-failure
```

持续运行的 watch 按 `watch.toast_enabled` 创建 Windows 通知能力，并按配置发送进度、完成和失败通知。通知失败报告写入可写数据目录下的 `.sunpack_watch/failures`。

## 验证

```powershell
cargo test --locked --manifest-path sunpack\Cargo.toml --workspace --profile ci
```

## 测试

完成开发环境构建后可直接运行 CLI 黑盒测试：

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\blackbox
```

直接运行 pytest 时，需要 Windows Watch Broker 的用例会被跳过。完整验收通过 `run_acceptance_tests.ps1` 准备隔离测试服务，运行 Rust 正确性测试和 CLI、Watch 黑盒测试，结束后自动卸载测试服务：

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

1. 用 Cargo 构建 Rust 运行时和 Watch Broker
2. 用 CMake 构建 CLI 启动器、worker、GUI 与 toast DLL
3. 放入配置、密码表、辅助脚本、许可证及其他发行文件
4. 检查 PE 架构，运行打包后的 CLI smoke tests
5. 按构建参数运行验收测试，用 Inno Setup 创建安装器

### NTFS / ReFS 的 USN 约定

两种文件系统共用 Broker 和日志恢复链路。仅当查询返回
`ERROR_JOURNAL_NOT_ACTIVE` 时，复用原有 32 MiB / 8 MiB 参数创建日志，
然后重新查询；Watch 先完成该步骤，再观察文件身份。其他错误照常报告，
不增加周期轮询或常驻索引。

卷读取按微软的 [READ_USN_JOURNAL_DATA_V1 说明](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-read_usn_journal_data_v1)
请求 V2–V3，单文件查询采用相同版本范围。V3 的文件和父目录 ID 完整保留
128 位，V2 补零匹配；目录恢复允许初始游标为 0，仍校验日志 ID 和保留边界。
现有 FileIdInfo、目录身份及紧凑 catalog 沿用完整 ID，符合微软的
[ReFS 身份要求](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/ns-fileapi-by_handle_file_information)。
不请求缺少文件名的 V4 范围记录。

ReFS 回归覆盖使用高 64 位非零的文件及父目录 ID 构造模拟 V3 记录，
并复用现有日志创建、版本请求、零游标和分页恢复测试。不依赖真实 ReFS 卷，
也不要求 CI 有创建 ReFS 卷的权限。真实卷验证仅作为本地临时验证，不纳入
项目测试套件或 CI 要求。
