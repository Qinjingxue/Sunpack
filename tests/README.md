# 测试结构

测试套件按“测试形态”组织，而不是按源码包组织。新增测试时，优先选择能锁住行为的最小测试，并通过项目公开入口表达预期行为。

## 目录说明

- `helpers/`：共享构造器、断言、测试配置、归档 fixture 和 CLI 辅助工具。
- `unit/`：聚焦公开模块或契约的测试，不覆盖黑箱模块内部算法。
- `functional/`：跨模块行为测试，尽量避免真实外部解压。
- `integration/`：pipeline、解压和真实执行路径测试。
- `real/`：按计划组织的真实归档和真实 watch 端到端矩阵；这里是完整真实场景的权威入口。
- `cli/`：CLI parser、命令契约和命令行为测试。

性能测量、profile 和压力脚本统一放在仓库根目录的 `benchmarks/`，不参与
pytest 收集。pytest 中只保留行为断言；资源或时序稳定性断言使用 opt-in marker。

## 运行测试

运行默认 pytest 套件：

```powershell
uv sync --locked --extra test
.\scripts\setup_windows_dev.ps1 -Arch x64
$workers = [math]::Max(1, [math]::Floor([Environment]::ProcessorCount / 4))
uv run --locked pytest -n $workers --dist worksteal
```

本地 CI 和 acceptance runner 默认使用逻辑 CPU 核心数的四分之一（向下取整，至少 1 个）
作为 worker 数量；GitHub Actions 验收显式使用 2 个 worker。本地直接运行 pytest 仍建议按机器性能手动调整，避免 `-n auto` 在高核心数
机器上造成过多进程与磁盘竞争。
性能、内存稳定性以及需要 Watch Broker 的测试必须使用 `-n 0`。Acceptance runner
会自动将 Broker/Plan 7 独占测试与普通并行测试分开；直接运行性能或内存测试时仍需
显式传入 `-n 0`。

列出性能场景：

```powershell
uv run --locked python -m benchmarks --list
```

运行项目验收脚本：

```powershell
.\run_acceptance_tests.ps1 -NoWait
```

运行本地 CI 风格检查：

```powershell
.\scripts\run_ci_tests.ps1
```

本地 CI 和 acceptance runner（包括根目录 `run_acceptance_tests.ps1`）默认使用逻辑 CPU 核心数的四分之一（下限为 1）个 worker，
也可通过 `-ParallelWorkers` 调整，例如 `.\scripts\run_ci_tests.ps1 -ParallelWorkers 4`。

`run_acceptance_tests.ps1` 会运行 CLI、unit、functional、integration 和完整 `tests/real` 真实归档/watch 矩阵，并执行 CLI smoke checks。

验收和 CI 入口会先检查依赖导入及组件级源码/产物 UTC 修改时间；缺失或过期时复用
`scripts/setup_windows_dev.ps1`，完成后重新检查，仍过期则在运行测试前失败。
共享 USN crate 的修改会同时使 Rust 扩展与 Broker 过期；LZ4、内置 7-Zip/zlib-ng、
构建配置和 toast 源码也纳入各自组件的检查，构建目录不参与扫描。Broker 只使用
`.cache/rust-target/<arch>/<target>/<profile>/` 的产物，不回退到 `native/target`。
这里不保存 manifest，也不计算源码或产物 hash。检查面向正常编辑/Git 工作流，
不能识别保留旧时间戳的源码替换；这类操作后应主动运行 setup。
测试用 Rust `real_fixture.exe` 也由 setup 统一构建并复制到对应架构的 tools 目录，
纳入 CI/验收的产物过期检查。pytest helper 只调用现成工具，缺失时明确报错，
不会执行 Cargo metadata/build，避免 xdist worker 重复编译和争用构建锁。
fixture 构建使用与 maturin 一致的 Python/PyO3 环境，避免在 wheel 和 fixture
之间来回使 PyO3 的 Cargo 缓存失效；构建后恢复调用方的环境变量。
WinGet manifest 的各场景在同一个 PowerShell 会话中调用真实脚本，使用 pytest
subtests 分别报告断言结果；普通测试仍使用 worksteal 并行调度。
setup 成功构建/安装后，只将旧产物时间推进到该组件的构建开始时间，以支持无需重新链接的
增量构建；新生成产物保留原时间，不破坏构建系统的增量判断。
验收入口的 `-SkipEnvironmentRefresh` 仍可显式跳过检查和自动刷新。

开发 setup、CI 和验收入口默认使用 `-BuildProfile ci`：Rust 保留 `opt-level=3`，关闭 LTO、使用
16 个 codegen units；C++ 保留 Release 优化和静态 CRT，关闭 IPO/LTO，包括 worker
内嵌的 Rust ENC 库。正式发布保持 Rust fat LTO 和 C++ LTO。可在本地复用同一配置：

```powershell
.\scripts\setup_windows_dev.ps1 -Arch x64 -BuildProfile ci -BuildJobs 4
.\run_acceptance_tests.ps1 -NoWait -BuildProfile ci -ParallelWorkers 2
```

Rust 的 ci/release 产物分别位于对应 profile 目录，CMake CI 使用 `build-<arch>-ci`，
发布使用 `build-<arch>`。测试 fixture 仍只预构建一次。`-Clean` 只清理 native 构建输出，
保留 `.venv`；setup 和打包脚本通过 uv 同步现有环境。

release workflow 的 setup 使用 `-BootstrapOnly -SkipAcceptanceTestTools`，只同步 Python
依赖并准备外部 7-Zip 工具，完整 native 构建只在 `build_windows.ps1` 中执行一次。
两个 CMake 项目共享 MSBuild 文件并行配置，`-BuildJobs 4` 配合 `--parallel 4`，
通过 MultiToolTask 限制跨项目的编译进程总数，避免项目级与文件级并行相乘。

Actions 按架构、profile、Python ABI、Rust/CMake/MSVC 工具链、锁文件和 native
源码缓存 Cargo registry/git、Rust target 和 CMake build 目录。仅当源码指纹相同时
恢复缓存中的输入时间戳，使 checkout 不会使有效的 CMake 产物过期；源码变化的
fallback 缓存保留新时间戳，正常触发重编译。该缓存快照仅用于 Actions，开发产物
preflight 仍扫描当前输入时间戳。真实 fixture 生成器另行缓存。

Nuitka 的编译缓存位于 `.cache/nuitka/<arch>` 并在 Actions 间持久化；正式发布继续
`--lto=yes`。手动 workflow 可勾选 `fast_build`，或本地传 `build_windows.ps1 -FastBuild`，
仅关闭 Nuitka LTO 以加快构建验证；tag 触发的正式发布始终保持完整优化。

脚本中的各测试步骤相互独立：某一步失败或超时后仍会继续执行后续步骤，最后统一汇总；只要存在失败步骤，脚本最终仍返回非零退出码。

Windows x64 的 acceptance 环境准备会自动缓存真实归档生成器到仓库根目录的
`.sunpack_test_tools/`（该目录被忽略，不会进入发布包）：RAR/WinRAR 固定使用
RARLAB WinRAR 6.22，以保留 Plan 7 所需的 RAR4 生成能力；zstd 固定使用官方
`facebook/zstd` v1.5.7 Windows x64 二进制。下载包会先校验 SHA-256，再安装或提取，
并由 acceptance preflight 检查 `Rar.exe`、`Default.SFX`、`WinRAR.exe` 和 `zstd.exe`。
如需使用镜像，可通过 `SUNPACK_TEST_RAR_INSTALLER_URI`、
`SUNPACK_TEST_RAR_INSTALLER_SHA256`、`SUNPACK_TEST_ZSTD_URI` 和
`SUNPACK_TEST_ZSTD_SHA256` 覆盖下载源及校验值。

完整真实归档/watch 场景统一从 `tests/real/` 运行；`tests/integration/` 只保留真实场景中仍有独立价值的底层关系解析、原生桥接、错误分类、性能和密码源更新契约，避免同一行为在两套端到端矩阵中重复维护。

真实归档测试默认运行。真实归档计划的完整入口示例：

```powershell
uv run --locked pytest tests/real -q
```

## 公共接口边界

测试默认不直接导入 `*/internal/*`、`detection.pipeline.*`，也不调用下划线私有方法或 monkeypatch 私有实现。黑箱模块只通过公开入口测试行为，例如 `DetectionScheduler`、`ExtractionScheduler`、`PostProcessActions`、`DirectoryScanner`、`RelationsScheduler`、CLI 和 coordinator 编排入口。

确实需要覆盖新规则或检测场景时，优先使用 functional 或 integration 测试，并从 `DetectionScheduler` 等公开入口进入，而不是直接测试 rule、processor、collector 的内部方法。

## 新增测试建议

常用位置：

- 新增 CLI 输出或命令形状：放到 `cli/`。
- 新增规则行为：放到 `functional/`；如果文件系统扫描和候选构建也重要，放到 `integration/`。
- 新增清理或扁平化行为：放到 `unit/` 或 `functional/`。
- 新增共享测试配置：`tests/helpers/config_factory.py`。
- 新增可复用文件系统构造：`tests/helpers/fs_builder.py` 或 `tests/helpers/generated_fixtures.py`。

昂贵的真实归档测试应放在 integration，或挂在慢速 marker 后面，保持默认测试套件足够快。
