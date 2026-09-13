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
$workers = [math]::Max(1, [math]::Floor([Environment]::ProcessorCount / 4))
uv run --locked pytest -n $workers --dist worksteal
```

CI 和 acceptance runner 默认使用逻辑 CPU 核心数的四分之一（向下取整，至少 1 个）
作为 worker 数量；本地直接运行 pytest 仍建议按机器性能手动调整，避免 `-n auto` 在高核心数
机器上造成过多进程与磁盘竞争。
性能、内存稳定性以及需要 Watch Broker 的测试必须使用 `-n 0`。Acceptance runner
会自动将 Broker/Plan 7 独占测试与普通并行测试分开；直接运行性能或内存测试时仍需
显式传入 `-n 0`。

列出性能场景：

```powershell
python -m benchmarks --list
```

运行项目验收脚本：

```powershell
.\run_acceptance_tests.ps1 -NoWait
```

运行本地 CI 风格检查：

```powershell
.\scripts\run_ci_tests.ps1
```

CI 和 acceptance runner（包括根目录 `run_acceptance_tests.ps1`）默认使用逻辑 CPU 核心数的四分之一（下限为 1）个 worker，
也可通过 `-ParallelWorkers` 调整，例如 `.\scripts\run_ci_tests.ps1 -ParallelWorkers 4`。

`run_acceptance_tests.ps1` 会运行 CLI、unit、functional、integration 和完整 `tests/real` 真实归档/watch 矩阵，并执行 CLI smoke checks。

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
pytest tests/real -q
```

## 公共接口边界

测试默认不直接导入 `*/internal/*`、`detection.pipeline.*`，也不调用下划线私有方法或 monkeypatch 私有实现。黑箱模块只通过公开入口测试行为，例如 `DetectionScheduler`、`ExtractionScheduler`、`PostProcessActions`、`DirectoryScanner`、`RelationsScheduler`、`RenameScheduler`、CLI 和 coordinator 编排入口。

确实需要覆盖新规则或检测场景时，优先使用 functional 或 integration 测试，并从 `DetectionScheduler` 等公开入口进入，而不是直接测试 rule、processor、collector 的内部方法。

## 新增测试建议

常用位置：

- 新增 CLI 输出或命令形状：放到 `cli/`。
- 新增规则行为：放到 `functional/`；如果文件系统扫描和候选构建也重要，放到 `integration/`。
- 新增清理或扁平化行为：放到 `unit/` 或 `functional/`。
- 新增共享测试配置：`tests/helpers/config_factory.py`。
- 新增可复用文件系统构造：`tests/helpers/fs_builder.py` 或 `tests/helpers/generated_fixtures.py`。

昂贵的真实归档测试应放在 integration，或挂在慢速 marker 后面，保持默认测试套件足够快。
