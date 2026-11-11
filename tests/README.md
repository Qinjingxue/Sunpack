# 测试结构

应用计算、协议和状态机的测试随 Rust/C++ 源码运行。这里的 Python 只负责通过真实进程、文件和安装脚本验证公开行为；测试不导入 SunPack 主程序或原生扩展。

- `blackbox/`：从隔离的安装目录启动真实 `sunpack.exe`、Rust 运行时和解压 worker。输入、输出、配置和状态使用各测试的临时目录。
- `integration/`：安装语言、用户数据权限和跨版本配置迁移。直接运行相应安装或 PowerShell 路径。
- `gui/`：双语模板文字及安装后 GUI 对用户数据的实际写权限。GUI 控件与显示历史的内部测试由 C++ 入口负责。
- `unit/`：右键菜单、WinGet manifest 和构建缓存等独立脚本契约。
- `real/`：独立工具生成的真实归档矩阵和 Watch 下载、重启、重试场景，使用与 `blackbox/` 相同的安装边界。见 [真实归档测试说明](real/README.md)。
- `helpers/`、`data/`：测试工具与固定兼容向量。

用粗粒度行为覆盖不同故障。新增用例需能说明：它独立发现什么故障、现有用例为何无法发现，以及覆盖是否值得运行成本。当前黑盒覆盖按故障边界分组：

| 边界 | 独立覆盖 |
| --- | --- |
| 归档发现与执行 | 同一请求处理伪装归档和嵌套载体；兼容 ENC 和压缩 TAR 的原生路径；缺卷阻止源清理；损坏归档的部分提取只保留经验证内容。 |
| 密码与选择性恢复 | 同一物理文件的不同路径不能共享未授权的作用域；多段载体只重试失败子输入，全部成功才清理；Watch 重启后沿用已完成子输入，持续 Watch 在密码表更新后恢复已提升的嵌套输入。 |
| 进程与数据一致性 | 并发启动器请求使用不同输出目录；常驻运行时看到配置与 GUI 密码写入；Watch 硬终止后清理未提交输出并重试，已取消代不能复活，恢复完成后再次重启不能重复执行；前台扫描结束后空闲 Watch 释放归档读取句柄。 |
| 安装与系统集成 | 升级保留用户数据与语言；安装修复已有和新建目录的权限，并允许真实 GUI 编辑；右键菜单传递 Unicode 路径和参数。 |

先使用现有开发环境构建对应 Windows 架构的原生产物。直接运行 pytest 默认使用 x64 的 `ci` 产物；其他架构或发布产物用 `SUNPACK_TEST_ARCH` 和 `SUNPACK_TEST_BUILD_PROFILE` 选择。需要 GUI 测试二进制时运行 `scripts/build_gui.ps1`。安装器用例需要 Inno Setup。

```powershell
uv sync --locked --extra test
.\scripts\setup_windows_dev.ps1 -Arch x64 -BuildProfile ci
.\.venv\Scripts\python.exe -m pytest tests -m "not requires_watch_broker"
cargo test --manifest-path native/Cargo.toml --locked --workspace --profile ci
```

`requires_watch_broker` 用例需要专用服务和管道；未配置时跳过。验收入口负责启动和清理隔离服务。运行本地 CI 或完整验收：

```powershell
.\scripts\run_ci_tests.ps1
.\run_acceptance_tests.ps1 -NoWait
```

完整验收需从管理员 PowerShell 启动：普通测试和 Cargo 通过 Python 降权助手运行；真实满盘用例单独保留管理员令牌并串行执行。该必跑步骤没有执行用例、出现任何跳过或无法读取 JUnit 报告都记为失败，不能以全跳过冒充通过。本地 CI 不包含 VHD 验证。

在管理员 PowerShell 中运行 `.\.venv\Scripts\python.exe -m pytest tests/integration/test_disk_full_pause_resume.py` 可单独验证真实满盘。用例只写自己创建并核对卷标的 32 MiB NTFS VHDX，不占满宿主卷；结束后卸载并删除镜像。可用 `SUNPACK_SPACE_TEST_VHD_DIR` 选择镜像所在目录。测试等待实际满盘事件后才释放空间、断开客户端或关闭常驻进程，覆盖双卷独立恢复和满盘时的输出回收。

验收脚本可向 pytest 传入 `--diagnostics-dir` 保存各 worker 的测试进度。真实结构语料通过独立工具生成，pytest 不临时构建 Rust/C++ 工具。性能测量在 [benchmarks](../benchmarks/README.md)，不作为 pytest 的行为断言。

## 硬崩溃恢复范围

Watch 用例直接终止真实常驻进程：开始输出时挂起 worker，验证未提交输出回收、取消状态持久化，以及伪装载体内嵌加密分卷的恢复；另一现有用例在载体一段成功、另一段密码阻塞后终止进程，撤掉成功段的密码再恢复，验证已提交内容不被重复执行。恢复后再次启动也检查输出不重复。

与 main 中旧 Python 故障注入工具相比，目前尚未恢复精确停在快照写入前后、WAL 退役边界，以及分卷提升的准备／部分移动／重定基准边界的进程级故障注入。Rust 的 WAL 帧、快照完整性与 journal durable/seal 测试仍需运行，但它们不能替代这些真实进程终止边界的验证。上述黑盒测试需要 Windows 和隔离 Watch Broker，Python 语法检查不能证明恢复行为通过。
