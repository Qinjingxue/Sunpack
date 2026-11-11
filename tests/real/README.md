# 真实归档结构语料

这里的黑盒用例从隔离的安装目录启动 `sunpack.exe`，使用真实 Rust 运行时和解压 worker。Watch 用例通过独立的 Watch Broker 运行。断言来自 CLI 报告、输出文件树及 Watch 发布的状态。

覆盖包括常规、伪装和 SFX 归档，多种压缩方法及加密方式，错误密码，缺卷，错名和候选分卷，带有前后杂项字节的载体，以及连续 Watch 的下载、重启与重试。多层用例同时验证健康分支、阻塞分支、输出目录和源文件清理。

在现有开发环境中构建测试工具后，可单独运行不需要 Watch Broker 的真实归档用例：

```powershell
.\scripts\setup_windows_dev.ps1 -Arch x64 -BuildProfile ci
.\.venv\Scripts\python.exe -m pytest tests/real -m "not requires_watch_broker"
```

`run_acceptance_tests.ps1 -NoWait` 和 Windows 验收工作流还会运行需要 Watch Broker 的用例。

可在干净工作区用真实系统工具生成一组带来源记录的结构样本：

```powershell
.venv/Scripts/python.exe -m scripts.generate_real_structure_corpus
```

语料覆盖 USTAR、PAX Unicode 长路径、GNU longname、重复 TAR/ZIP 成员、空 ZIP、CP437 ZIP 和 solid RAR5 等结构。样本可用原名、伪装名和带前后杂项字节的载体三种方式运行。期望输出的路径、大小和 CRC32 来源于原始文件。

脚本使用 bsdtar、WinRAR 和 `tools/real_fixture.exe`（ARM64 对应 `tools-arm64`）等独立工具。开发脚本预先构建 `real_fixture.exe`。测试用它组装载体、生成 LZ4 帧并清点文件。预生成语料可保存到 `tests/real/corpus/structure/`。pytest 在隔离目录生成所需样本。
