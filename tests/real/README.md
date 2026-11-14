# 真实归档结构语料

这里的黑盒用例从隔离的安装目录启动 `sunpack.exe`，使用真实 Rust 运行时和解压 worker。Watch 用例通过独立的 Watch Broker 运行。断言来自 CLI 报告、输出文件树及 Watch 发布的状态。

覆盖包括常规、伪装和 SFX 归档，多种压缩方法及加密方式，错误密码，缺卷，错名和候选分卷，带有前后杂项字节的载体，以及连续 Watch 的下载、重启与重试。多层用例同时验证健康分支、阻塞分支、输出目录和源文件清理。

`test_split_carrier_delivery.py` 补充了分卷内容、到达方式和源清理之间的交叉覆盖。输入由现有工具按需生成；结果比对原始文件的路径、大小和 CRC32。

| 入口与场景 | 独立验证 |
| --- | --- |
| CLI 扫描目录、Watch 接收整个移入的目录 | 7z 头卷载体同时含可递归解开的独立 ZIP；另一组 RAR 的每一卷都有独立的前后杂项字节。两组按不同密码解开，共享物理载体的内容均完成后才清理，保留同名前缀的无关文件。 |
| Watch 临时名改名、最终路径直写 | 多组加密分卷按块交错写入，头卷使用载体；验证没有串卷、重复输出或误删。 |
| Watch 写入 PKZIP 最后一盘 | 缺卷后等待 AES ZIP 的中央目录到达，覆盖运行时重启后原文件续写、弃掉半成品后同名改名提交、预分配最终大小但仍持有写句柄。 |
| Watch 跨根移动现成分卷 | 独立监控根不互借分卷；分卷移入正确的递归根后应自动恢复，无需重写数据。 |
| Watch 直写 RAR SFX 头卷 | `.exe` 是数据头卷。其他卷已到达、头卷仍有写句柄时不能提交头卷；关闭后应解压并清理。 |
| CLI 存在两个同长度的中间卷 | 同一卷位的坏候选不能挡住正确候选；解压后只清理实际使用的分卷，保留坏候选。 |

The live Watch wrapped-RAR tail-first regression requires successful extraction and configured cleanup of all source volumes after the remaining carriers arrive; a complete group remaining suspended is a failure.

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
