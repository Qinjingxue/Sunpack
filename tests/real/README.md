# 真实归档结构语料

此目录保留独立生成的真实归档语料，用于发现、解压和兼容性回归。Python 实现的 Plan 1–7 测试已退役。当前功能验收通过 [原生黑盒入口](../blackbox/) 和 Rust/C++ 测试执行。

可在干净工作区用真实系统工具生成一组带来源记录的结构样本：

```powershell
.venv/Scripts/python.exe -m scripts.generate_real_structure_corpus
```

语料覆盖 USTAR、PAX Unicode 长路径、GNU longname、重复 TAR/ZIP 成员、空 ZIP、CP437 ZIP 和 solid RAR5 等结构。样本可用原名、伪装名和带前后杂项字节的载体三种方式运行。期望输出的路径、大小和 CRC32 来源于原始文件。

脚本使用 bsdtar、WinRAR 和 `tools/real_fixture.exe`（ARM64 对应 `tools-arm64`）等独立工具。后者由 `scripts/setup_windows_dev.ps1` 从工作区预先构建。它以有界缓冲组装载体、生成 LZ4 帧并清点文件，不调用应用的扫描逻辑。可选输出位于忽略的 `tests/real/corpus/structure/`；pytest 收集不依赖它。
