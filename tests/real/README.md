# 真实归档结构语料

这里的黑盒用例从隔离的安装目录启动 `sunpack.exe`，使用真实 Rust 运行时和解压 worker。Watch 用例通过独立的 Watch Broker 运行。断言来自 CLI 报告、输出文件树及 Watch 发布的状态。

覆盖包括常规、伪装和 SFX 归档，多种压缩方法及加密方式，错误密码，缺卷，错名和候选分卷，带有前后杂项字节的载体，以及连续 Watch 的下载、重启与重试。多层用例同时验证健康分支、阻塞分支、输出目录和源文件清理。

## 疑难黑盒回归

这些用例使用真实 CLI、Watch Broker 和原生解压 worker。在 `93fa21a6` 的 Windows x64 `ci` 构建中，以下失败通过普通断言保留。

| 场景 | 独立覆盖 | 实测结果 |
| --- | --- | --- |
| [嵌套 RAR5 SFX 与尾部独立加密 7z](test_adversarial_carriers.py) | SFX 本身是 RAR 数据头卷，其他 RAR 卷位于伪装载体内。外部 7-Zip 对同一 SFX 分别验证 RAR5 和 7z，SunPack 必须解出两份且完整后才能清理源输入。 | 开启 deep detect 后，CLI 和 Watch 均提取 RAR 与尾部 7z，完整处理后清理源载体。 |
| [两组 RAR5 共享全部三个卷载体](test_adversarial_carriers.py) | 中间载体上的区段顺序反转，使用不同密码校验同格式卷组能按区段正确配对，不串卷或重复输出。 | CLI 和 Watch 均通过。 |
| [同名伪装加密卷组的失败分类](test_adversarial_split_classification.py) | 同一递归扫描里，完整组只缺密码，另一组有正确密码但缺中间卷。缺卷允许没有识别结果。 | 7z 和 RAR5 SFX 的 CLI、Watch 四个用例均通过。 |
| [外来 RAR5 第二卷顶替缺卷](test_adversarial_split_classification.py) | 用同名、同尺寸、同卷号的外来第二卷填入缺口。原组已提供密码，外来卷的头卷及密码均未提供。按文件核对失败归属。 | CLI 和 Watch 均将缺卷归于原 SFX 头卷，将密码错误归于外来第二卷，并保留源文件。 |
| [进程树提交内存上限](test_archive_job_memory_pressure.py) | 各入口一次提交三个使用 32 MiB LZMA2 字典的 7z，验证运行时与 worker 均在同一个 72 MiB Windows Job 中，三个 40 MiB 输出都必须完整。 | CLI 和 Watch 均通过。校准运行中两个入口各收到一次系统内存限额通知，解包仍完成。 |
| [CLI 和 Watch 的并发时序](../blackbox/test_watch_migration.py) | 用暂停真实 worker 和观察输出预留固定时序。覆盖 Watch 取消与同名 CLI 解压重叠、取消时源文件已经原地更新、CLI 输出预留后 Watch 停止并重启。 | 三个用例均通过。 |

### 归档内部结构与 Watch 事件顺序

| 场景 | 独立覆盖 | 实测结果 |
| --- | --- | --- |
| [ZIP 成员记录与名称](test_adversarial_archive_structures.py) | 中央目录逆序引用本地记录，空成员使用 ZIP64 数据描述符。另一个样本让两个成员的 Unicode 路径扩展指向同一名称，其中一个扩展的 CRC 因改名失效。 | 两个 CLI 用例均完整输出各自成员。 |
| [GNU TAR 多块稀疏映射](test_adversarial_archive_structures.py) | 26 个数据区段跨越两个映射扩展块，文件首尾和区段间有空洞，其后紧跟普通成员。 | Watch 输出与 Python `tarfile` 逐字节一致。 |
| [RAR5 硬链接和部分恢复](test_rar5_hardlink_members.py) | 以外部工具确认归档包含真实硬链接。验证 solid 归档里有内容和空文件的链接组，以及指向 CRC 失败成员的链接不会作为完整输出发布。 | 两个 CLI 用例均通过。同内容的独立文件保持独立文件身份。CRC 损坏时保留源归档和完整的普通成员。 |
| [持写句柄的归档跨 Watch 根移动](test_adversarial_watch_sequences.py) | 观察到 `candidate_busy` 后移动旧归档，立即在原路径放入同尺寸、同修改时间的新归档。 | 两个文件分别进入正确的输出根，各自完成后清理对应源文件。 |
| [Watch 停机时替换父目录](test_adversarial_watch_sequences.py) | 只移动已准备好的目录，比较路径、长度和修改时间相同且文件 ID 已变的子归档，与长度变化的子归档和直接改名移入的归档。 | 后两种在重启后解出。仅文件 ID 和内容变化的子归档被遗漏，失败保留为普通断言。 |

## 现有真实归档覆盖

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

`test_main_discovery_boundaries.py` 将 `main` 的三类发现边界放到真实 CLI 和 Watch 入口验证：同一批解包得到的不同输出树各自计算递归载体比例；完整的中间卷被文件名规则拒绝后，改名即可重新加入卷组；ZipCrypto 错误密码命中头部校验字节时，仍需验证文件内容并尝试正确密码。Watch 还验证修改密码表后能从这个错误命中恢复。

`test_legacy_volume_and_stream_boundaries.py` 补充 `main` 的旧式分卷、同名归档和载体边界用例，每组均走 CLI 和真实 Watch：

- RAR4 头卷改成伪装扩展名后，仍能识别 `.r00` 和 `.r01`。Watch 等到迟到的 `.r00` 才完成。
- 一个 TAR 头横跨两个使用不同校验方式的 XZ 流，中间有流填充。载体里紧随其后的独立 ZIP 也应解出。
- 独立 SFX 和缺中间卷的 7z 分卷同名时，独立 SFX 正常解压，未完成的源卷保留。
- 同一递归根的两个子目录中有同名分卷，完整组可先完成。另一组补齐后独立解压，已完成的输出不被改写。
- CRC 正确但结构无效的 7z 头不能遮住其声称包含的真实 ZIP。

另用同一份 RAR4 `-ma4 -vn` 旧式分卷验证了文件头加密的扩展组合。头卷改为 `.图片` 后，即使 `.r00` 和 `.r01` 齐全，重构分支和 `main` 的解压管线仍报告缺卷。旧式分卷的成功用例沿用 `main` 的未加密文件头输入。

`test_main_archive_output_boundaries.py` 补充 `main` 的格式兼容和输出边界，每个场景均通过 CLI 和真实 Watch：

- `.zx01` / `.zipx` 组成的分盘 ZIP 保留小于扫描阈值的尾盘。Watch 收到迟到的尾盘后自动解压。
- PAX 的 `size` 覆盖普通 TAR 头中的零值或过大值，载体内随后出现的独立 ZIP 仍能解出。
- 内含 7z 的无文件名 XZ 流在输出目录冲突时仍能递归解压，并保留原目录及其内容。
- TAR 成员经过 Windows 路径转换产生重名时，保留每个成员的内容，包括保留设备名、非法字符、重复分隔符和尾空格。
- 文件名中的 `part` 是单词的一部分时，独立归档保留各自名称，即使扩展名与真实格式不同。
- 同批 ZIPX 中，Zstandard 输入正常解压并清理，WavPack 方法报告不支持且源文件保留。

`test_main_volume_arbitration.py` 将 `main` 的卷位歧义和失败恢复用例接到真实 CLI 和 Watch。两组数字都能排成连续卷号时，7z 和 ZIP 仍须按验证成功的顺序提取。RAR 以文件头卷号纠正误导性的文件名，同名 7z 卷组保留卷组范围以外的数字尾卷。带加密 RAR 的独立载体与 7z 中间卷同名同长时，两组仍各自解压。另覆盖长尾部杂项字节的迟到 PKZIP 尾盘，以及补密码后同载体的 CRC 损坏区段继续阻止源清理。

`test_main_input_recovery.py` 覆盖 `main` 的替换与恢复场景。载体原路径、长度和修改时间均相同，但文件身份变化时，CLI 和 Watch 都会发现新增的区段。嵌套载体或伪装分卷因缺密码或缺卷被移到监控根或输入目录时，避开已有同名文件，补齐后清理生成的归档。另验证 Watch 重启后可分别恢复两个密码阻塞和一个缺卷阻塞，并保留用户后来投递的尾卷。

`test_split_head_disguises.py` 用外部 7-Zip 先验证原名卷组，再只改变头卷。6 种布局包括 7z、连续切分 ZIP、PKZIP 分盘、RAR4 `partN`、RAR4 `.r00` 旧式编号及 RAR5。完整卷组覆盖只改成 `.图片`、给保留卷号的头卷加前后杂项字节、在载体头上去掉卷号、把载体头伪装成另一种归档扩展名。每种布局还覆盖载体头已到达而尾卷后补。CLI 和 Watch 均要求输出完整文件树并清理已使用的输入。失败时附带 `scan` 是否将头卷列为入口，以及解压或 Watch 记录的错误类别。

当前失败保留为普通断言，修复后应直接通过：

| 场景 | CLI | Watch |
| --- | --- | --- |
| 文件头加密的旧式 RAR4，仅把头卷改为 `.图片` | 报缺卷 | 报缺卷 |
| 文件头加密的 RAR5，仅把头卷改为 `.图片` | 扫描从第二卷列组，解压报缺卷 | 未解压 |
| 文件头加密的 RAR4 `partN` 或 RAR5，载体头去掉卷号，或伪装为 `.zip` | 通过 | 报缺卷 |
| 去掉卷号的载体头先到，连续切分 ZIP、PKZIP、RAR4 `partN` 或 RAR5 的尾卷后到 | 通过 | 报缺卷 |
| `test_main_input_recovery.py` 的 `wrapped-split-head`，外层 ZIP 内的 7z 缺尾卷，且头卷另有前后杂项字节 | 头卷已移出，中间卷仍留在外层输出，补尾卷后仍报缺卷 | 同左 |

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

脚本使用 bsdtar、WinRAR 和 `real_fixture.exe`等独立工具。开发脚本预先构建 `real_fixture.exe`。测试用它组装载体、生成 LZ4 帧并清点文件。预生成语料可保存到 `tests/real/corpus/structure/`。pytest 在隔离目录生成所需样本。
