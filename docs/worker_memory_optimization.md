# Worker 内存恢复、准入开销和格式覆盖

2026-10-27，基于已提交的 `0a09f128`，继续验证用户对 `fbcd102e` 提出的恢复和分配开销问题。生产改动集中在 worker；没有 Python 内存调度、格式大小限制、降低 CPU credit 或线程额度。

## 恢复门槛

原实现把历史峰值直接作为重放准入量。C++ 复现：24 MiB 字典与 64 MiB 可选缓冲曾同时存在，释放可选缓冲后，另一个 32 MiB 必需分配在 48 MiB 容量下失败；随后容量恢复到 64 MiB。原实现仍等待历史 88 MiB，新实现记录失败当时的 `24 + 32 = 56 MiB`，可以恢复。

保留的是失败申请与当时仍存在的整个工作区，不是仅记单次申请的 32 MiB。外部撤销没有明确失败申请时，先记录当时占用；若归还本次任务的内存与 admission 后，外部容量又真实增加至少 4 MiB，则保留当前可用预算，允许一次受控重试。仍不可执行时重新等待实际失败的需求；不通过定时盲目重试或设置失败次数上限解决问题。

真实 VirtualAlloc 失败仍要求容量超过失败时的退款后额度。失败时强制重新采样，不能拿缓存中旧的乐观可用量设置这个门槛。C++ 测试同时验证：自身释放内存不触发循环、64 MiB 下恢复完整字典和输出工作区、低于旧峰值的容量增长可恢复更低内存执行，以及页尾提交与超大申请不会绕过预算。

## 分配开销

系统快照最多复用约 250 ms，沿用已有活动观察周期；期间对每笔大提交和实际释放准确扣还页对齐字节。预算更新和 VirtualAlloc/VirtualFree 保留同一短临界区，避免快照与释放交错导致重复退款。未新增任务数限制或解码字节路径监控。

以下情况立即重新查询：额度不足、Windows 低内存通知、真实 VirtualAlloc 失败、进入恢复队列、粗回收完成。普通释放只归还已记账额度并唤醒监控，不再每次都触发系统查询。空闲时仍无限等待事件，没有新增空闲轮询。

`sunpack_memory_admission_cost` 在两个逻辑处理器内测试最多 32 MiB 未触碰的提交。相同测试 executable 的前后比较：

| 工作量 | 修改前中位数 | 修改后中位数 | 系统查询 |
| --- | ---: | ---: | ---: |
| 1 线程、200 次 4 MiB 分配/释放 | 9.18 ms | 0.89 ms | 约 211 次 → 2 次 |
| 8 线程、1600 次 | 74.29 ms | 5.07 ms | 约 1665 次 → 2 次 |

这说明该分配路径约降低 93% 耗时，**不代表整体解压快 93%**。六种真实解码工作负载各做三轮交替 A/B，使用同样的测试遥测、Job 限额与预留配置，未发现稳定的整体吞吐变化。小样本单轮通常仅几十毫秒，CPU 时间有约 15.6 ms 粒度，不能据此宣称更细的性能差异。

## 全格式覆盖及 512 MiB 选值

使用真实受限子进程，CPU 通常限于本机总量 1%，绑定两个逻辑处理器；短任务动态测试降到 0.25%，让收缩和恢复都实际发生。固定提交上限通常为 768 MiB，动态扩容最高 1024 MiB。主机可用内存保持 13 GiB 以上，没有耗尽主机资源。Job 查询、2 ms 私有提交采样和精确 managed 提交观测全部留在测试 executable。

覆盖下列容器与执行路径：

| 路径 | 样本 |
| --- | --- |
| ZIP | Copy、Deflate/zlib-ng、Deflate64、BZip2、LZMA、PPMd、XZ、Zstd、LZFSE；ZipCrypto/AES |
| 7z | Copy、LZMA、LZMA2、PPMd、BZip2、Deflate、LZ4；BCJ2 多流；BCJ、ARM、ARMT、ARM64、PPC、IA64、SPARC、RISCV、Delta；加密头 |
| RAR | RAR4、RAR5；独立 RAR1/RAR2 样本；RAR PPMd/LZSS 转换 |
| 流与 TAR | gzip、bzip2、xz、zstd、lz4，原始 TAR 及五种 TAR 外层流 |
| ENC | 官方十种 cipher、两种额外 KDF 参数 |

默认 512 MiB 下，59 组样本各运行 32 个任务，1888 个任务全部完成，输出大小与 CRC32 均匹配独立原始输入/参考输出。RAR PPMd 样本额外用两个真实 decoder 解出各约 230 MiB 到 dry-run sink，避免为重复测试写入数 GiB 输出；managed 峰值 58 MiB，归档校验通过。TAR 外层流按原始 TAR 的 CRC32 校验；内层递归由真实 pipeline 测试覆盖。

扩展矩阵暴露出上轮漏测的未纳管增长：

| 场景 | 未纳管私有提交峰值 |
| --- | ---: |
| BCJ2，多流、32 任务、共享写入设施 | 约 312 MiB |
| BCJ2，32 个独立写入设施 | 约 384 MiB |
| 其余本轮普通样本 | 通常低于 120 MiB |

BCJ2 的多个不足 4 MiB 的字典、流缓冲与写入工作区叠加，一组采样在 250 ms 内增长约 290 MiB。它不是发现了一个遗漏的巨型 malloc，逐个跟踪这些小缓冲会增加复杂度。按用户允许的取舍，选择 **384 MiB 已观察峰值 + 128 MiB 粗余量 = 512 MiB**，保持 4 MiB 纳管粒度。既有小提交已经由系统可用量扣除，预留服务于未观测增长和恢复，不是小内存总量上限，也不会实际分配这 512 MiB。

256 MiB 对照在 272 MiB Job 硬上限下仍完成了 32 个 BCJ2 任务，但出现 11 次任务回收，不能把它写成 OOM 失败。512 MiB 配置在相同 16 MiB 管理额度、528 MiB 硬上限下完成且未回收。这是受限样本，不能由其耗时推导正常吞吐收益。另做三轮 31 个 BCJ2 加一个大字典任务，256/512 MiB 两种预留均完成；没有把单个样本成功当作绝对安全证明。

较大的单块仍沿已有路径管理：本轮确认 LZ4 最大块、XZ 32 MiB 字典、Zstd 长窗口、ENC KDF、7z/ZIP PPMd 与 BZip2 都进入相同分配器；没有增加格式上限。动态压力覆盖 LZMA2、PPMd、bzip2、ENC、LZ4、RAR5、XZ、Zstd，均完成收缩/扩张并校验输出。对过快完成、没等到恢复阶段的试验，脚本明确报“pressure cycle not exercised”，降低测试子进程 CPU 配额后重新执行，不计作成功压力周期。

8/16/32 GiB 使用相同 512 MiB 固定预留，比旧 10% 分别少约 307/1126/2765 MiB。实际机器测试平台为 32 个逻辑处理器；缩放预算测试不等于三台不同容量物理机。更多核心、极端条目数和更大外部突发仍需按相同工具测量，不能从有限样本证明任意输入都不会 OOM。

## 格式 bug 和回归

LZFSE `DecodeUncompressed` 忘记递减 `unpackSize`，导致合法 raw block 后的下一块与结束标记被写入输出，错误地报告损坏。项目内和本地 reference 中都存在这处循环；独立构造合法 ZIP/LZFSE 和独立 7-Zip 工具均重现。修复仅增加一次剩余量递减，新增多 raw block（含空块）测试。

压力运行时还发现既有异步写入测试假设“睡 50 ms 后生产者肯定已写入”；并行构建时生产者可能尚未调度，导致假失败。测试改为等待首块真实被接受的 promise，再取消；没有修改生产写入逻辑或增加生产等待。

最终功能验证：389 项 Python 测试及 24 个子测试、116 项真实归档 pipeline 测试、7 项 C++ 测试。覆盖 CLI/watch、密码、分卷及伪装、载体、嵌套、资源等待、取消、输入变化和输出重放。磁盘/内存两种恢复顺序仍用真实 writer 的磁盘满故障注入验证；本轮没有新增 VHD 满盘实验。

## 重现与证据

```powershell
cmake --build native/sevenzip_bridge/build-x64-ci --config Release --target sunpack_sevenzip_memory_probe sunpack_sevenzip_memory_worker sunpack_memory_admission_cost --parallel 4
.venv/Scripts/python.exe tests/memory/worker_format_probe.py --jobs 32
.venv/Scripts/python.exe tests/memory/worker_reserve_probe.py <归档> --format 7z --jobs 32 --dynamic
.venv/Scripts/python.exe tests/memory/worker_reserve_probe.py <BCJ2归档> --format 7z --jobs 32 --volumes 32 --limit-mib 1024
```

较快样本的动态测试加 `--cpu-rate 25`。`--volumes` 在同一测试磁盘上创建独立 writer facility，不代表测试了 32 个物理盘。`--reserve-mib 256` 可运行旧预留对照。

真实工作负载 A/B 工具为 `benchmarks/scenarios/worker_memory_admission.py`，接受修改前后测试 probe 路径、格式矩阵 `cases.json` 和输出目录。分配微测 target 为 `sunpack_memory_admission_cost`，不进入 ctest/default build，也不是“测试 benchmark 是否正常”。

本机原始数据保留在忽略目录 `reports/worker-memory-optimization-20261027/`：每轮 CSV、JSONL 事件、summary、CRC 校验结果与 `cases.json`；A/B 在 `ab-final/comparison.json`。关键轮次：

- `7z-BCJ2-1793086506974799200`：256 MiB 预留下的高峰样本。
- `7z-1793087379980227900`：512 MiB、32 个独立写入设施。
- `mixed-reserve256-*` / `mixed-reserve512-*`：两种余量的三轮混合格式。
- `dynamic-*-7z-PPMd-*`、`dynamic-*-tar-bzip2-*`、`dynamic-*-enc-params_10-*`：两轮真实收缩恢复。
- `dynamic-large-dictionary.xz-1793087632481608700`、`dynamic-large-window.zst-1793087646440007900`：大字典/长窗口的真实恢复与 CRC32。

旧 ZIP 样本来自 [Apache Commons Compress](https://github.com/apache/commons-compress/tree/master/src/test/resources)，RAR1/RAR2 来自 [rarfile](https://github.com/markokr/rarfile/tree/master/test/files)，RAR PPMd 使用本地 [libarchive corpus](https://github.com/libarchive/libarchive/tree/master/libarchive/test)。`--corpus <目录>` 可加入这些独立样本，测试脚本不在运行时下载资料。

机制参考：[Windows 内存资源通知的中间区间](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-creatememoryresourcenotification)、[PrivateUsage 提交量](https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-process_memory_counters_ex)、[SQLite 先回收非必需缓存的内存管理](https://www.sqlite.org/malloc.html)。本实现的快照账本与恢复门槛是针对现有 worker 的工程选择，不声称这些参考实现采用相同策略。
