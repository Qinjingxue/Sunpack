# 4 线程 IOCP writer：Gzip / ZIP，300 MiB 短测

2026-10-02，基于 HEAD `e181826b` 的工作区。i9-13980HX（24 核 / 32 逻辑处理器），约 32 GiB RAM，C: Samsung NVMe。保留默认预取、CPU 额度和缓冲额度；不修改格式配额。

结论：IOCP 对 Gzip 有实质收益；ZIP 多任务没有稳定收益。本节初测中单任务没有观察到退化，8 并发的 RSS 基本不变。后续全格式测量发现 `.zst` 8 并发返回时间约慢 10%，含刷新总时间约慢 1%；详见[全格式回归报告](benchmark_worker_iocp_fullformats_300m.md)。保留通用 IOCP 实现，但不能据此宣称所有格式均无退化。

## 测量口径

复用 Rust 生成的 300 MiB 混合样本：150 MiB 重复文本、150 MiB 确定性随机数据。Gzip 解出原始 TAR 文件，ZIP 解出两个文件。每个任务输出独立目录，8 并发共约 2.4 GiB。一个持久 worker 对比独立 7z.exe 进程，进程准备在 worker 的解压计时之外；CLI 含进程启动，与既有基准一致。

每种格式、每条路径先测 1 / 8 并发各两轮，第二轮逆序；再只对 8 并发补一轮。普通旧 writer、IOCP 和 CLI 同批交替，不与其他性能测试重叠。正式性能数据使用普通 Release 构建，`SUP7Z_ENABLE_WRITER_PROBE=OFF`。

同时记录两种边界：

- **返回时间**：既有 worker / CLI 基准的解压完成时间。
- **含刷新总时间**：调用返回后立即由 Rust 遍历全部输出、打开写句柄并执行 `File::sync_all()`，完成后停止外部计时。包含测量驱动启动/采样收尾及刷新辅助进程启动开销，不等于严格的纯内核 I/O 时间。

返回与刷新之间不做输出验证。刷新后在所有计时之外检查大小、文件数，并用 Rust 逐字节比较输出与原始 TAR / 原始两份文件；所有实测输出通过。Python 仅做调度和元数据处理。此测试缓存较热，不清空输入缓存；磁盘计数为全机计数，不能当成逐进程硬件归因。

## 结果

单位 ms。单任务为两轮中位数，8 并发为三轮中位数。

| 格式 / 并发 | 旧 writer 返回 | IOCP 返回 | CLI 返回 | 旧 writer 含刷新 | IOCP 含刷新 | CLI 含刷新 |
|---|---:|---:|---:|---:|---:|---:|
| Gzip / 1 | 96.0 | 84.8 | 200.0 | 207.9 | 199.1 | 308.3 |
| ZIP / 1 | 101.1 | 85.0 | 190.7 | 253.8 | 205.7 | 317.2 |
| Gzip / 8 | 648.6 | 457.9 | 417.3 | 917.4 | 761.7 | 732.0 |
| ZIP / 8 | 434.3 | 434.1 | 419.3 | 748.8 | 766.4 | 728.1 |

Gzip 三轮配对的含刷新总耗时（旧 → IOCP）：917.4 → 761.7、868.3 → 786.8、934.6 → 761.1，分别缩短约 17%、9%、19%。返回时间缩短约 13%–32%。收益并非全部来自把写回移到返回以后。

ZIP 三轮含刷新耗时：748.8 → 766.4、798.5 → 801.9、746.7 → 739.9。正负波动都小，没有稳定收益。单任务数字是短测趋势，尤其 ZIP 含刷新结果有一轮旧路径波动，不能把百分比泛化到其他机器和冷缓存。

8 并发 RSS：Gzip 旧 / IOCP 都约 104 MiB；ZIP 都约 98 MiB。没有用扩大缓冲池换速度。

## 实现与边界

每卷当前默认 8 个 IOCP 消费线程（本报告初测使用 4 个），既处理提交工作包，也处理完成包。文件句柄关联同一个 completion port；每个缓冲有稳定的 `OVERLAPPED`、输出偏移和已确认写入前缀。删除旧的每缓冲 event 和 `GetOverlappedResult(..., TRUE)` 等待；只有完成包到达后才能记账、释放缓冲或续写短写。即使 `WriteFile` 立即返回成功，也由完成包统一回收，防止双重释放。

保留 1 MiB 缓冲、64 个共享缓冲、每文件 8 MiB、每任务 32 MiB 在途上限。完成顺序可以不同，但文件偏移与内容顺序不变。任务关闭等待全部在途请求结算；取消不会提前释放内核仍使用的缓冲。

保留决定之后又统一了冷路径：删除恢复协调线程、其两组条件变量、完成结果桥接状态及阻塞的 open/close 重试实现。空间失败立即上报并保留原缓冲/句柄；monitor 采样、恢复及取消通过弱订阅投递合并的 IOCP 唤醒包。消费线程非阻塞领取 Ready/Probe/Terminal 裁决，只有真实完成才能结算探测许可；Pending 只留在恢复队列中。目录创建仍复用同一个 gate 的阻塞裁决，许可结算规则与 IOCP 共享。取消先唤醒等待容量的生产者，再封闭文件，IOCP 消费线程可直接结算已取消的排队请求。

最终按用户选定策略统一为每卷默认 8 个 IOCP 消费线程，删除 seek penalty 查询、机械盘分支、在途请求数配额、配额等待队列及唤醒包。每卷仍有独立线程池/完成端口，不额外限制同时在途 I/O 请求数；原有按字节计量的缓冲内存预算保留。删除同步输出 stream 和 probe 的 sync 选择分支，不保留同步 writer 替代链路。

普通写入不会创建 gate 等待者。显式 write-through 的 `FlushFileBuffers` 本身仍是同步 Win32 操作，但满盘时也只尝试一次后排队，不等待恢复。弱订阅不持有 writer，关停在全部文件/请求结算后先禁用唤醒目标再关闭端口，防止持久卷状态引用已回收设施。

“不阻塞”指不再逐请求等待 I/O 完成；Windows 的缓冲 `WriteFile` 调用本身仍可能同步阻塞，IOCP 不会消除文件系统和缓存内部工作。[Microsoft 异步 I/O 文档](https://learn.microsoft.com/en-us/windows/win32/fileio/synchronous-and-asynchronous-i-o)说明了这个边界，以及立即成功仍会发完成包的语义。

本次结果证明旧的逐请求等待限制了 Gzip 的流水线，不能证明剩余 ZIP 耗时来自某个 NTFS 锁或 NVMe 饱和；没有采集 ETW 栈。格式识别、密码、载体与分卷分析仍复用原链路，CLI/watch 共用这一个 writer。

## 正确性与复现

6 个 native CTest 通过，涵盖 IOCP 写入、满盘恢复、短写、关闭、记账和 COM/Deflate 契约。99 项 Python 测试通过，包含 worker 传输、密码/伪装名、分卷、嵌套、CLI 与 watch 密码重试。新增同卷排队取消和阻塞生产者取消/关停用例。

```powershell
cmake -S native/sevenzip_bridge -B native/sevenzip_bridge/build-x64 -DSUP7Z_ENABLE_WRITER_PROBE=OFF
cmake --build native/sevenzip_bridge/build-x64 --config Release --parallel
uv run python -m benchmarks.scenarios.worker_iocp_300m `
  --baseline benchmarks/.cache/writer-probe/pre-iocp.exe `
  --candidate native/sevenzip_bridge/build-x64/Release/sunpack_sevenzip_worker.exe `
  --runs 2 --concurrency 1,8 --prefetch on `
  --json-out benchmarks/results/worker-iocp-retest.json
```

旧基线须在替换源代码之前构建并保存；本次 SHA256 为 `AA24CC1DE06B6C1E42500D988846A2440811978CB39EF9CE72B82D6973B3EA92`。性能测量后继续修正了冷路径、关闭和错误处理，最终普通构建重新通过全部正确性测试。

原始本地数据：[两轮 1 / 8 并发](../../benchmarks/results/worker-iocp-300m-20261002.json)、[8 并发第三轮](../../benchmarks/results/worker-iocp-300m-third-20261002.json)。旧 writer 的输出消融数据：[关闭预取](../../benchmarks/results/writer-probe-controlled-20261001.json)、[默认预取](../../benchmarks/results/writer-probe-default-20261001.json)。
