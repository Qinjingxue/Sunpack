# Worker OVERLAPPED 双缓冲

2026-10-30：已替换正式输入链路。单文件、逻辑分卷和载体 ranges 共用
`OverlappedPrefetcher`；旧 `SequentialPrefetcher`、同步预取句柄缓存、线程、
互斥锁、条件变量和可变队列深度已删除。

每个启用预取的输入流默认使用两个 512 KiB 缓冲区，缓冲区只分配一次。
预取最多持有两个文件句柄和两个事件，分卷数量增加不会扩大句柄缓存。
提交、消费和取消都在调用输入流的线程完成。Seek 和析构先请求取消，
再等待挂起 I/O 完成，随后才复用或释放缓冲。短读和未覆盖的请求复用原有直接读取路径。

物理偏移和可读边界来自输入流已有的文件、分卷或 range 元数据，
预取不会重新识别格式、扫描签名或探测密码。

## 默认策略

| 输入 | 策略 |
| --- | --- |
| 7z、ZIP/ZIPX、BZip2、普通 RAR、其他未禁用格式 | 双缓冲 |
| Gzip、XZ、Zstd、LZ4、TAR | 直接读取 |
| 原生 RAR 分卷回调 | 直接读取，沿用原默认策略 |

Gzip 单任务补测中双缓冲耗时增加约 13%，CPU 时间从约 125 ms 增至 172 ms；
XZ 的并发收益不明确，并增加 CPU 和内存开销，因此默认关闭。
Zstd、LZ4 的初轮结果也没有显示一致优于直接读取。
BZip2 在四并发补测中耗时减少约 5%，CPU 时间减少约 4%，因此保留。
这些选择依据本机热缓存样本；原生 RAR 分卷保持原策略，未根据普通 RAR 样本推断分卷收益。

环境变量 `SUNPACK_SEVENZIP_PREFETCH=0/1` 可分别强制关闭/启用，用于显式覆盖和 A/B。
未设置时采用上表。窗口仍可通过 `SUNPACK_SEVENZIP_PREFETCH_WINDOW_KIB` 调整，
缓冲数量固定为二，旧 `SUNPACK_SEVENZIP_PREFETCH_DEPTH` 已移除。
常规并发和 CLI 格式矩阵默认使用正式格式策略，显式 `--prefetch on/off` 才覆盖。

## 验证和测量

- 强制启用预取后，109 个 Python 测试、6 个子测试、2 个 C++ 测试通过。
  包括加密与未知密码候选、伪装与不完整分卷、载体、嵌套，以及 CLI/watch 的并发场景。
- C++ 测试用两条命名管道制造真实挂起读取，不靠睡眠或线程时序碰运气，
  检查 Seek 取消、缓冲复用、析构回收和句柄释放；小文件样本覆盖跨窗口、短读与 EOF。
- 最终构建实际读取诊断确认：Gzip/XZ/Zstd/LZ4/TAR/原生 RAR 分卷关闭，7z/ZIP 启用。
- 最终四并发 concat ranges 解压与直接读取输出一致，范围请求在物理分卷边界截断。
- 最终八并发、六轮交替测量中，ZIP 的 worker CPU 中位数从 5938 ms 降至 4641 ms；
  7z 峰值 RSS 中位数从 4052 MiB 降至 3696 MiB。7z 的 CPU 中位数基本持平。
  存在后台负载和较大的耗时波动，不将单轮或中位数耗时差解释为稳定吞吐保证。

[production-results.json](production-results.json) 保存本轮格式选择及最终构建的样本、
二进制快速指纹和实际开关结果。
[results.json](results.json) 是上一轮仅修改单文件流的原始实验，保留作历史对照。
当前正式源码已覆盖三个输入流，不再使用临时实验补丁。

复用 [worker_overlapped_input.py](../../scenarios/worker_overlapped_input.py) 可比较保存的旧 worker
与当前构建：`--engines thread,policy` 比较旧预取与正式策略，
`--engines sync,overlapped` 比较新实现的关/开，`--layout ranges` 复用相同语料测 range 流。
每轮交替或轮换顺序，预热不计入样本。真实落盘时，每种模式首次输出用 Rust 快速哈希
检查一致性，校验在计时区间外；每次解压仍执行原有原生完整性校验。
