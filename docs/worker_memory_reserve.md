# worker 固定内存预留：测量与选值

2026-10-27：默认预留从物理内存的 10% 改为 **256 MiB（268435456 字节）**。配置为 `performance.worker.memory_reserve_bytes`，传输环境变量为 `SUNPACK_NATIVE_MEMORY_RESERVE_BYTES`。旧比例字段不再参与决策。

这份预留不实际占用内存，也不是压缩包大小、字典大小或任务并发上限。已经提交的小内存本来就在系统可用量中扣除；预留主要吸收下一次大块准入/监测之前的小分配增长，以及撤销、排空、保存重放记录和重新创建输出设施的临时开销。

## 怎样测量

专用 `sunpack_sevenzip_memory_probe` 使用同一份 worker、解码器和内存管理源码。仅测试翻译单元拦截管理器的 `VirtualAlloc/VirtualFree`，在相同测试锁内更新实际提交字节数并读取 `PrivateUsage`，另外每 2 ms 补充采样：

`未纳管提交 = 进程 PrivateUsage − 当前已纳管提交（按页对齐）`

这不是 RSS，不把尚未触碰的字典漏算。分配/释放和记账同步，避免释放的瞬间把整个字典错误算成未纳管内存。测试自身的一个线程和少量 CRT 开销也计入未纳管量，因此结果略保守。2 ms 不是峰值的严格保证，尤其是纯小分配的短暂尖峰；同时记录 Windows 持续维护的 Job 提交峰值，交叉检查纯小分配场景。

Windows Job 限制只施加到测试子进程：通常最多 768 MiB，CPU rate 为 100/10000，亲和性限于两个逻辑处理器。Job 剩余提交量通过测试版 Windows 查询替代系统提交量，从而真实触发分配拒绝、撤销和恢复。正式 worker 不包含 Job 查询、测试环境开关或细密采样。测试中宿主机最低可用物理内存仍超过 12 GiB。

早期临时探针存在“大块释放后、账本更新前”的观测间隙，其 70–137 MiB 的若干 LZMA 读数不能用作结论；下表使用消除该间隙后的读数。

## 实测

下列是进程范围的未纳管提交，包含 CRT、线程栈、路径/元数据、解码小缓冲和输出池，不能解释成单个任务的需求。并发数是请求/执行 lane 数，内存不足时大工作区按原仲裁器准入；限额模拟不会把 CPU credit 人为减半。

| 场景 | 未纳管峰值 MiB | 备注 |
| --- | ---: | --- |
| 4 / 16 / 32 路 LZMA，dry-run | 4.4 / 8.0 / 14.3 | 包含全部执行线程；字典已纳管 |
| 16 路 LZMA，真实写盘 | 74.5 | 包含共享输出池 |
| 32 路 Deflate，真实写盘 | 108.3 | 无纳管大分配；Job 提交峰值 110.7 MiB |
| 4 路 ZIP，每包 12000 条目，dry-run | 24.5 | 条目、名称和结果序列化 |
| 16 路 ENC | 21.6 | 20 MiB KDF 工作区纳管，先释放再解密 |
| 16 路 LZ4，合法最大块/linked frame | 71.0 | 最大块及历史缓冲已纳管 |
| 32 路 XZ，3 MiB 小字典 | 50.6 | 字典低于纳管粒度；Job 提交峰值 61.3 MiB |
| 8 路外部收缩、恢复，最终连续三轮 | 27.2 / 30.2 / 46.9 | 恢复期间较首次回收前增长 24.7 / 27.7 / 44.4 MiB |

常规已观察峰值约 110 MiB，向上取整至 128 MiB；再保留一个 128 MiB 的粗粒度余量，覆盖已观察的恢复增长、采样漏峰、线程/CRT 和混合任务的短暂叠加，选择 256 MiB。它是根据这组数据选择的工程余量，不是数学最小值，也没有声称 128 MiB 必然失败。

8 GiB、16 GiB、32 GiB 机器都使用同一个 256 MiB。相较旧 10% 策略，分别少预留约 563、1382、3021 MiB。没有新增小缓冲逐个记账、内部并发限额或闲时轮询。

最终三轮均使用 `304 → 768 → 416 → 768 MiB` 的真实 Job 提交限额，24/24 任务自动完成，24 份输出逐个通过 CRC32 校验，进程均正常退出。初始 304 MiB 中的 256 MiB 为固定预留；剩余量不足 64 MiB 字典，先确认等待通知，再扩张、收缩、恢复。

## 测量中修复的问题

1. 写入设施的 `std::thread` 创建不经过 SDK allocator。骤减提交额度时，MSVC 会抛出 `std::system_error(EAGAIN)`，原通用异常分支只结束任务，未发送结果。任务边界现在记录 `memory_thread_resource_retry` 并沿原资源等待链路重试；其他未识别异常也返回明确结果。零预留对照中已观察到 error_code=11 后任务成功恢复。
2. `GetStream` 的路径准备把 `bad_alloc` 转成 `E_FAIL`；内层目录安全检查也可能把它当成路径权限失败。现在仅这两个相关边界保留明确内存错误，返回 `E_OUTOFMEMORY`，由现有重放路径处理。没有增加所有位置兜底捕获。

另做零预留反例：三轮中两轮完成，第三轮在强行将 Job 限额降到当前提交量以下时以 `0xC0000409` 退出。它说明完全耗尽提交额度后，进程可能连恢复代码都无法运行；没有用复杂 SEH 或强行吞掉系统故障来掩盖这个边界。

本轮检查了 7-Zip My/Mid/Big allocator、C++ 大容器、ENC FFI 工作区、LZ4 custom allocator 和 zlib-ng 固定缓冲，未确认新的遗漏大分配需要接入。保留原 4 MiB 纳管粒度；没有为了测量把 1 MiB 缓冲逐个纳管。

## 复现和证据

```powershell
cmake --build native/sevenzip_bridge/build-x64-ci --config Release --target sunpack_sevenzip_memory_probe sunpack_sevenzip_memory_worker --parallel 4
.venv/Scripts/python.exe tests/memory/worker_reserve_probe.py <压缩包路径> --format 7z --jobs 8 --dynamic
```

静态测量可去掉 `--dynamic`，使用 `--jobs 32 --limit-mib 768`；元数据测量加 `--dry-run`；ENC 可指定 `--password`。改变 `--reserve-mib` 可做预留对照。脚本的 60 秒截止只用于终止没有返回结果的测试子进程，不改变生产任务的等待行为。

本机原始 CSV、事件、摘要和输出保留在 `reports/worker-reserve-20261027/`，该目录按项目规则不入 Git。关键记录：

- 消除记账观测间隙后的测量：`lzma-32-1793084387786557600`、`lzma-output-16-1793084396799963300`、`deflate-32-1793084403246549800`。
- 独立测试 executable 的最终格式轮次：`enc-16-1793084960472349100`、`lz4-16-1793084963716464300`、`small-dictionary-32-1793085200393827300`。
- 最终默认预留恢复：`final-dynamic-0-1793085446749635800`、`final-dynamic-1-1793085450221100800`、`final-dynamic-2-1793085453209296200`。
- 零预留对照：`fixed-zero-margin-0-1793085487627539300`、`fixed-zero-margin-1-1793085491176386500`、`fixed-zero-margin-2-1793085494729023300`。

最终验证：388 项 Python 测试、24 个子测试、7 项 C++ 测试通过。包含 CLI/watch、取消、输入变化、密码、分卷、载体、嵌套、磁盘/内存同时等待的既有覆盖。8/16/32 GiB 使用固定预留的缩放模型，不是三台物理机；本轮未新增真实满盘 VHD 测试。

有限样本不能给出任意并发、任意文件条目数或瞬间外部无限分配下的绝对保证。固定预留针对未纳管量的增长，不代表这些量永远小于 256 MiB；既有小内存仍通过真实系统可用量参与预算。超多核心、多个输出卷或极端元数据工作负载可按同一工具继续测量，并调整这一个字节数，无须扩展生产管理机制。

计量口径参考：[Windows PrivateUsage/Commit Charge](https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-process_memory_counters_ex)、[Job 提交限额与持续峰值](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_extended_limit_information)。
