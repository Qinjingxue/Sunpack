# Worker 线程分配短测：300 MiB，8 并发，2 轮

日期：2026-10-01。源代码 HEAD：`dfdbe8c6`。i9-13980HX，24 物理核 / 32 逻辑处理器，约 32 GiB RAM，C: NVMe。

结论：不存在稳定的全格式并发优势。解码预算的原子计数没有发现超发证据，但它不是整个进程的 CPU 预算；格式内并行收益、预取和输出侧才是主要差异。不能统一把总额度改成 16，也不能统一增加内部线程。

## 方法与有效数据

每份样本解压后 300 MiB：150 MiB 重复文本 + 150 MiB 确定性随机数据。完整 18 格式/变体 corpus 已准备；根据用户缩减时间预算的要求，正式结论采用 7 个典型变体，固定 8 个并发任务，每批 2.4 GiB，2 轮交替 worker/7z 顺序。单个持久 worker，传 Rust 解析的真实输出卷标识；7z 使用 8 个独立进程。默认配置为 32 CPU credits、4 writer、格式感知预取开启。

输出校验和删除不计入时间。RSS 每 20ms 采样；CPU 用 Windows 进程句柄计时，CPU 核数 = CPU 时间 / 墙钟时间。启用读诊断；当前 Release 未编译 pipeline timing。未清空 Windows 文件缓存，也未强制持久化刷盘，因此是缓存较热的端到端吞吐，不能解释为 NVMe 持久写入带宽。2 轮小于约 10% 的差异只作趋势。

原完整梯度测试在中断后发生两轮重叠，已停止并排除；不从那份 JSON 提取正式结论。初版测试驱动的提交锁与事件管道干扰也已修正，并有回归测试。

## 默认配置的实际解压

单位 ms；比值为 worker/7z，大于 1 表示 worker 慢。

| 变体 | Worker | 7z.exe | 耗时比 | Worker 平均 CPU 核 | 7z 平均 CPU 核 |
|---|---:|---:|---:|---:|---:|
| 7z 非 solid | 675.1 | 491.2 | 1.37 | 6.93 | 7.40 |
| 7z solid | 897.2 | 490.7 | 1.83 | 7.31 | 10.56 |
| BZip2 | 3883.5 | 3891.8 | 1.00 | 24.29 | 12.40 |
| Gzip | 362.5 | 365.9 | 0.99 | 5.74 | 5.40 |
| RAR5 非 solid | 517.4 | 365.5 | 1.42 | 5.81 | 5.43 |
| RAR5 solid | 513.2 | 837.0 | 0.61 | 20.46 | 7.65 |
| ZIP | 351.4 | 319.4 | 1.10 | 6.82 | 6.60 |

默认预取、无输出的对照（worker dry_run / 7z t）：

| 变体 | Worker ms | 7z ms | 耗时比 |
|---|---:|---:|---:|
| 7z 非 solid | 451.8 | 280.7 | 1.61 |
| 7z solid | 437.8 | 276.8 | 1.58 |
| Gzip | 115.2 | 146.6 | 0.79 |
| RAR5 非 solid | 172.2 | 137.9 | 1.25 |
| RAR5 solid | 363.8 | 694.4 | 0.52 |
| ZIP | 148.9 | 140.1 | 1.06 |

## 线程分配与瓶颈判断

1. **总额度不宜统一减半。** 在关闭预取、无输出的同一对照中，BZip2 从额度 32 改为 16：3757 → 3950ms（慢约 5%），CPU 从 24.24 → 13.82 核，CPU 总时间约降低 40%。而 RAR5 solid 从 468 → 633ms（慢约 35%）。这表明 BZip2 的额外 lanes 在多任务时收益低；RAR5 solid 对并行额度仍有明显需求。应按格式和边际收益分配，不是统一减少外层并发。

2. **没有发现解码额度本身超发的证据，但存在预算边界。** `NativeCpuBudget::acquire_up_to` 用 CAS 原子保留额度；MtDec/LZMA2 首 lane 在调用线程执行，新增 lane 借额度；BZip2 借额度后投递 block、完成后释放；RAR5 新增 worker 先借额度，session 结束等待 idle 后释放。本样本 decoder_started 事件观察到 7z 约 2 credits/job、RAR5 约 4，BZip2 到此峰值 extra 为 3；Gzip/ZIP 为 1。预取每条输入流可另建线程，writer 每卷 4 线程，均不属于该额度。32 credits 不等于进程最多 32 个消耗 CPU 的线程。IO 线程大量时间在等待，不能把每个 IO 线程都机械扣掉一整核。事件是启动时快照，不是完整的瞬时运行线程追踪；本次不是全格式全路径超额审计。

3. **BZip2 偏重计算资源，Gzip/ZIP 没有解码线程不足的证据。** BZip2 8 并发无输出时约 24 核，与 CLI 约 12 核的吞吐几乎相同。Gzip/ZIP 关闭预取、无输出分别 52/96ms，对应 CLI 153/142ms；其顺序流解码没有显示需要更多线程。不要为提高“利用率”强行增加不能带来吞吐的 lanes。

4. **4 个 writer 不能保证输出不成瓶颈。** 相同关闭预取对照下，Gzip/ZIP 从无输出 52/96ms 变为有输出 570/422ms，CLI 153/142 → 374/365ms。再次测 4/8 writer：Gzip 388 → 325ms，ZIP 437 → 403ms；配套 CLI 耗时有波动，ZIP 相对 CLI 优势基本没改善。因此输出路径已被定位为限制之一，但“线程翻倍就解决”不成立。源码有每卷共享队列、互斥锁、1 MiB staging 拷贝、64 buffer、producer notify_all，4 条写线程仍会受到队列竞争、复制、缓存写入/NTFS 及磁盘压力影响。此次未作 ETW 栈分析，不能把全部输出损失具体归罪于某一个锁或 NVMe 本体。

5. **读取/预取策略确实影响收益。** 无输出时，预取 off → on：7z 非 solid 385 → 452ms，solid 358 → 438ms；Gzip 52 → 115ms；RAR5 非 solid 130 → 172ms；RAR5 solid 则 468 → 364ms。当前默认策略只对 TAR、原生 RAR 分卷特殊关闭，其他这些格式都可启用。预取命中很多，但增加复制、线程交接、锁和维护文件位置的成本；缓存较热/高速解码时可得不偿失，RAR5 solid 却能获益。读 trace 的同步 ReadFile 计时不包含全部预取线程工作，不能看到 ReadFile 接近 0 就宣称没有读取成本。关闭预取时 7z 每任务 ReadFile 耗时约 117–157ms，读/缓冲链路仍值得检查。

6. **7z 不是简单的总额度过大。** 无输出且无预取，把额度从 32 → 16 基本不变；进一步到 8，让这组作业各只拿 1 credit，非 solid 385 → 363ms，solid 358 → 338ms，仍落后 CLI 约 263–281ms。额外 lane 有较低边际收益，但不是全部差距；输入/缓冲、decoder 和回调路径剩余开销尚未细分到函数。

7. **不能把差距直接归于 Windows 或外部程序。** 13980HX 是 P/E 混合核心，32 逻辑处理器不是 32 个等性能独立核心；超线程共享执行资源，多个计算线程还共享缓存和内存带宽。一个逻辑处理器一个线程不保证完全没有竞争。无输出短测时，worker 以外的主机 CPU 通常约 0.3–2 核，未看到外部程序打满 CPU 的证据；有输出时系统工作更明显。没有 ETW 调度/带宽证据，不能进一步声称 Windows 调度就是根因。

## 优先处理方向

优先调 BZip2 在多任务下借 extra credits 的收益门槛；保留 RAR5 solid 的有益并行。让预取按格式、实际读等待/解码速度选择，避免热缓存快速流盲目预取。优化共享 writer 的 staging/唤醒/排队路径，并用吞吐和等待时间判断写线程收益。预算应区分潜在 decoder lanes 与实际活动，关注 RAR5 session / MtDec decoder 生命周期持有额度但等待的情况；不要靠无用等待或降低任务并发掩盖竞争。

本次仅增加基准和诊断选项，未修改产品调度、读取或写入实现。CLI/watch 共用的原生 worker 是测量对象，但未跑整条 CLI/watch 的扫描、密码、嵌套、载体和缺卷流程；没有对这些正确性路径作改变。13 个相关测试通过。

## 数据与复现

- [有效原始数据：worker-typical-8-default](../../benchmarks/results/worker-typical-8-default-20261001.json)
- [有效原始数据：worker-typical-8-default-dry](../../benchmarks/results/worker-typical-8-default-dry-20261001.json)
- [有效原始数据：worker-typical-8](../../benchmarks/results/worker-typical-8-20261001.json)
- [有效原始数据：worker-typical-8-dry](../../benchmarks/results/worker-typical-8-dry-20261001.json)
- [有效原始数据：worker-typical-8-dry-cap16](../../benchmarks/results/worker-typical-8-dry-cap16-20261001.json)
- [有效原始数据：worker-typical-8-dry-cap8](../../benchmarks/results/worker-typical-8-dry-cap8-20261001.json)
- [有效原始数据：worker-typical-8-writers8](../../benchmarks/results/worker-typical-8-writers8-20261001.json)
- [有效原始数据：worker-typical-8-writers4-repeat](../../benchmarks/results/worker-typical-8-writers4-repeat-20261001.json)

短测命令：

```powershell
uv run python -m benchmarks extraction worker-concurrency-300m --format 7z --format bz2 --format gz --format zip --format rar --concurrency 8 --runs 2 --profile --no-mixed --prefetch on --json-out benchmarks/results/worker-typical-8-default-20261001.json
```

增加 `--dry-run` 做无输出对照；`--prefetch off` 隔离预取；`--worker-capacity 16`/`8` 和 `--writer-threads 8` 仅供诊断。默认入口现在采用 8 并发、2 轮，避免再次做过密梯度。

## README 单任务复测与并发反转（同日追加）

按 README 原入口 `_run_worker_case` / `_run_seven_zip_case` 的执行和计时方式，关闭预取与诊断，每项两轮、无 warmup，复测全部 18 格式/变体；全部成功。16 项 worker 领先；RAR4 solid 671.5/654.3ms、TAR 127.4/122.6ms，差距很小且轮间有波动，不作明确回归判断。各项中位数之和 worker 6435.8ms，7z 10618.5ms，worker 低 39.4%，接近 README 历史的 41.2%。

为控制时间，复用本次 Rust 生成的 300 MiB corpus：数据形状、大小相同，随机字节与历史 Python 生成器不同。本次单任务和并发用相同输入，当前 worker/7z/dll SHA256 已重新核对，与前述短测一致；这不是历史 commit 的重新构建。产品代码未改。

再用同一并发测试入口、关闭预取/诊断、每项两轮交替顺序，比较 1 和 8 并发，排除入口差异。8 并发列是整个 2.4 GiB 批次墙钟时间，不能当成单任务延迟：

| 变体 | 1 任务 Worker/7z ms | 8 任务 Worker/7z ms | Worker/7z 比值变化 |
|---|---:|---:|---:|
| 7z:non-solid | 198.5/258.2 | 680.2/519.3 | 0.77 → 1.31 |
| 7z:solid | 164.0/209.9 | 779.8/527.8 | 0.78 → 1.48 |
| bz2 | 1753.9/2966.6 | 4021.0/4036.0 | 0.59 → 1.00 |
| gz | 82.5/208.1 | 746.3/346.0 | 0.40 → 2.16 |
| rar:non-solid | 128.6/183.1 | 439.7/371.4 | 0.70 → 1.18 |
| rar:solid | 196.6/768.0 | 714.5/891.1 | 0.26 → 0.80 |
| zip | 92.8/197.7 | 402.2/362.8 | 0.47 → 1.11 |

进一步无输出对照（关闭预取，读诊断开启，双方模式是 worker dry_run / 7z t；该模式仍包含解码/校验/协议，不是纯 decoder）：

| 变体 | 1 任务 Worker/7z ms | 8 任务 Worker/7z ms |
|---|---:|---:|
| 7z:non-solid | 175.2/183.6 | 411.5/286.3 |
| 7z:solid | 125.0/133.3 | 394.2/288.6 |
| gz | 39.0/132.7 | 54.4/162.7 |
| zip | 76.2/124.8 | 99.5/160.4 |

解释：

- **按需求借线程只表示 decoder 有可并行工作并且额度可用，不表示该线程在当前负载下有正的吞吐收益。** 当前预算发放只检查 wanted/minimum_grant/available 的原子计数，没有根据完成速率、CPU 成本、IO 等待测算边际收益。额度是许可，既不是一直运行的核心，也不是自动最优调度。
- **BZip2 的单任务收益不能线性叠加。** 单任务平均 CPU 3.21 核，CLI 1.59；8 任务 worker 23.96 核，CLI 12.51，却都约 4 秒。worker 每份归档 CPU 时间从约 5.6 秒变成 12.0 秒，CLI 从约 4.7 秒变成 6.3 秒。多线程扩展成本明显更高；具体由 HT/异构核心、缓存/带宽、内部同步各贡献多少，尚无采样栈证据。前述 32→16 额度对照进一步支持额外 lanes 边际收益低。
- **Gzip/ZIP 的解码并发没有失去优势。** 无输出 8 并发 worker 54/99ms，CLI 163/160ms；有输出变为 746/402ms，CLI 346/363ms。主要损失发生在增加输出后，包含共享 writer、复制/排队/唤醒、Windows 文件系统和缓存写入。不能断言 NVMe 本体或某个锁单独负责。Gzip 有输出在不同短测中波动很大，精确倍数不宜泛化。
- **7z 的差距在无输出时也存在。** 单任务无输出仅领先约 5–6%；8 并发 worker 394–412ms，CLI 286–289ms。solid 启动快照由单任务 3 credits 降至多任务常见 2 credits，且多任务 CPU 平均 9.66 核，对方 13.46 核；非 solid 两边快照都常见 2 credits。快照不能代表全程。本轮证据支持读取/解码/缓冲及同步链路扩展效率不足，不能只归因写入，也不能据此直接要求加线程：前述无输出额度32→8仍落后。具体函数热点仍需后续短栈采样定位。
- **RAR5 solid 的内部并行仍有收益。** 本轮单任务约 3.9 倍、8 任务仍约 1.25 倍快，说明所有格式统一缩减线程不会得到最优结果。
- **进程启动开销在并发时可重叠。** 持久 worker 的单任务优势包含避免启动 CLI 的收益；8 个 CLI 的启动时间不应按串行相加。这会缩小优势，但无法独自解释 7z 无输出的吞吐反转和 Gzip 的输出损失。

因此 README 的单任务优势与并发反转可以同时成立。需要修正的是“按内部需求借线程 = 最优并行分配”的假设；应按格式判断额外 lanes 的边际收益，并处理共享输出与 7z 输入/解码链路的扩展效率，不能直接把问题归咎于总额度超发或 Windows 调度。

数据：

- [README 18 项两轮复测](../../benchmarks/results/worker-readme-retest-20261001.json)
- [同入口 1/8 并发两轮对照](../../benchmarks/results/worker-readme-scaling-retest-20261001.json)
- [同入口 1/8 并发无输出两轮对照](../../benchmarks/results/worker-readme-scaling-dry-retest-20261001.json)
