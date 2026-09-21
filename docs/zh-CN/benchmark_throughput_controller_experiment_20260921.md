# 智能吞吐量控制器第一轮实验报告

实验日期：2026-09-21  
机器：32 logical processors，Windows，native worker Release build  
正式批次：CPU/IO 两类 workload，固定并发 `1/2/4/8`，每个并发 5 次 oracle；adaptive 每类 3 次稳态、2 类 scheduled pressure、persistent/transient Probe collision。每次 backlog 为 128 个 64 MiB job。

原始结果：

- [formal 58-row report](../../benchmarks/results/controller_experiment_formal.json)
- [ON→OFF pressure lifecycle report](../../benchmarks/results/controller_experiment_onoff.json)
- [event-level smoke report](../../benchmarks/results/controller_experiment_event_smoke.json)

## 结论摘要

当前实现的“正确性链路”是通过的，但“控制性能”还不能判定为达到目标：58 行正式实验和 14 行 ON→OFF 补充实验均保持 128/128 job 成功；然而 adaptive 在本轮有限 backlog 中几乎没有进入稳定 oracle 平台，`Accepted` 在正式 adaptive 样本中为 0，绝大多数时间处于平台外探索、污染或回退路径。

最重要的结果是：

1. CPU workload 的 formal oracle 是并发 8；并发 4 已接近但低于 98% 平台阈值。此前单次高并发边界观测中，16/32 的吞吐回落，同时 RSS 升至约 1.17/2.33 GiB，说明继续全开不是合理策略。
2. IO workload 的 98% 近最优平台是并发 4–8，按“吞吐相当时偏好较低并发”的规则，oracle 取 4。
3. 稳态 adaptive 的 CPU 中位 oracle efficiency 约 87.7%，累计 regret 中位约 1.20 GB（约 1.12 GiB），平台外时间比例约 98.4%；IO 的吞吐接近 oracle，但多次被判为 `Contaminated`，没有形成稳定 `Accepted` 工作点。
4. Probe collision 中，persistent pressure 没有观察到 false accept，且能产生 `Contaminated`；transient pressure 也没有 false accept，但仍会被判为 `Contaminated`，本轮没有把“只作用于 B、且在 Verify 前完全消失”的 B-only 情况严格隔离出来，因此不能据此宣称 A-B-A 已解决该理论盲点。
5. Scheduled CPU/IO pressure 的 ON→OFF 补充批次确认压力进程实际启动并停止，持续约 0.735–0.739 秒；正式批次中没有出现 `EnvironmentChanged`，环境变化主要在 Probe/Verify 路径表现为 `Contaminated` 或 `RolledBack`。

## 1. Oracle 吞吐曲线

formal batch 使用固定 active-job limit，5 次运行顺序交错，近最优平台定义为最大吞吐的 98%。中位吞吐如下，单位 MiB/s：

| workload | N=1 | N=2 | N=4 | N=8 | 98% plateau | oracle |
|---|---:|---:|---:|---:|---|---:|
| CPU-heavy | 1360.1 | 2179.4 | 2359.0 | 2498.1 | `{8}` | 8 |
| IO-heavy | 2293.5 | 2420.1 | 2512.8 | 2557.1 | `{4, 8}` | 4 |

CPU 的重复样本存在明显热/主机状态漂移：早期 run 的 N=4/8 明显高于后期 run。交错顺序降低了简单的顺序偏差，但没有温度/频率遥测，因此 CPU 的 oracle 应视为本机本 workload 的当前估计，不应当解释为跨机器常数。

## 2. 主动 adaptive

当前 native controller 的实际实现是窗口测量 + fast/slow log EWMA/CUSUM 变化趋势 + Probe/Verify 的 A-B-A 判断；配置默认值来自 [native_runtime_control.hpp](../../native/sevenzip_bridge/src/internal/native_runtime_control.hpp)，控制循环位于 [worker.cpp](../../native/sevenzip_bridge/src/worker.cpp)。

正式 adaptive 轨迹显示：

- 初始并发为 2，controller 能发出 `ProbeUp`、`VerifyStarted`、`Contaminated`、`RolledBack`、`ProbeDown` 等事件，事件级 trace 链路工作正常。
- CPU 稳态样本的中位 efficiency 约 0.877，3 次 Probe，约 2 次到 3 次 Verify，`Accepted=0`，`Contaminated=1`、`RolledBack=1`，平台外比例约 0.984。
- IO 稳态样本的吞吐大致落在 oracle 附近，但 3 次样本均发生约 2 次 `Contaminated`，仍没有稳定接受候选点。
- `settling_time` 大多没有形成，说明当前 workload 在 controller 完成一次可确认探索前就结束，或者测量被持续漂移打断。

因此当前主动策略的结论不是“找到了 oracle”，而是：探索动作和归因事件已经可观测，但默认窗口/扰动下的 finite-batch 收敛成本过高，当前不能以最终 active limit 作为成功标准。

## 3. 被动压力与 ON→OFF

补充批次把压力注入安排为 activity 开始后 1 秒启动、0.75 秒后停止。四种 workload/pressure 组合的 trace 均记录了：

```text
pressure_started = true
pressure_stopped = true
pressure_duration_seconds ≈ 0.735–0.739
```

但本轮没有观察到 `EnvironmentChanged`。这说明当前实验已经证明“外部资源压力可以和 controller 同时运行”，还没有证明 passive detector 能在稳定段快速、稳定地产生目标事件。压力在 Probe/Verify 期间更常以 `Contaminated` 或 `RolledBack` 体现。

## 4. Probe collision 与 A-B-A 边界

事件钩子在收到 `ProbeUp` 后精确启动 CPU pressure，避免了随机碰撞。formal trace 的共同特征是：

- persistent：至少一个 Probe 得到 `Contaminated`；未观察到 `Accepted`。
- transient：同样未观察到 `Accepted`，但仍可能得到 `Contaminated`；部分 run 后续没有足够窗口完成最终分类。

这不是对 B-only 理论边界的否定。当前 transient 定时器按固定时长停止，尚未用实际 `VerifyStarted` 事件做“Verify 前停止”的硬同步，因此不能把它当成纯 B-only 干扰。下一轮应改为：`ProbeUp` 启动，收到该 probe 的 `VerifyStarted` 前强制停止，再单独统计最终 `Accepted/RolledBack/Contaminated`。

## 5. 风险与下一步

当前最优先的问题是测量/实验时长，而不是继续暴力扫参数：

1. 给 controller 提供可持续至少数个完整 A-B-A 周期的 backlog，并记录 CPU temperature/frequency，先消除 thermal drift 对 oracle 的污染。
2. 把 B-only collision 改成事件同步注入，严格保证压力在 Verify 前停止；若仍出现 false accept，再评估 A-B-A-B 或二次 candidate confirmation。
3. 单独设计足够长的 stable/noise/step-change 三组，测 `ARL0`、detection delay 和 `EnvironmentChanged`，当前正式批次的 `EnvironmentChanged=0` 不能作为 detector 已经可靠的证据。
4. 在接受/回退正确性满足约束后，再优化窗口长度、detector、阈值、probe cadence；本轮数据不支持直接调整成某个新的固定比例。
5. 重复 oracle 时把 16/32 作为低频边界点，并同时设 RSS 上限；本机单次观测已经显示 N=32 的资源代价不适合作为默认搜索方向。

## 验证状态

新增统一 benchmark 与事件钩子已通过编译；相关既有测试通过：`10 passed`（small-file scheduling benchmark 与 benchmark CLI）。

统一驱动入口为：

```powershell
python -m benchmarks extraction worker-throughput-controller --capacities 1,2,4,8,16 --oracle-runs 5 --adaptive-runs 3
```

## 6. 继续实验：细粒度 oracle、长时噪声与 Hold 被动注入

本节是同一工作日对上面结论的追加实验。所有追加批次均为 `all_passed=true`，没有发现解压正确性回归。

### 6.1 细粒度固定并发 oracle

CPU 扫描了 N=1..12、16；IO 扫描了 N=1..12、16，每点 5 次。局部梯度按 `g_N = T(N+1)/T(N)-1` 计算。中位吞吐如下，单位 MiB/s：

| workload | N=1 | N=2 | N=3 | N=4 | N=5 | N=6 | N=7 | N=8 | N=9 | N=10 | N=11 | N=12 | N=16 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| CPU-heavy | 1359.7 | 2150.7 | 2291.6 | 2325.8 | 2392.9 | 2340.2 | 2363.6 | 2379.0 | 2390.2 | 2396.6 | 2409.9 | 2402.4 | 2403.1 |
| IO-heavy | 2251.4 | 2578.7 | 2420.8 | 2438.3 | 2448.2 | 2716.2 | 2860.3 | 2459.8 | 2469.5 | 2467.8 | 2719.9 | 2648.2 | 2453.3 |

CPU 的梯度在 N=2 后迅速下降：`g_2≈+6.5%`、`g_3≈+1.5%`、`g_4≈+2.9%`，N=7 之后大多是 ±1% 级。IO 的 N=6、7、11 出现不连续跃升，且 N=7 之后又回落；这不符合平滑的并发收益曲线，更像缓存、后台负载或存储状态污染。因此这轮细扫得到的 CPU 98% 平台 `{5,7,8,9,10,11,12,16}` 和 IO 单点平台 `{7}` 不能替代上一轮 formal oracle，只能证明当前实验环境的固定点噪声足以改变平台判定。

### 6.2 固定 N 的窗口噪声

使用 512 个 job 把 CPU N=4/N=8 和 IO N=4 拉长到约 10–28 秒，并打开 native resource diagnostics。固定模式下 controller trace 的 `throughput_mode` 不会填充完整 throughput 窗口值，因此本节使用同一事件采样流中的 `io_write_bytes_per_second` 作为写入吞吐代理；这是一项明确的测量限制，不把它冒充为正式 controller throughput。

相邻采样的 `log(T_t/T_{t-1})` 绝对值分位数为：

| workload / N | p50 | p90 | p95 | p99 |
|---|---:|---:|---:|---:|
| CPU / 4 | 0.080 | 0.284 | 0.342 | 0.450 |
| CPU / 8 | 0.145 | 0.318 | 0.447 | 0.642 |
| IO / 4 | 0.407 | 1.052 | 1.124 | 2.083 |

结论很直接：IO 的窗口级波动远大于 3% improvement/regression 比例；CPU N=8 也比 N=4 更噪。当前 `Contaminated` 高频出现并非偶然，先扩大阈值或直接改变接受规则都缺少统计基础，必须先把测量窗口改成能稳定估计分布的形式。

### 6.3 长时 adaptive 与初始 N=2/N=4

在 512-job、约 12–17 秒的 CPU 批次中，初始 N=2 的 adaptive 三轮吞吐为 2139.5、2081.9、2023.3 MiB/s；每轮约 10–12 次 Probe、10–12 次 Verify、6–9 次 Contaminated，Accepted=0，并有 1 次无外部压力的 `EnvironmentChanged`。初始 N=4 的三轮为 1941.0、2211.3、1863.0 MiB/s，同样 Accepted=0，且主要落在 Contaminated/RolledBack 路径。

这不是“初始 N=4 一定更差”的严格 paired 证明，因为两批次受主机热状态和缓存影响；但至少没有观察到从 N=2 改为 N=4 能降低探索成本或提升稳定接受率。当前主要瓶颈仍是 controller 在短 finite backlog 内不断重启 probe/verify，而不是初始并发单点。

### 6.4 Hold-phase 被动压力与误报

追加驱动只在 trace 首次出现 `phase=hold`/`decision=holding` 后启动 workload-matched pressure，检测到 `EnvironmentChanged` 立即停止，否则 5 秒超时停止。

- CPU：3 轮无扰动 stationary 中有 2 次 `EnvironmentChanged`；3 轮被动实验中仅 1 轮进入 Hold 并启动压力，约 0.79 秒后检测到 `EnvironmentChanged`，另外 2 轮在 15 秒窗口内没有进入 Hold，未注入压力。
- IO：2 轮无扰动 stationary 中有 2 次 `EnvironmentChanged`，其中 1 次还出现 Accepted；2 轮被动实验均未进入 Hold，因此没有实际压力注入。

因此目前可以确认“进入 Hold 后的事件级注入和停止链路”可工作，但不能确认 Hold detector 的可靠性：Hold 到达率低，且无扰动误报已经在 CPU/IO 两类 workload 中出现。应先以 stable/noise 长跑估计 ARL0，再讨论 detection delay；当前的 `EnvironmentChanged=0` 或偶发 `EnvironmentChanged=1` 都不能单独作为 detector 成功/失败结论。

追加结果文件：

- [fine oracle](../../benchmarks/results/controller_experiment_fine_oracle.json)
- [CPU window noise](../../benchmarks/results/controller_experiment_noise_cpu.json)
- [IO window noise](../../benchmarks/results/controller_experiment_noise_io.json)
- [long CPU, initial N=2](../../benchmarks/results/controller_experiment_long_cpu_n2.json)
- [CPU passive Hold v2](../../benchmarks/results/controller_experiment_passive_cpu_v2.json)
- [IO passive Hold](../../benchmarks/results/controller_experiment_passive_io.json)
- [CPU initial N=4](../../benchmarks/results/controller_experiment_initial_n4_cpu.json)

### 6.5 更新后的结论与下一步

当前实现已经具备可复现实验所需的 oracle、扰动进程、事件级 trace 和 Hold 后注入能力；但控制性能仍不能判定为达标。证据优先级如下：

1. 先修测量：固定并发模式也应输出与 adaptive 相同定义的窗口 throughput，或明确提供 benchmark-only 的固定窗口观测接口；否则 IO 噪声只能通过系统写入代理估计。
2. 在 controller 参数不变的情况下做更长 stable/noise 批次，至少按 workload/N 重复多个 10–20 秒窗口，报告 false-positive rate、ARL0、p95/p99 和 Hold 到达率。
3. 重新做严格的 step-change：必须保证 pressure 在 Hold 后启动，并记录从 `pressure_started` 到 `EnvironmentChanged` 的延迟；未进入 Hold 的批次应单独记为 censoring，不能与“未检测到变化”混为一类。
4. 在误报和窗口估计稳定前，不调整 improvement threshold，也不把当前细 oracle 的单个峰值用于改默认 active limit。

## 7. 继续实验：native 固定窗口测量与账本闭合

本轮按上一节的优先级先补测量，不改 controller 的 improvement/regression threshold、EWMA/CUSUM、cooldown、hold 或 Probe/Verify 策略。新增 fixed-mode 的 native measurement diagnostics：固定并发也使用 native window 产生 `accepted/written/completed` 窗口增量，同时输出真实 writer pending gauge、累计 counters、window 秒数和吞吐。事件类型仍为 `native_controller`，事件名为 `measurement`。

### 7.1 测量实现校正

首次 v2 分析发现 `Window::clear()` 漏清 `accepted_bytes`，导致 accepted 在事件中跨窗口累加；这会把“窗口接收量”误读成累计量。已修复，并增加 native smoke 检查：

- fixed diagnostics 只产生观测，不改变 `active_limit`；
- 连续两个窗口的 accepted/written/jobs/files 都是窗口增量；
- 每个 measurement 事件同时保留真实 pending 和累计计数器。

修复后的 v3 trace 中，所有 workload/N 的累计账本残差均为 0：

```text
counter_accepted - counter_written - discarded - writer_pending = 0
```

这说明当前这批数据的 writer 账本是闭合的；此前 v2 的异常主要是观测窗口清零 bug，而不是可以直接归因给压缩器吞吐的“巨大积压”。

### 7.2 v3 native exact-window 结果

CPU 使用 N=2/3/4/5/8，IO 使用 N=2/4/6/8，每点 768 个 64 MiB job、单次 oracle、窗口目标约 0.25–1.5 秒。所有 9 个配置均 `all_passed=true`。下表的吞吐是 measurement window 的中位数，噪声列是相邻窗口 `|Δlog(T)|` 的 p95，pending 是真实 writer pending 的 p95。

| workload | N | windows | median T (MiB/s) | `|Δlog T|` p95 | pending p95 (MiB) |
|---|---:|---:|---:|---:|---:|
| CPU | 2 | 187 | 735.5 | 0.284 | 3.7 |
| CPU | 3 | 118 | 1142.7 | 0.233 | 8.9 |
| CPU | 4 | 80 | 1587.7 | 0.186 | 4.2 |
| CPU | 5 | 69 | 1980.7 | 0.407 | 30.8 |
| CPU | 8 | 66 | 2123.2 | 0.257 | 56.0 |
| IO | 2 | 155 | 981.1 | 1.003 | 2.7 |
| IO | 4 | 122 | 1039.6 | 1.046 | 17.9 |
| IO | 6 | 133 | 981.4 | 0.743 | 30.0 |
| IO | 8 | 141 | 941.0 | 0.776 | 51.5 |

吞吐量随时间图：

- [CPU exact-window throughput](../../benchmarks/results/controller_native_measurement_plots_v3/cpu-throughput-vs-time.png)
- [IO exact-window throughput](../../benchmarks/results/controller_native_measurement_plots_v3/io-throughput-vs-time.png)

图中 CPU 的初始窗口存在明显瞬态，随后 N=5/N=8 大致进入 2.0–2.1 GiB/s 区间；N=8 的 pending 长时间接近 64 MiB 上限，说明提高并发主要换来更大的写入队列，而不是稳定的窗口吞吐增益。IO 在所有并发下都呈强烈突发，N=4 的单次总吞吐最高，但窗口 p95 的相邻 log 变化仍约为 1.046，约等于一个窗口内出现 2.85 倍量级的跳变，不能作为当前 controller 的平稳反馈信号。

本轮总 wall-time oracle 的单次 sweep 结果是 CPU 最高点 N=8、IO 最高点 N=4；CPU N=2–N=8 的总吞吐从约 838 增至 2226 MiB/s，主机状态漂移明显，因此这只是本机单次 sweep 估计，不足以修改默认 active limit。IO N=4 约 1184 MiB/s，高于 N=6/N=8，但同样需要重复批次确认。

### 7.3 当前结论

这一轮把问题进一步收敛为：

1. native exact-window measurement、真实 pending 和累计账本已经可以同时观测，且账本闭合；
2. CPU 的主要不确定性是起始瞬态、主机漂移和高并发 pending 增长；
3. IO 的主要问题是窗口级 burst/noise，而不是 controller 探索动作本身；
4. 以当前 3% improvement/regression 比例直接做严格因果判断仍不成立，尤其不能把 IO 的单窗口跃迁判成环境变化或候选优劣。

因此下一步仍不调控制参数。应先在固定并发下重复多个较长 stable/noise 批次，分别报告 median/MAD、p95/p99、lag-1 autocorrelation、pending 分布和主机温度/频率；之后再用事件同步的 step-change 重新估计 false-positive、ARL0 和 detection delay。

本轮追加结果：

- [CPU v3 report](../../benchmarks/results/controller_native_measurement_cpu_v3.json)
- [IO v3 report](../../benchmarks/results/controller_native_measurement_io_v3.json)
- [v3 event-level analysis](../../benchmarks/results/controller_native_measurement_analysis_v3.json)
