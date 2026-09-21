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

