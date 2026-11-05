# 文件静默算法基准协议

研究依据见 [RESEARCH.md](RESEARCH.md)。[初始基线](BASELINE.md)固定了优化前的生产算法；[时间衰减 P90 实验](TIME_DECAY.md)记录后续候选及其配对比较。

## 运行与工件

使用项目 `.venv` 和现有 benchmark workspace/report envelope；不添加依赖。注册在 `scheduling` 组，离线回放不需要安装 Watch Broker。

```powershell
# 完整基线：3 个独立划分，每划分 16 个 seed；全部通道、并发及两种同刻次序
uv run --no-sync python -m benchmarks scheduling watch-quiet-window --pin-report benchmarks/quiet_window/baseline.json

# 开发期间只使用 development；确定算法及参数后再查看 validation
uv run --no-sync python -m benchmarks scheduling watch-quiet-window --splits development

# 基线目录中保存的原始轨迹用于后续严格配对；不要重新造不同样本后比较均值
uv run --no-sync python -m benchmarks scheduling watch-quiet-window --corpus <baseline-dir>/traces.jsonl.gz --compare benchmarks/quiet_window/baseline.json

# 单独测量 tracker 成本：7 个新进程内交替顺序配对，内存分开测量
uv run --no-sync python -m benchmarks scheduling watch-quiet-cost --baseline-source <baseline-dir>/quiet_policy.py.txt --pin-report benchmarks/quiet_window/time_decay_cost.json
```

每次运行保留 `traces.jsonl.gz`、`outcomes.jsonl.gz`、`report.json`、生产 `quiet_policy.py.txt`、生成器/评估器源码快照、工作树 diff。gzip 固定头部，无文件名/时间污染；XXH128 仅用于识别完全相同的语料和源码，不对解压输出计算安全摘要。`--pin-report` 只固定报告，不悄悄覆盖原始轨迹。原始工件保存在 `benchmarks/results/`，须连同报告归档；仅复制 compact report 不能替代原始实验材料。

## 任务、真值与观察

1. `FileTruth` 是写入者/评估器侧数据，包含物理 mutation、可见时间、内容完成时间、占用区间、档案组及输入形态。`complete_at=null` 表示取消或尚未完成，绝不从 EOF 推断结束。
2. `Observation` 是估计器唯一可见输入：观察时间、文件 key、观察后的 size/mtime/USN、已分类的内容变化及是否学习该间隔。不传入完成时间、未来写入、负载类别、输入形态或 seed。语义分类已在本任务边界之前完成；本基准不测 USN 内容变化分类器。
3. 延迟通知在 **送达时** 取当前快照，批内合并相同快照；不把旧 write 快照伪装成当前 stat。元数据变更可推进 mtime/USN，但不构造内容间隔。
4. 每次真实观测到内容变化，替换该文件的 deadline；metadata/duplicate 不重置它。deadline 触发后只提案一次，直到新的内容代际重新激活。使用事件堆及虚拟时间，无空闲轮询、真实 sleep 或失败次数上限。
5. 默认分别执行 observation-first 和 timer-first。同一时刻谁先发生影响边界分数，两种次序分层保留。
   预算指标采用整数纳秒、包含右端点的比较，避免浮点时间相减把恰好 500ms 错判为超时。该量化只用于预算计分，不修改估计器输入或 deadline。
6. 各 trace 有明确 recording horizon：本合成语料最后物理活动/可用时间之后 3600 秒。它是观察区间，**不是静默窗口上限或生产超时**。超过区间的提案是删失，不按成功处理，也不强制窗口缩短；`infinity` 等永不提案策略同样不能靠缺失延迟获得好成绩。

### 估计器与系统边界

调用现有 `AdaptiveQuietTracker`，没有复制其实现。每文件一个估计器，在 trace 内保留历史，trace 结束释放。该生命周期用于隔离估计器能力，**不等同于生产 pipeline 完成后 tracker 退休、保留 quiet 标量、丢弃区间历史的生命周期**。后续优化必须额外在既有真实 Watch 基准中确认退休/恢复行为。

这里记录的是稳定性**提案**，不是 pipeline 成功或一定会被 WatchScheduler 放行。没有实现第二套 `_pop_ready`、OS probe、边界确认轮询、WAL、任务占用和密码探测。`busy_proposals` 表示原生就绪检查可能挡下的提案；不会把这些提案当成真实解压已经发生。`censored_usable_rate` 记录提案未达到可见且可读状态的比例，但不模拟占用解除后的调度重试。

伪装、嵌套、密码候选、完整/缺失分卷及载体是 ground-truth 场景标签，估计器看不到它们。档案组在成员未完成、不可用或缺卷时产生的提案另记为 `early_group_proposals`，**不把一个已稳定的分卷判作稳定算法出错**。不在 Python 层分析或模拟压缩格式、嵌套解压及密码正确性。真实五类输入及 CLI/Watch 的完整链路继续复用现有 format/arrival/split 基准，不能凭标签覆盖宣称端到端已验证。

## 覆盖矩阵

| 维度 | 覆盖 |
|---|---|
| 到达/生命周期 | 原子到达、初始已有、临时名完成后到达、直接复制、空文件后写、替换、取消、未结束 |
| 节奏 | 快/中/慢恒定、均匀抖动、指数、对数正态、Pareto 尾、相关停顿、突发、周期 flush、加/减速、交替速率、30–300 秒暂停、1–2 小时恢复 |
| 写入操作 | 追加、关闭重开、共享句柄、内容完成后独占占用、预分配、分段/随机范围、多写入者、同 size/mtime、截断重写、旧时间戳恢复、元数据尾流 |
| 观察通道 | 即时；250ms 批处理+20ms 交付；重复/元数据噪声；丢部分通知但终态恢复观察；丢终态通知且没有恢复 |
| 并发 | 1；快写、突发、随机范围及元数据尾流额外覆盖 8/64 个交错文件，独立随机流。是估计器状态隔离/输入交错，不是实测 OS 调度吞吐 |
| 形态 | disguised、nested、encrypted_candidates、split_complete、split_missing、carrier；同一档案组形态一致，跨 seed 轮换 |

采用有说明的部分因子设计：静默估计器不看格式，重复所有格式 × 写入 × 并发会重复大量等价输入。并发选取四个代表性节奏，正常化后每个 family 权重相等。字节偏移/写入者编号在物理真值中保留；估计器不读取它们。真正的稀疏填洞、mmap、文件系统缓存/磁盘争用应由 native/真实轨迹补充，不把虚拟 offset 当性能测量。

## 对照与指标

当前生产 `adaptive`；零等待及 0.05/0.5/2/10/180 秒固定等待；独立的 EWMA 间隔+波动控制。固定等待只在 benchmark 内存在，不恢复已移除的生产配置。2 秒对照不是完整 Chokidar。未实现的 φ、贝叶斯和变点算法不冒充已经评估。

| 指标 | 分母/解释 |
|---|---|
| `false_ready_file_rate` | 所有文件中至少有一次内容完成前提案的比例；必须同时看 completed/incomplete family，不能解释为真实损坏率 |
| `premature_proposals_per_file` | 过早提案次数/文件；避免一次误判与上百次无效处理等价 |
| `premature_exposure_seconds_per_file` | 过早提案至下一真实写入/完成/观察结束的持续时间之和；每次提案解除激活，区间不重叠 |
| `censored_complete_rate` | 已知完成文件中，观察结束前没有完成后提案的比例 |
| `mean_detection_latency_seconds` | 仅对检出的已完成文件计算；相对内容完成时间，不能脱离删失率单独排名 |
| `within_50ms/500ms/2s/10s/60s` | 全部已完成文件中，预算内检出的比例；未检出留在分母，避免“永不触发”作弊 |
| `busy_proposals_per_file` | 提案时仍不可读的次数/文件，作为与 native 就绪保护衔接的诊断 |
| `early_group_proposals_per_file` | 档案组尚不可用时的提案次数/文件；分卷/组层诊断，不是文件静默错误 |

逐文件结果还保留提案时间及条件延迟；不能取各 case 的 p95 再宣称它是总体 p95。compact report 使用明确定义的 macro mean，原始 outcomes 足以重算需要的分布。

每个 seed 内先平均同一 family 的通道、并发和同刻次序，再等权平均 family；不会让 64 文件和噪声回调压倒其他场景。报告按划分、family、channel、width、tie order 展示，后四者是诊断分层，不能与 family-balanced 总体权重混淆。默认 16 个独立 seed block，2000 次 block bootstrap 得到 95% 区间；这是生成模型下的样本不确定性，不包括真实应用分布误设、机器差异或代码错误。16 个 seed 不能证明罕见故障概率足够低；同质数据得到零宽区间也不能证明零风险。

配对比较要求 corpus XXH128、评估器源码身份、合同、计分语义和同刻次序相同；对同 split/seed 的 adaptive macro 值先作差，再对差值重采样。风险、次数、删失和延迟越低越好，预算内检出比例越高越好。条件均值的检出集合可能变化，优先同时检查无条件预算指标。没有偷偷选一个综合分数掩盖安全/延迟取舍。

`replay_cpu_ns` 含 Python 回放堆、打分及估计器，轮转算法次序以减少顺序偏差；不是纯算法 CPU 成本，也不是 Windows 实测吞吐。`peak_live_estimators` 是对象数量，不是内存字节。本文不给单次进程计时附上虚假的机器性能置信区间；后续若优化 CPU/内存，应另做多进程重复资源测量。

`cost.py` 单独调用实际 tracker（含构造和 `observe`），输入为 development seed 0、全部 family、immediate 通道、width 1。每个新进程内先预热，再交替基线/候选顺序；计时不含生成、JSON 和磁盘 IO，报告进程 CPU 时间及配对比值范围，不把这个范围当置信区间。此工作负载约 76% 是内容观察，其余为元数据；不是全内容事件吞吐上限。另用共享 policy 的 4096 个活跃 tracker 填满历史，通过 tracemalloc 测量每对象存活分配和释放后残留；它不是进程 RSS 或调度器总内存，单批释放检查也不构成长时间无泄漏证明。原始源码及各进程结果随报告归档。

## 后续研究规则

- development 用于开发，validation 用于选择参数；heldout 只用于预先固定候选的最后一次比较。基线公布 heldout 是为了固定起点，不允许据其逐 family 结果反复调参再自称盲测。新增应用轨迹按应用/会话划分，不随机打散同一文件的事件。
- 每个优化在同一冻结语料上与基线配对；不得删掉难例、减少并发、调高容许失败次数或修改真值使算法过关。协议/计分变更须新建 contract 并重跑两边，不能混比。
- 不新增“测试 benchmark 是否能运行”的 pytest。语料读入检查只保护研究输入的有效性。这里实际执行的是完整实验，不是把 benchmark 包装为正确性测试。
- 初始基线没有改变生产调度算法；后续候选继续复用同一调度和 Rust 归档分析/密码探测链路。研究结果不能直接推出线上默认值，应再在已有真实 NTFS、格式、分卷、CLI/Watch 链路复核。
