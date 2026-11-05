# 复杂写入者静默基准

本基准研究文件完整、可见、齐卷且句柄已允许处理后的启动延迟。写入者实现及一手来源见 [WRITERS.md](WRITERS.md)，相关论文与公开基准调查见 [RESEARCH.md](RESEARCH.md)。主语料由 28 种复合写入程序组成；不再生成纯恒定/随机间隔、随机格式标签等旧语料。旧生成代码、兼容分支、固定报告、原始轨迹及工作目录已删除。

## 优化目标

1. 已完整到达但没有有效提案的输入数必须为零。报告同时给出绝对数量和 `censored_valid_proposal_rate`，不能用低平均延迟抵消漏提案。
2. 核心指标 `mean_ready_to_valid_proposal_seconds`：从内容完整、目标路径可见、分卷齐备且句柄已允许处理的首个时刻，到首次有效提案。不兼容句柄尚未释放的等待在计时起点之前，不计入延迟；未有效提案不记零，也不混入条件平均值。另看严格 `<100ms` 的 `valid_under_100ms`，以及 50ms/500ms/2s/10s/60s 预算命中率，未提案保留在分母。
3. 第二指标为整条写入者轨迹中任意 100ms、1s、10s 滑动窗口内的最大无效提案数。先对每个逻辑输入求峰值，再报告均值、每条 trace 内 P95 和最大值；另将同一并发 trace 的全部逻辑输入合并求峰值。报告保留全局、每族、每并发宽度的实际最坏峰值。窗口采用纳秒精度的半开区间 `[start,start+span)`，没有固定分桶边界；同时发生的多次提案分别计数。单文件一个逻辑输入，四个分卷合计一个；合并的是提案时间线，不去重真实尝试。
4. `invalid_proposals_per_file` 降为诊断，不用于搜索或验收；CPU、IO 和在途工作量也不作为函数搜索或验收目标。旧资源字段仅供理解实验执行成本。首次有效提案延迟继续优先，峰值用于限制不可接受的短时错误尝试膨胀，不将这些指标加权成可以掩盖漏处理的总分。

`invalid_burst_<100ms|1s|10s>_per_input` 是每个逻辑输入峰值的均值；`p95_per_trace` 是 trace 内逻辑输入峰值的 P95；`input_max_per_trace` 是 trace 内最坏单输入峰值；`all_inputs` 是并发合计峰值。这些 trace 指标按原有分组规则汇总，因此跨 trace 的值可能为小数，不能把“trace 最大值的均值”解释为全实验的最坏值。报告的 `burst_worst` 单独取真实最大值，按全局、family、width 分层保留，不平均。取消/暂停等没有完成的负例也参与全部峰值统计。

取消和暂停保留三个未填范围，`complete_at=null`。这两个负例检查算法是否在没有新内容时不断重复尝试；没有完整到达，所以不进入主延迟和漏提案分母。它们不代表“末次通知随机丢失”。

## 真值与观察

`writers.py` 生成有时间戳的 `WriterAction`：范围写入、错误块、预分配、截断、替换、已有块、句柄打开/关闭、校验、侧车 checkpoint、缓存接收、flush 和发布 rename。它通过有序区间并集/差集维护正确目标字节的覆盖；不分配文件内容，不计算内容 hash，不解析压缩包。

- `expected_size` 是写入者已知的最终目标长度。预分配只改变 EOF，不增加正确字节。重试重叠部分只算一次；错误块保持无效，直到实际修复写入。
- `complete_at` 从正确范围覆盖及精确目标长度推导。不是最后一个事件、最后一次 close、最后一次 flush 或轨迹 EOF。主指标另由 `processing_ready_at` 将可读性与齐卷条件合入计时起点。最后 32 字节头部回填前，即便 EOF 已正确也仍未完成；内容写齐后的同内容重传、恢复 mtime、共享句柄关闭不会推迟内容完成。
- `visible_at` 是目标路径发布时刻。发布程序选择监控范围外暂存：临时文件写入只在写入者侧出现，rename 后才向目标路径交付观察，不伪造临时文件对最终路径的写通知。不假设 SunPack 自动忽略任意 `.tmp`/`.partial` 后缀；监控范围内临时路径迁移继续由现有真实 arrival-matrix/temporary_rename 场景验证。
- `blocked` 是无法通过生产 readiness 门控的句柄区间并集。每个 open 明确记录 READ/WRITE/DELETE access 和 share。生产请求 READ、仅分享 READ，因此仍开的 WRITE/DELETE access 即便允许共享读也会阻塞；只读且允许分享 READ 的句柄不阻塞。关闭重开可以在中间出现可处理窗口；多个不兼容句柄必须全部释放。
- 分卷只在三个真实多成员程序中出现，每组四个文件，有实际错峰/并行/落后成员。评分以整组完整可见且全部可读为起点，以任意成员首次有效提案为终点。

估计器只能看到 `Observation`：观察时间、key、当时的 size/mtime/USN、已分类的内容变化、是否学习间隔、已见 journal CLOSE 阶段边界。没有范围覆盖、目标长度、完成标记、未来写入、writer 类型、seed、真实句柄存活表或分卷完成 oracle。生产调度器另外使用真实链路已有的元数据探测和可读性探测接口。

物理变化与通知送达分离。所有延迟通知在送达时读取当前物理快照；同一内容版本的重复通知不会被误算成多个内容间隔。mtime 恢复是物理元数据变化，推进 USN 但不推进内容版本。侧车 checkpoint、只读校验和网络收包不直接伪装成目标内容变化。目标 close 不构造新内容。写入者侧跟踪全部句柄，最后一个句柄关闭时产生含本阶段累计原因的 journal CLOSE；留存只读句柄可以令文件先 ready、后 CLOSE。观察中的 phase_boundary 从自上次已见 USN 起的 CLOSE 记录推导，重复交付不会重复产生边界。EXTEND/OVERWRITE/TRUNCATION 分别保留，CLOSE 的累计原因不重复当作新内容。真实 NTFS 对同类数据变更还可进一步合并，因此这些仍是声明的可观察行为投影。

全部程序平衡 open/close，包括取消、暂停、重连和最终写句柄释放；仍有字节洞时 close 不会令内容完整。每文件在生成完整写入程序后独立抽取一个 flush 模式：逐写 flush 或保留未 flush 的目录变更，不改变网络/写入时序；这是覆盖设计，不是客户端占比估计。逐写 flush 可以使 close 时没有新的目录回调；不再给每个 close 自动追加通知。`Observation.source` 区分 directory/reconcile；arrival 交付 created 或 moved，其余变化交付 modified。当前生产没有 USN CLOSE 主动订阅，本语料也不伪造该来源。

真实 Windows 锚点入口为 `uv run --no-sync python -m benchmarks watch quiet-calibrate --repeats 3`。复用隔离 Watch Broker 服务和生产 Observer，验证 56 种 access/share 组合，以及未 flush、flush、只读句柄留存、两个写句柄四类生命周期。具体结果与局限见 [LIFECYCLE_RESULTS.md](LIFECYCLE_RESULTS.md)。

## 运行入口

主入口 `scheduling watch-quiet-scheduler` 使用已有生产 `WatchScheduler.enqueue`、deadline 堆、`_pop_ready`、边界确认、Rust 内存状态及 tracker 退休，替换元数据 IO、可读性和时钟。Pipeline 时长为零，完成后执行生产状态完成/退休。没有新增第二套调度算法。

辅助入口 `scheduling watch-quiet-window` 在同一语料上隔离估计器：每个观测内容版本提案一次，内容变化后重新激活，历史一直保留到 trace 结束。其生命周期不同于生产退休，只用于解释估计器行为，不能作为真实漏处理率。

```powershell
# development 小规模：全部复杂行为、即时通道、单文件或四卷
uv run --no-sync python -m benchmarks scheduling watch-quiet-scheduler --seeds 2 --splits development --channels immediate --widths 1,4

# 针对多连接尾部拖慢、断点恢复与重叠重试研究
uv run --no-sync python -m benchmarks scheduling watch-quiet-scheduler --splits development --families segmented_straggler,segmented_resume,segmented_retry_overlap

# 需要正式测量时显式执行：三个划分、16 seeds、四通道、部分因子并发设计
uv run --no-sync python -m benchmarks scheduling watch-quiet-scheduler --pin-report benchmarks/quiet_window/current.json

# 策略比较：冻结源码，并在同一导出语料上执行；不得混用旧语料/评估器
uv run --no-sync python -m benchmarks scheduling watch-quiet-scheduler --policy-source C:/experiment/before.py --pin-report C:/experiment/before.json
uv run --no-sync python -m benchmarks scheduling watch-quiet-scheduler --corpus C:/experiment/traces.jsonl.gz --compare C:/experiment/before.json
```

`--families`、`--splits`、`--channels`、`--widths`、`--tie-orders` 可缩小研究范围。生成和导入都执行相同选择；比较时必须保持相同语料及评估身份。策略比较前冻结语料和算法，开发看 development，确定后看 validation，heldout 只作最终验证，不能看完再调参。

## 观察通道与实验设计

| 维度 | 设计及目的 |
|---|---|
| immediate | 及时交付目标路径通知 |
| batched | 250ms 批次，额外 20ms 交付；写入快照在交付时取值 |
| noisy | 每条观察附近增加八条重复观察，内容版本保持不变 |
| lossy_reconciled | 合并部分中间通知，保留末次目标变化，并在最后物理变化/发布后 1s 补终态观察；不模拟无信号终态丢失 |
| width | 普通程序基准宽度 1；分卷程序基准宽度 4；代表性跨文件竞争程序额外 8/64 |
| 并发代表 | segmented_straggler、cached_piece_writeback、sync_reused_blocks、close_reopen_batches、multipart_parallel |
| 同刻次序 | observation-first、timer-first 均保留；物理快照在该时刻已生效，次序表示通知送达与 timer 的竞争 |
| 独立重复 | development/validation/heldout 各 16 个 seed；按 seed block 重采样，而非把通知当独立重复 |

完整默认设计为 7,296 traces、76,224 个物理文件；这是设计计数，尚未执行整套实验。每个 split/seed/channel 有 38 traces、397 个物理文件。先在每族内等权平均通道/宽度/同刻次序，再对 writer family 等权平均；不会让 64 文件或通知风暴支配分数。报告保留 family/channel/width/tie 分层及种子置信区间。

每条 trace 的观察区间是最后写入者活动/目标可见/句柄释放后 3600s。这是实验记录终点，不是生产静默时间上限；超出它的 deadline 记删失，不强行缩短等待。

## 工件与资源

轨迹合同 `sunpack.writer-behaviour/3`，估计器计分合同 `sunpack.quiet-window/7`，生产入场回放合同 `sunpack.quiet-scheduler/5`。旧摘要不直接比较；双方在同一评估器上重放。已保存的完整提案时间线可以按明确的新统计定义重新计分，不重建提案、不混用旧摘要。

复用 benchmark workspace/report envelope。每次实验保存 canonical gzip 轨迹、完整提案时间线、报告、冻结策略、生成器/评估器/相关生产源码。直接冻结当前源码，不把已经删除的数据通过 git diff 再存进工件。使用现有 Rust xxh128 标识语料和源码；指纹仅用于复现身份，不校验文件内容。两边语料和评估器不一致时拒绝配对。

报告分别记录回放 CPU、观测数、峰值 tracker 数、元数据和可读性 probe 数。JSON、生成与 gzip 不计入回放 CPU。`scheduling watch-quiet-cost --baseline-source ...` 在新进程中以相同复杂语料单独测 tracker CPU/有界历史分配，避免把虚拟 FS 和报告开销归给算法。

## 适用边界

这是有来源的合成行为模型，不是实际客户端抓取的轨迹，也不是完整 Watch 服务/解压测量。它不模拟 OS 缓存持久性、设备排队、真实 CPU/磁盘竞争、解压时长、密码探测、group blocker 的完整反馈、USN checkpoint/维护恢复或源占用声明。真实的五类档案输入、Watch/CLI 和并发解压继续使用项目现有原生/端到端场景；本基准没有用格式标签扩充无意义的笛卡尔积。

映射页与云占位符只覆盖“已分类、可观察的范围可见性”投影；不承诺每次 mapped store 都立即生成 Windows USN/目录通知，也不模拟读取触发的自动 hydration。缓存 flush 表示写入者阶段，内容到达按对读者可见的写入计算，不能等同于断电持久性。

不可读期间，回放将状态不变的重复 busy timer/probe 合并：正间隔按原重试周期解析推进，保留下一 deadline 的周期相位；零间隔合并无时间推进的自旋。同一文件物理变化、通知或句柄释放时继续调用真实 `_pop_ready`，记录 `coalesced_busy_timer_runs`。无关文件通知不会唤醒它。因此回放 CPU/probe 数不代表生产 busy 重试成本；生产没有新增轮询、等待或失败次数上限。对前版 608 条回放逐项比较提案时间，数量全部一致，最大浮点差 3.34e-13 秒。

阶段模型的配对实验使用三个划分各 8 个 seed；参数只依据 development 冻结。结果与适用边界见 [PHASE_RESULTS.md](PHASE_RESULTS.md)。这是默认 16 seeds 设计的一半；不能沿用已删除旧语料的数字，也不能把合成 heldout 解释为真实下载器的外部验证。

## 映射函数搜索

入口、冻结计划、搜索空间、峰值边界、筛选与独立审核流程见 [SEARCH.md](SEARCH.md)。搜索复用上述生产调度回放，不新增生产分析路径，不把完成真值交给策略，不将归档输入的实际处理成本引入目标。
