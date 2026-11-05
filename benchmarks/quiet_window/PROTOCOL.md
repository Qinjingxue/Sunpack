# 复杂写入者静默基准

本基准研究文件完整到达后的处理启动延迟。写入者实现及一手来源见 [WRITERS.md](WRITERS.md)，相关论文与公开基准调查见 [RESEARCH.md](RESEARCH.md)。主语料由 28 种复合写入程序组成；不再生成纯恒定/随机间隔、随机格式标签等旧语料。旧生成代码、兼容分支、固定报告、原始轨迹及工作目录已删除。

## 优化目标

1. 已完整到达但没有有效提案的输入数必须为零。报告同时给出绝对数量和 `censored_valid_proposal_rate`，不能用低平均延迟抵消漏提案。
2. 核心指标 `mean_complete_arrival_to_valid_proposal_seconds`：从内容完整且目标路径可见，到首次完整、可读、齐卷的有效提案。句柄导致的等待包含在延迟中；未有效提案不记零，也不混入条件平均值。另看 50ms/500ms/2s/10s/60s 预算命中率，未提案保留在分母。
3. `invalid_proposals_per_file` 为第二指标。在主回放中名字里的 file 指逻辑输入：单文件一个，四个分卷合计一个。每次无效提案只计一次；不重复累加内容未齐、占用和缺卷诊断。优化不能靠显著增加无效尝试换延迟，必须同时报告每族的尝试变化和资源成本，不把两项加权成可以掩盖漏处理的总分。

取消和暂停保留三个未填范围，`complete_at=null`。这两个负例检查算法是否在没有新内容时不断重复尝试；没有完整到达，所以不进入主延迟和漏提案分母。它们不代表“末次通知随机丢失”。

## 真值与观察

`writers.py` 生成有时间戳的 `WriterAction`：范围写入、错误块、预分配、截断、替换、已有块、句柄打开/关闭、校验、侧车 checkpoint、缓存接收、flush 和发布 rename。它通过有序区间并集/差集维护正确目标字节的覆盖；不分配文件内容，不计算内容 hash，不解析压缩包。

- `expected_size` 是写入者已知的最终目标长度。预分配只改变 EOF，不增加正确字节。重试重叠部分只算一次；错误块保持无效，直到实际修复写入。
- `complete_at` 从正确范围覆盖及精确目标长度推导。不是最后一个事件、最后一次 close、最后一次 flush 或轨迹 EOF。最后 32 字节头部回填前，即便 EOF 已正确也仍未完成；内容写齐后的同内容重传、恢复 mtime、共享句柄关闭不会推迟内容完成。
- `visible_at` 是目标路径发布时刻。发布程序选择监控范围外暂存：临时文件写入只在写入者侧出现，rename 后才向目标路径交付观察，不伪造临时文件对最终路径的写通知。不假设 SunPack 自动忽略任意 `.tmp`/`.partial` 后缀；监控范围内临时路径迁移继续由现有真实 arrival-matrix/temporary_rename 场景验证。
- `blocked` 是禁止读访问的句柄区间并集。共享读句柄不阻塞；关闭重开可以在中间出现可读窗口；多个不兼容句柄必须全部释放。
- 分卷只在三个真实多成员程序中出现，每组四个文件，有实际错峰/并行/落后成员。评分以整组完整可见为起点，以任意成员首次有效提案为终点。

估计器只能看到 `Observation`：观察时间、key、当时的 size/mtime/USN、已分类的内容变化、是否学习间隔。没有范围覆盖、目标长度、完成标记、未来写入、writer 类型、seed、句柄关闭标记或分卷完成 oracle。生产调度器另外使用真实链路已有的元数据探测和可读性探测接口。

物理变化与通知送达分离。所有延迟通知在送达时读取当前物理快照；同一内容版本的重复通知不会被误算成多个内容间隔。mtime 恢复是物理元数据变化，推进 USN 但不推进内容版本。侧车 checkpoint、只读校验和网络收包不直接伪装成目标内容变化。目标 close 可以交付重复观察，但不构造新内容。

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

轨迹合同 `sunpack.writer-behaviour/1`，估计器计分合同 `sunpack.quiet-window/4`，生产入场回放合同 `sunpack.quiet-scheduler/2`。不读取旧合同，也不保留历史重评分兼容入口。

复用 benchmark workspace/report envelope。每次实验保存 canonical gzip 轨迹、完整提案时间线、报告、冻结策略、生成器/评估器/相关生产源码。直接冻结当前源码，不把已经删除的数据通过 git diff 再存进工件。使用现有 Rust xxh128 标识语料和源码；指纹仅用于复现身份，不校验文件内容。两边语料和评估器不一致时拒绝配对。

报告分别记录回放 CPU、观测数、峰值 tracker 数、元数据和可读性 probe 数。JSON、生成与 gzip 不计入回放 CPU。`scheduling watch-quiet-cost --baseline-source ...` 在新进程中以相同复杂语料单独测 tracker CPU/有界历史分配，避免把虚拟 FS 和报告开销归给算法。

## 适用边界

这是有来源的合成行为模型，不是实际客户端抓取的轨迹，也不是完整 Watch 服务/解压测量。它不模拟 OS 缓存持久性、设备排队、真实 CPU/磁盘竞争、解压时长、密码探测、group blocker 的完整反馈、USN checkpoint/维护恢复或源占用声明。真实的五类档案输入、Watch/CLI 和并发解压继续使用项目现有原生/端到端场景；本基准没有用格式标签扩充无意义的笛卡尔积。

映射页与云占位符只覆盖“已分类、可观察的范围可见性”投影；不承诺每次 mapped store 都立即生成 Windows USN/目录通知，也不模拟读取触发的自动 hydration。缓存 flush 表示写入者阶段，内容到达按对读者可见的写入计算，不能等同于断电持久性。

生产零等待且文件仍不可读时，虚拟时间可能不前进。回放仅将状态不变的重复 busy probe 合并，等待同一文件下一物理变化、通知或句柄释放后继续调用真实 `_pop_ready`，并记录 `coalesced_zero_delay_busy_checks`。无关文件通知不反复唤醒它，避免适配层成本随交错文件数放大。因此它不能测这种自旋的真实 CPU/probe 次数；没有引入空闲轮询、生产额外等待或失败次数上限。

小规模 development 回放只用于观察新行为下的算法表现，不作为正式基线或验证集结论。当前没有固定的新全量性能报告；不能沿用已删除旧语料的数字。
