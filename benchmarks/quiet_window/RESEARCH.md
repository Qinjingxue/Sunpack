# 静默估计的研究依据

调查日期：2026-11-04 至 2026-11-05。查阅范围包括文件完成检测、文件系统通知、超时/故障检测、存储工作负载及实验统计；实际写入者的逐项来源和映射见 [WRITERS.md](WRITERS.md)。

在此次查阅的作者论文、官方文档和源码中，未找到同时提供“写入者目标完成真值、Windows 观察轨迹、暂停/恢复/取消、完整到达至有效处理启动延迟”的公开标准数据集。这是有范围的检索结论，不是不存在此类数据的证明。因此本项目使用公开机制驱动的合成 writer programs，不把存储吞吐轨迹冒充完成检测基准。

| 一手来源 | 本基准采用的研究约束 |
|---|---|
| Chen、Toueg、Aguilera，*On the Quality of Service of Failure Detectors*，[作者论文目录](https://www.cs.cornell.edu/info/people/sam/FDpapers.html) | 检测速度和错误怀疑同时报告；本任务按用户目标把完整输入零漏提案置于首位，其次延迟，再看无效尝试 |
| Hayashibara 等，2004，*The φ Accrual Failure Detector*，[JAIST 论文](https://dspace.jaist.ac.jp/dspace/bitstream/10119/4784/1/IS-RR-2004-010.pdf) | 同一带真值轨迹比较不同等待策略；不把心跳数据当文件写入分布 |
| Paxson 等，2011，[RFC 6298](https://www.rfc-editor.org/rfc/rfc6298.html) | 保留 SRTT+4×RTTVAR 启发的独立诊断对照，去掉 TCP floor/backoff，因此不声称 RFC 合规 |
| Adams、MacKay，2007，*Bayesian Online Changepoint Detection*，[论文](https://arxiv.org/abs/0710.3742) | 在真实机制组合中表达速率突变、恢复和末尾拖慢，不再靠新增纯随机间隔族凑覆盖 |
| Roselli、Lorch、Anderson，2000，*A Comparison of File System Workloads*，[USENIX](https://www.usenix.org/conference/2000-usenix-annual-technical-conference/comparison-file-system-workloads) | 文件写入不只有追加，还包括覆盖、范围局部性和映射访问；研究对象不能只有 size 增长 |
| Tarasov、Zadok、Shepler，2016，*Filebench: A Flexible Framework for File System Benchmarking*，[USENIX](https://www.usenix.org/publications/login/spring2016/tarasov)、[源码](https://github.com/filebench/filebench) | 用可组合的操作、writer 和时间线建模；复用本项目回放，不引入额外依赖 |
| Kalibera、Jones，2013，*Rigorous Benchmarking in Reasonable Time*，[作者稿](https://kar.kent.ac.uk/33611/) | 独立 seed block、配对和置信区间；同一轨迹中的通知不是独立样本 |
| Microsoft，[Change Journal Records](https://learn.microsoft.com/en-us/windows/win32/fileio/change-journal-records)、[ReadDirectoryChangesW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-readdirectorychangesw) | 物理变化与交付快照分离，不假定一次 write 对应一条通知；本任务不加入随机、无信号的终态通知消失 |

仅凭已经观察到的静默，无法证明未来不会恢复写入；完全相同的历史可以接结束，也可以接一小时后的重试。基准评估有限行为覆盖下的延迟和错误尝试，不承诺任意写入者下零误判。

当前所有时长、块数、速率、暂停、坏块比例和并发数均为声明的 stress 参数，没有声称来自客户端实测拟合。按机制系统覆盖能够发现纯间隔模型漏掉的问题，但不能保证涵盖所有软件、版本和环境。真实外部验证仍需带 writer 完成标记的 Windows 轨迹，按客户端/机器/会话划分数据；增加合成 seed 不能替代该证据。


## 2026-11-05：暂停与写入阶段的识别

本次结论是采样语义问题优先于替换分位数模型。最新的长间隔既可能是低频写入，也可能夹着暂停；给它更高时间权重，会立即污染正常写入频率。以下来源采用的思想相近，但本项目的模型与阈值是自己的工程假设，不声称是论文的复现。

| 来源 | 核心启发与采用边界 |
|---|---|
| Kleinberg，2002，[Bursty and Hierarchical Structure in Streams](https://ecommons.cornell.edu/entities/publication/04b75865-7103-4954-a660-ee6c38e5e9a5) | 将事件流分成速率状态，而非用一个分布解释所有间隔；原模型面向文档流，不能直接证明文件完成 |
| Adams、MacKay，2007，[BOCPD](https://arxiv.org/abs/0710.3742) | 维护新阶段与原阶段的竞争解释；完整 run-length 后验的计算与先验选择没有在当前 12 样本任务中得到优势证据，因此没有引入依赖或完整贝叶斯实现 |
| Akka，[PhiAccrualFailureDetector 源码](https://github.com/akka/akka-core/blob/main/akka-remote/src/main/scala/akka/remote/PhiAccrualFailureDetector.scala) | 恢复心跳若已被判为不可用，不把跨故障长间隔加入历史；SunPack 借鉴样本准入，不照搬固定心跳初值、宽限秒数和标准差下限 |
| Linux，[tcp_bbr.c](https://github.com/torvalds/linux/blob/master/net/ipv4/tcp_bbr.c) | application-limited 样本不能任意拉低网络能力估计；SunPack 没有 socket 的发送队列信号，不能直接照搬 app_limited 标签 |
| [RFC 6298 §3](https://www.rfc-editor.org/rfc/rfc6298.html#section-3) | Karn 算法排除计时含义不明确的样本；这里排除含暂停的候选间隔，不采用 TCP 的秒级下限、退避或重传机制 |
| [RFC 7661 §2](https://www.rfc-editor.org/rfc/rfc7661.html#section-2) | 实际区分 application-limited 与 idle 可能不可靠；相同事件历史允许不同未来，阶段判断须保留不确定性，不能声称完全识别写入者意图 |
| Microsoft，[Change Journal Records](https://learn.microsoft.com/en-us/windows/win32/fileio/change-journal-records) | USN 是卷日志位置，差值不是该文件写入次数；同类修改可合并，CLOSE 是自打开以来原因的汇总，不能把汇总 DATA 位当新写入 |

### SunPack 可用信息审计

| 可用信息 | 当前用途 / 实验结论 |
|---|---|
| 单调观察时间、12 个有效间隔 | 建立正常阶段时间尺度与加权 P90；正常间隔不改变原时间衰减模型 |
| 活跃/退休状态、上次内容时刻、已学窗口 | 摘要跨退休保留；直接丢弃跨退休间隔会丢掉低频写入的学习能力，错误尝试显著增加 |
| 已分类内容变化、USN 原因（含剔除 CLOSE 汇总后的原因） | 保留现有去重和元数据分类；不使用 USN 数值差当样本数量或字节量 |
| 新到达的 journal CLOSE | 独立阶段边界：断开跨句柄间隔、清空待确认间隔，保留已学正常频率；既不直接提案，也不宣称齐卷/完整/可读 |
| size 增长、覆盖、截断，file_id 替换 | EOF 不代表实际有效范围。只对同大小覆盖应用暂停过滤，会错过追加/组装暂停；截断和身份替换显式重置旧阶段 |
| mtime、恢复时间戳 | 不是可靠的写入时钟，映射写入可不更新，下载器可恢复服务器时间；仅沿用现有内容/元数据判别 |
| 可读性、元数据边界复核 | 沿用真实 admission guard，不增加提前打开文件、轮询或定时采样；边界探测间隔不用于训练频率 |
| rename、源占用、分卷发现、密码失败与缺卷反馈 | 保留既有 Watch/原生分析链路；这些状态不是通用的写入频率标签，也不在 Python 重做档案分析 |
| 目标总长度、正确字节覆盖、writer 类型与 phase、未来 close 时刻 | 仅写入者真值/评分可见，算法不可使用 |

### 模型

保留最多 12 个 `(interval, observed_at)` 的加权 P90，以及原线性 + 对数等待映射。常驻摘要新增 `cadence_seconds` 和 `pending_interval_seconds` 两个 f64；前者是最近正常分布的有效间隔，后者是一条尚未被采纳的间隔。

- 未建立频率，或新间隔超过当前频率的 8 倍时，先隔离该间隔，等待窗口不增长。
- 如果下一条有效间隔与候选相差不超过 2 倍，承认新的频率阶段，清除旧分布，以这两个间隔重新建立分布。否则替换候选；如果恢复正常间隔，直接丢掉候选。
- 8 与 2 都是无量纲比率。确认过程不阻止提案，不是最小等待、最小收缩样本数或固定半衰期。
- 新的 CLOSE 记录断开间隔链；正常窗口保留。截断/替换重置旧文件阶段。边界检查得到的内容更新不形成定时间隔，并打断连续确认。
- 对暂存间隔不做周期性复查；只处理已有内容/元数据事件与既有 deadline，空闲期间没有新增工作。

### 开发消融与适用边界

初筛使用 development 8 seeds、28 个复杂写入者、4 个观察通道、普通宽度 1 / 分卷宽度 4、observation-first。先按 family/seed 聚合；这些是合成行为上的模型选择，不是外部客户端分布。

1. 旧估计器在该初筛语料产生 12 个完整但超期的输入。
2. 只过滤超出正常频率的间隔仍不能解决无历史、只观察到两批写入的组装场景；只做启动确认、关闭暂停过滤则仍有 7 个超期输入。
3. 确认 + 暂停过滤的 2/4/8 倍比率均为 0 超期；8 倍在平均延迟和错误尝试之间略好，随后冻结，不在 validation/heldout 调参。
4. 取消跨退休摘要使错误尝试约 35.95 次/输入；保留摘要约 4.97 次。摘要是必要状态，而非长期保留整段样本。
5. 将长间隔过滤限制为同大小写入，平均延迟从约 59.23 秒恶化为约 89.72 秒，说明 size 本身不足以分阶段。
6. 在新增 CLOSE 元数据投影后的同一新版语料上，活动 tracker 使用 CLOSE 提示使关闭重开族延迟从 62.2605 秒降至 0.1168 秒；总体从 58.3195 秒降至 55.9255 秒，错误尝试从 5.0893 增至 5.1228。常驻 catalog 也保存阶段结束事实，避免 tracker 已退休时漏掉这一信息。

以上初筛值采用当时的内容完整到达起点，仍包含独占句柄等待，仅用于记录开发选择依据。用户随后将主起点修订为完整、可见、齐卷且句柄允许处理；最终两策略在完全相同的既有提案时间线上统一重新评分，独占句柄等待全部在主指标起点之前，正式结果以该新定义为准。未获得任何可用历史、也没有明确阶段边界时，孤立慢写与暂停不可辨识，本模型选择先保证低提案延迟，代价是增加少量尝试。阶段确认也只是可检验的假设；不能保证任意真实写入者下完全正确。

最终配对结果、源码指纹、CPU/内存与验证范围见 PHASE_RESULTS.md。
