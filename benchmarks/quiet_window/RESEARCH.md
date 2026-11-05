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
