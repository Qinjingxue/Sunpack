# 文件稳定／静默估计：文献与公开基准调查

调查日期：2026-11-04。范围：文件写入结束判定、文件通知稳定化、在线超时估计、存储工作负载与实验统计。检索词包括 `file write completion detection benchmark`、`filesystem watcher quiescence`、`adaptive timeout failure detector`、`file system workload traces`。

在本次查阅的论文、作者仓库和项目文档中，**未找到直接提供“写入者结束真值 + Windows 通知轨迹 + 暂停/恢复/取消 + 稳定检测风险与延迟”这一完整任务的标准公开基准**。这是有范围的检索结论，不是不存在此类数据集的证明。下列来源可以借鉴，但不能当作本项目已有的外部验证集。没有下载、复制或重新分发论文中的数据。

| 一手来源 | 与任务的关系 | 本基准采用什么；不作什么推论 |
|---|---|---|
| Chen、Toueg、Aguilera，*On the Quality of Service of Failure Detectors*，[作者论文目录](https://www.cs.cornell.edu/info/people/sam/FDpapers.html) | 同时考虑检测速度与错误怀疑 | 同时报告延迟、误判次数和错误持续时间；网络节点存活不等于文件写入结束 |
| Hayashibara 等，2004，*The φ Accrual Failure Detector*，[JAIST 论文](https://dspace.jaist.ac.jp/dspace/bitstream/10119/4784/1/IS-RR-2004-010.pdf) | 用近期到达间隔估计怀疑程度，并呈现不同激进程度的取舍 | 用相同轨迹比较一组等待阈值；不声称本项目已有 φ 实现，也不把心跳轨迹当下载器写入分布 |
| Paxson 等，2011，[RFC 6298](https://www.rfc-editor.org/rfc/rfc6298.html) | 平滑间隔及波动的经典超时估计 | 加入 SRTT + 4×RTTVAR 启发的 EWMA 对照；明确去掉 TCP 的最小 RTO、重传及退避规则，因此不称作 RFC 合规实现 |
| Adams、MacKay，2007，*Bayesian Online Changepoint Detection*，[作者论文](https://arxiv.org/abs/0710.3742) | 在线估计分布突变 | 加速、减速、交替速率和相关停顿作为独立负载；这里只建立评估输入，没有预先选定后续优化算法 |
| Roselli、Lorch、Anderson，2000，*A Comparison of File System Workloads*，[USENIX](https://www.usenix.org/conference/2000-usenix-annual-technical-conference/comparison-file-system-workloads) | 跨环境文件系统轨迹，包含 NT；写入局部性、覆盖和映射访问 | 覆盖追加之外的原位写入、相同大小覆盖、写入突发；该论文的存储轨迹不是逐下载任务完成标签 |
| Tarasov、Zadok、Shepler，2016，*Filebench: A Flexible Framework for File System Benchmarking*，[USENIX](https://www.usenix.org/publications/login/spring2016/tarasov)、[官方实现](https://github.com/filebench/filebench) | 可组合的文件系统工作负载生成框架 | 借鉴分解写入操作、进程/线程和并发维度；未引入 Filebench 依赖，也不把 IO 吞吐基准当稳定检测准确率基准 |
| Kalibera、Jones，2013，*Rigorous Benchmarking in Reasonable Time*，[作者接受稿及更正版](https://kar.kent.ac.uk/33611/) | 强调实验重复层次及不确定性 | 以独立 seed block 重采样，并保留配对；不能把同一文件的数千次回调当数千个独立样本 |
| Microsoft，[Change Journal Records](https://learn.microsoft.com/en-us/windows/win32/fileio/change-journal-records)、[ReadDirectoryChangesW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-readdirectorychangesw) | USN 理由可累积，通知受缓存及缓冲区溢出影响 | 写入时间与观察时间分离；加入批处理、重复、丢通知和恢复观察；不假定一条通知对应一次写入 |
| Chokidar，[官方 awaitWriteFinish 文档](https://github.com/paulmillr/chokidar#performance) | 工业界存在按大小保持不变一段时间的策略；阈值影响响应速度 | 固定 2 秒只是一个对照工作点。没有安装或执行 Chokidar，固定等待对照也不是其轮询、原子写入及过滤行为的完整复现 |

## 原项目基准的适用边界

- `tests/helpers/watch_write_simulator.py`：8 种间隔序列，只计相邻间隔越过窗口；适合已有功能回归，不承担研究评估。没有把该模拟器复制或扩充为第二个生产算法。
- `tests/integration/watch_validation.py`：已有真实 NTFS 写入者，包括追加、重开、预分配、并行分段、浏览器临时文件、aria2 边车、时间戳恢复、占用句柄和事件风暴；继续作为真实文件观察链路的参考，不能与虚拟估计器分数混合汇总。
- `watch arrival-matrix`、`split-arrival`：真实到达方式和分卷次序。
- `watch format-matrix`、`cli-format-matrix`、`real-file`：真实格式、密码和解压阶段计时。静默算法优化仍须使用这些链路检验完整行为。

## 研究推论与限制

仅凭过去一段没有写入，不能确定写入者已经永久结束：完全相同的历史可以接“写入结束”，也可以接“一小时后恢复”。因此不能用一个固定等待值承诺任意输入下零误判与有限延迟。这里是基于有限标注语料的风险估计，不是文件完整性的证明。

合成分布是明确声明的覆盖设计，**不是从 Chrome、aria2、BT、SMB、杀毒软件或云同步客户端实测拟合的分布**。名称描述行为模式，不代表对相应应用实现的忠实仿真。后续应采集带写入者完成标记的真实轨迹，按应用/机器/会话划分训练与外部验证集，再评估外推能力。只增加更多合成 seed 不能弥补这项外部效度缺口。
