# SunPack 命中索引评估协议

协议日期：2026-11-03。机器可读参数在 `protocol.json`，源码锁定在 `sources.lock.json`。
这是依据论文和成熟实现制定的项目评估协议，不是已有的 ISO、SPEC 或行业认证标准。
它评估“带类型、可重复的有序命中索引”，不能据此宣称整个解压系统优于所有已有算法。

## 1. 研究问题和有效结论

需要分别回答：

1. 完整语义相同时，空间、构建、遍历、筛选、随机访问和跳转的取舍是什么？
2. 改进来自整数编码、类型布局、目录、分区还是构建生命周期？
3. 离线压缩收益能否保留到真实并行扫描的 prepare、收集、spill、映射和释放阶段？
4. 哪些分布退化，最坏分层是什么，完整扫描是否受益？

不把“全部数据、全部指标都第一”设为默认验收标准。报告 Pareto 前沿、用途对应的收益及退化。
若要声称全面占优，必须在事先列出的全部必需分层、全部目标指标上成立，不能只比较均值。
文献中的数字不能直接和本机数字相除；本协议使用固定源码在同机重跑。

## 2. 文献依据及落实方式

| 一手资料 | 采用的细节 | 避免的误用 |
|---|---|---|
| [SIMD 整数压缩论文，§6.4–6.5](https://arxiv.org/html/1209.2137v7) | 原作者 Uniform/ClusterData 生成器；按长度分层；差分恢复计入解码 | 自造“均匀分布”冒充原论文；只测 unpack、不测前缀和 |
| [Partitioned Elias–Fano，SIGIR 2014，§5](https://pages.di.unipi.it/rossano/assets/pdf/papers/SIGIR14.pdf) | Access、Next、NextGEQ 分开；分区与目录成本；统一批量查询接口 | 用逐元素 FFI 拖慢某个算法；只报压缩主体 |
| [Roaring 实现与实验](https://arxiv.org/html/1603.06549v4) | 区分数组、位图及连续段分布；启用 run optimization；公开真实集合 | 把不保留重复项的集合当成完整多重集索引 |
| [Variable-byte 分区研究](https://arxiv.org/html/1804.10949v2) | 密疏转换、异常间隔位置、分区尺度是独立实验轴 | 平均间隔相同就认为分布相同；用单一块长代表全部设计 |
| [FAW 原论文](https://doi.org/10.1016/j.simpa.2023.100612) | 比较原地编码与可直接查询的帧结构 | 将新增的秩目录说成原作者算法；用原版缺陷证明算法优势 |
| [Kalibera–Jones，2013](https://kar.kent.ac.uk/33611/45/p63-kaliber.pdf) | 进程间重复与进程内重复分层；报告不确定性 | 把内层循环当作几千个独立样本 |
| [ACM artifact policy](https://www.acm.org/publications/policies/artifact-review-and-badging-current) | 记录来源、构建、输入、运行步骤和原始结果 | 只有汇总图、没有可重新执行的材料 |
| [PISA 索引格式](https://pisa.readthedocs.io/en/latest/indexing_pipeline.html) | 支持外部 `.docs` 的原始 posting list 输入 | 仅凭“Gov2”名称就认为预处理和 doc-ID 排列相同 |

文献中 Uniform/ClusterData 的宇宙大小、数组数量及长度与本项目默认矩阵不同；本协议是明确参数化的扩展，不能称为原论文原样复现。
特别是 Gov2/ClueWeb：不同论文的分词、停用词处理、文档排序可能不同，必须记录这些参数。

## 3. 输入契约和基线

事实为 `(absolute_offset: u64, pattern_id: u8)`，14 类。按偏移升序，同偏移按生产 `hit_name()` 的字典序排列。
保留相同偏移的不同类型和完全相同的重复元组。owner/job 仅用于重放生产构建，不改变索引内容。
空输入、短尾、绝对偏移大于 32 位、单窗口跨度超过 28 位都不能静默截断。

| 配置 | 固定实现 | 适配和限制 |
|---|---|---|
| raw-packed / raw64 | 本基准中的 4 字节相对 packed / 9 字节无 padding 元组数组 | packed 跨度小于 2^28；raw64 为完整兜底参照 |
| sunpack | 当前生产 `hit_storage.rs` 的完整源码副本 | 私有 Rust 导出；没有重写生产编码；宽跨度拆成生产物理段 |
| svb / svb0124 | StreamVByte 原库 | delta SIMD 解码；0124 单独标明；共同类型列和块目录 |
| bp128 / fastpfor128 / optpfor | FastPFOR 原库 | 原库 SIMD 前缀和；VariableByte 处理相应短尾；保留准确压缩长度 |
| simple8b / vse | FastPFOR 中的原作者实现 | 完整差分恢复及公共类型列计费 |
| ef / pef-uniform / pef-opt | `ot/partitioned_elias_fano` + `ot/succinct` | 保留原分区、编码、select、枚举器；Windows/Boost 兼容层仅替换平台和通用工具 |
| roaring | CRoaring | 启用 `run_optimize`、`shrink_to_fit`；重复偏移用 offset+rank 变换，并修正访问/查找 |
| roaring-packed | CRoaring | offset+类型次序组成集合键；完全重复元组标为 unsupported，不能去重后继续评分 |
| faw | 原作者 FAW encode | 正整数偏移、必要时 offset+rank；基准新增稀疏帧目录和等价解码/查询适配 |
| faw-repaired | 明确标记的本地修正版 | 仅修复 FR 连续条件和新 base 的状态重置；保留原版结果和修复记录 |

所有库锁定完整 Git commit，工作树非干净或 commit 不符即拒绝运行。生产 Rust probe 使用常规 allocator；分配计数构建必须独立运行，不能混入计时。
微基准把全部类型置于一个可查询流，统一比较完整有序序列；Builder 层保留生产的主流/XZ-footer 双流布局，并校验合并后的完整事实。
PEF 和 FAW 的查询包含本协议适配器，结果应称为“该实现及适配下的完整类型索引”，不能冒充作者原 benchmark 的结果。
偏移去重、将 u64 截断到 u32、去掉类型或用哈希相等代替元组相等均不允许。

主配置块长 128，另报 SVB/BP 的 4096、FastPFOR 的 4096/65536，揭示目录与随机访问的取舍。
此层是完整类型索引对比，不是纯整数 kernel 微基准；公共类型列、目录和查询适配仍在计时内。不能由这些数字单独推断原库纯 unpack 的速度。
这不是所有成熟压缩库的穷尽清单。尚未接入的 TurboPFor、MaskedVByte、PISA 的其他优化分区算法不能被写成已战胜。
若某新方法与这些方法直接相关，投稿前应增补对应作者实现；新增基线必须通过相同语义校验。

## 4. 数据构造与选择

### 合成矩阵

`quick` 是开发反馈集，不产生论文确认性结论。包含空、短、均匀、聚簇、规则等差、异常间隔、连续段、密疏转换、重叠类型、重复元组、高绝对地址及位宽边界。

`conformance` 覆盖 0/1/2、32/64/128/256/4096 附近的长度，共 17 个长度 × 5 个分布 × 2 个开发种子，加 8 个宽地址、连续尾和位宽边界用例，共 178 个输入。
其目的为完整语义准入，不使用这些数据上的小规模计时证明性能。

`evaluation` 为 1620 个合成输入：

- 4 个长度：4096、65536、262144、1048576；9 个分布；6 个类型模式；5 个固定评估种子，共 1080。
- 异常间隔周期 16/128/1024、幅度 256/4096/65536、相位 0/1/63/127，5 个种子，共 540。

异常相位按周期取模，有些组合等价；需保留标签并在论文归纳时避免把等价点当作独立分布。
类型含单类型、均匀 14 类、局部 3 类、99% 单类、256 项连续类型段和周期类型。
重复偏移与完全重复元组分别统计。分布范围过小直接失败，不自动缩放成有利于压缩的新分布。
偏移、类型和查询使用独立确定性随机流。开发种子与评估种子分离；评估种子公开，不能宣称盲测。

### 公共真实整数集合

默认使用 CRoaring 同一固定 commit 下的 `census-income`、`weather_sept_85`，各 200 个文件。
C++ 原生解析全部集合并测量基数，以 `bit_length(n)` 分桶；quick 每桶固定种子抽 1 个，evaluation 每桶抽最多 3 个。
保存全部桶的计数和选中列表。不能按 SunPack 胜负选择集合。
这些是真实集合分布，不是实际压缩包扫描轨迹，不能代替下面的层次。

外部 posting list：原生入口接受 `--postings data.docs --posting-list N`。
读取 PISA 的 `[1, document_count]` 头和 `[length, sorted_u32_values...]`；必须记录数据许可、生成工具 commit、分词、文档 ID 排列、全集规模和选取列表。
正式 IR 对比至少按长度的对数桶取固定数量列表，同时报告 list-weighted 和 query/workload-weighted 结果；查询权重必须来自独立 workload，不能用表现决定。
没有拿到 Gov2/ClueWeb 时写明未运行。默认公开集合不能冠名为这两个数据集。

### 实际后过滤命中轨迹

复用项目 `ArchiveFixtureFactory` 和大型嵌入样本工厂，构造 13 个输入：ZIP、TAR、XZ、加密 7z、加密伪装分卷载体、非首卷、多条目 ZIP、嵌套 ZIP、空文件及 128 个混合嵌入段。
多条目 ZIP 同时包含固定长度和变量长度两类，各有 2048/32768 个条目；变量型使用独立固定随机流生成文件名、内容和大小，大小为 70% 的 0–512、29% 的 512–8192、1% 的 65536–262144 字节，保留宽间隔和多个 IOCP job。
固定长度 ZIP 的偏移接近等差，仅用于规则性诊断，不代表普通用户 ZIP；必须与变量型共同报告。
在隔离源码副本的真实 Rust `scan_sample_batch` 输出后、`prepare` 前记录；没有另写魔数扫描器。
保留生产已过滤事实、绝对偏移、类型、job 所有者和记录到达次序。
校验完整读取及工厂已知的嵌入根位置，再冻结原输入、轨迹、完整候选结果和 XXH128 身份。
捕获锁与写盘会影响任务完成顺序，所以“记录次序”只是一次合法受仪器影响的次序，不能称为无干扰的生产到达分布。
捕获构建与捕获运行的时间完全不参与性能结论。

单个小合成压缩包不能代表真实用户分布。发表广泛系统结论还需加入经许可的真实目录/文件样本，记录来源及五类输入比例；使用相同原生捕获入口冻结。

## 5. 四层评估

| 层 | 实际执行 | 结论范围 |
|---|---|---|
| 完整类型索引 | 编码、全遍历、掩码、随机访问、lower_bound、前向 seek、同偏移枚举、释放 | 隔离索引算法及适配成本 |
| 生产 Builder | 实际 prepare、push、finish；正常、全局反序、窗口内反序；真实轨迹另重放记录次序 | 并行 prepare、目录、spill、完成顺序敏感性 |
| 真实轨迹 | 所有基线处理同一份冻结的真实后过滤事实 | 命中分布是否代表真实扫描 |
| 完整扫描 | 新进程真实 `NativeArchiveSession` 扫描至 session close 和资源清理 | 索引收益是否穿透其他扫描成本 |

Builder 固定 4 个 worker、窗口 6；稠密百万命中、45000 个逻辑槽的稀疏目录以及 90000 命中的 spill 场景分开。
另在同一进程中连续构建/释放 12 轮，保留每轮 private bytes、映射、句柄和释放时间，检查长期驻留趋势；这只是有限长度观察，不构成无泄漏证明。
模块加载在 Builder 计时外，第一次 Rayon 线程池启动在 prepare 内，后续同进程轮次复用线程池；两类结果分开解释。
不能通过人为减并发或插入等待修复正确性。线程数/窗口/块长变化属于独立参数实验，不能混入主表。
本地 replay 不重演 IOCP 的时序，只重放保留下来的 job 与完成排序；全局反序是压力分布，不宣称是有界实际执行的典型情况。

完整扫描结果必须和冻结的候选结构、命中统计完全一致，并检查 complete/read_bytes。
仅跑 installed 版本得到的是基准点；只有提供冻结 candidate module 并交替 A/B，才能声称完整扫描改进。
模块构建 profile 必须相同；不能拿捕获模块的 CI 构建和 release 构建比速度。

索引修改进入生产前还需要现有 CLI/Watch 格式、嵌套、密码和分卷集成评估；本基准不会将索引微基准伪装成这些端到端证明。
可复用 `reader embedded-scan`、`extraction split-pressure`、`watch format-matrix`、`watch split-arrival`，按本次修改影响面选择并记录。

## 6. 正确性与计时

先运行独立校验可执行文件：完整解码逐元组比较；随机访问逐项比较；lower_bound 对照 `std::lower_bound`；掩码和 seek 对照独立标量实现产生的完整序列。
计时可执行文件编译时去掉审核序列收集。求和只用于防死代码消除，不承担正确性证明；不做输出 SHA-256。
crash/invalid/unsupported 都保留在覆盖分母，不给缺失单元格虚构性能值。
候选在必需输入上出现任何一种非 ok 状态都不能合格；原版 FAW 失败单列，不影响其余有效基线的记录。

一批操作只跨一次虚调用/FFI，没有逐命中跨语言调用。初始化单列；类型构建、键变换和目录构建包含在 build。
输入生成、原始数组、oracle、正确性校验不在构建/查询计时内，但它们在进程内存中，需用阶段差值解释。
主计时为 steady_clock 墙钟，附进程 CPU 时间。Windows CPU 计数对短批次可能为零；quick 的 CPU 数字不宜用于细微比较。

每种操作先预热和校准重复次数，再保留每个样本及重复次数。
默认输出 ns/整批操作，不是 ns/命中。查询数、实际命中/缺失数量、n、类型频次、重复数量随结果保存；论文转换单位时必须写清分母。
`operation_inputs` 记录每个操作的输入单位数：遍历/掩码为原始 n，访问/查找/seek 为目标数，equal_offset 为请求组数；筛选后的输出条数不能与这些输入分母混淆。
`mask_common`/`mask_rare` 当前固定为类型 0/1；这些名称仅对相应类型分布成立，实际选择率以记录的频次为准。`mask_absent` 为未分配第 15 位。
缺失查询在全稠密输入上会退化为边缘缺失，不能称为均匀内部缺失；极值 0/MAX 包含在混合查询内。
`equal_offset` 用公共的 lower_bound 和 128 项 rank page 枚举，最多 32 组；是组合接口成本，不是生产 Cursor 的专门组枚举能力。

每个 case/config/block 开新进程，按事先固定的打乱和循环顺序交错算法，按 block 轮转操作顺序。
精确次序均衡需要完整循环；7 个 block 不保证 21 配置完全均衡。不要同时运行多个计时 shard。
记录 CPU、系统、编译器、源码 commit、构建输入身份、DLL/exe 身份；发布时补充电源计划、亲和性、后台负载和 CPU 特征设置。
本协议不清空 Windows 文件缓存，不能称为冷盘测试。不同 CPU/编译器的推广结论需要独立重复。

## 7. 空间与生命周期口径

`bytes` 是所有实际编码流（含类型、目录、对齐、读取 padding）加共同 64 字节逻辑 envelope 的空间账本；不是已经生成并验证过的可移植磁盘格式。
envelope 可容纳 schema/codec、n、base、universe、参数和流长度等八个 u64。
SunPack 类型与偏移在原生流内组合；其他基线使用同一局部 palette 类型列，每 128 项一个 8 字节目录。全局单类型用一个字节表示，不强加每块类型目录。
Roaring 使用库的 portable size，PEF 使用完整 bit-vector，FAW 包含新增帧秩目录。
目录和短输入的固定成本不能省略。Builder 输出的 bytes 为原生产 Blob 字节，不加微基准 envelope，分开报告，禁止跨层直接相除。

`reported_capacity_bytes` 仅为当前可直接取得的容量诊断：部分适配器包括 wrapper 和解码 scratch，SunPack 为三个 Blob；不保证包含全部库对象、allocator 元数据和私有工作区。
未知时为 null，不能当成零或统一的全堆分配指标。
完整内存比较使用同阶段的 private bytes/working set 及进程绝对高水位，明确减去 input-ready/initialized 的基线。
验证缓冲区会抬高绝对 peak；不能把“peak - built”说成构建峰值。
释放后保留的 RSS 可能来自 allocator reserve；结合映射字节、handle 数及重复生命周期判断，不能仅凭 RSS 认定泄漏。
Win32 transfer bytes 是进程传输量，不是物理磁盘写入量。

## 8. 统计、决策与发布门槛

进程内多个 sample 先取中位数；同 case、同 seed、同 block 的配置作配对比值，再在分布族内归纳。
默认比值为 baseline/SunPack，小于 1 表示该 baseline 更省空间或更快。
按 case 和进程 block 分层 bootstrap，保存 95% 区间、最坏/最好 case。合成 seed 变体不是新真实用户，不可扩展总体解释。
内层重复不能提高独立 N。失败配置的剩余成功子集可能有选择偏差，必须同时展示有效覆盖数。
无总体加权分数；空间、构建、各种查询、释放分别看。发布尾部退化和小输入结果，不能只发表大列表优势。

候选优化前登记：目标 workload、主指标、预期效应阈值、允许的空间/时间退化、拟修改参数。
先用开发种子调参；锁定实现后运行评估种子。若根据评估结果重新调参，这批数据转为开发集，并登记新的确认样本。
确认区间需能分辨事先登记的效应；不够时增加进程 block 或独立机器，而不是重复挑选最好的一次。

完整评估需要：178 项 conformance；1620 项合成矩阵和固定公共集合；全部算法配置及 block；真实轨迹和 Builder；完整扫描；来源/构建/输入/失败清单；全部 shard。
仅合成正式矩阵就有 1620 × 21 × 7 = 238140 个独立进程单元；按每单元 10 操作 × 5 样本 × 20 ms 的目标，计时预算约 66 小时，另有校验、初始化和慢操作成本。分片是为管理运行，不是允许并行争抢 CPU。
`quick` 只提供方向和协议落地证据。外部 IR、真实用户目录、CLI/Watch 和其他 CPU 未运行时必须写清，不能用默认勾选宣称完成。
执行器只检查机械完整性；它不会自动认证论文结论、统计效力或对全体已有算法的领先性。

## 9. 执行与材料

要求：Windows x64、现有 `.venv`、VS 2022 BuildTools（C++/LLVM/CMake/Ninja）、Rust 及项目已有归档工具。
复用项目依赖，不重建环境。首次 `--fetch` 只下载锁定的第三方源码和公共数据。

```powershell
# 完整语义准入（不当作速度证据）
uv run --no-sync python -m benchmarks scan hit-index --fetch --suite conformance --no-public --strict

# 开发对比：真实轨迹 + 同一输入的实际扫描
uv run --no-sync python -m benchmarks scan hit-index --fetch --real --full-scan --strict

# 完整矩阵可顺序分片运行；所有分片复用同一冻结 corpus.json
uv run --no-sync python -m benchmarks scan hit-index --suite evaluation `
  --corpus-manifest benchmarks/results/scan.hit-index/<capture-run>/corpus.json `
  --conformance-report benchmarks/results/scan.hit-index/<conformance-run>/report.json `
  --full-scan --shard-count 16 --shard-index 0 --strict

# 固定候选 probe 与原版同批 A/B；完整扫描另指定包根目录
uv run --no-sync python -m benchmarks scan hit-index --candidate-bridge C:\frozen\probe.dll `
  --candidate-module-root C:\frozen\python-package-root `
  --corpus-manifest C:\frozen\corpus.json --full-scan --strict
```

候选 probe 用独立输出目录构建，避免被参考 probe 的重建覆盖：

```powershell
uv run --no-sync python -m benchmarks.hit_index.build --bridge `
  --source-root C:\frozen\sunpack-source --output-root C:\frozen\candidate-probe-build
```

也可使用历史运行保存的 `reference-probe.dll` 作为固定候选，反转参照方向时明确说明。
生产 `hit_storage.rs` 只复制一次；完整 native module 用项目已有构建链产生。
独立优化分支的 probe/export 版本必须相容，否则报错，不能退回旧实现冒充候选。

结果位于 `benchmarks/results/scan.hit-index/<run>/`：`report.json`、`report.md`、`raw.jsonl`、`validation.json`、`lifecycle.json`、`lifetime.json`、`full-scan.json`、`corpus.json`、`protocol.json`、`sources.lock.json`、源码身份/差异和 probe 构建输入。
冻结 corpus 内的真实输入及 `.hits` 路径为绝对路径；迁移机器时需要整体复制并显式重定位，重新校验 XXH128。
`.hits` 为 8 字节 magic `SPHITS\0\0`、四个 LE u64（文件大小、条数、保留 base、chunk），之后每条 16 字节：偏移 u64、类型 u8、零 padding 3 字节、job u32。
评估过程不安装 probe/capture 到 `.venv`，不修改生产扫描逻辑。

分片完成后合并（显式列出全部 `report.json`；参数、源码、工具、语料或重复单元格不一致会拒绝）：

```powershell
uv run --no-sync python -m benchmarks.hit_index.analysis `
  benchmarks/results/scan.hit-index/<shard-0>/report.json `
  benchmarks/results/scan.hit-index/<shard-1>/report.json `
  --output benchmarks/results/scan.hit-index/merged
```

合并报告列出缺失门槛；只有全部分片、正式参数、全部必需数据层和匹配的完整 conformance 证据齐全，才标为机械完整。
这不替代对统计效应、真实数据代表性和论文论点的判断。
