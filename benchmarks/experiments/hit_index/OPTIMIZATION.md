# 命中索引优化实验

日期：2026-11-03。依据 [评估协议](../../hit_index/PROTOCOL.md)，在同一台 Windows x64 机器上比较。
优化前为 `91124801aae38fce2eecd203857384bf9fec8899`。原版 probe、完整 native 源码及 release 扩展已在修改前独立保存，未覆盖安装环境。

## 实现范围

| 层面 | 实际修改 | 适用边界 |
|---|---|---|
| 分区 | 在至多 128 项的窗口中，根据包含目录成本的编码大小判断是否在主导大间隔前切分；保存累计秩 | 有界贪心选择，不是 PEF 的全局最优分区；固定分区仍可直接按 rank/128 寻址 |
| 表示 | 增加补丁 d-gap、位图及连续/重复段；d-gap 使用每 8 项的压缩检查点 | 以完整查询表示的大小选择；检查点带来空间成本，局部前缀恢复也可能拖慢随机访问 |
| 构建 | 叶内复用统计；切分时只重统计较短侧，另一侧由整体减去已知侧；批量位打包；128 项 d-gap 的 SSE2 垂直打包/解包及前缀和；全局等差快路径；匹配时逐叶编码 | 统计相减仅用于大于 1 的切分间隔，不跨相同位置组或连续段；x64 使用 SSE2，其他目标保留标量实现；新编码选择的统计成本也计入构建 |
| 查询 | 游标保存当前物理段；整段单类型 AR 不展开位置缓存；批量解码类型；直接读取查找所需的目录字段 | 每个消费者独立游标；没有跨请求保存可变游标 |
| 类型 | 主类型加稀疏例外；唯一位置加类型掩码及累计重数 | 出现完全重复元组时不使用会丢失重数的 GROUP 表示；同位置按生产 hit_name 字典序恢复 |
| 内存 | 不先物化整个匹配作业的原始命中数组；压缩后按实际 Vec capacity 回收明显余量；物理段改为 8 字节对齐 | 保留边界事实和归一化窗口；不是任意输入流的常数内存保证，也不是进程 RSS 的硬上限 |

只有 Rust 匹配后的索引构建和查询发生变化。既有格式校验、分卷/载体归属、密码事实、spill、IOCP 和解压路径继续复用。

## 顺序与生命周期约束

匹配器按扫描锚点推进，TAR 归一化最多向前移动 257 字节，重叠签名恢复的回移不超过已有 overlap。
流式缓冲只提交严格早于 `maximum_offset - (257 + overlap)` 的内部事实，窗口内用整数排序键保持偏移和类型顺序；读边界的 head/tail 仍由原 Builder 仲裁。
这依赖生产匹配器的有界乱序契约，不接受任意无界乱序的事件源。

每个作业持有已编码主体、叶目录、未提交的短窗口和边界事实。全局等差前缀只保留首项、步长和数量，之后出现不同事实时再转为叶。
某些低可压缩流会多付叶目录成本；逐叶构建不能自动保证所有输入比离线 RAW 更小。
压缩例外、GROUP、目录和对齐均计费。`reported_capacity_bytes` 是实际索引容器容量诊断，不能替代整个进程的峰值内存。

编码不持久化到用户输入，存活期限于一次 scan；映射和临时文件继续由已有 scratch 所有者释放。
没有增加等待、降低并发、扫描重试上限或新增依赖。

## 正确性验证

- Rust 扩展全部 263 项测试通过，包含索引/IOCP/载体边界的 29 项扫描测试。
- release 候选通过 172 项 Python 测试及 6 项子测试：完整 Plan 5、真实 CLI/Watch 密码续作与恢复、deep detection、worker 共享并发和 CLI 契约。
- 178 个 conformance 输入对原版及候选进行完整元组和查询校验。
- 流式构建接入后，13 份真实扫描输入重新捕获，逐项比较 `(offset, pattern, owner)` 多重集及最终候选，与冻结参考完全一致。记录在 `benchmarks/.cache/hit-index-optimization/capture-check/report.json`；最终统计复用版本另外通过下面的完整扫描对照。

扩充既有的三个索引粗粒度测试，覆盖全部编码、稀疏类型、重复元组、同位置筛选、流式生产者和乱序完成/spill。
这些故障可能被正确的格式检测结果掩盖；没有新增“benchmark 能不能运行”的测试。
单次 native 全套测试约 1.3 秒，增加覆盖的成本小于真实归档矩阵。
Watch 验证包含真实载体、WAL 恢复和密码续作；本轮未运行依赖临时系统服务的完整 Plan 7 下载矩阵。

## 对照实现与可复现性

成熟库、论文作者实现、块长配置和缺陷说明沿用 [原基线记录](README.md) 与协议。
每次运行保存原始计时、失败/unsupported、输入、工具和源码身份、完整生产 diff、冻结 exe/DLL。
外部参考 probe 会明确记录其来源，不把工作缓存中的其他源码误记为该 DLL 的源码。

完整扩展比较使用相同的 `cargo build --offline --release` 配置：`opt-level=3`、fat LTO、一个 codegen unit；索引 probe 也固定为相同 release 配置。
初期 CI 构建只用于开发筛查，其端到端数字不用于 release 收益结论。

下面的主比较使用最终的切分统计复用源码。之前的完整 quick 保留在 `20261103T130719Z-3d50a03a`，其中候选尚未复用左右切分统计；不可将其完整扫描数字当成最终源码的结果。

最终源码未根据本轮计时继续修改。三轮进程比较仍属于开发集反馈，不替代协议规定的 1620 输入确认矩阵。

## 最终开发集结果

完整 quick：[`20261103T133051Z-9bc4d2f6/report.json`](../../results/scan.hit-index/20261103T133051Z-9bc4d2f6/report.json)。
对应 conformance：[`20261103T132934Z-88814886/report.json`](../../results/scan.hit-index/20261103T132934Z-88814886/report.json)。
两者的候选 probe 身份一致，生产源码身份一致，运行期间源码未变化。

61 个输入 × 22 个配置 × 3 个进程 block，共 4026 个单元：3996 个有效，12 个 unsupported，18 个 invalid。
后两类仍分别来自 roaring-packed 的重复元组限制和原版 FAW 的已记录缺陷；SunPack 原版与候选均无错误。

下表比值均为 **候选 / 原版 SunPack**，小于 1 表示候选更省或更快。
空间、构建及查询各自计算配对进程比值，再在族内取几何平均；完整分层 bootstrap 区间保留在报告中。

| 输入族 | 编码空间 | 构建时间 | 顺序消费 | 混合 lower_bound | 随机访问 | 前向 seek |
|---|---:|---:|---:|---:|---:|---:|
| census-income 公共集合 | 0.829 | 1.447 | 0.665 | 1.188 | 1.200 | 0.699 |
| weather_sept_85 公共集合 | 0.846 | 1.470 | 0.595 | 1.095 | 1.241 | 0.635 |
| 真实后过滤扫描轨迹 | 0.988 | 1.176 | 0.747 | 1.061 | 1.043 | 0.498 |
| 异常间隔 | 0.665 | 1.819 | 0.492 | 1.507 | 1.508 | 0.623 |
| 连续段 | 0.756 | 1.231 | 0.424 | 1.683 | 1.557 | 0.568 |
| 同位置多类型 | 0.347 | 1.325 | 0.784 | 0.750 | 0.917 | 1.198 |
| 等差位置 | 1.000 | 0.907 | 0.236 | 1.126 | 1.008 | 0.016 |

公共集合的空间减少约 15%–17%，顺序消费耗时减少约 34%–41%。
异常间隔空间减少约 33%，同位置多类型减少约 65%。
这些收益同时伴随明显成本：公共集合构建耗时增加约 45%–47%，异常间隔增加约 82%；并非全面加速。

尾部不能由族平均掩盖。按逐输入跨进程中位数计算，最大空间膨胀为固定长度小 ZIP 的 1.015 倍；
最慢构建为 `census-income.csv67` 的 2.105 倍。`census-income.csv135` 的 lower_bound 为 4.037 倍、随机访问为 3.078 倍。
最大顺序消费退化为伪装分卷载体的 1.231 倍；短输入固定成本也保留在原始结果中。

变量长度大 ZIP 的索引空间从 70160 降至 65536 字节，顺序消费为原版的 0.668 倍，构建为 1.783 倍。
固定长度大 ZIP 的空间从 6284 增至 6292 字节；不能用其规则偏移上的快速遍历代替变量长度结果。
切分统计复用后的块尾异常间隔构建比值为 1.943，前一完整 quick 为 2.663；两轮计时条件存在波动，这只是优化方向证据，不是独立随机消融实验。

## Builder、容量与完整扫描

288 次 Builder 重放全部通过：两版本各 144 次，覆盖三种压力输入、13 份真实轨迹、三个完成次序和三个进程 block。
下表仍为候选 / 原版，时间及容量比值先按同 case、block、order 配对，再取中位数。

| 场景 | Blob 字节 | 实际保留 capacity | 构建时间 |
|---|---:|---:|---:|
| 百万稠密命中 | 0.999 | 0.999 | 1.520 |
| 稀疏槽目录 | 0.926 | 0.667 | 1.065 |
| spill 压力 | 0.942 | 0.942 | 1.050 |
| 固定长度 ZIP，2048 条目 | 0.307 | 0.193 | 1.064 |
| 变量长度 ZIP，32768 条目 | 0.906 | 0.530 | 1.667 |

变量长度大 ZIP 的 Blob 从 79620 降至 72148 字节，保留容量从 137216 降至 72724 字节。
稀疏目录的容量从 622592 降至 415292 字节。
收益不是只减少逻辑编码长度；但小 ZIP/TAR 的容量仍可能增加至 1.25 倍，稠密输入也没有明显容量收益。
这些容器容量不能推导为进程峰值内存减少同样比例。

两版本、三种压力场景各连续构建/释放 12 轮，共 72 轮全部通过，释放后句柄均为 50。
私有内存有分配器保留与波动，本轮有限观察未证明长期无泄漏。

13 个实际输入 × 两个相同 release profile 扩展 × 三个进程 block，共 78 次完整扫描全部通过，
候选结构、命中、完整读取和资源清理检查与冻结参考一致。
逐项检查 78 份清理后诊断：reader 的 `open_handles`、`cache_entries`、`container_capacity` 均为 0，进程句柄数相对扫描前的增量均为 0。
完整扫描含释放的配对耗时比值范围为 0.895–1.061；两个大 ZIP 分别为 1.061（固定长度）和 0.997（变量长度）。
主要样本多数约 1–3 ms，进程 CPU 时间的粒度也不足以区分小差异。当前不能声称整次扫描获得稳定加速。

## 与成熟实现的剩余差距

以下改用 **所列实现 / 最终候选 SunPack**，三个 block 的配对比值中位数；小于 1 表示所列实现更省或更快。

| 输入 | 实现 | 空间 | 构建时间 | 顺序消费 | 混合 lower_bound |
|---|---|---:|---:|---:|---:|
| 块尾异常间隔 | FastPFOR-128 | 0.908 | 0.539 | 0.801 | 2.293 |
| 块尾异常间隔 | FastPFOR，4096 项块 | 0.438 | 0.420 | 0.486 | 17.688 |
| 块尾异常间隔 | 优化分区 PEF | 0.578 | 16.317 | 1.629 | 9.729 |
| 变量长度大 ZIP | SVB | 1.132 | 0.359 | 0.444 | 1.432 |
| 变量长度大 ZIP | FastPFOR-128 | 1.033 | 0.959 | 0.649 | 3.948 |
| 变量长度大 ZIP | 优化分区 PEF | 0.890 | 18.869 | 1.276 | 0.567 |

最终候选仍没有全面超过成熟实现。描述性的中位数 Pareto 前沿中，候选在空间/构建/顺序消费上占 9/61 个输入，
空间/lower_bound 占 3/61，空间/前向 seek 占 17/61；前沿尚未扣除测量不确定性。
不能把不同实现的最小空间与最快查询拼成同一个结果。

## 复现命令与结论范围

在现有 `.venv` 中执行，无需重建环境。原版源码快照和 DLL 来自前述修改前缓存；候选使用最终工作树。

```powershell
.venv/Scripts/python.exe -m benchmarks.hit_index.build --bridge --output-root benchmarks/.cache/hit-index-optimization/reused-stats-probe

.venv/Scripts/python.exe -m benchmarks scan hit-index --suite conformance --no-public --algorithms sunpack --reference-bridge benchmarks/.cache/hit-index-optimization/before/reference-probe.dll --candidate-bridge benchmarks/.cache/hit-index-optimization/reused-stats-probe/target/release/sunpack_hit_index_probe.dll --strict

.venv/Scripts/python.exe -m benchmarks scan hit-index --corpus-manifest benchmarks/results/scan.hit-index/20261103T105334Z-7f153eff/corpus.json --reference-bridge benchmarks/.cache/hit-index-optimization/before/reference-probe.dll --candidate-bridge benchmarks/.cache/hit-index-optimization/reused-stats-probe/target/release/sunpack_hit_index_probe.dll --reference-module-root benchmarks/.cache/hit-index-optimization/before-release/module --candidate-module-root benchmarks/.cache/hit-index-optimization/reused-stats-release/module --conformance-report benchmarks/results/scan.hit-index/20261103T132934Z-88814886/report.json --full-scan --strict
```

扩展构建使用 `cargo build --offline --release --manifest-path native/Cargo.toml -p sunpack-native`，
原版对其独立源码快照使用相同命令和 profile，分别复制到表中 module root。
最终 Python 回归日志为 `benchmarks/.cache/hit-index-optimization/pytest-reused-stats-release.log`，263 项 Rust 测试也在最终源码上重新通过。

本轮完成了六个层面的实现和开发集验证，证明了空间、顺序消费与部分 seek 收益及相应成本。
正式 1620 输入矩阵、外部 IR、真实用户目录、完整 Plan 7 系统下载矩阵和跨 CPU 重复尚未执行，不能写成论文确认性结论。
构建和随机定位仍是后续优化重点；若继续调参，应登记新版本，再用独立确认数据评价。
