# 静默映射函数的闭环搜索

搜索入口：

```powershell
uv run --no-sync python -m benchmarks scheduling watch-quiet-search --candidates 512 --jobs 12 --output benchmarks/results/quiet-function-search.json
```

只重新统计已经保存的完整提案时间线：

```powershell
uv run --no-sync python -m benchmarks scheduling watch-quiet-search --rescore path/to/outcomes.jsonl.gz --output benchmarks/results/bursts.json
```

CPU、IO、在途工作量及总错误次数均不进入优化或验收。目标为零漏有效提案，在预先登记的短时错误峰值边界内，最小化首次有效提案平均延迟。其他峰值与表达式复杂度用于随后排序；同时导出延迟与六项峰值均值的 Pareto 前沿。边界是离线模型选择条件，不是生产重试次数、超时、等待上限或并发限制。

完整 development 评价后同时冻结数值最低延迟函数和现有函数族的最佳参数点。默认 `--selection-rule latency` 按用户优先级选择峰值边界内平均首次有效提案延迟最低的函数。可选 `--selection-rule paired-simplicity`：对满足峰值边界的较低复杂度候选，计算其与数值赢家的逐 seed 延迟差；若开发集配对 bootstrap 95% 区间包含零，将其视为未显示稳定劣势的候选，优先较低复杂度，再比较平均延迟。这只是防止追逐选模噪音的工程启发式，不是等价检验或泛化保证，必须另做新的独立审核。参数搜索对照在完整 development 上重新选择，不能把初筛选出的参数点误称为最佳调参结果。

## 第二指标

按照 [PROTOCOL.md](PROTOCOL.md) 对完整轨迹求任意位置的 100ms、1s、10s 滑动窗口峰值，包含未完成的取消/暂停负例。时间戳以纳秒表示，窗口为半开区间；单个逻辑输入与并发合计分别统计。保留 trace 内分布、实际最坏值及 family/width 分层。

默认推荐边界 `--burst-ratio 1.10` 在观察候选结果之前写入 `search-plan.json`：

- family 等权的单输入峰值均值及并发峰值均值，不超过同批基线的 110%。
- 每个并发宽度的对应均值也满足该边界，避免平均值掩盖并发问题。
- 全局、每族、每宽度的实际最坏单输入/并发峰值，不超过 `max(基线+1, ceil(基线*1.10))`。一次余量明确处理整数分辨率和基线为零的情况。

10% 是本轮的保守工程默认值，不代表用户规定了这一容忍度。完整候选分数及前沿一并保存，后续可以按其他边界重新选择，不能把某个有限容忍度下的推荐项声称为任意目标下的唯一最优。

## 结构和参数

冻结阶段确认、加权 P90、十二样本历史、边界确认及 tracker 退休，只搜索 `target_seconds(I)`。非控制候选写成 `A * g(I/P)`，其中 `A`、`P` 为秒单位的正常数，`g` 无量纲。线性形式消去不可辨识的公共尺度。语法从 `x` 开始，递归组合：

- `log1p(g)`、`sqrt(g)`、`g/(1+g)`、`g**p`；
- `r*g+(1-r)*h`、`g*h`。

最多三个语法算子、深度最多四层；最多一个加权混合和一个可调幂，最多四个独立常数。交换律等价的二元结构只生成一份，加权相同子树直接排除。常数保留三位有效数字；`A,P` 范围为 `[0.001,100]`，`r` 为 `[0,1]`，`p` 为 `[0.25,1.5]`。整个语法保证非负、单调、零点为零；另外检查多个数量级的数值有效性。常数边界是搜索域，不是生产静默时间截断。

按复杂度与根算子交错采样结构，每个初始结构尝试多个尺度；再对表现好的不同结构做无导数坐标邻域优化，同时保留接近峰值边界的少量低延迟候选。幅度和尺度还会联合移动，避免只改单个常数而无法穿越狭窄的可行区域。每一项扰动都重新运行闭环回放。当前公式、零等待负对照、上一轮纯对数候选及线性加对数函数族的参数搜索控制同时保留。零等待只作控制；它不能绕过零漏提案和错误峰值边界。常数搜索的坐标步长及轮数写入计划，属于有限预算启发式优化，不声称穷尽所有结构或连续参数。

这借鉴了 [ESR](https://arxiv.org/abs/2211.11461) 的复杂度受限表达式搜索、[符号策略发现](https://proceedings.mlr.press/v139/landajuela21a.html) 的执行反馈目标，以及 [Hyperband](https://www.jmlr.org/papers/v18/16-558.html) 的逐步资源分配思路。实现采用标准库，无新增依赖，没有引入 RNN、贝叶斯代理或将这些方法的理论保证套用于本任务。

## 数据隔离和资源分配

默认先在 development seed 0 的全部 28 族、四通道、原有 1/4/8/64 宽度设计、两种同刻次序上评价。结构/参数候选逐步晋级到三个 development seed，再对最终候选覆盖八个 seed。初筛也保留完整困难轨迹、并发宽度和观察终点，绝不截断写入尾部。

同一个写入者实例的不同通道、宽度与同刻次序始终在同一个 seed block 内，不把它们当独立训练/审核样本。每个 trial 新建原有 Rust catalog/state，使用真实 enqueue、deadline、可读性探测、完成和退休路径。改变映射会改变未来 tracker 状态；不能复用固定的 I 序列。只缓存不可变语料和同一表达式的完整 seed-block 得分。

推荐项及前沿在查看 validation 之前写入 `selection-frozen.json`。之后完整执行 validation seeds 0–7，以及本次搜索未使用的 heldout seed block。首轮为此前未执行的 seeds 8–15；后续默认从已有搜索工件中查找已实际评价的审核 seed，自动选择下一批未使用的 seed，显式指定已使用范围时拒绝将其当成全新审核。后者仅为新的同分布合成审核，不是真实客户端验证。若审核失败，报告明确记为未通过，不依据该审核结果静默调参或切换赢家。按 seed block 报告配对差值；development 赢家的区间仅描述本批数据，不能消除模型选择偏差。参考 [Cawley 与 Talbot](https://www.jmlr.org/papers/v11/cawley10a.html)。

并行使用独立进程，避免生产调度回放的全局 patch 在线程间相互干扰；每进程保留一个不可变 seed block，元数据夹具相互隔离。离线进程数量不改变任何一条被测轨迹的生产并发。

## 工件和应用范围

搜索计划、所有已执行结构/常数、逐 seed 得分、开发集前沿、冻结推荐项、validation/audit 指标、完整提案时间线、语料与执行源码身份保存在已有 benchmark workspace。使用已有 Rust xxh128 仅标识实验身份。`winner_policy.py` 是完整冻结策略，只替换原有映射方法，可直接用于 `watch-quiet-scheduler --policy-source ...`；搜索代码不会进入生产热路径。

`--resume <旧结果目录>` 为新的冻结运行复用得分：要求语料指纹、评估源码及关键 scorer 定义相同，按实际函数源码身份命中缓存。旧版线性表达式重载曾重复归一化，恢复运行明确排除旧线性得分并重算；不会将那部分失效结果混入新比较。改变搜索步长可以复用未改变的函数评价，改变评分语义则拒绝复用。

推荐项冻结后，可用纯 development 数据检查常数邻域；幅度/尺度扰动 ±5%，混合/幂扰动 ±0.01，输出全部差值，不重新选择赢家。诊断入口还比较已冻结的数值赢家在审核集上的结果；可用 `--skip-audit-reference` 只执行 development 邻域诊断：

```powershell
uv run --no-sync python -m benchmarks.quiet_window.search_diagnostics path/to/selection-frozen.json --seeds 0,7 --output benchmarks/results/quiet-sensitivity.json
```

当前回放和原有基准同样不模拟真实处理耗时，但这些成本按本轮要求不构成优化或验收条件。搜索不改变归档分析、密码探测、格式判断、解压或 CLI 链路。生产默认映射是否替换应依据最终报告明确说明；框架本身不会自动写入生产公式。
