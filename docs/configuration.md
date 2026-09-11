# 配置文件说明

常用配置文件为 `sunpack_config.json`，只保留最常改的字段。完整高级配置文件为 `sunpack_advanced_config.json`，保留全部可调字段。

运行时会先读取 `sunpack_advanced_config.json`，再用 `sunpack_config.json` 覆盖同名字段：对象字段递归合并，数组和普通值整体覆盖。也就是说，简化配置优先级更高；用户可以把任意高级字段搬进 `sunpack_config.json` 接管它，也可以删掉字段让高级配置兜底。

源码运行时通常读取仓库根目录或当前工作目录中的配置；打包版本优先读取可执行文件旁边的外部配置，因此用户可以在不重新打包的情况下调整行为。

检查配置：

```powershell
python sunpack.py config validate
```

查看配置：

```powershell
python sunpack.py config show
```

## 运行时覆盖

程序支持通过环境变量 `SUNPACK_CONFIG_OVERRIDES` 在启动前动态覆盖任意配置项，不需要修改配置文件。值可以是内联 JSON 对象，也可以是某个 JSON 文件的路径。

合并顺序（后覆盖先）：`sunpack_advanced_config.json` → `sunpack_config.json` → 运行时覆盖。覆盖遵循与配置层相同的合并规则：对象字段递归合并，命名模块列表（如 `filesystem.scan_filters`、`detection.rule_pipeline.precheck`）按 `name` 合并，因此覆盖里只需写要改的那一项。

例如临时放行小文件：

```powershell
$env:SUNPACK_CONFIG_OVERRIDES = '{"filesystem": {"scan_filters": [{"name": "size_range", "enabled": false}]}}'
python sunpack.py scan C:\Archives
```

或保留过滤器、把阈值降到 0：

```powershell
$env:SUNPACK_CONFIG_OVERRIDES = '{"filesystem": {"scan_filters": [{"name": "size_range", "range": "r >= 0"}]}}'
```

覆盖里出现未知的顶层配置节会直接报错，避免拼错字段名被静默忽略。CLI 参数（如 `--recur`、`--cleanup`）与运行覆盖共用同一套合并逻辑，在加载完成后作为最后一层生效。

pytest 默认注入一份覆盖，关闭 `size_range` 过滤器，因此测试可以使用小于 1MB 的文件；调用方如果自己设置了 `SUNPACK_CONFIG_OVERRIDES`，pytest 会保留调用方的值。

## 顶层结构

```json
{
  "cli": {},
  "thresholds": {},
  "recursive_extract": "*",
  "nested_extraction_policy": {},
  "post_extract": {},
  "filesystem": {},
  "performance": {},
  "analysis": {},
  "verification": {},
  "repair": {},
  "detection": {}
}
```

## cli

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `language` | `str` | CLI 语言。`zh` 启用中文，其它值回退英文。 |

## thresholds

| 字段 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `archive_score_threshold` | `int` | `6` | detection 分数达到该值时生成解压任务。 |
| `maybe_archive_threshold` | `int` | `3` | 分数达到该值但低于归档阈值时标记为可疑归档，但不生成解压任务。 |

`maybe_archive_threshold <= score < archive_score_threshold` 只保留诊断状态；项目没有 detection confirmation 层，也不会在该区间启动昂贵的二次确认。

## recursive_extract

| 值 | 说明 |
| --- | --- |
| `*` | 无限递归，内部上限为 999 轮。 |
| 正整数 | 固定递归轮数。 |
| `?` | 每轮递归后询问是否继续。 |

递归轮次只表示最多允许继续扫描多少轮。第一轮完全按用户选择的文件或目录扫描范围执行，不做目录语义门控。第一轮完成后，coordinator 会用 `NestedOutputScanPolicy` 发现输出中的压缩包；从第二轮开始，`nested_extraction_policy` 在实际分析和解压前做目录语义授权。

CLI 可用 `--recur` 临时覆盖。

## nested_extraction_policy

该策略批量判断自动从解压结果中发现的压缩包是否像用户语义上的独立归档。它不会弹出确认，也不会减少 detection 的完整候选发现；被拒绝的候选在进入 analysis、密码处理和实际解压前停止。用户请求的第一轮扫描始终绕过该策略；第二轮起所有候选统一判断，包括输出根目录第一层的候选。

判断使用同一次 filesystem 枚举产生的过滤前原始快照，因此黑名单、大小过滤等不会把普通游戏文件从目录上下文中隐藏。统计和候选合并在 Rust 中一次完成，不会为每个嵌套压缩包重复扫描目录。

| 字段 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `enabled` | `bool` | `true` | 是否启用解压前批量授权。 |
| `byte_ratio_exponent` | `float` | `1` | 字节占比赔率的指数，越大越重视候选压缩包的字节主体性，必须为正数。 |
| `project_ratio_exponent` | `float` | `1` | 压缩项目占比赔率的指数，越大越惩罚候选项目占比过低，必须为正数。 |
| `authorization_bias` | `float` | `0` | 加在融合 log-odds 上的有限偏置；正数更宽松，负数更保守。 |
| `minimum_authorization_score` | `float` | `0.85` | 局部和根目录授权评分均需达到的最低值。 |
| `minimum_archive_byte_ratio` | `float` | `0.1` | 局部或根目录候选字节占比低于此值时直接拒绝。 |
| `hard_maximum_other_projects` | `int` | `1000` | 防止递归任务爆炸的安全上限；局部或根目录有效非候选项目超过此值时直接拒绝。 |

设候选字节占比为 `B`，候选压缩项目数为 `A`，有效非候选项目数为 `O`，压缩项目占比为 `P = A / (A + O)`。授权分使用赔率融合：`S = sigmoid(c + a×logit(B) + b×logit(P))`，其中 `a`、`b`、`c` 分别对应上述两个指数和偏置。`S` 是位于 `0..1` 的确定性置信分，不是在标注数据上校准过的真实概率。赔率模型会让接近 `100%` 的字节占比快速增强主体证据，同时让接近 `0%` 的压缩项目占比快速增强反对证据。默认参数下，字节占比为 `99%` 时，压缩项目占比约 `5%` 是授权边界。

候选位于更深目录时，以扫描根下包含它的第一个目录作为局部语义子树，并同时统计完整输出根；最终取两个评分中的较低值。每个独立候选归档计一个压缩项目，一组分卷仍只计一个；普通非候选文件逐个计数，不含候选的首层旁支目录额外计数；候选路径上的连续包装目录不计数。同一范围里的多个压缩包统一聚合，分卷成员去重求和。拒绝结果以 `nested_extraction_policy` 策略跳过记录在运行摘要中，不作为解压失败。

## post_extract

| 字段 | 类型 | 可选值 | 说明 |
| --- | --- | --- | --- |
| `archive_cleanup_mode` | `str` | `d`、`r`、`k` | 成功后如何处理原归档：删除、回收站、保留。 |
| `flatten_single_directory` | `bool` | `true` / `false` | 解压结果只有一个顶层目录时，是否把内容提升一层。 |

建议默认用 `r`，避免误删原始归档。

## filesystem

### directory_scan_mode

| 值 | 说明 |
| --- | --- |
| `*` | 递归扫描目标目录及子目录。 |
| `-` | 只扫描目标目录第一层文件。 |

该设置只影响输入目录扫描范围，不影响解压后的递归轮次。

### scan_filters

`scan_filters_enabled` 是扫描过滤器总开关。设为 `false` 时保留 `scan_filters` 配置但不应用任何过滤器，适合临时排查是否被黑名单、大小范围、修改时间范围或目录剪枝挡掉。

扫描过滤器在目录遍历阶段执行，被过滤的条目不会进入 relation、detection 或 analysis。

`scan_filters` 按配置数组中的顺序执行；第一个启用的过滤器就第一个处理扫描条目。`whitelist` 默认关闭，启用后文件必须命中 whitelist 才会继续进入它后面的过滤器；字段与 `blacklist` 一致，但语义是“允许”。例如：

```json
{
  "name": "whitelist",
  "enabled": false,
  "path_globs": ["archives/**"],
  "prune_dir_globs": ["archives"],
  "allowed_files": ["sample.zip"],
  "allowed_extensions": [".zip", ".7z"]
}
```

`whitelist` 使用 `allowed_files` 和 `allowed_extensions` 表示允许的完整文件名和扩展名。每个 whitelist 字段为空时表示该维度不限制；多个非空字段会同时作为约束。`blacklist` 使用 `blocked_files` 和 `blocked_extensions` 表示禁止的完整文件名和扩展名。

`directory_prune` 的 `prune_dir_globs` / `path_globs` 在原生目录遍历阶段执行；命中的目录不会入栈，其整个子树也不会进入后续过滤器。`prune_dir_globs` 匹配任意层级的目录名，`path_globs` 匹配相对于扫描根的路径。`blacklist` 只负责具体文件名和扩展名过滤。

`blacklist` 常用字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `blocked_files` | `list[str]` | 完整文件名精确匹配，例如 `Thumbs.db`、`desktop.ini`。 |
| `blocked_extensions` | `list[str]` | 阻止扫描的文件扩展名。 |

`size_range` 用文件大小限制 filesystem 输出。只有落在配置范围内的文件才会进入 relation、detection 或 analysis；目录不受该过滤器影响。推荐写数学不等式，`r` 表示文件大小：

```json
{"name": "size_range", "enabled": true, "range": "1 MB < r < 10 MB"}
```

大小单位支持 `B`、`KB`、`MB`、`GB`、`TB` 和 `KiB`、`MiB`、`GiB`、`TiB`，按 1024 进位。也兼容旧的原始范围字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `gt` / `greater_than` | `int` | 文件大小必须大于该值。 |
| `gte` / `greater_than_or_equal` | `int` | 文件大小必须大于等于该值。 |
| `lt` / `less_than` | `int` | 文件大小必须小于该值。 |
| `lte` / `less_than_or_equal` | `int` | 文件大小必须小于等于该值。 |
| `eq` / `equal` | `int` | 文件大小必须等于该值。 |

`mtime_range` 用文件修改时间限制 filesystem 输出，推荐写数学不等式，`d` 表示文件修改时间：

```json
{"name": "mtime_range", "enabled": false, "date": "20260430 01:40 > d > 20250320 01:30"}
```

日期值支持纳秒时间戳、ISO 时间字符串，以及 `YYYYMMDD HH:MM` / `YYYYMMDD HH:MM:SS` / `YYYYMMDD`。旧的 `gt/gte/lt/lte/eq` 字段仍兼容。

目录扫描使用 Rust `scan_directory_snapshot`。过滤器无法映射到 native 参数时会显性报错，不做 Python fallback。

## performance

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `performance.worker.watchdog_no_progress_timeout_seconds` | `int` / `float` | worker 无进展超时，`0` 表示不限。任务没有总时长上限：只要 worker 仍在输出事件就持续推进，只有真正停滞才会被判定超时。 |
| `performance.worker.thread_capacity` | `int` | `IInArchive` 线程硬容量；`0` 由 worker 按机器能力探测。实际活动任务数由 native 自适应准入。 |
| `performance.worker.stage_thread_capacity` | `int` | 同步扫描、分析、校验、修复和后处理的固定 worker 线程容量；`0` 自动按机器能力选择。 |
| `performance.worker.max_inflight_files` | `int` | 同时存在的文件级异步状态机上限；`0` 自动取 worker 总容量的 4 倍，范围 64–512。 |
| `performance.worker.max_pending_stage_jobs` | `int` | Python blocking lane 的待执行作业硬上限，满载时异步生产者等待而不创建新线程。 |
| `performance.worker.adaptive_enabled` | `bool` | 是否启用基于实际输出吞吐的 native 动态并发控制。 |
| `performance.worker.initial_active_jobs` | `int` | native 初始活动任务数，`0` 自动选择。 |
| `performance.worker.exploration_strategy` | `str` | `calibrated`（默认，从 CPU 校准值小步探索）、`rapid`（大步起探）或 `full`（从线程容量向下探索）。 |
| `performance.worker.resource_diagnostics_enabled` | `bool` | 是否附带采样 CPU 和进程 IO，仅供校准诊断，生产默认关闭。 |
| `performance.worker.sample_interval_ms` | `int` | native 吞吐采样间隔，最小 100 ms。 |
| `performance.worker.minimum_window_seconds` / `maximum_window_seconds` | `float` | 单个稳定吞吐窗口的最短和最长时间。 |
| `performance.worker.large_window_bytes` | `int` | 达到该实际写入量后使用字节/秒比较并发探测。 |
| `performance.worker.small_window_jobs` / `small_window_files` | `int` | 小任务窗口达到该完成量后使用任务/秒或文件/秒比较。 |
| `performance.worker.improvement_ratio` / `regression_ratio` | `float` | 接受探测和触发回退的滞回阈值。 |
| `performance.worker.cooldown_windows` / `hold_windows` | `int` | 回退冷却和稳定点保持的窗口数。 |
| `performance.worker.warm_start_decay_seconds` | `float` | 活动会话完全空闲后保留最近确认并发作为温启动提示的线性衰减时间；`0`（默认）禁用温启动，且任何值都不会保留旧吞吐窗口。 |
| `performance.worker.warm_start_confirmations` | `int` | 最近并发至少被相邻吞吐窗口确认多少次后才允许用于温启动。 |
| `performance.worker.max_queue_jobs` | `int` | native 任务队列上限；达到上限时返回可重试的背压结果。 |
| `performance.worker.priority_aging_quantum` | `int` | native 优先级老化步长，避免低优先级请求长期饥饿。 |
| `performance.worker.writer_threads` | `int` | native worker 统一写出线程数。 |
| `performance.worker.memory_budget_bytes` | `int` | native worker 的估算内存准入预算；`0` 使用可用物理内存的默认比例。 |
| `performance.worker.job_buffer_budget_bytes` | `int` | 单个 native 解压任务的输出 inflight 缓冲上限。 |
| `performance.worker.memory_pause_available_mb` / `memory_resume_available_mb` | `int` | 系统可用内存进入紧急区时暂停新任务准入，以及恢复准入的阈值。 |
| `resource_guard` | `dict` | 可选资源护栏，用 analysis 估算的文件数、解包大小、压缩比等限制任务。 |

native worker 启动时采集逻辑处理器数和可用物理内存。线程容量为逻辑处理器数和 32 的最小值，不再由内存槽位裁剪；前台初始并发为 `ceil(逻辑处理器数 / 2)`，后台为 `ceil(逻辑处理器数 / 4)`。自动内存预算取启动时可用物理内存的 70%，但只作为累计任务 reservation 的硬准入预算。`thread_capacity`、`initial_active_jobs` 和 `memory_budget_bytes` 的正数值分别覆盖自动结果，`0` 表示自动计算。

所有解压任务共用的异步写入器提供累计实际接收字节、实际写入字节、完成文件和完成任务计数。控制器把一次从空闲到再次完全空闲的过程视为活动会话，但只在队列持续积压、活动任务接近当前上限时开启饱和测量段。大数据窗口比较实际写入字节/秒，小任务窗口比较完成任务/秒或文件/秒；吞吐上升时保留并继续小步探索，下降时退回之前的稳定并发并进入冷却。backlog 中断会立即放弃未完成探测、回到最近稳定并发并清空窗口；完全空闲会保存计数基线并让控制器无限期休眠。若显式启用温启动，下一活动会话可以使用随空闲时间衰减的最近确认并发作为启动提示，但仍必须重新采 baseline；实测默认禁用。CPU 和进程 IO 不参与生产决策，只有开启 `resource_diagnostics_enabled` 后才采样和输出。控制器不读取 `profile_key`，也不根据格式或 solid 状态选择并发。

归档格式、算法、solid 状态和文件数量不再产生 CPU 权重；solid 归档也没有全局单任务互斥。Python 只向 native 提供字典大小和内存 reservation，调度器据此执行硬内存准入；其余并发差异全部由整体实际吞吐反馈学习。

`resource_guard` 当前常用字段：

| 字段 | 说明 |
| --- | --- |
| `enabled` | 是否启用资源护栏。 |
| `max_file_count` | 归档条目数超过该值时阻止解压，`0` 表示不限。 |
| `max_total_unpacked_size` | 估算总解包大小上限，字节，`0` 表示不限。 |
| `max_largest_item_size` | 单个最大条目上限，字节，`0` 表示不限。 |
| `max_compression_ratio` | 压缩比上限，`0` 表示不限。 |

## watch

`watch` 配置控制 `sunpack watch` 的默认行为；CLI 参数仍可临时覆盖对应值。

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `cold_start_seconds` | `float` | 文件首次进入活跃态、尚无写入间隔样本时的等待时间，默认 1 秒。设为 `0` 会关闭动态等待。旧字段 `quiet_seconds` 仍作为该字段的兼容别名。 |
| `quiet_min_seconds` | `float` | 取得首个有效间隔后，动态静默时间的下限，默认 2.5 秒。它可以高于冷启动时间。 |
| `quiet_max_seconds` | `float` | 动态静默时间上限，默认 180 秒。 |
| `recursive` | `bool` | 是否递归监控目录。 |
| `initial_scan` | `bool` | 启动 watcher 时是否扫描已有文件。 |
| `max_folders` | `int` | 单次 watch 接受的最大路径数量。 |
| `observer_stop_timeout_seconds` | `float` | 停止 watchdog observer 时等待线程退出的超时。 |
| `partial_output_policy` | `string` | 部分恢复产物的处置方式：`discard`（默认）清理试解压目录，`promote` 将部分恢复产物提升到正式输出目录。 |

没有活跃文件或待处理密码重试时，watch 服务会无限等待 watchdog 或控制事件；只有静默期和 debounce 尚未到期时才设置一次性 deadline。

watch 不按扩展名或下载器类型推测下载状态。`created`、`moved`、`modified` 事件使输入进入活跃态；首次使用 `cold_start_seconds`，取得首个有效内容变化间隔后立即进入不低于 `quiet_min_seconds` 的动态区间，随后按该文件最近 12 次实际内容变化的最大间隔调整。长间隔会立即拉长，缩短时每次只向目标移动一部分，最终受 `quiet_min_seconds` 和 `quiet_max_seconds` 限制。只有 size 或 mtime 变化的事件参与间隔学习，但其他内容事件仍会重置当前静默计时。每个活跃周期只触发一次主流程；普通成功、部分成功和失败都不会自行重试。新分卷到达或密码源变化会把受影响的输入重新置为活跃态。

watch 的试解压输出位于监控根目录下的 `.sunpack_watch_probes`。该顶层目录在 watcher 运行和多次尝试之间保持存在；启动恢复以及每次尝试结束时只清理其内部工作内容，避免监控目录因为顶层临时目录反复创建、删除而刷新。完整成功始终提升到正式输出目录；部分成功按 `partial_output_policy` 清理或提升；失败始终清理试解压工作内容。

## extraction

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `write_progress_manifest` | `bool` | 是否把内部 progress manifest 写成输出目录中的 `.sunpack/extraction_manifest.json`；默认只保留在内存里供 verification/repair 使用。 |

## input_planning / repair_inspection / analysis

三组配置分别对应业务输入规划、repair 检查缓存和通用分析能力。正常主流程由 Detection/input planner 调用 Analysis 形成 worker 输入；只有 repair loop 进入 Repair Inspection。

`input_planning` 字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `enabled` | `bool` | 是否启用归档输入规划。 |
| `cache_size` | `int` | request 级中立 Analysis report 缓存数量。输入规划按任务顺序执行，不再由 Python 任务 worker 数量控制。 |

`repair_inspection.cache_size` 控制 repair 状态报告缓存数量。cache identity 包含 source identity、分卷、patch digest 和 repair inspection request，避免不同修复状态互相污染。

`analysis` 只配置单次通用能力调用：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `max_concurrent_reads` | `int` | 单视图并发读取上限。 |
| `shared_cache_mb` | `int` | 二进制视图共享读缓存。 |
| `max_read_mb_per_archive` | `int` / `null` | 单归档最多读取大小，`null` 表示不限。 |
| `prepass` | `dict` | signature prepass 配置。 |
| `fuzzy` | `dict` | fuzzy binary profile 配置。 |
| `thresholds.extractable_confidence` | `float` | analysis 认为可直接抽取的置信度。 |
| `thresholds.repair_confidence` | `float` | 保留给损坏/修复倾向判断的置信度参考。 |
| `modules` | `list[dict]` | ZIP/RAR/7z/TAR/压缩流等结构模块开关和参数。 |

完整 embedded 深扫由顶层共享配置控制：

```json
"embedded_scan": {
  "enabled": true
}
```

`embedded_scan.enabled` 默认为 `true`。Analysis 先执行低成本头尾 prepass；只有没有选出可解压结构时，才调用其内部 Rust 全流 scanner。Detection 已经完成扫描时，调用层把完整 prepass 放入 `AnalysisRequest`，避免重复读取文件。完整深扫没有 Python fallback、扫描窗口或最大命中数配置。

重要行为：

- Analysis 的中等置信度不直接触发 repair。流程先尝试 extraction，再由 verification 判断是否需要 repair。
- Input planning cache 以归档 source fingerprint 分组；Inspect cache 额外区分 patch digest 和 request fingerprint。
- 结构读取和大文件 I/O 走 Rust binary view，不保留 Python 大文件解析 fallback。

常见 module 参数：

| 模块 | 常用字段 |
| --- | --- |
| `zip` | `max_cd_entries_to_walk` |
| `rar` | `max_blocks_to_walk` |
| `seven_zip` | `max_next_header_check_bytes` |
| `tar` | `max_entries_to_walk` |
| `gzip` / `bzip2` / `xz` / `zstd` / `tar_*` | `max_probe_bytes` |

## verification

`verification` 不再是简单分数阈值模型。它会汇总多个 method 的观察结果，计算完整度、文件状态、source integrity、recoverable upper bound 和下一步决策。

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `enabled` | `bool` | 是否启用解压结果校验流水线。 |
| `max_retries` | `int` | verification 失败后的普通重试次数。 |
| `cleanup_failed_output` | `bool` | 重试前是否清理失败输出目录。 |
| `accept_partial_when_source_damaged` | `bool` | 源归档损坏时是否允许接受部分恢复结果。 |
| `partial_min_completeness` | `float` | 部分恢复最低完整度。 |
| `complete_accept_threshold` | `float` | complete 判定完整度阈值。 |
| `partial_accept_threshold` | `float` | partial 判定完整度阈值。 |
| `retry_on_verification_failure` | `bool` | verification 失败时是否允许普通重试。 |
| `methods` | `list[dict]` | 有序 verification method 列表。 |

旧配置项 `initial_score`、`pass_threshold`、`fail_fast_threshold` 已不是当前模型的一部分，不应再写入配置。

内置 method：

| 方法 | 说明 |
| --- | --- |
| `extraction_exit_signal` | 消费 worker 状态、诊断和 progress manifest。 |
| `output_presence` | 检查输出目录是否存在、是否为空，并合并 worker manifest 进度。 |
| `expected_name_presence` | 用 detection/analysis 提供的条目名样本检查输出命中情况。 |
| `manifest_size_match` | 用归档条目数和原始大小估算完整度。 |
| `archive_test_crc` | 用 7z.dll 读取归档状态，并由 Rust 扫描输出、建立 path/basename 索引、计算 CRC 和覆盖率。 |
| `sample_readability` | 用 Rust 抽样读取输出文件头尾，确认产物基本可读。 |

`archive_test_crc` 和 `sample_readability` 当前默认启用。前者已经 Rust 化输出索引和 CRC 比较，适合大量小文件场景。

## repair

`repair` 只响应 verification 的 `repair` 决策。它生成候选或 patch plan，候选必须重新 extraction + verification，由比较器决定是否接受、继续修复或停止。

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `enabled` | `bool` | 是否启用 repair 层。 |
| `workspace` | `str` | repair 候选工作目录。 |
| `keep_candidates` | `bool` | 是否保留候选文件。 |
| `max_modules_per_job` | `int` | 单个 repair job 最多尝试多少模块。 |
| `max_attempts_per_task` | `int` | 兼容字段；当前主要使用 repair round 限制。 |
| `max_repair_rounds_per_task` | `int` | 单任务 repair loop 上限。 |
| `max_repair_seconds_per_task` | `int` / `float` | 单任务 repair 总耗时上限。 |
| `max_repair_generated_files_per_task` | `int` | 单任务最多生成候选文件数。 |
| `max_repair_generated_mb_per_task` | `int` / `float` | 单任务最多生成候选总大小。 |
| `stages` | `dict` | `targeted`、`safe_repair`、`deep` 阶段开关。 |
| `safety` | `dict` | `allow_unsafe`、`allow_partial`、`allow_lossy`。 |
| `deep` | `dict` | deep 模块候选数、输入/输出大小、条目数和验证预算。 |
| `auto_deep` | `dict` | targeted/safe 无改进时自动放行少量 deep 候选。 |
| `beam` | `dict` | patch plan beam 搜索和候选评估上限。 |
| `policy` | `dict` | 内置 diagnosis HGT 与 repair policy transformer 的运行控制。 |
| `modules` | `list[dict]` | 显式 repair 模块开关。 |

### policy

| 字段 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `enabled` | `bool` | `true` | 是否启用内置双模型 repair policy。 |
| `strict_model_errors` | `bool` | `false` | 模型推理异常时是否直接抛出；关闭时记录模型错误并返回 unavailable。 |
| `graph_stop_stale_patience` | `int` | `100` | repair 图连续多少次没有最佳状态提升后强制 stop。 |

双模型由 `sunpack.repair.model.RepairModelRuntime` 直接管理。`provider_package`、`step_mode`、`fallback_to_selector` 和 `disable_beam_when_model_active` 均已删除，配置中出现会直接报错。模型资产由根目录 `models/manifest.json` 管理，可用 `python -m pytest tests\unit\test_model_runtime.py` 检查。

### repair stages

| stage | 用途 |
| --- | --- |
| `targeted` | 精确字段修复，例如 ZIP EOCD、7z header CRC、RAR end block。 |
| `safe_repair` | 边界修剪、尾部垃圾、元数据降级、低风险部分恢复。 |
| `deep` | 高成本扫描或重建，例如 ZIP deep partial、nested payload、7z solid block salvage、RAR quarantine。 |

`stages.deep` 默认关闭，但 `auto_deep.enabled` 默认开启：只有 targeted/safe 失败、verification 仍请求 repair、且输入大小低于限制时，才自动尝试少量 deep 候选。

### beam

| 字段 | 说明 |
| --- | --- |
| `enabled` | 是否启用候选 beam 评估。 |
| `beam_width` | 每轮保留的状态数量。 |
| `max_candidates_per_state` | 每个状态最多展开候选数。 |
| `max_analyze_candidates` | 每轮进入 analysis 的候选上限。 |
| `max_assess_candidates` | 每轮进入 extraction/verification 的候选上限。 |
| `max_rounds` | 单次 beam 最多轮数。 |
| `min_improvement` | 候选必须超过 incumbent 的最小完整度提升。 |

候选比较会综合 assessment status、完整度、complete/partial/failed/missing 文件数、source integrity、patch cost 和 repair module 排名。完整度没有提升时，loop 会主动停止。

### 当前模块矩阵

配置文件中的 `repair.modules` 应与注册表一致。可以用下面的脚本检查：

```powershell
@'
from sunpack.repair.pipeline.registry import discover_repair_modules, get_repair_module_registry
discover_repair_modules()
print(sorted(get_repair_module_registry().all()))
'@ | python -
```

当前主要能力：

| 格式 | 能力 |
| --- | --- |
| ZIP | EOCD/comment/CD count/CD offset/ZIP64/local header/data descriptor 修复，central directory rebuild，entry quarantine，partial/deep recovery，overlap/duplicate/conflict resolver。 |
| TAR | header checksum、metadata downgrade、sparse/PAX/GNU longname、trailing junk、trailing zero block、压缩 TAR 截断恢复。 |
| gzip/bzip2/xz/zstd | trailing junk trim、footer/frame salvage、truncated partial recovery。 |
| 7z | start header CRC、next header field、boundary trim、precise boundary、CRC field、solid block partial salvage。 |
| RAR | trailing junk、carrier crop、block chain trim、end block repair、file quarantine rebuild。 |
| nested/carrier | carrier crop deep recovery、nested payload salvage。 |

旧键 `repair.trigger_on_medium_confidence`、`repair.trigger_on_extraction_failure` 和 `repair.thresholds` 已移除；配置中出现这些键会直接报错。

## detection

| 字段 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `enabled` | `bool` | `true` | detection 层总开关。设为 `false` 时不执行 detection 规则，只对常规归档扩展名/分卷入口生成任务；需要完全绕过初始扫描时使用 `extract --direct-file <file>`。 |

## detection.fact_collectors

| 名称 | 作用 |
| --- | --- |
| `file_facts` | 采集路径、名称、父目录、大小等基础信息。 |
| `magic_bytes` | 读取文件头 magic bytes。 |
| `scene_markers` | 采集目录场景 marker，供 `scene_facts` 处理器使用。 |

## detection.processors

| 名称 | 作用 |
| --- | --- |
| `embedded_archive` | 对普通归档检测尚未解决且入选大小覆盖集的文件调用共享 embedded scanner。 |
| `scene_facts` | 识别游戏、程序、资源目录等场景。 |
| `zip_structure` | 检查 ZIP local header。 |
| `zip_eocd_structure` | 检查 ZIP EOCD 和 central directory。 |
| `tar_header_structure` | 检查 TAR header checksum 和 ustar marker。 |
| `compression_stream_structure` | 检查 gzip、bzip2、xz、zstd 轻量流结构。 |
| `pe_overlay_structure` | 检查 PE overlay 中的归档载荷。 |
| `seven_zip_structure` | 检查 7z signature、start header CRC、next header 范围和 NID。 |
| `rar_structure` | 检查 RAR4/RAR5 signature、main header 和 block/header walk。 |

嵌入扫描只有一个成本字段，位于 `embedded_payload_identity` 规则：

| 字段 | 说明 |
| --- | --- |
| `deep_scan_single_candidate_ratio` | 单个未解决逻辑候选达到未解决候选总字节数的最低占比；默认 `0.3`。达到阈值的候选均执行可靠完整扫描。 |

单候选占比决定“哪些逻辑候选获准执行整个 embedded payload precheck 模块”，不限制单个候选的读取范围。未获准的候选不会解析 PE、识别安装器或扫描嵌入归档。分卷只作为一个逻辑候选参与总大小计算，成员卷不会重复计数。获准后先识别 executable carrier；命中已知安装器会立即拒绝且不启动完整嵌入扫描。Detection 复用 `sunpack.analysis.embedded` 的 Rust scanner、文件身份缓存和结果契约。嵌入扫描不检查扩展名，也没有窗口、最大命中数或扫描档位；结构校验得到的候选和命中图会传给 Analysis，避免再次执行全流扫描。

## detection.rule_pipeline

Detection 不调用完整 analysis scheduler 做确认。Detection 中的任意位置 embedding 由递归控制器授权后的 `embedded_payload_identity` 执行；绕过 Detection 的任务则由 Analysis 在头尾分析未解决时调用同一个 scanner。其他格式事实均由有界 Rust probe 产生。大文件压缩流只读取头尾窗口，ZIP 读取 EOCD 尾窗和有限目录项，7z/RAR/TAR 读取受配置上限约束的头部或条目。

检测规则分两层：

- `precheck`：完整结构的严格识别。每个格式规则声明常见格式和扩展名；关系层提供逻辑分卷提示后，匹配规则会被临时提前，校验失败再回到配置顺序。安装器否决与 embedded payload 识别固定最后执行。
- `scoring`：只处理字段损坏、结构不完整等模糊证据。

每条规则至少包含：

```json
{"name": "zip_structure_accept", "enabled": true}
```

`config validate` 会校验规则名和规则 schema。默认配置的主要规则：

| 规则 | 层 | 说明 |
| --- | --- | --- |
| `zip_structure_accept` | precheck | 结构可信的 ZIP 快速接受。 |
| `tar_structure_accept` | precheck | 结构可信的 TAR 快速接受。 |
| `seven_zip_structure_accept` | precheck | start/next header 可信的 7z 快速接受。 |
| `rar_structure_accept` | precheck | main header/block walk 可信的 RAR 快速接受。 |
| `compression_stream_accept` | precheck | 完整校验 gzip、bzip2、xz、zstd 流并快速接受。 |
| `embedded_payload_identity` | precheck | 先否决已知安装器，再对获准深扫且找到可靠嵌入归档的文件直接接受。 |
| `zip_structure_identity` | scoring | 累计 local header、EOCD、目录锚点和逻辑命名先验。 |
| `tar_structure_identity` | scoring | 累计 ustar、成员名、数值字段、typeflag、payload 范围和逻辑命名先验。 |
| `seven_zip_structure_identity` | scoring | 累计 signature、版本、next-header 范围、CRC/NID 和逻辑命名先验。 |
| `rar_structure_identity` | scoring | 累计 signature、版本、header type/size、后续块和逻辑命名先验。 |
| `compression_stream_identity` | scoring | 累计流 signature、header 字段、第二锚点、局部完整性和逻辑命名先验。 |

Scoring 不执行严格完整性校验，也不调用 analysis scheduler。扩展名不是独立规则，而是各格式规则内部最多 2 分的命名先验；扩展名或分卷名称本身永远达不到归档阈值。格式字段由 Rust probe 读取，CRC、目录闭合、完整解码和精确流尾仍只用于 precheck 强接受，失败时 scoring 可继续组合其他独立字段。

模糊证据字段依据 PKWARE ZIP APPNOTE、7-Zip 官方恢复说明、RARLAB RAR 5.0 technote、POSIX ustar、RFC 1952、bzip2 1.0.8 manual、XZ File Format 1.2.1 和 Zstandard Compression Format 设计。历史 `extension`、`magic_bytes`、`embedded_archive`、`structure_evidence_identity` scoring 规则、detection 专用 `structure_evidence` processor、CAB/ARJ/CPIO 孤立支持和 confirmation 层均不再存在。

### deep_scan_single_candidate_ratio

默认扫描普通检测尚未解决集合中，单个逻辑候选大小占该集合总大小至少 30% 的候选：

```json
{
  "detection": {
    "rule_pipeline": {
      "precheck": [
        {
          "name": "embedded_payload_identity",
          "deep_scan_single_candidate_ratio": 0.3
        }
      ]
    }
  }
}
```

`0` 禁用该阶段。阈值使用 `>=` 判断，所有达到阈值的候选都会扫描；默认 `0.3` 因而同一集合最多选中三个正大小候选。`1` 只会扫描独占未解决候选总大小的单个候选。例如只扫描占比至少 50% 的候选：

```json
{
  "name": "embedded_payload_identity",
  "enabled": true,
  "deep_scan_single_candidate_ratio": 0.5
}
```

## 密码文件

`builtin_passwords.txt` 是内置高频密码表，按每行一个密码读取。不存在时程序会尝试创建默认文件。

`passwords.clipboard_passwords_enabled` 控制普通 CLI 启动时是否读取当前剪贴板文本作为本次运行的密码来源。该开关不影响 watch 服务的剪贴板监控；watch 监控仍由 `watch.clipboard_monitor_enabled` 控制，并会把最近剪贴板密码合并进内置密码文件的托管区。

密码来源顺序：

1. `--password` 和 `--pw-file` 提供的用户密码。
2. 最近成功密码。
3. `builtin_passwords.txt` 内置密码。

使用 `--no-builtin-pw` 可禁用内置密码。

## 修改建议

- 想减少误解压：优先调 `filesystem.scan_filters`、结构 identity 和确认规则。
- 想提高召回率：优先调 `extension`、结构 identity、`embedded_payload_identity` 和阈值。
- 想控制修复成本：调 `repair.max_repair_*`、`deep`、`auto_deep` 和 `beam`。
- 想看为什么失败或为什么接受：跑 `inspect -v`，再看 recovery report 和 verification coverage。
- 修改后运行 `python sunpack.py config validate`。
