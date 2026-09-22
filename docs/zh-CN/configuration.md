# 配置文件说明

[English](../configuration.md) | **简体中文**

常用配置文件是 `sunpack_config.json`，完整配置文件是 `sunpack_advanced_config.json`。程序先读取高级配置，再用简化配置覆盖同名字段：对象递归合并，数组和普通值整体覆盖。

源码运行时通常从仓库根目录或当前工作目录读取配置。安装版固定读取 `%ProgramData%\SunPack\sunpack_config.json`，并以安装目录中的 `sunpack_advanced_config.json` 作为随版本更新的基础层，因此无需重装即可调整 `sunpack_config.json`。

检查和查看有效配置：

```powershell
python sunpack.py config validate
python sunpack.py config show
```

## 运行时覆盖

环境变量 `SUNPACK_CONFIG_OVERRIDES` 可以在启动前覆盖任意配置项。值可以是内联 JSON 对象，也可以是 JSON 文件路径。

合并顺序为：`sunpack_advanced_config.json` → `sunpack_config.json` → 运行时覆盖。命名模块列表 `filesystem.scan_filters`、`detection.fact_collectors`、`detection.processors` 和 `detection.rule_pipeline.precheck` 按 `name` 合并，覆盖时只需写要改变的模块。

例如临时关闭大小过滤：

```powershell
$env:SUNPACK_CONFIG_OVERRIDES = '{"filesystem": {"scan_filters": [{"name": "size_range", "enabled": false}]}}'
python sunpack.py scan C:\Archives
```

未知顶层配置节会直接报错。CLI 参数（例如 `--recur`、`--cleanup`）在配置加载后作为最后一层覆盖。

测试运行时默认关闭 `size_range` 过滤器，使测试可以使用小于 1 MB 的文件；调用方已经设置的 `SUNPACK_CONFIG_OVERRIDES` 会被保留。

## 顶层结构

```json
{
  "cli": {},
  "runtime": {},
  "recursive_extract": "*",
  "nested_extraction_policy": {},
  "post_extract": {},
  "filesystem": {},
  "performance": {},
  "watch": {},
  "passwords": {},
  "extraction": {},
  "embedded_scan": {},
  "input_planning": {},
  "analysis": {},
  "verification": {},
  "detection": {}
}
```

## cli

| 字段 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `language` | `str` | `zh` | CLI 语言。`zh` 使用中文，其它值使用英文。 |

## recursive_extract

| 值 | 说明 |
| --- | --- |
| `*` | 只要每轮仍产生新的可处理嵌套归档，就持续处理。 |
| 正整数 | 固定允许的递归轮数。 |
| `?` | 每轮产生新的可处理嵌套归档后询问是否继续。 |

第一轮完全按用户给出的文件或目录范围执行。后续轮次会对解压输出中的候选归档应用 `nested_extraction_policy`，再决定是否继续处理。

CLI 可以用 `--recur` 临时覆盖该设置。

## nested_extraction_policy

该策略在嵌套归档进入密码处理和解压前，根据目录上下文批量判断它是否属于用户语义上的独立归档。第一轮用户明确指定的输入不受该策略影响；第二轮起，输出中发现的候选统一参与判断。

判断使用一次目录快照中的原始条目，保留黑名单和大小过滤前的目录上下文。多个候选统一聚合，一组分卷只计一个归档。拒绝的候选会出现在运行摘要的策略跳过记录中，不计为解压失败。

| 字段 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `enabled` | `bool` | `true` | 是否启用嵌套归档授权。 |
| `byte_ratio_exponent` | `float` | `1` | 候选归档字节占比的指数，必须为正数。 |
| `project_ratio_exponent` | `float` | `1` | 候选归档项目占比的指数，必须为正数。 |
| `authorization_bias` | `float` | `0` | 授权分偏置；正数更宽松，负数更保守。 |
| `minimum_authorization_score` | `float` | `0.85` | 局部目录和输出根目录授权分的最低值。 |
| `minimum_archive_byte_ratio` | `float` | `0.1` | 候选字节占比低于该值时拒绝。 |
| `hard_maximum_other_projects` | `int` | `1000` | 有效非候选项目超过该值时拒绝。 |

候选字节占比为 `B`，候选归档项目数为 `A`，有效非候选项目数为 `O`，压缩项目占比为 `P = A / (A + O)`。授权分为：

```text
S = sigmoid(c + a × logit(B) + b × logit(P))
```

其中 `a`、`b`、`c` 对应两个指数和偏置。`S` 是确定性的 `0..1` 评分，不表示校准概率。

## post_extract

| 字段 | 类型 | 可选值 | 说明 |
| --- | --- | --- | --- |
| `archive_cleanup_mode` | `str` | `d`、`r`、`k` | 成功后处理原归档：删除、移入回收站、保留。 |
| `flatten_single_directory` | `bool` | `true` / `false` | 结果只有一个顶层目录时，是否提升该目录内容。 |

默认清理模式为 `r`。

## filesystem

### directory_scan_mode

| 值 | 说明 |
| --- | --- |
| `*` | 递归扫描目标目录及子目录。 |
| `-` | 只扫描目标目录第一层文件。 |

该设置只影响输入目录扫描范围，不影响解压输出的递归轮次。

### scan_filters

`scan_filters_enabled` 是过滤器总开关。设为 `false` 时，过滤器配置会保留但不执行。

过滤器按数组顺序执行。`directory_prune` 会在目录遍历阶段剪枝；`whitelist`、`blacklist`、`size_range` 和 `mtime_range` 作用于扫描条目。被过滤的文件不会进入关系识别、检测或结构分析。

`whitelist` 示例：

```json
{
  "name": "whitelist",
  "enabled": false,
  "path_globs": ["archives/**"],
  "prune_dir_globs": ["archives"],
  "allowed_files": ["sample.zip"],
  "allowed_extensions": [".zip", ".7z", ".rar"]
}
```

`whitelist` 的非空字段同时作为约束；`allowed_files` 匹配完整文件名，`allowed_extensions` 匹配扩展名。`blacklist` 使用对应的 `blocked_files` 和 `blocked_extensions`。

`directory_prune` 支持 `prune_dir_globs` 和 `path_globs`。前者匹配任意层级的目录名，后者匹配相对于扫描根的路径；被剪枝目录的整个子树都不会继续遍历。

`size_range` 用文件大小限制扫描结果，`r` 表示字节数：

```json
{"name": "size_range", "enabled": true, "range": "1 MB < r < 10 MB"}
```

支持 `B`、`KB`、`MB`、`GB`、`TB` 以及 `KiB`、`MiB`、`GiB`、`TiB`，按 1024 进位。也支持以下等价字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `gt` / `greater_than` | `int` | 文件大小必须大于该值。 |
| `gte` / `greater_than_or_equal` | `int` | 文件大小必须大于等于该值。 |
| `lt` / `less_than` | `int` | 文件大小必须小于该值。 |
| `lte` / `less_than_or_equal` | `int` | 文件大小必须小于等于该值。 |
| `eq` / `equal` | `int` | 文件大小必须等于该值。 |

`mtime_range` 用文件修改时间限制扫描结果，`d` 表示修改时间：

```json
{"name": "mtime_range", "enabled": false, "date": "20260430 01:40 > d > 20250320 01:30"}
```

日期支持纳秒时间戳、ISO 时间字符串，以及 `YYYYMMDD HH:MM`、`YYYYMMDD HH:MM:SS` 和 `YYYYMMDD`。也支持 `gt`、`gte`、`lt`、`lte`、`eq` 字段。

目录扫描和过滤由原生扫描能力执行；过滤器无法映射到原生参数时会明确报告错误。

## runtime

`runtime` 控制 Watch 与前台工作负载共享的进程级 Runtime 行为。

| 字段 | 默认 | 说明 |
| --- | ---: | --- |
| `process_mode` | `normal` | 共享 RuntimeHost 与 native worker 的 Windows 调度基线。 `normal` 使用正常优先级；`background` 启用 Windows Background Processing Mode；`high` 使用 `HIGH_PRIORITY_CLASS`，可能降低其它应用的响应性。 |

前台 `extract`、`scan`、`inspect` 会用各自的 `--process-mode` 临时覆盖该基线；未显式指定时 CLI override 默认是 `high`。命令结束后 override 不立即失效，而是在现有空闲维护时机（`watch.runtime_cache_cleanup_idle_seconds`）到期后清除，并恢复最新热重载的 `runtime.process_mode`。Watch 运行时修改 `runtime.process_mode` 会热应用且不重启 scheduler；若 CLI override 仍有效，则仍由 override 优先，直到空闲到期。

## performance

运行时和 worker 参数都位于 `performance`。默认值如下：

| 字段 | 默认 | 说明 |
| --- | ---: | --- |
| `persistent_server_idle_seconds` | `15` | 常驻服务空闲多久后退出。 |
| `worker.watchdog_no_progress_timeout_seconds` | `180` | 没有进展达到该时长时报告停滞；`0` 表示不限。 |
| `worker.thread_capacity` | `0` | 解压线程容量；`0` 自动按机器能力选择。 |
| `worker.stage_thread_capacity` | `0` | 扫描、分析、校验和后处理的线程容量；`0` 自动选择。 |
| `worker.max_inflight_files` | `0` | 文件级并发上限；`0` 自动选择，自动范围为 64–512。 |
| `worker.max_pending_stage_jobs` | `4096` | 阶段作业等待上限。 |
| `worker.adaptive_enabled` | `true` | 是否允许被动吞吐控制器在外部环境显著变化时降低或恢复 CPU 配额。 |
| `worker.resource_diagnostics_enabled` | `false` | 是否采样 CPU 诊断数据；不参与配额决策。 |
| `worker.observation_window_seconds` | `1.0` | 被动吞吐观察窗口，单位秒。 |
| `worker.throughput_change_ratio` | `0.40` | 相对基线吞吐变化达到该比例时调整 CPU 配额。 |
| `worker.max_queue_jobs` | `4096` | 原生任务队列上限。 |
| `worker.priority_aging_quantum` | `32` | 优先级老化步长。 |
| `worker.backpressure_retries` | `120` | 遇到队列背压时的重试次数。 |
| `worker.writer_threads` | `4` | 写出线程数。 |
| `worker.job_buffer_budget_bytes` | `33554432` | 单任务输出缓冲上限。 |
| `worker.space_gate_enabled` | `true` | 是否在任务进入写出阶段前检查磁盘空间。 |
| `worker.space_poll_interval_ms` | `1000` | 磁盘空间检查间隔。 |
| `worker.space_status_report_interval_ms` | `15000` | 磁盘空间状态报告间隔。 |

Native worker 以 CPU credit 作为唯一解压并发预算。默认 nominal budget 等于逻辑核心数，每个已准入归档任务先占 1 个 base credit；格式不分配固定权重。7-Zip 内部 decoder 只有在真正准备创建额外并行执行线程时，才同步向同一个 budget 申请 extra credits；申请不到就少开线程或退回串行路径，因此外层任务与内层 decoder 不会形成两个互不知情的并发层。

吞吐量控制器不再主动搜索最优并发。它只在 CPU credit 恰好打满（`reserved_cpu_credits == effective_cpu_budget`）时按实际写出吞吐被动观察；低于配额说明任务不足，高于配额只会出现在非抢占降档后的短暂过渡期，这两种情况都直接丢弃当前未完成窗口。默认观察窗口为 1 秒；相对当前稳定基线下降至少 40% 时，effective CPU budget 按 `max(1, logical_processors / 8)` 降低一级；相对基线提高至少 40% 时，按同样步长恢复，最高回到 nominal budget。每次配额变化后旧基线立即失效。第一次采样观察到新配额恰好打满时只确定窗口起点，不计入该次采样之前的时间和字节；从下一次采样起连续满配额累计满 1 秒后才形成新窗口并建立基线。期间一旦不再恰好打满，当前窗口立即作废并等待下一次满配额重新起点。

## watch

`watch` 控制监控服务的等待、输出、剪贴板和通知行为。CLI 监控根目录保存在程序资源目录下的 `sunpack_watch_roots.txt`，每行可以写 `输入目录` 或 `输入目录 | 输出根目录`。

| 字段 | 默认 | 说明 |
| --- | ---: | --- |
| `cold_start_seconds` | `0.0` | 文件首次进入活跃态时的等待时间。默认值为 0，文件准备好后可立即处理。 |
| `quiet_min_seconds` | `0.0` | 动态静默时间下限。 |
| `quiet_max_seconds` | `180.0` | 动态静默时间上限；`cold_start_seconds` 为 0 时不进入动态静默等待。 |
| `boundary_confirmation_seconds` | `0.5` | 文件边界确认的观察时间。 |
| `max_folders` | `16` | 配置中的目录数量上限字段，当前 CLI 目录列表由 `sunpack_watch_roots.txt` 管理。 |
| `observer_stop_timeout_seconds` | `5.0` | 停止文件系统观察线程的等待时间。 |
| `runtime_cache_cleanup_enabled` | `true` | 是否清理空闲运行缓存。 |
| `runtime_cache_cleanup_idle_seconds` | `10.0` | 共享空闲维护等待时间。到期时 CLI process-mode override 失效；`runtime_cache_cleanup_enabled` 为 true 时同时清理运行缓存。 |
| `password_retry_debounce_seconds` | `0.5` | 密码文件或剪贴板变化后，触发失败任务重试前的等待时间。 |
| `password_retry_include_subtree` | `true` | 密码来源变化时是否重试对应目录的子树任务。 |
| `directory_password_file_auto_create` | `true` | Watch 是否在每个监控目录下自动创建 `sunpack-passwords.txt`；设为 `false` 时仍会读取已有文件。 |
| `clipboard_monitor_enabled` | `true` | 是否监控剪贴板密码变化。 |
| `clipboard_builtin_max_entries` | `30` | 保留的剪贴板密码数量。 |
| `enabled` | `false` | 配置层标记；CLI 服务实际运行状态由 `watch start` 和 `watch stop` 管理。 |
| `roots` | `[]` | 配置中的默认根目录列表；CLI 服务使用根目录文件中的列表。 |
| `out_dir` | `.` | 未在根目录文件中指定输出根时使用的默认输出位置；相对路径按输入目录解析。 |
| `tray_enabled` | `true` | 是否启用托盘入口。 |
| `toast_enabled` | `true` | 是否发送 Windows 通知。 |
| `toast_update_interval_ms` | `50` | 通知进度更新间隔。 |
| `toast_completion_debounce_ms` | `800` | 合并完成通知的等待时间。 |
| `toast_success_ttl_seconds` | `3.0` | 成功通知保留时间。 |
| `toast_failure_ttl_seconds` | `5.0` | 失败通知保留时间。 |
| `toast_report_retention_days` | `30` | 通知失败报告保留天数。 |
| `toast_report_max_files` | `16` | 失败报告文件数量上限。 |
| `toast_report_max_bytes` | `2097152` | 失败报告总大小上限，单位为字节。 |
| `state_dir` | `""` | 监控状态目录；为空时使用根目录文件旁的 `.sunpack_watch`。 |

监控服务只观察每个根目录的直接文件，不递归监听子目录。输入根必须位于 NTFS 卷，并且该卷有可读取的 USN Journal；否则该根无法启动监控。

`created`、`moved` 和 `modified` 事件会使文件进入活跃态。监控按实际内容变化学习静默间隔；单纯 size 或 mtime 变化会参与间隔学习，其它内容事件会重置当前计时。一个活跃周期只提交一次主处理流程。新分卷到达或密码来源变化会重新激活受影响任务。

输出根可以跨盘。完整输出、部分输出和失败输出都直接写入对应输出根；输出根位于监控输入目录下时，输出目录事件不会被当作新的输入候选。不同监控根的输出根不能互为严格的祖先和子目录，相同输出根可以共享。

## passwords

| 字段 | 默认 | 说明 |
| --- | ---: | --- |
| `clipboard_passwords_enabled` | `true` | 普通 CLI 启动时是否读取当前剪贴板文本。 |
| `directory_passwords_enabled` | `true` | 是否读取归档同目录的密码文件。 |
| `directory_passwords_max_file_bytes` | `1048576` | 同目录密码文件的最大读取大小。 |
| `directory_passwords_max_password_length` | `512` | 单条密码的最大长度。 |

同目录密码文件名为 `sunpack-passwords.txt`，一行一个密码。归档解压时，候选来源按“最近成功密码 → 同目录密码 → CLI 参数和密码文件 → 剪贴板 → 内置密码”合并并去重；在归档加密状态尚未确定时，空密码也可能作为首个候选尝试。`--no-builtin-pw` 和 `--no-dir-pw` 可以分别关闭内置密码和同目录密码。

## extraction

| 字段 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `write_progress_manifest` | `bool` | `false` | 是否把进度清单写入输出目录的 `.sunpack/extraction_manifest.json`。 |
| `content_requirement` | `str` | `complete` | 内容要求，可选 `complete` 或 `allow_partial`。 |

## embedded_scan

| 字段 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `enabled` | `bool` | `true` | 是否允许扫描文件载体中的嵌入归档。 |

该设置不依赖扩展名。系统会优先使用低成本头尾信息；需要时对获准候选执行受边界约束的完整嵌入扫描。同一输入已经得到的嵌入扫描结果会在后续判断中复用。

## input_planning

| 字段 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `enabled` | `bool` | `true` | 是否启用归档输入规划。 |
| `cache_size` | `int` | `512` | 单次请求中保留的分析报告数量。 |

输入规划把结构分析结果转换为普通归档、分卷和嵌入输入；它不改变源文件。

## analysis

| 字段 | 默认 | 说明 |
| --- | ---: | --- |
| `max_concurrent_reads` | `1` | 单个输入的并发读取上限。 |
| `shared_cache_mb` | `64` | 共享二进制读取缓存大小。 |
| `max_read_mb_per_archive` | `256` | 单个归档的读取上限；`null` 表示不限。 |
| `prepass.enabled` | `true` | 是否读取头尾区域进行快速预检。 |
| `prepass.head_bytes` / `tail_bytes` | `1048576` / `1048576` | 头部和尾部预检大小。 |
| `fuzzy.enabled` | `true` | 是否启用二进制特征分析。 |
| `thresholds.extractable_confidence` | `0.85` | 可直接抽取的最低置信度。 |

默认结构模块及主要上限：

| 模块 | 默认上限 |
| --- | --- |
| `zip` | `max_cd_entries_to_walk = 64` |
| `rar` | `max_blocks_to_walk = 4096` |
| `seven_zip` | `max_next_header_check_bytes = 1048576` |
| `tar` | `max_entries_to_walk = 64` |
| `gzip`、`bzip2`、`xz`、`zstd`、`tar_gz`、`tar_bz2`、`tar_xz`、`tar_zst` | `max_probe_bytes = 4194304` |

`fuzzy.modules.binary_profile` 默认使用 65536 字节窗口、最多 8 个窗口、最多 1048576 字节样本；熵阈值为高 `6.8`、低 `3.5`、跳变 `1.25`，ngram top-k 为 `8`，ngram 样本上限为 `262144` 字节。

## verification

校验会综合解压退出状态、输出存在性、条目命中、清单大小、CRC 和样本可读性，再给出完整、部分或失败结论。

| 字段 | 默认 | 说明 |
| --- | ---: | --- |
| `enabled` | `true` | 是否启用结果校验。 |
| `max_retries` | `2` | 校验失败后的普通重试次数。 |
| `cleanup_failed_output` | `true` | 重试前是否清理失败输出。 |
| `complete_accept_threshold` | `0.999` | 完整结果最低完整度。 |
| `partial_accept_threshold` | `0.2` | 部分结果最低完整度。 |
| `retry_on_verification_failure` | `true` | 是否允许校验失败后重试。 |
| `methods` | 见下表 | 有序校验方法列表。 |

默认方法及关键参数：

| 方法 | 关键参数 | 作用 |
| --- | --- | --- |
| `extraction_exit_signal` | `enabled: true` | 读取解压状态、诊断和进度清单。 |
| `output_presence` | `enabled: true` | 检查输出目录及输出内容。 |
| `expected_name_presence` | `max_expected_names: 50`、`required_match_ratio: 0.8` | 检查预期条目名命中率；缺失惩罚为 `10/35/60`。 |
| `manifest_size_match` | `max_expected_names: 2000`、文件数容差 `2` 或 `5%`、大小容差 `1048576` 字节或 `2%` | 对比归档清单和输出规模。 |
| `archive_test_crc` | `max_items: 200000`、`max_reported_items: 20` | 读取归档状态并比较 CRC。 |
| `sample_readability` | `max_samples: 64`、`read_bytes: 4096`、`max_reported_items: 20` | 抽样读取输出文件，确认产物基本可读。 |

## detection

| 字段 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `enabled` | `bool` | `true` | 检测总开关。关闭后仍会按常规归档扩展名和分卷入口生成任务；完全绕过初始扫描可使用 `extract --direct-file`。 |

### fact_collectors

| 名称 | 作用 |
| --- | --- |
| `file_facts` | 采集路径、名称、父目录、大小等基础信息。 |
| `magic_bytes` | 读取文件头 magic bytes。 |

### processors

| 名称 | 作用 |
| --- | --- |
| `embedded_archive` | 处理普通归档识别未解决且获准进行嵌入扫描的文件。 |
| `zip_structure` | 检查 ZIP local header。 |
| `zip_eocd_structure` | 检查 ZIP EOCD 和 central directory。 |
| `tar_header_structure` | 检查 TAR header checksum 和 ustar marker。 |
| `compression_stream_structure` | 检查 gzip、bzip2、xz、zstd 轻量流结构。 |
| `pe_overlay_structure` | 检查 PE overlay 中的归档载荷。 |
| `executable_carrier` | 检查可执行载体及其归档区域，默认读取上限 `8388608` 字节。 |
| `seven_zip_structure` | 检查 7z signature、start header CRC、next header 范围和 NID。 |
| `rar_structure` | 检查 RAR4/RAR5 signature、main header 和 block/header walk。 |

### rule_pipeline.precheck

默认规则：

| 规则 | 作用 |
| --- | --- |
| `zip_structure_accept` | 结构可信的 ZIP 快速接受；默认允许空 ZIP。 |
| `tar_structure_accept` | 结构可信的 TAR 快速接受。 |
| `seven_zip_structure_accept` | start/next header 可信的 7z 快速接受，next header 检查上限 `1048576` 字节。 |
| `rar_structure_accept` | RAR main header/block walk 可信时接受，首个 header 检查上限 `1048576` 字节。 |
| `compression_stream_accept` | 完整校验 gzip、bzip2、xz、zstd 流。 |
| `embedded_payload_identity` | 先识别可执行载体，再对获准且找到可靠嵌入归档的文件接受。 |

`embedded_payload_identity.deep_scan_single_candidate_ratio` 默认是 `0.3`：单个逻辑候选占未解决候选总字节数达到 30% 时执行完整嵌入扫描。`0` 关闭该阶段，`1` 只选择占全部大小的候选。分卷按一个逻辑候选计数，成员卷不会重复计算。

## 密码表和密码文件

`builtin_passwords.txt` 每行保存一个内置密码；文件缺失时程序会尝试创建默认文件。同目录密码文件为 `sunpack-passwords.txt`，受 `passwords` 配置节的大小和长度限制。

## 修改建议

- 想减少误解压：调整 `filesystem.scan_filters` 和 `detection.rule_pipeline.precheck`。
- 想提高伪装归档和载体的召回率：检查 `embedded_scan`、`detection.processors` 和 `analysis`。
- 想分析一次输入的判定过程：使用 `inspect --analyze -v`。
- 修改后运行 `python sunpack.py config validate`。
