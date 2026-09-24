# 开发边界说明

[English](../development_boundaries.md) | **简体中文**

本文档定义 SunPack 的包边界。Python 包顶层分为三层：`sunpack.runtime` 负责 CLI、GUI 和 Watch 入口，`sunpack.pipeline` 负责处理阶段，`sunpack.core` 提供它们共同使用的契约和能力。

## 总原则

1. `sunpack.runtime` 可以依赖 `sunpack.pipeline` 和 `sunpack.core`。
2. `sunpack.pipeline` 可以依赖 `sunpack.core`，禁止导入 `sunpack.runtime`。
3. `sunpack.core` 禁止导入 `sunpack.pipeline` 和 `sunpack.runtime`。
4. `sunpack.core.contracts` 放共享数据契约，不放流程控制。
5. `sunpack.pipeline.coordinator` 负责编排，不实现各阶段算法。
6. Runtime 入口把 CLI、GUI 和 Watch 交互适配到 pipeline。
7. Rust/C++ 承接性能热点和 ABI 适配，Python 保留最终业务决策。
8. 配置别名属于用户接口；内部适配层必须有明确边界。

## 推荐依赖方向

```text
sunpack.runtime
  -> sunpack.pipeline
  -> sunpack.core

sunpack.pipeline
  -> sunpack.core

sunpack.core
  -> 标准库 / native 能力
  （禁止依赖 pipeline 或 runtime）

sunpack.pipeline.coordinator
  -> pipeline.discovery.*
  -> pipeline.extraction
  -> pipeline.verification
  -> pipeline.postprocess
  -> core.contracts / core.analysis / core.passwords

sunpack.pipeline.discovery
  -> sunpack.core

sunpack.pipeline.extraction
  -> sunpack.core.contracts / sunpack.core.passwords

sunpack.runtime.watch
  -> sunpack.pipeline 公开入口
```

## 公开入口

| 领域 | 公开入口 | 职责 |
| ---- | -------- | ---- |
| CLI | `sunpack.runtime.cli.cli.main` | 命令行入口。 |
| GUI | `sunpack.runtime.gui.main.main` | 无控制台托盘入口。 |
| Watch | `sunpack.runtime.watch.runtime.run_watch_service` | 长期运行的 Watch 服务入口。 |
| 配置 | `sunpack.core.config.loader.load_config` / `sunpack.core.config.schema` | 配置读取和归一化。 |
| 应用配置校验 | `sunpack.runtime.config_validation.validate_config_payload` | 校验配置与 pipeline 注册能力是否匹配。 |
| 契约 | `sunpack.core.contracts.*` | 共享数据结构，包括 `RunContext`。 |
| 文件系统发现 | `sunpack.pipeline.discovery.filesystem.directory_scanner.DirectoryScanner` | 目录扫描和过滤。 |
| 关系发现 | `sunpack.pipeline.discovery.relations.RelationsScheduler` | 分卷、候选组、逻辑名和分卷成员查询。 |
| 检测 | `sunpack.pipeline.discovery.detection.DetectionScheduler` | 根据候选 facts 做规则判断。 |
| Embedded 发现 | `sunpack.pipeline.discovery.embedded.EmbeddedDiscovery` | 将载体中的归档候选转为 pipeline 输入。 |
| 候选编排 | `sunpack.pipeline.coordinator.task_provider.ArchiveTaskProvider` | 串联发现和结构救援。 |
| 递归策略 | `sunpack.pipeline.coordinator.output_scan_policy.NestedOutputScanPolicy` | 判断输出目录是否进入下一轮扫描。 |
| 通用归档分析 | `sunpack.core.analysis.ArchiveAnalyzer` | 提供无业务调度的格式、结构、边界和 embedded 分析能力。 |
| 输入规划 | `sunpack.pipeline.discovery.detection.input_planning.ArchiveInputPlanningStage` | 把分析报告转换为归档输入和 embedded 子任务。 |
| 密码 | `sunpack.core.passwords` | 密码候选、调度、fast verifier 和 worker 确认。 |
| 解压 | `sunpack.pipeline.extraction.scheduler.ExtractionScheduler` | 单归档输出、密码解析和 worker 解压。 |
| 校验 | `sunpack.pipeline.verification.scheduler.VerificationScheduler` | 解压完整度、来源完整性和下一步决策。 |
| 后处理 | `sunpack.pipeline.postprocess.actions.PostProcessActions` | 成功后清理和扁平化。 |

## 领域边界

### runtime

`sunpack.runtime` 管理 CLI、GUI 和 Watch 入口，把交互和进程生命周期适配到 pipeline 与 core 的公开 API。Runtime 可以依赖 pipeline 和 core；这两层不能反向依赖 runtime。

### core.config

`sunpack.core.config` 负责外部配置读取、字段声明和归一化。将配置与 Detection、Verification 注册能力对照的应用校验放在 `sunpack.runtime.config_validation`。配置别名如 `recursive_extract: "*" / "?"`、`filesystem.directory_scan_mode: "*" / "-"`、`archive_cleanup_mode: "d/r/k"` 是用户接口的一部分。Pipeline 代码消费归一化后的值。

### core.contracts

`sunpack.core.contracts` 是共享数据契约层。`DiscoveryCandidate`、`ResolvedArchiveInput`、`StageResult`、`ArchiveTask`、`ExtractionResult`、`VerificationResult` 和 `RunContext` 放在这里。Discovery 阶段通过类型化契约交换数据，任务级可变知识封装在 `ArchiveTask` 内。

### pipeline.discovery.filesystem

`sunpack.pipeline.discovery.filesystem` 负责显式目录遍历、过滤和 `DirectorySnapshot` 构建，不管理长期运行的 Watch 服务。`sunpack.runtime.watch` 负责 OS 通知、NTFS/USN 观察和文件 ready 状态；它判断物理文件何时稳定到可以进入 pipeline。压缩包过滤与解释仍属于 pipeline discovery。

### pipeline.discovery.relations

`sunpack.pipeline.discovery.relations` 负责文件关系：严格分卷主文件、成员、SFX companion、结构证据仲裁和逻辑名。初始发现不得用宽松文件名直接建组；确认缺卷后只允许执行一次由结构锚点约束的重找。外部模块只能调用 `RelationsScheduler`，不得直接依赖 `sunpack.pipeline.discovery.relations.internal`。完整契约见 [Structure-first volume resolution](volume_resolution.md)。

允许公开的关系能力包括：

- `build_candidate_groups(snapshot)`
- `detect_split_role(filename)`
- `logical_name_for_archive(filename)`
- `select_first_volume(paths)`
- `should_scan_split_siblings(...)`
- `find_standard_split_siblings(archive)`
- `parse_numbered_volume(path)`
- `resolve_volume_once(current_paths, candidate_paths, format_hint=...)`
- `resolve_volume_once_in_directory(current_paths, directory, format_hint=...)`

### pipeline.discovery.detection

`sunpack.pipeline.discovery.detection` 只回答“候选是否应进入解压任务”。它分三层：

目录扫描和关系分组由 `sunpack.pipeline.coordinator` 驱动。Detection 可通过 `sunpack.core.analysis` 公共能力获得中立结构证据，并独自拥有候选授权、规则、评分以及归档输入规划。

- `facts`：采集初等事实，例如路径、大小和 magic bytes。
- `processors`：从初等 facts 推导结构事实、embedded payload 和 7z probe/test 结果。
- `rules`：只读 facts 和配置，输出 accept/reject/confirm。

规则层不应依赖 processor 实现细节；共享默认值放到公共 constants/config 模块。

### core.analysis

`sunpack.core.analysis` 是无业务策略的通用归档分析能力层。公共入口 `ArchiveAnalyzer` 接收 file、multi-volume、range 或 segment source 和 `AnalysisRequest`，输出格式证据、片段边界、置信度与损坏标记。`sunpack.core.analysis.embedded` 负责 embedded 全流扫描、结果归一化和可执行载体检查；`probe_volume_anchor_paths` 为 Relations 提供批量、有界、只读的原生分卷结构证据。Analysis 不得依赖 `ArchiveTask`、Detection 或 Coordinator，也不得写业务 knowledge。

### core.passwords

`sunpack.core.passwords` 管理候选密码、批量调度、缓存和 Rust bounded fast verifier。ZIP/RAR/7z 的强证据可直接确定密码；弱匹配只作为候选交给 extraction worker，在真实解压事务中做 bounded backend confirmation。密码层不调用独立的 7-Zip full-payload probe/test。

### pipeline.extraction

`sunpack.pipeline.extraction` 是单归档解压执行层。它消费由 Detection/input planner 完整解析的 `ArchiveTask`、`source.*` 输入和 password resolution，调用 `sunpack_sevenzip_worker.exe` 通过 `7z.dll` 解压普通文件、`file_range` 或 `concat_ranges` 虚拟输入。它不查询 Relations、不扫描候选、不调度 pipeline 批次，也不做成功后清理。

### pipeline.verification

`sunpack.pipeline.verification` 是解压结果校验的事实来源。它从 `ArchiveTask`、`ExtractionResult`、canonical `ArchiveInputDescriptor` 和 `PasswordSession` 构建证据，按配置执行 method，返回完整度、文件观察、source integrity、recoverable upper bound 和 decision hint。是否普通重试、是否清理失败输出，由 coordinator 决定。

### pipeline.postprocess

`sunpack.pipeline.postprocess` 只处理成功后的清理和扁平化。它可以接收 `sunpack.core.contracts.RunContext` 来消费成功归档和扁平化候选，但 `sunpack.pipeline.postprocess.internal` 不依赖 coordinator。

### pipeline.coordinator

`sunpack.pipeline.coordinator` 是唯一 pipeline 流程依赖拥有者，负责 filesystem→relations→detection/input planning→extraction→verification→postprocess。它还负责递归轮次、批量调度、资源 token、普通 verification retry 和 summary。它不实现各阶段算法；所有能力均通过公开入口调用。归档清理通过 postprocess 公开动作完成。

其他 pipeline 阶段禁止反向导入 `sunpack.pipeline.coordinator`。Detection 只能调用 Analysis 公共能力；Analysis 不得依赖 pipeline 阶段。跨阶段数据通过 `sunpack.core.contracts` 中的共享结果契约传递。

### core.support

`sunpack.core.support` 放共享资源查找、JSON、缓存、路径 helper、work context 和输出路径预留。不要把检测策略、解压或后处理策略塞进 core.support；它也不能导入 pipeline/runtime。

### native

`native/sunpack_native` 承接跨平台热点：目录扫描、二进制视图、signature prepass、格式 probe、carrier scan、输出 CRC/readability、输出文件索引匹配、密码 fast verifier 等。

`native/sevenzip_bridge` 承接 Windows embedded 7-Zip 执行能力：资源查询、worker 内部的 bounded 密码候选确认，以及 `sunpack_sevenzip_worker.exe` 解压。格式/结构/加密分析由 Python/Rust analysis 层完成，不在这里维护第二套 archive probe/test。

### Windows Watch Broker / USN

`native/sunpack_usn_core` 是 Windows-only 的共享 Rust crate，负责卷标识、USN Journal 探测、有限范围的 reason 读取和 named-pipe 客户端协议。`native/sunpack_watch_broker` 编译为 Windows service，集中持有卷级 Journal 访问能力；`sunpack_native` 只向 Python 暴露文件观察和 lease 能力。

watch 启动前必须确认根目录位于 NTFS 卷且 Journal 可读。文件观察先读取文件元数据和当前 USN；当前 USN 超过上次记录时，客户端请求 broker 读取 `previous_usn < usn <= current_usn` 的 reason，单次最多 1 MiB。watcher 根据 reason 区分内容变化和元数据变化，并把内容变化交给活跃/静默状态机。

标准服务身份是 `SunPackWatchBroker`，标准管道为 `\\.\pipe\SunPack.WatchBroker.v1`。客户端以进程级 lease 使用服务：首个 lease 建立连接，嵌套 lease 复用连接，最后一个 lease 释放连接。测试只能使用 `SunPackWatchBrokerTest_` 和 `\\.\pipe\SunPack.WatchBroker.Test.` 前缀的隔离身份。

## 禁止清单

以下写法通常表示边界坏掉：

```python
from sunpack.some_domain.internal import ...
```

跨领域不要依赖 internal。补 public facade 或把共享契约移到 `sunpack.core.contracts`。

```python
knowledge = task.knowledge()
```

不要读取任务私有状态。使用 `ArchiveTask.knowledge()` / 类型化 contract，或补公开方法。

```python
from sunpack.pipeline.coordinator.engine import PipelineEngine  # inside runtime Watch scheduler
```

`sunpack.runtime.watch` 不直接构造 coordinator engine。应用组合层创建并启动进程级
`PipelineEngine`，再把实例注入 watcher；watcher 只提交稳定输入和消费请求结果。

`PipelineEngine` 拥有跨请求常驻的扫描器、分析器、验证组件、资源调度器和
7-Zip worker pool。`PipelineResponse`、输出策略、后处理清单和统计属于请求，不能
写回 Engine 的全局累计状态。

```python
from sunpack.pipeline.discovery.detection.formats import CONFIRMERS
```

Detection 通过 `sunpack.pipeline.discovery.detection.formats` 中的独立模块确认已路由的单文件格式。Relations 负责 RAR、7z、ZIP 身份，Embedded 负责载体扫描。

## 重构检查清单

每次改动后至少运行：

```powershell
rg "from sunpack\.[^.]+\.internal" sunpack tests
rg "\._facts|FactBag\._facts" sunpack tests
powershell -ExecutionPolicy Bypass -File scripts\run_ci_tests.ps1
```

人工确认：

- runtime 是否只适配 CLI、GUI 和 Watch 交互？
- pipeline coordinator 是否仍只是编排？
- relation 能力是否通过 `RelationsScheduler` 暴露？
- analysis 是否仍是无业务调度的通用能力，detection 是否只通过公共入口调用？
- verification 是否先于普通重试给出完整度和 source integrity？
- 正常主流程是否保持 extraction → verification → postprocess 的单向生命周期？
- core.support 是否没有混入业务策略或导入 pipeline/runtime？

## 当前结构速览

```text
sunpack/
  core/
    analysis/       归档分析和 embedded 扫描能力
    config/         配置读取、归一化和字段声明
    contracts/      跨模块数据契约
    i18n/           翻译目录和上下文
    passwords/      密码候选、调度和 verifier
    platform/       Windows 平台能力
    support/        共享基础设施和 work context
  pipeline/
    coordinator/    流水线编排、批量调度和递归
    discovery/      filesystem / relations / detection / embedded
    extraction/     worker 解压和 output inventory
    verification/   解压结果校验
    postprocess/    成功后的清理和扁平化
  runtime/
    cli/            CLI 命令、参数和输出适配
    gui/            托盘和 GUI 入口
    watch/          长期运行的 Watch 服务和启动生命周期
```

`PipelineEngine` 拥有进程级资源调度器和调用层 executor。调度器随 Engine 启停；跨任务 input planning 并发由 Coordinator 管理，Analysis 只使用注入的 capability executor，不拥有跨任务生命周期。

仓库级目录：

```text
native/sunpack_native/  Rust/PyO3 热路径
native/sunpack_usn_core/ Windows USN 核心与客户端协议
native/sunpack_watch_broker/ Windows Watch Broker 服务
native/sevenzip_bridge/ Windows 7z.dll bridge 与 worker
```

### Watch / Pipeline 边界

Watch 是 runtime 的一种输入模式，只负责 OS 事件、文件稳定性、quiet window、持久状态、重试与通知。Watch 不识别压缩格式、不解析分卷、不调用 discovery 内部实现；稳定文件通过 `sunpack.pipeline.coordinator.engine.PipelineEngine.run()` 进入完整 pipeline，并仅消费公开响应中的 `claimed_paths` / `blocked_paths` 等事实。CLI 与 Watch 从进入 pipeline 起共享相同的 discovery、planning、extraction 与 verification 路径。
