# 开发边界说明

[English](../development_boundaries.md) | **简体中文**

本文档是 SunPack 当前架构的边界约定。项目采用 native-first、verification-driven 流水线：文件系统扫描/监控、关系、检测、结构分析、密码、解压、校验、后处理和 CLI 都应保持清晰职责。

## 总原则

1. 跨领域调用公开入口，不直接依赖别的领域的 `internal`。
2. `contracts` 放共享数据契约，不放流程控制。
3. `coordinator` 只编排流程，不实现领域算法。
4. `app` 只做 CLI 参数、交互和输出适配。
5. `support` 只放跨领域基础设施和外部 ABI 绑定，不放业务策略。
6. Rust/C++ 原生层承接性能热点和 ABI 适配，不拥有最终业务 decision。
7. 配置别名属于用户接口，可以保留；新增内部适配层或 Python fallback 必须有明确的边界和测试。

## 推荐依赖方向

```text
app
  -> config
  -> coordinator
  -> passwords
  -> watch

coordinator
  -> filesystem
  -> relations
  -> detection
  -> extraction
  -> verification
  -> postprocess
  -> contracts

detection
  -> contracts
  -> analysis public capabilities
  -> support/native helpers

analysis
  -> native binary view/probes and embedded scanner
  -> neutral contracts/result objects

extraction
  -> contracts
  -> passwords
  -> rename public API
  -> sevenzip worker

verification
  -> contracts
  -> passwords session

postprocess
  -> contracts.RunContext
  -> postprocess internal actions

filesystem / relations
  -> contracts
  -> sunpack_native narrow helpers

passwords
  -> support.sevenzip_bridge
  -> native/Rust fast verifiers

config
  -> support

contracts
  -> standard library
```

## 公开入口

| 领域 | 公开入口 | 职责 |
| ---- | -------- | ---- |
| CLI | `sunpack.cli.cli.main` | 命令行入口。 |
| GUI Watch | `sunpack.gui.main.main` | 无控制台托盘入口，复用 watch runtime。 |
| 配置 | `config.loader.load_config` / `config.schema` | 配置读取、校验、归一化。 |
| 契约 | `contracts.*` | 跨模块共享数据结构，包括 `RunContext`。 |
| 文件系统 | `filesystem.directory_scanner.DirectoryScanner` | 目录扫描和过滤。 |
| 关系 | `relations.RelationsScheduler` | 分卷、候选组、逻辑名和分卷成员查询。 |
| 检测 | `detection.DetectionScheduler` | 对 Coordinator 提供的候选 facts 做规则判断。 |
| 候选编排 | `coordinator.task_provider.ArchiveTaskProvider` | 串联 filesystem、relations、detection 和结构救援。 |
| 递归策略 | `coordinator.output_scan_policy.NestedOutputScanPolicy` | 判断输出目录是否进入下一轮扫描。 |
| 通用归档分析 | `analysis.ArchiveAnalyzer` | 提供无业务调度的格式、结构、边界、fuzzy 和 embedded 分析能力。 |
| 输入规划 | `detection.input_planning.ArchiveInputPlanningStage` | 把中立分析报告转换为主流程归档输入和 embedded 子任务。 |
| 密码 | `sunpack.passwords` | 密码候选、调度、fast verifier、7z.dll 最终确认。 |
| 解压 | `extraction.scheduler.ExtractionScheduler` | 单归档输出目录、密码解析、worker 解压。 |
| 校验 | `verification.VerificationScheduler` | 解压结果完整度、来源完整性和下一步决策。 |
| 后处理 | `postprocess.actions.PostProcessActions` | 成功后清理和扁平化。 |
| 文件系统监控 | `watch.runtime.run_watch_service` / `watch.WatchScheduler` | CLI/GUI 共用服务入口、watchdog 事件、活跃到静默状态机和自动处理。 |
| Native ABI | `support.sevenzip_bridge` | C++ 7z.dll bridge 绑定和缓存。 |

## 领域边界

### app

`app` 只负责 CLI 适配：参数解析、密码交互、配置覆盖、结果输出和退出码。它可以调用 coordinator、watch、passwords 和 config 的公开入口，不直接导入 detection/extraction 的内部实现。

### config

`config` 接管外部配置读取、字段声明、归一化和展示。配置别名如 `recursive_extract: "*" / "?"`、`filesystem.directory_scan_mode: "*" / "-"`、`archive_cleanup_mode: "d/r/k"` 是用户接口的一部分，可以保留。领域运行时应消费归一化后的内部值。

### contracts

`contracts` 是共享数据契约层。`DiscoveryCandidate`、`ResolvedArchiveInput`、`StageResult`、`ArchiveTask`、`ExtractionResult`、`VerificationResult` 和 `RunContext` 应放这里。Discovery 阶段使用类型化契约交换数据，任务级可变知识统一封装在 `ArchiveTask` 内。

### filesystem

`filesystem` 只负责 pipeline discovery 所需的显式目录遍历、过滤与 `DirectorySnapshot` 构建，不再拥有长期运行的 Watch 服务。独立的 `watch` 领域负责 OS 通知、NTFS/USN 观察、文件 ready/quiet 状态，只判断物理文件何时稳定到可以进入 `PipelineEngine`；压缩包过滤与解释仍全部留在 pipeline 内。

### relations

`relations` 负责文件之间的关系：严格分卷主文件、成员、SFX companion、结构证据仲裁和逻辑名。初始发现不得用宽松文件名直接建组；确认缺卷后只允许执行一次由结构锚点约束的重找。外部模块只能调用 `RelationsScheduler`，不要直接依赖 `relations.internal`。完整契约见 [Structure-first volume resolution](volume_resolution.md)。

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

### detection

`detection` 只回答“候选是否应进入解压任务”。它分三层：

目录扫描和关系分组由 Coordinator 驱动。Detection 可通过 Analysis 公共能力获得中立结构证据，并独自拥有候选授权、规则、评分以及归档输入规划。

- `facts`：采集初等事实，例如路径、大小和 magic bytes。
- `processors`：从初等 facts 推导结构事实、embedded payload 和 7z probe/test 结果。
- `rules`：只读 facts 和配置，输出 accept/reject/confirm。

规则层不应依赖 processor 实现细节；共享默认值放到公共 constants/config 模块。

### analysis

`analysis` 是无业务策略的通用归档分析能力层。公共入口 `ArchiveAnalyzer` 接收 file、multi-volume、range 或 segment source 和 `AnalysisRequest`，输出格式证据、片段边界、置信度与损坏标记；`probe_volume_anchor_paths` 为 Relations 提供批量、有界、只读的原生分卷结构证据。它内部可以执行 signature prepass、fuzzy、格式 probe 和 embedded fallback，但不得依赖 `ArchiveTask`、Detection 或 Coordinator，也不得写业务 knowledge。

### passwords

`passwords` 管理候选密码、批量调度、缓存和 Rust bounded fast verifier。ZIP/RAR/7z 的强证据可直接确定密码；弱匹配只作为候选交给 extraction worker，在真实解压事务中做 bounded backend confirmation。密码层不再调用独立的 7-Zip full-payload probe/test。

### extraction

`extraction` 是单归档解压执行层。它消费由 Detection/input planner 完整解析的 `ArchiveTask`、`source.*` 输入和 password resolution，调用 `sunpack_sevenzip_worker.exe` 通过 `7z.dll` 解压普通文件、`file_range` 或 `concat_ranges` 虚拟输入。它不查询 Relations、不负责扫描候选、不做批量并发、不做成功后清理。

### verification

`verification` 是解压结果校验的事实来源。它从 `ArchiveTask`、`ExtractionResult`、`ArchiveState` 和 `PasswordSession` 构建证据，按配置执行 method，返回完整度、文件观察、source integrity、recoverable upper bound 和 decision hint。是否普通重试、是否清理失败输出，由 coordinator 决定。

### postprocess

`postprocess` 只处理成功后的清理和扁平化。它可以接收 `contracts.RunContext` 来消费成功归档和扁平化候选，但 `postprocess.internal` 不依赖 coordinator。

### coordinator

`coordinator` 是唯一流程依赖拥有者，负责 filesystem→relations→detection/input planning→extraction→verification→postprocess 主流程。它还负责递归轮次、批量调度、资源 token、普通 verification retry 和 summary。它不实现领域算法；所有领域能力均通过公开入口调用。归档清理通过 postprocess 公开动作完成。

流程领域包禁止反向导入 `coordinator`。Detection 只能调用 Analysis 公共能力；Analysis 不得反向依赖它们。跨阶段数据通过共享结果契约或 `contracts` 传递。

### support

`support` 放资源查找、JSON、缓存、路径 helper 和 7z.dll wrapper 绑定。不要把检测策略、输出目录策略、密码解析或清理策略塞进 support。

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

跨领域不要依赖 internal。补 public facade 或把共享契约移到 `contracts`。

```python
knowledge = task.knowledge()
```

不要读取任务私有状态。使用 `ArchiveTask.knowledge()` / 类型化 contract，或补公开方法。

```python
from sunpack.coordinator.engine import PipelineEngine  # inside filesystem watcher scheduler
```

`watch` 不直接构造 coordinator engine。应用组合层创建并启动进程级
`PipelineEngine`，再把实例注入 watcher；watcher 只提交稳定输入和消费请求结果。

`PipelineEngine` 拥有跨请求常驻的扫描器、分析器、验证组件、资源调度器和
7-Zip worker pool。`PipelineResponse`、输出策略、后处理清单和统计属于请求，不能
写回 Engine 的全局累计状态。

```python
from sunpack.detection.formats import CONFIRMERS
```

Detection 通过 `detection.formats` 中独立模块确认已路由的单文件格式。Relations 负责 RAR、7z、ZIP 身份，Embedded 负责载体扫描。

## 重构检查清单

每次改动后至少运行：

```powershell
rg "from sunpack\.[^.]+\.internal" sunpack tests
rg "\._facts|FactBag\._facts" sunpack tests
powershell -ExecutionPolicy Bypass -File scripts\run_ci_tests.ps1
```

人工确认：

- app 是否仍只是 CLI 适配？
- coordinator 是否仍只是编排？
- relation 能力是否通过 `RelationsScheduler` 暴露？
- analysis 是否仍是无业务调度的通用能力，detection 是否只通过公共入口调用？
- verification 是否先于普通重试给出完整度和 source integrity？
- 正常主流程是否保持 extraction → verification → postprocess 的单向生命周期？
- support 是否没有混入业务策略？

## 当前结构速览

```text
sunpack/
  app/          CLI 命令、参数、输出和运行时适配
  analysis/     无业务策略的归档分析、probe、view 和 embedded 能力
  config/       配置读取、校验、归一化和领域配置视图
  contracts/    跨模块数据契约
  coordinator/  pipeline 编排、批量调度和递归
  detection/    候选检测、fact 采集、结构规则判断
  extraction/   worker 解压黑盒和解压结果
  filesystem/   通用目录扫描、过滤和 watcher 监控能力
  passwords/    密码候选、调度和 verifier
  postprocess/  解压成功后的清理和扁平化
  relations/    文件关系、分卷和候选组
  support/      资源、JSON、缓存、7z.dll ABI 绑定等基础设施
  verification/ 解压结果校验流水线
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

Watch 是独立输入层，只负责 OS 事件、文件稳定性、quiet window、持久状态、重试与通知。Watch 不识别压缩格式、不解析分卷、不调用 Relations/Detection/Embedded/DiscoveryScanSession；稳定文件统一通过 `PipelineEngine.run()` 进入完整 pipeline，并仅消费 `PipelineResponse.discovery` 暴露的 `claimed_paths` / `blocked_paths` 等公开事实。CLI 与 Watch 从进入 pipeline 起共享完全相同的 discovery、planning、extraction 与 verification 路径。
