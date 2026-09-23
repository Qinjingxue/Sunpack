# Development boundaries

**English** | [简体中文](zh-CN/development_boundaries.md)

This document defines the boundary conventions of the current SunPack architecture. The project uses a native-first, verification-driven pipeline: filesystem scanning, Watch monitoring, relations, detection, structural analysis, passwords, extraction, verification, post-processing, and the CLI all keep clear responsibilities.

## General principles

1. Cross-domain calls go through public entry points; never depend directly on another domain's `internal`.
2. `contracts` holds shared data contracts, not flow control.
3. `coordinator` only orchestrates the flow; it does not implement domain algorithms.
4. `app` only does CLI arguments, interaction, and output adaptation.
5. `support` holds only cross-domain infrastructure and external ABI bindings, not business policy.
6. The Rust/C++ native layer handles performance hotspots and ABI adaptation; it does not own final business decisions.
7. Configuration aliases are part of the user interface and may be kept; any new internal adaptation layer or Python fallback must have explicit boundaries and tests.

## Recommended dependency direction

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
  -> native/Rust fast verifiers

config
  -> support

contracts
  -> standard library
```

## Public entry points

| Domain | Public entry point | Responsibility |
| ---- | -------- | ---- |
| CLI | `sunpack.cli.cli.main` | Command-line entry point. |
| GUI Watch | `sunpack.gui.main.main` | Console-less tray entry point; reuses the watch runtime. |
| Configuration | `config.loader.load_config` / `config.schema` | Configuration loading, validation, normalization. |
| Contracts | `contracts.*` | Cross-module shared data structures, including `RunContext`. |
| Filesystem | `filesystem.directory_scanner.DirectoryScanner` | Directory scanning and filtering. |
| Relations | `relations.RelationsScheduler` | Volumes, candidate groups, logical names, and volume-member queries. |
| Detection | `detection.DetectionScheduler` | Rule decisions over the candidate facts provided by the Coordinator. |
| Candidate orchestration | `coordinator.task_provider.ArchiveTaskProvider` | Chains filesystem, relations, detection, and structural rescue. |
| Recursion policy | `coordinator.output_scan_policy.NestedOutputScanPolicy` | Decides whether an output directory enters the next scan round. |
| General archive analysis | `analysis.ArchiveAnalyzer` | Provides format, structure, boundary, and embedded analysis without business scheduling. |
| Input planning | `detection.input_planning.ArchiveInputPlanningStage` | Converts neutral analysis reports into main-pipeline archive inputs and embedded subtasks. |
| Passwords | `sunpack.passwords` | Password candidates, scheduling, fast verifiers, final 7z.dll confirmation. |
| Extraction | `extraction.scheduler.ExtractionScheduler` | Per-archive output directory, password resolution, worker extraction. |
| Verification | `verification.VerificationScheduler` | Extraction result completeness, source integrity, and the next-step decision. |
| Post-processing | `postprocess.actions.PostProcessActions` | Cleanup and flattening after success. |
| Watch | `watch.runtime.run_watch_service` / `watch.WatchScheduler` | Shared CLI/GUI service entry point, watchdog events, the active-to-quiet state machine, and automatic processing. |

## Domain boundaries

### app

`app` is responsible only for CLI adaptation: argument parsing, password interaction, configuration overrides, result output, and exit codes. It may call the public entry points of coordinator, watch, passwords, and config, and must not import detection/extraction internals directly.

### config

`config` takes over external configuration reading, field declarations, normalization, and presentation. Configuration aliases such as `recursive_extract: "*" / "?"`, `filesystem.directory_scan_mode: "*" / "-"`, and `archive_cleanup_mode: "d/r/k"` are part of the user interface and may be kept. Domain runtime code should consume the normalized internal values.

### contracts

`contracts` is the shared data contract layer. `DiscoveryCandidate`, `ResolvedArchiveInput`, `StageResult`, `ArchiveTask`, `ExtractionResult`, `VerificationResult`, and `RunContext` belong here. Discovery stages exchange typed contracts; task-local mutable knowledge stays behind `ArchiveTask`.

### filesystem

`filesystem` owns explicit directory traversal, filtering, and `DirectorySnapshot` construction for pipeline discovery. It does not own the long-running Watch service. The standalone `watch` domain owns OS notifications, NTFS/USN observations, readiness/quiet-state tracking, and decides only when a physical file is stable enough to enter `PipelineEngine`; archive filtering and interpretation remain inside the pipeline.

### relations

`relations` handles relationships between files: strict volume primary files, members, SFX companions, arbitration of structural evidence, and logical names. Initial discovery must not group files directly by loose file names; after a missing volume is confirmed, only one re-search constrained by a structural anchor is allowed. External modules may only call `RelationsScheduler`, and must not depend on `relations.internal` directly. See [Structure-first volume resolution](volume_resolution.md) for the complete contract.

Publicly allowed relation capabilities include:

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

`detection` only answers whether a candidate should become an extraction task. It has three layers:

Directory scanning and relation grouping are driven by the Coordinator. Detection can obtain neutral structural evidence through public Analysis capabilities, and solely owns candidate authorization, rules, scoring, and archive input planning.

- `facts`: collect elementary facts such as path, size, and magic bytes.
- `processors`: derive structural facts, embedded payloads, and 7z probe/test results from elementary facts.
- `rules`: read only facts and configuration, and output accept/reject/confirm.

The rule layer must not depend on processor implementation details; shared defaults belong in a common constants/config module.

### analysis

`analysis` is the general archive analysis capability layer without business policy. The public entry point `ArchiveAnalyzer` accepts a file, multi-volume, range, or segment source plus an `AnalysisRequest`, and outputs format evidence, fragment boundaries, confidence, and damage markers; `analysis.embedded` owns embedded full-stream scanning, result normalization, and executable carrier inspection; `probe_volume_anchor_paths` provides Relations with batched, bounded, read-only native volume structural evidence. Analysis must not depend on `ArchiveTask`, Detection, or the Coordinator, and must not write business knowledge.

### passwords

`passwords` manages candidate passwords, batch scheduling, caching, and bounded Rust fast verifiers. Strong ZIP/RAR/7z proofs resolve a password directly; weak matches are passed to the extraction worker as candidates for bounded backend confirmation during the extraction transaction. The password layer does not perform full-payload 7-Zip probe/test calls.

### extraction

`extraction` is the per-archive extraction execution layer. It consumes the `ArchiveTask` fully resolved by Detection/input planner, the `source.*` inputs, and password resolution, and calls `sunpack_sevenzip_worker.exe` to extract plain files, `file_range`, or `concat_ranges` virtual inputs through `7z.dll`. It does not query Relations, is not responsible for scanning candidates, does not do batch concurrency, and does not clean up after success.

### verification

`verification` is the source of truth for extraction result verification. It builds evidence from `ArchiveTask`, `ExtractionResult`, `ArchiveState`, and `PasswordSession`, runs methods according to the configuration, and returns completeness, file observations, source integrity, a recoverable upper bound, and a decision hint. Whether to retry normally and whether to clean up failed output is decided by the coordinator.

### postprocess

`postprocess` only handles cleanup and flattening after success. It may accept `contracts.RunContext` to consume successful archives and flattening candidates, but `postprocess.internal` does not depend on the coordinator.

### coordinator

`coordinator` is the sole owner of flow dependencies, responsible for the filesystem→relations→detection/input planning→extraction→verification→postprocess main pipeline. It is also responsible for recursive rounds, batch scheduling, resource tokens, normal verification retries, and the summary. It does not implement domain algorithms; all domain capabilities are called through public entry points. Archive cleanup is performed through public postprocess actions.

Packages in the flow domains must not import `coordinator` in reverse. Detection may only call public Analysis capabilities; Analysis must not depend on them in reverse. Cross-stage data is passed through shared result contracts or `contracts`.

### support

`support` holds cross-domain infrastructure such as resource lookup, JSON, caching, path helpers, and collision-free output path reservation. It may allocate output path names, but must not own extraction or post-processing policy.

### native

`native/sunpack_native` takes on cross-platform hotspots: directory scanning, binary views, signature prepass, format probes, carrier scan, output CRC/readability, output file index matching, password fast verifiers, and so on.

`native/sevenzip_bridge` takes on Windows embedded 7-Zip execution: worker-internal bounded password candidate confirmation and extraction through `sunpack_sevenzip_worker.exe`. Format, structure, and encryption analysis belong to the Python/Rust analysis layer rather than a second native probe/test stack.

### Windows Watch Broker / USN

`native/sunpack_usn_core` is a Windows-only shared Rust crate responsible for volume identification, USN Journal probing, bounded reason reads, and the named-pipe client protocol. `native/sunpack_watch_broker` compiles to a Windows service that centrally holds volume-level Journal access; `sunpack_native` exposes only file observation and lease capabilities to Python.

Before watch starts, it must confirm that the root directory is on an NTFS volume with a readable Journal. File observation first reads file metadata and the current USN; when the current USN exceeds the last recorded one, the client asks the broker to read the reasons for `previous_usn < usn <= current_usn`, at most 1 MiB per call. The watcher distinguishes content changes from metadata changes based on the reasons, and hands content changes to the active/quiet state machine.

The standard service identity is `SunPackWatchBroker`, with the standard pipe `\\.\pipe\SunPack.WatchBroker.v1`. Clients use the service through process-level leases: the first lease establishes the connection, nested leases reuse it, and the last lease release closes it. Tests may only use the isolated identities with the `SunPackWatchBrokerTest_` and `\\.\pipe\SunPack.WatchBroker.Test.` prefixes.

## Prohibited list

The following patterns usually mean a broken boundary:

```python
from sunpack.some_domain.internal import ...
```

Do not depend on `internal` across domains. Add a public facade, or move the shared contract into `contracts`.

```python
knowledge = task.knowledge()
```

Do not read private task state. Use `ArchiveTask.knowledge()` / typed contracts, or add a public method.

```python
from sunpack.coordinator.engine import PipelineEngine  # inside watch scheduler
```

`watch` does not construct the coordinator engine directly. The application composition layer creates and starts the process-level
`PipelineEngine`, then injects the instance into the watcher; the watcher only submits stable inputs and consumes request results.

`PipelineEngine` owns the scanner, analyzer, verification components, resource scheduler, and
7-Zip worker pool that persist across requests. `PipelineResponse`, the output policy, the post-processing manifest, and statistics belong to a request and must not be written back into the Engine's global accumulated state.

```python
from sunpack.detection.formats import CONFIRMERS
```

Detection confirms routed single-file formats through independent modules in `detection.formats`. Relations owns RAR, 7z, and ZIP identity; Embedded owns carrier scanning.

## Refactoring checklist

After every change, at least run:

```powershell
rg "from sunpack\.[^.]+\.internal" sunpack tests
rg "\._facts|FactBag\._facts" sunpack tests
powershell -ExecutionPolicy Bypass -File scripts\run_ci_tests.ps1
```

Manually confirm:

- Is app still only CLI adaptation?
- Is coordinator still only orchestration?
- Are relation capabilities exposed through `RelationsScheduler`?
- Is analysis still a general capability without business scheduling, and does detection call it only through public entry points?
- Does verification provide completeness and source integrity before a normal retry?
- Does the normal main pipeline keep the one-way lifecycle extraction → verification → postprocess?
- Has support avoided mixing in business policy?

## Current structure at a glance

```text
sunpack/
  app/          CLI commands, arguments, output, and runtime adaptation
  analysis/     Archive analysis, probe, view, and embedded capabilities without business policy
  config/       Configuration loading, validation, normalization, and domain configuration views
  contracts/    Cross-module data contracts
  coordinator/  Pipeline orchestration, batch scheduling, and recursion
  detection/    Candidate detection, fact collection, structural rule decisions
  extraction/   Worker extraction black box and extraction results
  filesystem/   General directory scanning and filtering
  watch/         OS monitoring, readiness tracking, durable watch state, and pipeline submission
  passwords/    Password candidates, scheduling, and verifiers
  postprocess/  Cleanup and flattening after successful extraction
  relations/    File relationships, volumes, and candidate groups
  support/      Infrastructure such as resources, JSON, caching, and 7z.dll ABI bindings
  verification/ Extraction result verification pipeline
```

`PipelineEngine` owns the process-level resource scheduler and the invocation-layer executor. The scheduler starts and stops with the Engine; cross-task input planning concurrency is managed by the Coordinator, and Analysis only uses the injected capability executor without owning cross-task lifecycles.

Repository-level directories:

```text
native/sunpack_native/  Rust/PyO3 hot paths
native/sunpack_usn_core/ Windows USN core and client protocol
native/sunpack_watch_broker/ Windows Watch Broker service
native/sevenzip_bridge/ Windows embedded 7-Zip worker
```

### Watch / Pipeline boundary

Watch is an independent input layer responsible only for OS events, file readiness, quiet windows, durable state, retries, and notifications. It does not identify archive formats, resolve split families, or call Relations/Detection/Embedded/DiscoveryScanSession. Stable files enter the complete pipeline through `PipelineEngine.run()`, and Watch consumes only public `PipelineResponse.discovery` facts such as `claimed_paths` and `blocked_paths`. CLI and Watch therefore share the same discovery, planning, extraction, and verification path once a target enters the pipeline.
