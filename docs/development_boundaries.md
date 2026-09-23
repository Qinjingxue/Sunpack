# Development boundaries

**English** | [简体中文](zh-CN/development_boundaries.md)

This document defines the package boundaries of SunPack. The Python package has three top-level layers: `sunpack.runtime` handles CLI, GUI, and Watch entry points; `sunpack.pipeline` owns processing stages; and `sunpack.core` provides the contracts and shared capabilities they use.

## General principles

1. `sunpack.runtime` may depend on `sunpack.pipeline` and `sunpack.core`.
2. `sunpack.pipeline` may depend on `sunpack.core`, but must not import `sunpack.runtime`.
3. `sunpack.core` must not import `sunpack.pipeline` or `sunpack.runtime`.
4. `sunpack.core.contracts` holds shared data contracts, not flow control.
5. `sunpack.pipeline.coordinator` orchestrates the flow; it does not implement stage algorithms.
6. Runtime entry points adapt CLI, GUI, and Watch interactions to the pipeline.
7. Rust/C++ handles performance hotspots and ABI adaptation; Python owns final business decisions.
8. Configuration aliases are part of the user interface and may be kept; internal adaptation layers must have explicit boundaries.

## Recommended dependency direction

```text
sunpack.runtime
  -> sunpack.pipeline
  -> sunpack.core

sunpack.pipeline
  -> sunpack.core

sunpack.core
  -> standard library / native capabilities
  (never pipeline or runtime)

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
  -> sunpack.pipeline public entry points
```

## Public entry points

| Domain | Public entry point | Responsibility |
| ---- | -------- | ---- |
| CLI | `sunpack.runtime.cli.cli.main` | Command-line entry point. |
| GUI | `sunpack.runtime.gui.main.main` | Console-less tray entry point. |
| Watch | `sunpack.runtime.watch.runtime.run_watch_service` | Long-running Watch service entry point. |
| Configuration | `sunpack.core.config.loader.load_config` / `sunpack.core.config.schema` | Configuration loading and normalization. |
| Application configuration checks | `sunpack.runtime.config_validation.validate_config_payload` | Checks config against registered pipeline capabilities. |
| Contracts | `sunpack.core.contracts.*` | Shared data structures, including `RunContext`. |
| Filesystem discovery | `sunpack.pipeline.discovery.filesystem.directory_scanner.DirectoryScanner` | Directory scanning and filtering. |
| Relations discovery | `sunpack.pipeline.discovery.relations.RelationsScheduler` | Volumes, candidate groups, logical names, and volume-member queries. |
| Detection | `sunpack.pipeline.discovery.detection.DetectionScheduler` | Rule decisions over candidate facts. |
| Embedded discovery | `sunpack.pipeline.discovery.embedded.EmbeddedDiscovery` | Turns embedded archive candidates into pipeline inputs. |
| Candidate orchestration | `sunpack.pipeline.coordinator.task_provider.ArchiveTaskProvider` | Chains discovery and structural rescue. |
| Recursion policy | `sunpack.pipeline.coordinator.output_scan_policy.NestedOutputScanPolicy` | Decides whether output enters the next scan round. |
| General archive analysis | `sunpack.core.analysis.ArchiveAnalyzer` | Format, structure, boundary, and embedded analysis without business scheduling. |
| Input planning | `sunpack.pipeline.discovery.detection.input_planning.ArchiveInputPlanningStage` | Converts analysis reports into archive inputs and embedded subtasks. |
| Passwords | `sunpack.core.passwords` | Candidate passwords, scheduling, fast verifiers, and worker confirmation. |
| Extraction | `sunpack.pipeline.extraction.scheduler.ExtractionScheduler` | Per-archive output, password resolution, and worker extraction. |
| Verification | `sunpack.pipeline.verification.scheduler.VerificationScheduler` | Extraction completeness, source integrity, and next-step decisions. |
| Post-processing | `sunpack.pipeline.postprocess.actions.PostProcessActions` | Cleanup and flattening after success. |

## Domain boundaries

### runtime

`sunpack.runtime` owns CLI, GUI, and Watch entry points. It adapts user interaction and process lifecycle to public pipeline and core APIs. Runtime may depend on pipeline and core; neither of those layers may depend on runtime.

### core.config

`sunpack.core.config` owns external configuration loading, field declarations, and normalization. Application checks that compare config with registered Detection or Verification capabilities live in `sunpack.runtime.config_validation`. Configuration aliases such as `recursive_extract: "*" / "?"`, `filesystem.directory_scan_mode: "*" / "-"`, and `archive_cleanup_mode: "d/r/k"` are part of the user interface. Pipeline code consumes normalized values.

### core.contracts

`sunpack.core.contracts` is the shared data contract layer. `DiscoveryCandidate`, `ResolvedArchiveInput`, `StageResult`, `ArchiveTask`, `ExtractionResult`, `VerificationResult`, and `RunContext` belong here. Discovery stages exchange typed contracts; task-local mutable knowledge stays behind `ArchiveTask`.

### pipeline.discovery.filesystem

`sunpack.pipeline.discovery.filesystem` owns explicit directory traversal, filtering, and `DirectorySnapshot` construction. It does not own the long-running Watch service. `sunpack.runtime.watch` owns OS notifications, NTFS/USN observations, and readiness tracking; it decides when a physical file is stable enough to enter the pipeline. Archive filtering and interpretation remain in pipeline discovery.

### pipeline.discovery.relations

`sunpack.pipeline.discovery.relations` handles relationships between files: strict volume primary files, members, SFX companions, arbitration of structural evidence, and logical names. Initial discovery must not group files directly by loose file names; after a missing volume is confirmed, only one re-search constrained by a structural anchor is allowed. External modules may only call `RelationsScheduler`, and must not depend on `sunpack.pipeline.discovery.relations.internal` directly. See [Structure-first volume resolution](volume_resolution.md) for the complete contract.

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

### pipeline.discovery.detection

`sunpack.pipeline.discovery.detection` only answers whether a candidate should become an extraction task. It has three layers:

Directory scanning and relation grouping are driven by `sunpack.pipeline.coordinator`. Detection can obtain neutral structural evidence through public `sunpack.core.analysis` capabilities, and solely owns candidate authorization, rules, scoring, and archive input planning.

- `facts`: collect elementary facts such as path, size, and magic bytes.
- `processors`: derive structural facts, embedded payloads, and 7z probe/test results from elementary facts.
- `rules`: read only facts and configuration, and output accept/reject/confirm.

The rule layer must not depend on processor implementation details; shared defaults belong in a common constants/config module.

### core.analysis

`sunpack.core.analysis` is the general archive analysis capability layer without business policy. Its public entry point `ArchiveAnalyzer` accepts a file, multi-volume, range, or segment source plus an `AnalysisRequest`, and outputs format evidence, fragment boundaries, confidence, and damage markers. `sunpack.core.analysis.embedded` owns embedded full-stream scanning, result normalization, and executable carrier inspection. `probe_volume_anchor_paths` provides Relations with batched, bounded, read-only native volume evidence. Analysis must not depend on `ArchiveTask`, Detection, or the Coordinator, and must not write business knowledge.

### core.passwords

`sunpack.core.passwords` manages candidate passwords, batch scheduling, caching, and bounded Rust fast verifiers. Strong ZIP/RAR/7z proofs resolve a password directly; weak matches are passed to the extraction worker as candidates for bounded backend confirmation during the extraction transaction. The password layer does not perform full-payload 7-Zip probe/test calls.

### pipeline.extraction

`sunpack.pipeline.extraction` is the per-archive extraction execution layer. It consumes the `ArchiveTask` fully resolved by Detection/input planning, the `source.*` inputs, and password resolution, and calls `sunpack_sevenzip_worker.exe` to extract plain files, `file_range`, or `concat_ranges` virtual inputs through `7z.dll`. It does not query Relations, scan candidates, schedule pipeline batches, or clean up after success.

### pipeline.verification

`sunpack.pipeline.verification` is the source of truth for extraction result verification. It builds evidence from `ArchiveTask`, `ExtractionResult`, `ArchiveState`, and `PasswordSession`, runs methods according to the configuration, and returns completeness, file observations, source integrity, a recoverable upper bound, and a decision hint. Whether to retry normally and whether to clean up failed output is decided by the coordinator.

### pipeline.postprocess

`sunpack.pipeline.postprocess` only handles cleanup and flattening after success. It may accept `sunpack.core.contracts.RunContext` to consume successful archives and flattening candidates, but `sunpack.pipeline.postprocess.internal` does not depend on the coordinator.

### pipeline.coordinator

`sunpack.pipeline.coordinator` is the sole owner of pipeline flow dependencies, responsible for filesystem→relations→detection/input planning→extraction→verification→postprocess. It is also responsible for recursive rounds, batch scheduling, resource tokens, normal verification retries, and the summary. It does not implement stage algorithms; domain capabilities are called through public entry points. Archive cleanup is performed through public postprocess actions.

Other pipeline stages must not import `sunpack.pipeline.coordinator` in reverse. Detection may call only public Analysis capabilities; Analysis must not depend on pipeline stages. Cross-stage data is passed through shared result contracts in `sunpack.core.contracts`.

### core.support

`sunpack.core.support` holds shared infrastructure such as resource lookup, JSON, caching, path helpers, work context, and collision-free output path reservation. It may allocate output path names, but must not own extraction or post-processing policy or import pipeline/runtime packages.

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

Do not depend on `internal` across domains. Add a public facade, or move the shared contract into `sunpack.core.contracts`.

```python
knowledge = task.knowledge()
```

Do not read private task state. Use `ArchiveTask.knowledge()` / typed contracts, or add a public method.

```python
from sunpack.pipeline.coordinator.engine import PipelineEngine  # inside filesystem watcher scheduler
```

`sunpack.runtime.watch` does not construct the coordinator engine directly. The application composition layer creates and starts the process-level
`PipelineEngine`, then injects the instance into the watcher; the watcher only submits stable inputs and consumes request results.

`PipelineEngine` owns the scanner, analyzer, verification components, resource scheduler, and
7-Zip worker pool that persist across requests. `PipelineResponse`, the output policy, the post-processing manifest, and statistics belong to a request and must not be written back into the Engine's global accumulated state.

```python
from sunpack.pipeline.discovery.detection.formats import CONFIRMERS
```

Detection confirms routed single-file formats through independent modules in `sunpack.pipeline.discovery.detection.formats`. Relations owns RAR, 7z, and ZIP identity; Embedded owns carrier scanning.

## Refactoring checklist

After every change, at least run:

```powershell
rg "from sunpack\.[^.]+\.internal" sunpack tests
rg "\._facts|FactBag\._facts" sunpack tests
powershell -ExecutionPolicy Bypass -File scripts\run_ci_tests.ps1
```

Manually confirm:

- Does runtime only adapt CLI, GUI, and Watch interactions?
- Is the pipeline coordinator still only orchestration?
- Are relation capabilities exposed through `RelationsScheduler`?
- Is analysis still a general capability without business scheduling, and does detection call it only through public entry points?
- Does verification provide completeness and source integrity before a normal retry?
- Does the normal main pipeline keep the one-way lifecycle extraction → verification → postprocess?
- Has core.support avoided mixing in business policy or importing pipeline/runtime?

## Current structure at a glance

```text
sunpack/
  core/
    analysis/       Archive analysis and embedded scanning capabilities
    config/         Configuration loading, normalization, and field declarations
    contracts/      Cross-module data contracts
    i18n/           Translation catalogs and context
    passwords/      Password candidates, scheduling, and verifiers
    platform/       Windows platform capabilities
    support/        Shared infrastructure and work context
  pipeline/
    coordinator/    Pipeline orchestration, batch scheduling, and recursion
    discovery/      filesystem / relations / detection / embedded
    extraction/     Worker extraction and output inventory
    verification/   Extraction result verification
    postprocess/    Cleanup and flattening after successful extraction
  runtime/
    cli/            CLI commands, arguments, and output adaptation
    gui/            Tray and GUI entry points
    watch/          Long-running Watch service and startup lifecycle
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

Watch is a runtime input mode responsible for OS events, file readiness, quiet windows, durable state, retries, and notifications. It does not identify archive formats, resolve split families, or call discovery internals. Stable files enter the pipeline through `sunpack.pipeline.coordinator.engine.PipelineEngine.run()`, and Watch consumes only public response facts such as `claimed_paths` and `blocked_paths`. CLI and Watch therefore share the same discovery, planning, extraction, and verification path once a target enters the pipeline.
