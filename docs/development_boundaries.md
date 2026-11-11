# Development boundaries

**English** | [简体中文](zh-CN/development_boundaries.md)

The Windows runtime lives in `native/sunpack_native`. Its dependency direction is `runtime → pipeline → core`. Both the pipeline and core use the existing archive analysis, I/O, and filesystem modules.

| Layer | Responsibility |
| --- | --- |
| `runtime` | CLI and Watch entry points, persistent launcher sessions, NTFS readiness, Watch state, tray, and notifications |
| `pipeline` | Discovery, extraction admission, worker requests, recursive processing, checkpoints, and cleanup |
| `core` | Typed configuration, password snapshots, localization, resource paths, and shared Windows process facilities |
| Native computation | Format analysis, logical readers, volume relationships, password probes, directory scans, and output inventories |

CLI and Watch submit the same typed request to `pipeline::Engine`. Archive analysis establishes the logical source layout and structural facts during discovery. Password probes, worker planning, recovery, and reporting reuse that state. JSON serialization belongs at the CLI, diagnostics, and persistence boundaries. The C++ worker receives the data required for execution through the existing SPBF protocol.

## Archive identity and recovery

A physical source can carry several independent logical archives. Each logical input has its own source ranges, result, and recovery checkpoint. Cleanup runs for the physical group after its logical work is resolved. A checkpoint records source generations and output identities, and retains the winning volume selection when it can be matched to current discovery. Checkpoints retain neither passwords nor live readers.

Uncertain volume plans share source extents and ordered slot domains. The worker enumerates feasible compositions lazily and reports selected source indexes. Memory withdrawal replays the current composition. A password result that depends on an unresolved volume choice cannot enter the exact-input negative cache.

Watch owns readiness, restart recovery, and durable publication. The pipeline reports output reservations, completed inputs, and promoted nested sources at the filesystem transition that needs a durable record. Recovery validates source and output identity before reusing a checkpoint.

## Lifetime and tests

Directory snapshots, password snapshots, and compiled filters are borrowed or shared for the lifetime of active work. In-flight source and output claims are released with their requests. Native correctness tests cover the computation core. Python boundary tests invoke native executables or scripts and inspect user-visible effects.
