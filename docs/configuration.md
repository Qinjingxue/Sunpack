# Configuration file reference

**English** | [简体中文](zh-CN/configuration.md)

The commonly used configuration file is `sunpack_config.json`; the complete configuration file is `sunpack_advanced_config.json`. The program reads the advanced configuration first, then overrides fields with the same name from the simplified configuration: objects are merged recursively, while arrays and plain values are overridden wholesale.

When running from source, the configuration is usually read from the repository root or the current working directory. The installed version always reads `%ProgramData%\SunPack\sunpack_config.json` and takes `sunpack_advanced_config.json` from the install directory as the versioned base layer, so `sunpack_config.json` can be adjusted without reinstalling.

Check and view the effective configuration:

```powershell
python sunpack.py config validate
python sunpack.py config show
```

## Runtime overrides

The `SUNPACK_CONFIG_OVERRIDES` environment variable can override any configuration item before startup. Its value may be an inline JSON object or a path to a JSON file.

The merge order is: `sunpack_advanced_config.json` → `sunpack_config.json` → runtime overrides. The named module lists `filesystem.scan_filters`, `detection.fact_collectors`, `detection.processors`, and `detection.rule_pipeline.precheck` are merged by `name`, so an override only needs to contain the modules to be changed.

For example, to temporarily disable the size filter:

```powershell
$env:SUNPACK_CONFIG_OVERRIDES = '{"filesystem": {"scan_filters": [{"name": "size_range", "enabled": false}]}}'
python sunpack.py scan C:\Archives
```

An unknown top-level configuration section is reported as an error directly. CLI options (such as `--recur` and `--cleanup`) are applied as the last override layer after the configuration is loaded.

Test runs disable the `size_range` filter by default so that tests can use files smaller than 1 MB; a `SUNPACK_CONFIG_OVERRIDES` already set by the caller is preserved.

## Top-level structure

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

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `language` | `str` | `zh` | CLI language. `zh` uses Chinese; any other value uses English. |

## recursive_extract

| Value | Description |
| --- | --- |
| `*` | Keep processing nested archives while each round produces new processable archives. |
| Positive integer | A fixed number of allowed recursive rounds. |
| `?` | Ask whether to continue after each round that produces new processable archives. |

The first round runs exactly over the file or directory scope the user gave. Subsequent rounds apply `nested_extraction_policy` to the candidate archives found in the extraction output, and then decide whether to continue processing.

The CLI can override this setting temporarily with `--recur`.

## nested_extraction_policy

Before a nested archive enters password handling and extraction, this policy decides in bulk, based on directory context, whether it is a standalone archive in the user's sense. Inputs explicitly specified by the user in the first round are not affected by this policy; from the second round on, all candidates found in the output take part in the decision.

The decision uses the raw entries of a single directory snapshot and keeps the directory context from before the blacklist and size filters. Multiple candidates are aggregated together, and a volume set counts as only one archive. Rejected candidates appear in the run summary's policy-skip records and are not counted as extraction failures.

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | `bool` | `true` | Whether nested archive authorization is enabled. |
| `byte_ratio_exponent` | `float` | `1` | Exponent of the candidate archive byte ratio; must be positive. |
| `project_ratio_exponent` | `float` | `1` | Exponent of the candidate archive project ratio; must be positive. |
| `authorization_bias` | `float` | `0` | Authorization score bias; positive is more permissive, negative is more conservative. |
| `minimum_authorization_score` | `float` | `0.85` | Minimum authorization score for the local directory and the output root directory. |
| `minimum_archive_byte_ratio` | `float` | `0.1` | Reject when the candidate byte ratio is below this value. |
| `hard_maximum_other_projects` | `int` | `1000` | Reject when the number of valid non-candidate projects exceeds this value. |

Let the candidate byte ratio be `B`, the number of candidate archive projects be `A`, and the number of valid non-candidate projects be `O`; then the archive project ratio is `P = A / (A + O)`. The authorization score is:

```text
S = sigmoid(c + a × logit(B) + b × logit(P))
```

where `a`, `b`, and `c` correspond to the two exponents and the bias. `S` is a deterministic `0..1` score and is not a calibrated probability.

## post_extract

| Field | Type | Values | Description |
| --- | --- | --- | --- |
| `archive_cleanup_mode` | `str` | `d`, `r`, `k` | How to handle the original archive on success: delete, move to Recycle Bin, keep. |
| `flatten_single_directory` | `bool` | `true` / `false` | Whether to lift the contents of that directory when the result has only one top-level directory. |

The default cleanup mode is `r`.

## filesystem

### directory_scan_mode

| Value | Description |
| --- | --- |
| `*` | Recursively scan the target directory and its subdirectories. |
| `-` | Scan only the first level of files in the target directory. |

This setting only affects the input directory scan scope, not the recursive rounds of the extraction output.

### scan_filters

`scan_filters_enabled` is the master switch for filters. When set to `false`, the filter configuration is kept but not executed.

Filters run in array order. `directory_prune` prunes during directory traversal; `whitelist`, `blacklist`, `size_range`, and `mtime_range` act on scan entries. Filtered files do not enter relationship resolution, detection, or structural analysis.

`whitelist` example:

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

The non-empty fields of `whitelist` also act as constraints; `allowed_files` matches the complete file name, and `allowed_extensions` matches extensions. `blacklist` uses the corresponding `blocked_files` and `blocked_extensions`.

`directory_prune` supports `prune_dir_globs` and `path_globs`. The former matches directory names at any level, the latter matches paths relative to the scan root; the whole subtree of a pruned directory is skipped.

`size_range` restricts scan results by file size, where `r` denotes the byte count:

```json
{"name": "size_range", "enabled": true, "range": "1 MB < r < 10 MB"}
```

`B`, `KB`, `MB`, `GB`, `TB` as well as `KiB`, `MiB`, `GiB`, `TiB` are supported, advancing by 1024. The following equivalent fields are also supported:

| Field | Type | Description |
| --- | --- | --- |
| `gt` / `greater_than` | `int` | The file size must be greater than this value. |
| `gte` / `greater_than_or_equal` | `int` | The file size must be greater than or equal to this value. |
| `lt` / `less_than` | `int` | The file size must be less than this value. |
| `lte` / `less_than_or_equal` | `int` | The file size must be less than or equal to this value. |
| `eq` / `equal` | `int` | The file size must equal this value. |

`mtime_range` restricts scan results by file modification time, where `d` denotes the modification time:

```json
{"name": "mtime_range", "enabled": false, "date": "20260430 01:40 > d > 20250320 01:30"}
```

Dates support nanosecond timestamps, ISO time strings, and `YYYYMMDD HH:MM`, `YYYYMMDD HH:MM:SS`, and `YYYYMMDD`. The `gt`, `gte`, `lt`, `lte`, and `eq` fields are also supported.

Directory scanning and filtering are executed by native scanning capabilities; when a filter cannot be mapped to native parameters, an error is reported explicitly.

## runtime

`runtime` controls process-wide runtime behavior shared by Watch and foreground workloads.

| Field | Default | Description |
| --- | ---: | --- |
| `process_mode` | `normal` | Baseline Windows scheduling mode for the shared RuntimeHost and native worker. `normal` uses normal priority; `background` enables Windows Background Processing Mode; `high` uses `HIGH_PRIORITY_CLASS` and may reduce responsiveness of other applications. |

Foreground `extract`, `scan`, and `inspect` requests temporarily override this baseline with their `--process-mode` value; when omitted, that CLI override defaults to `high`. The override remains after the command finishes and expires at the existing idle-maintenance deadline (`watch.runtime_cache_cleanup_idle_seconds`), then the latest hot-reloaded `runtime.process_mode` becomes effective again. Changing `runtime.process_mode` while Watch is running is hot-applied without restarting the scheduler; an active CLI override still wins until it expires.

## performance

Both resource analysis and worker parameters live under `performance`. Defaults are:

| Field | Default | Description |
| --- | ---: | --- |
| `precise_resource_min_size_mb` | `256` | Perform a more precise resource assessment at or above this size when the conditions hold. |
| `persistent_server_idle_seconds` | `15` | How long the persistent server stays idle before exiting. |
| `worker.watchdog_no_progress_timeout_seconds` | `180` | Report a stall when there has been no progress for this long; `0` means unlimited. |
| `worker.thread_capacity` | `0` | Extraction thread capacity; `0` selects automatically based on machine capability. |
| `worker.stage_thread_capacity` | `0` | Thread capacity for scanning, analysis, verification, and post-processing; `0` selects automatically. |
| `worker.max_inflight_files` | `0` | File-level concurrency limit; `0` selects automatically, in the automatic range 64–512. |
| `worker.max_pending_stage_jobs` | `4096` | Upper limit of waiting stage jobs. |
| `worker.adaptive_enabled` | `true` | Whether to adjust extraction concurrency dynamically according to actual throughput. |
| `worker.initial_active_jobs` | `0` | Initial number of active jobs; `0` selects automatically. |
| `worker.exploration_strategy` | `calibrated` | Concurrency exploration strategy; one of `calibrated`, `rapid`, `full`. |
| `worker.resource_diagnostics_enabled` | `false` | Whether to sample CPU and process I/O diagnostic data. |
| `worker.minimum_window_seconds` / `maximum_window_seconds` | `0.25` / `1.5` | Shortest and longest duration of a throughput observation window. |
| `worker.settle_seconds` | `0.1` | Settling time after a concurrency adjustment. |
| `worker.large_window_bytes` | `33554432` | Actual written bytes for a large-task window. |
| `worker.small_window_jobs` / `small_window_files` | `4` / `16` | Job count and file count for a small-task window. |
| `worker.improvement_ratio` / `regression_ratio` | `1.03` / `0.97` | Thresholds for accepting an improvement and for declaring a regression. |
| `worker.aggressive_step` | `4` | Step size during rapid exploration. |
| `worker.cooldown_windows` / `hold_windows` | `2` / `8` | Number of windows for backoff cooldown and steady hold. |
| `worker.warm_start_decay_seconds` / `warm_start_confirmations` | `0` / `2` | Decay duration and confirmation count for warm-start hints. |
| `worker.max_queue_jobs` | `4096` | Upper limit of the native job queue. |
| `worker.priority_aging_quantum` | `32` | Priority aging step. |
| `worker.backpressure_retries` | `120` | Number of retries on queue backpressure. |
| `worker.writer_threads` | `4` | Number of writer threads. |
| `worker.memory_budget_bytes` | `0` | Memory admission budget; `0` selects automatically from available memory. |
| `worker.job_buffer_budget_bytes` | `33554432` | Output buffer limit per job. |
| `worker.memory_pause_available_mb` / `memory_resume_available_mb` | `1024` / `2048` | Thresholds at which job admission is paused and resumed under memory pressure. |
| `worker.space_gate_enabled` | `true` | Whether to check disk space before a job enters the write-out stage. |
| `worker.space_poll_interval_ms` | `1000` | Disk space check interval. |
| `worker.space_status_report_interval_ms` | `15000` | Disk space status report interval. |

Automatic concurrency is driven mainly by the throughput of actual writes, completed jobs, and completed files. Large tasks compare bytes/second, small tasks compare jobs/second or files/second; when throughput drops, the system returns to the stable concurrency and enters cooldown. Format, algorithm, solid state, and file count are not used as extra CPU weights. Resource diagnostics are sampled only when explicitly enabled.

### resource_guard

| Field | Default | Description |
| --- | ---: | --- |
| `enabled` | `false` | Whether the resource guard is enabled. |
| `max_file_count` | `0` | Entry count limit; `0` means unlimited. |
| `max_total_unpacked_size` | `0` | Total unpacked size limit, in bytes; `0` means unlimited. |
| `max_largest_item_size` | `0` | Single largest entry limit, in bytes; `0` means unlimited. |
| `max_compression_ratio` | `0` | Compression ratio limit; `0` means unlimited. |

## watch

`watch` controls the waiting, output, clipboard, and notification behavior of the monitoring service. CLI monitored roots are stored in `sunpack_watch_roots.txt` inside the program resource directory; each line may hold `input directory` or `input directory | output root`.

| Field | Default | Description |
| --- | ---: | --- |
| `cold_start_seconds` | `0.0` | Wait time when a file first becomes active. The default is 0, so a file can be processed as soon as it is ready. |
| `quiet_min_seconds` | `0.0` | Lower bound of the dynamic quiet time. |
| `quiet_max_seconds` | `180.0` | Upper bound of the dynamic quiet time; when `cold_start_seconds` is 0, no dynamic quiet wait is entered. |
| `boundary_confirmation_seconds` | `0.5` | Observation time for file boundary confirmation. |
| `max_folders` | `16` | Upper limit field for the number of directories in the configuration; the current CLI directory list is managed by `sunpack_watch_roots.txt`. |
| `observer_stop_timeout_seconds` | `5.0` | Wait time for stopping the file system observer thread. |
| `runtime_cache_cleanup_enabled` | `true` | Whether to clean up idle runtime caches. |
| `runtime_cache_cleanup_idle_seconds` | `10.0` | Shared idle-maintenance delay. At this deadline a CLI process-mode override expires; runtime caches are also cleared when `runtime_cache_cleanup_enabled` is true. |
| `password_retry_debounce_seconds` | `0.5` | Wait time before triggering a retry of failed jobs after the password file or clipboard changes. |
| `password_retry_include_subtree` | `true` | Whether a password source change retries the subtree tasks of the corresponding directory. |
| `directory_password_file_auto_create` | `true` | Whether Watch automatically creates `sunpack-passwords.txt` in each monitored directory. Existing files are still used when this is `false`. |
| `clipboard_monitor_enabled` | `true` | Whether to monitor clipboard password changes. |
| `clipboard_builtin_max_entries` | `30` | Number of clipboard passwords to keep. |
| `enabled` | `false` | Configuration-layer marker; the actual running state of the CLI service is managed by `watch start` and `watch stop`. |
| `roots` | `[]` | Default root directory list in the configuration; the CLI service uses the list in the root directory file. |
| `out_dir` | `.` | Default output location used when no output root is given in the root directory file; relative paths are resolved against the input directory. |
| `tray_enabled` | `true` | Whether the tray entry point is enabled. |
| `toast_enabled` | `true` | Whether to send Windows notifications. |
| `toast_update_interval_ms` | `50` | Notification progress update interval. |
| `toast_completion_debounce_ms` | `800` | Wait time for coalescing completion notifications. |
| `toast_success_ttl_seconds` | `3.0` | How long success notifications are kept. |
| `toast_failure_ttl_seconds` | `5.0` | How long failure notifications are kept. |
| `toast_report_retention_days` | `30` | Retention days for notification failure reports. |
| `toast_report_max_files` | `16` | Upper limit of failure report files. |
| `toast_report_max_bytes` | `2097152` | Upper limit of total failure report size, in bytes. |
| `state_dir` | `""` | Monitoring state directory; when empty, `.sunpack_watch` next to the root directory file is used. |

The monitoring service only observes the direct files of each root directory and does not recursively watch subdirectories. The input root must be on an NTFS volume, and that volume must have a readable USN Journal; otherwise the root cannot start monitoring.

`created`, `moved`, and `modified` events make a file active. Monitoring learns the quiet interval from actual content changes; plain size or mtime changes take part in interval learning, while other content events reset the current timing. One active cycle submits the main processing pipeline only once. The arrival of a new volume or a change in password sources reactivates the affected tasks.

The output root may be on a different drive. Complete output, partial output, and failed output are all written directly to the corresponding output root; when an output root sits inside a monitored input directory, output directory events are not treated as new input candidates. The output roots of different monitored roots must not be strict ancestors or descendants of one another; the same output root may be shared.

## passwords

| Field | Default | Description |
| --- | ---: | --- |
| `clipboard_passwords_enabled` | `true` | Whether to read the current clipboard text when a normal CLI starts. |
| `directory_passwords_enabled` | `true` | Whether to read the password file in the archive's own directory. |
| `directory_passwords_max_file_bytes` | `1048576` | Maximum read size of the per-directory password file. |
| `directory_passwords_max_password_length` | `512` | Maximum length of a single password. |

The per-directory password file is named `sunpack-passwords.txt`, one password per line. During archive extraction, candidate sources are merged and deduplicated in the order "most recent successful password → per-directory passwords → CLI arguments and password files → clipboard → built-in passwords"; while the archive's encryption state is still undetermined, the empty password may also be tried as the first candidate. `--no-builtin-pw` and `--no-dir-pw` disable built-in passwords and per-directory passwords respectively.

## extraction

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `write_progress_manifest` | `bool` | `false` | Whether to write a progress manifest to `.sunpack/extraction_manifest.json` in the output directory. |
| `content_requirement` | `str` | `complete` | Content requirement; one of `complete` or `allow_partial`. |

## embedded_scan

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | `bool` | `true` | Whether scanning for embedded archives in file carriers is allowed. |

This setting does not depend on file extensions. The system prefers low-cost head/tail information first; when needed, it performs a boundary-constrained full embedded scan on authorized candidates. Embedded scan results already obtained for the same input are reused in later decisions.

## input_planning

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | `bool` | `true` | Whether archive input planning is enabled. |
| `cache_size` | `int` | `512` | Number of analysis reports retained within a single request. |

Input planning turns structural analysis results into plain archives, split volumes, and embedded inputs; it does not modify the source files.

## analysis

| Field | Default | Description |
| --- | ---: | --- |
| `max_concurrent_reads` | `1` | Concurrency limit for reads of a single input. |
| `shared_cache_mb` | `64` | Size of the shared binary read cache. |
| `max_read_mb_per_archive` | `256` | Read limit for a single archive; `null` means unlimited. |
| `prepass.enabled` | `true` | Whether to read the head and tail regions for a quick pre-check. |
| `prepass.head_bytes` / `tail_bytes` | `1048576` / `1048576` | Head and tail pre-check sizes. |
| `fuzzy.enabled` | `true` | Whether binary signature analysis is enabled. |
| `thresholds.extractable_confidence` | `0.85` | Minimum confidence for direct extraction. |

Default structural modules and their main limits:

| Module | Default limit |
| --- | --- |
| `zip` | `max_cd_entries_to_walk = 64` |
| `rar` | `max_blocks_to_walk = 4096` |
| `seven_zip` | `max_next_header_check_bytes = 1048576` |
| `tar` | `max_entries_to_walk = 64` |
| `gzip`, `bzip2`, `xz`, `zstd`, `tar_gz`, `tar_bz2`, `tar_xz`, `tar_zst` | `max_probe_bytes = 4194304` |

`fuzzy.modules.binary_profile` uses a 65536-byte window by default, at most 8 windows, and at most 1048576 sampled bytes; the entropy thresholds are high `6.8`, low `3.5`, and delta `1.25`, the ngram top-k is `8`, and the ngram sample limit is `262144` bytes.

## verification

Verification combines the extraction exit status, output presence, entry matches, manifest sizes, CRC, and sample readability, and then produces a complete, partial, or failed verdict.

| Field | Default | Description |
| --- | ---: | --- |
| `enabled` | `true` | Whether result verification is enabled. |
| `max_retries` | `2` | Number of normal retries after a verification failure. |
| `cleanup_failed_output` | `true` | Whether to clean up failed output before retrying. |
| `complete_accept_threshold` | `0.999` | Minimum completeness for a complete result. |
| `partial_accept_threshold` | `0.2` | Minimum completeness for a partial result. |
| `retry_on_verification_failure` | `true` | Whether a retry is allowed after a verification failure. |
| `methods` | see the table below | Ordered list of verification methods. |

Default methods and key parameters:

| Method | Key parameters | Purpose |
| --- | --- | --- |
| `extraction_exit_signal` | `enabled: true` | Read the extraction status, diagnostics, and progress manifest. |
| `output_presence` | `enabled: true` | Check the output directory and its contents. |
| `expected_name_presence` | `max_expected_names: 50`, `required_match_ratio: 0.8` | Check the hit ratio of expected entry names; the missing penalty is `10/35/60`. |
| `manifest_size_match` | `max_expected_names: 2000`, file count tolerance `2` or `5%`, size tolerance `1048576` bytes or `2%` | Compare the archive manifest against the output scale. |
| `archive_test_crc` | `max_items: 200000`, `max_reported_items: 20` | Read the archive status and compare CRC. |
| `sample_readability` | `max_samples: 64`, `read_bytes: 4096`, `max_reported_items: 20` | Sample-read output files to confirm the artifacts are basically readable. |

## detection

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | `bool` | `true` | Master detection switch. When disabled, tasks are still generated from conventional archive extensions and split-volume entry points; use `extract --direct-file` to bypass the initial scan entirely. |

### fact_collectors

| Name | Purpose |
| --- | --- |
| `file_facts` | Collect basic information such as path, name, parent directory, and size. |
| `magic_bytes` | Read the file header magic bytes. |

### processors

| Name | Purpose |
| --- | --- |
| `embedded_archive` | Handle files that plain archive identification did not resolve and that are authorized for embedded scanning. |
| `zip_structure` | Check the ZIP local header. |
| `zip_eocd_structure` | Check the ZIP EOCD and central directory. |
| `tar_header_structure` | Check the TAR header checksum and ustar marker. |
| `compression_stream_structure` | Check the lightweight stream structure of gzip, bzip2, xz, and zstd. |
| `pe_overlay_structure` | Check archive payloads in the PE overlay. |
| `executable_carrier` | Check executable carriers and their archive regions; the default read limit is `8388608` bytes. |
| `seven_zip_structure` | Check the 7z signature, start header CRC, next header range, and NID. |
| `rar_structure` | Check the RAR4/RAR5 signature, main header, and block/header walk. |

### rule_pipeline.precheck

Default rules:

| Rule | Purpose |
| --- | --- |
| `zip_structure_accept` | Fast accept for structurally trustworthy ZIP files; empty ZIP files are allowed by default. |
| `tar_structure_accept` | Fast accept for structurally trustworthy TAR files. |
| `seven_zip_structure_accept` | Fast accept for 7z files with a trustworthy start/next header; the next header check limit is `1048576` bytes. |
| `rar_structure_accept` | Accept when the RAR main header/block walk is trustworthy; the first header check limit is `1048576` bytes. |
| `compression_stream_accept` | Fully validate gzip, bzip2, xz, and zstd streams. |
| `embedded_payload_identity` | Identify an executable carrier first, then accept files that are authorized and contain a reliable embedded archive. |

`embedded_payload_identity.deep_scan_single_candidate_ratio` defaults to `0.3`: a full embedded scan is performed when a single logical candidate accounts for 30% or more of the total unresolved candidate bytes. `0` disables that stage, and `1` selects only candidates that account for the entire size. A volume set counts as one logical candidate, and member volumes are not counted repeatedly.

## Password table and password files

`builtin_passwords.txt` stores one built-in password per line; when the file is missing, the program tries to create a default file. The per-directory password file is `sunpack-passwords.txt`, subject to the size and length limits of the `passwords` configuration section.

## Tuning suggestions

- To reduce wrong extractions: adjust `filesystem.scan_filters` and `detection.rule_pipeline.precheck`.
- To improve recall for disguised archives and carriers: review `embedded_scan`, `detection.processors`, and `analysis`.
- To analyze the decision process of a single input: use `inspect --analyze -v`.
- After changes, run `python sunpack.py config validate`.
