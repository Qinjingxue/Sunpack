# Configuration guide

**English** | [简体中文](zh-CN/configuration.md)

Edit `sunpack_config.json` to change everyday settings. For a development build, use the file in the project root. For an installed copy, use `%ProgramData%\SunPack\sunpack_config.json`. `sunpack_advanced_config.json` supplies the remaining defaults.

Ordinary configuration values take precedence over the same fields in the advanced file; `SUNPACK_CONFIG_OVERRIDES` remains the final explicit override layer. Objects are merged by field, and `filesystem.scan_filters` entries are merged by `name`. Other arrays are replaced as a whole. Watch reloads configuration changes automatically.

Check your changes and view the resulting configuration:

```powershell
sunpack.exe config validate
sunpack.exe config show
```

## Common settings

| Setting                                 | What to set                                                                                                                  |
| --------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `cli.language`                          | `zh` for Chinese or `en` for English.                                                                                        |
| `recursive_extract`                     | `"*"` to keep processing nested archives, a positive integer for a fixed number of rounds, or `"?"` to ask after each round. |
| `recursive_authorization.enabled`       | `true` to apply the nested archive selection policy; `false` to skip this policy.                                            |
| `post_extract.archive_cleanup_mode`     | `"r"` to recycle the original archive after complete success, `"k"` to keep it, or `"d"` to delete it.                       |
| `post_extract.flatten_single_directory` | `true` to lift the contents of a single top-level output folder.                                                             |
| `passwords.clipboard_passwords_enabled` | `true` reads the current clipboard for CLI password candidates.                                                              |
| `watch.deduplication`                   | `"file_id"`for hard links, `"none"` for no deduplication, or `"hash"` for identical logical archive contents.                |
| `watch.deduplication_scope`             | `"root"` compares within one monitored root; `"global"` compares across all monitored roots.                                 |
| `watch.clipboard_monitor_enabled`       | `true` lets a running Watch save clipboard password history.                                                                 |
| `watch.clipboard_builtin_max_entries`   | Keep the newest 30 clipboard history entries by default, minimum 1.                                                          |
| `watch.toast_report_retention_days`     | Keep failure reports for 30 days by default, minimum 1.                                                                      |
| `extraction.content_requirement`        | `"complete"` to require a complete result, or `"allow_partial"` to accept partial recovery.                                  |

For example, add these fields to the main configuration to keep original archives:

```json
{
  "post_extract": { "archive_cleanup_mode": "k" }
}
```

CLI options such as `-r`, `-c`, and `-o` let you set extraction behavior for one command. See the [CLI parameter reference](cli_parameters.md).

Directory discovery is shallow by default. Use `-R` with `scan` or `extract`. Use `-r` for nested extraction. Upgrades from installed versions below 1.4.0 reset managed runtime data and convert legacy scan-filter fields. See [Automatic runtime settings](#automatic-runtime-settings) for the data retained during migration.

## Extraction results and partial success

The worker's final result determines extraction success after decoding, writing and closing outputs. A successful empty archive or directory-only archive is complete. Container warnings alone do not trigger a second source walk, output CRC pass or LZ4 plan/receipt comparison. Success concerns the logical input and members processed by the worker; it does not prove that a damaged container exposed every original member.

`extraction.content_requirement` in `sunpack_config.json` controls partial acceptance. `"complete"` is the default. `"allow_partial"` accepts damaged or missing-volume results only when the final worker report identifies at least one completed file, including a zero-byte file. Written bytes, unfinished members and unreported files do not establish completion. Authentication, process and output I/O failures remain failures. Partial acceptance retains the extraction output; it does not repair or independently validate damaged files.

Coordinator owns this decision, per-input checkpoints and recovery. Complete siblings survive retries of failed inputs. Only complete success authorizes source cleanup, including the existing shared-carrier ownership checks. CLI, Watch and nested extraction share this behavior.

The verification framework, method settings, completeness thresholds and quality scores have been removed. Installation upgrades discard the old `verification` configuration section. The partial-success setting remains available in the GUI; ordinary configuration takes precedence over an older advanced setting.

## Scan filters

Set `filesystem.scan_filters_enabled` to `false` to turn off all scan filters. To change one filter, add an entry with its `name` under `filesystem.scan_filters`:

```json
{
  "filesystem": {
    "scan_filters": [{ "name": "size_range", "enabled": false }]
  }
}
```

Available filters are `blacklist`, `whitelist`, `size_range`, and `mtime_range`. Edit their fields in `sunpack_config.json`; the shipped `sunpack_advanced_config.json` shows the expected shapes. Extension filters can hide archives with disguised names.

Blacklists and whitelists use four lists of records:

```json
{
  "name": "blacklist",
  "enabled": true,
  "paths": [{ "value": ".git", "regex": false }],
  "files": [{ "value": "report*", "regex": false }],
  "extensions": [{ "value": "zip", "regex": false }],
  "full_names": [
    { "value": "report[final]+.zip", "regex": false },
    { "value": "\\.(?:tmp|log|bak)\\z", "regex": true }
  ]
}
```

Each record has an independent `regex` boolean. When disabled, `*` matches zero
or more characters and `?` matches one Unicode character; other symbols are
literal. These rules match the whole selected value. Neither wildcard crosses
`/`, and repeated stars have no recursive meaning. Enabled uses Rust regex
syntax, which excludes look-around and backreferences, and searches the selected
value. All four fields are case-sensitive for ordinary and regex rules; Unicode
text is matched directly. Regex inline flags retain their standard meaning.

`files` selects the filename before its last dot, `extensions` selects the part
after that dot (without a leading dot), and `full_names` selects the full basename.
For `bundle.part01.rar.jpg` these values are `bundle.part01.rar`, `jpg`, and
`bundle.part01.rar.jpg`. Without a dot, the filename is unchanged and there is no
extension to match. A final dot gives an empty extension; `.zip` has an empty
filename and extension `zip`. These selectors apply only to files. Archive
detection still uses content, including for disguised names and split volumes.

`paths` matches only directories. For a file, its final filename is removed before
matching; use `files`, `extensions`, or `full_names` to match the filename. A bare
ordinary path matches a directory component at any depth. Ordinary rules containing
`/` or `\` are relative to the scan root. Path regexes search root-relative directory
paths with `/` separators; the expression itself is preserved. A matched directory includes
its subtree, including matches ending in `\z`: `\Adownloads\z` selects the root's
downloads directory and its descendants. The scan root itself is never pruned.
Whitelist traversal retains ancestors of possible matches; unanchored regexes
may match at any depth. A field uses OR; blacklists reject any matching field,
while whitelists require every nonempty field. Empty arrays impose no restriction.

The GUI checkbox controls the current record and defaults off. Click a tag to
edit it; blue tags denote regex records. Enter submits the change.
Validation failures retain the draft and leave the saved configuration intact.
Enter regex backslashes normally in the GUI; saving handles JSON escaping.

The installer converts the released v1.3.0–v1.3.4 filter schema; the modern
v1.3.5 shape is retained. Untagged development schemas have no compatibility
guarantee. Old complete filenames move to `full_names`, and old extension entries
to `extensions`; their whitelist AND relationship remains in one module.
Directory-prune and blacklist rules merge when both old modules are enabled.
If only one is enabled, only that module's active rules are retained; the disabled
side is discarded so its rules are not silently enabled. If both are disabled,
the merged rules are retained with the blacklist disabled. Old path Globs retain
component-boundary matching, using regex records when necessary. Legacy whitelist
path groups are combined into one OR list instead of separate AND conditions.
Runtime uses only the current schema.

Size bounds are inclusive integer bytes from 0 to 18446744073709551615. Equal bounds select one exact size. Time bounds use UTC minute strings in `YYYY-MM-DDTHH:mmZ` format, including the start and excluding the end. `null` leaves that side unbounded; specify both bounds explicitly to override defaults. For example:

```json
{
  "filesystem": {
    "scan_filters": [
      {
        "name": "size_range",
        "enabled": true,
        "min_bytes": 1,
        "max_bytes": null
      },
      {
        "name": "mtime_range",
        "enabled": true,
        "start_utc": "2024-01-01T00:00Z",
        "end_utc": "2027-01-01T00:00Z"
      }
    ]
  }
}
```

The GUI edits time in the Windows local time zone and saves UTC. Size units accept decimals with exact byte rounding. Expressions, field aliases, and second/subsecond timestamps are not accepted; runtime configuration migration is not provided.

## Watch and passwords

Monitored roots are stored in `sunpack_watch_roots.txt` and managed through the GUI or `watch add/remove`. Start and stop monitoring through the GUI or `watch enable/disable`. The unused `watch.enabled`, `watch.roots`, `watch.max_folders`, and `performance.worker.priority_aging_quantum` settings have been removed.

Monitored input folders require NTFS or ReFS. On startup or configuration reload, the backend removes paths confirmed to use neither filesystem from the watch list and displays a classic Windows error dialog in `cli.language`, listing the paths, filesystems, and removal result. Monitoring starts for the remaining folders without waiting for dialog acknowledgment. An empty list still allows the service to start and wait for new folders. Files and folders are not deleted, and temporarily offline paths are retained.

Analysis recognizes only the current archive layer. GZIP, BZIP2, XZ, Zstandard and LZ4 streams are extracted first; a resulting TAR is discovered and extracted by the normal recursive pipeline. The former `tar_*` analysis modules and all `max_probe_bytes` settings have been removed. Ordinary TAR analysis starts at offset zero; only the canonical embedded scanner can supply TAR candidates at other offsets. `watch.event_log_retention_days` controls task history and event retention shared by CLI and Watch.

Add a monitored directory with `sunpack.exe watch add C:\Downloads`. Use `-o E:\Output` to choose its output directory; leaving it empty writes beside each archive. `watch list` shows the configured roots. Watch monitors files directly in each root, not its subdirectories.

## Automatic runtime settings

Archive discovery produces the execution plan once. The former Direct-file planning pass, its stream report cache, and the `analysis.modules` controls have been removed. Deep mode uses full-file Embedded discovery in every extraction round; ordinary mode retains its fast discovery routes. Both reuse the existing password and volume resolvers. The shared analysis cache remains 64 MiB and the worker job buffer budget remains 32 MiB. Independent reads retain existing cache synchronization and resource lifecycle protection. The removed `input_planning`, `analysis.shared_cache_mb`, `analysis.max_concurrent_reads`, and `performance.worker.job_buffer_budget_bytes` controls have no runtime compatibility path.

Native worker and Python stage thread capacities always use their existing automatic strategies. Queue limits are internal (4096), with existing backpressure retained. Native memory reserve is automatic: 128 MiB plus 16 MiB per nominal CPU credit. Disk-space pause/retry and idle cache maintenance are always enabled. `watch.runtime_cache_cleanup_idle_seconds` remains configurable (default 10 seconds); maintenance is event/deadline driven, not periodic idle polling. The native worker internally uses 4 writer threads per volume.

The two clipboard switches and history limit are exposed in the ordinary configuration and remain in the advanced template. They are independent: disabling current clipboard use does not disable Watch history collection; disabling both does not erase saved history. Clipboard history is saved as plaintext in `builtin_passwords.json`.

Failure reports use only `watch.toast_report_retention_days`. Count and byte limits and detail truncation have been removed. Complete details are streamed to disk during a batch. Native encoding uses fixed-size buffers and lazy failure views rather than joining error text, building copied failure trees or allocating full escaped JSON strings. Report work runs through the existing work broker, releases the GIL during encoding/I/O, and does not hold the notification-state lock while writing. Cancellation drains the writer and removes incomplete output. This bounds additional report-encoding memory, not the extraction diagnostics and native inventories already held by their owners; traversal also needs space proportional to nesting depth. Expired reports and abandoned temporary reports are cleaned when a new report is written, not by a new timer.

State always lives in `.sunpack_watch` under the writable data directory (`%ProgramData%\SunPack` for installed copies). It is shared by CLI, Watch and the GUI. There is no state-directory setting or runtime directory-switch mechanism.

The installer and `scripts/upgrade_config.ps1` own upgrades. For installed numeric base versions below 1.4.0, the new ordinary template defines the retained fields: existing ordinary values (including `false`, `0`, empty values and `null`) take precedence, then old advanced values for fields promoted to ordinary settings, then new defaults. New fields are added and retired fields removed. Manually copied advanced-only fields and unknown extensions are not retained; the advanced file is replaced by the new template.

For this upgrade, SunPack retains ordinary settings, Watch roots and nonblank built-in passwords. Watch root paths, outputs, `deep_detect`, `recursive` and comments are preserved, and `initial_scanned` resets to `false`. The upgrade removes other managed data, including recovery tasks, the catalog, task and event history, caches and failure reports. In a custom Watch state directory, it removes only known SunPack records. Versions 1.4.0 and newer keep their existing managed data and remove retired verification settings. Development builds identified only by a commit hash, timestamp or custom label keep their existing managed data and skip version-specific migration. The same applies when the previous version is missing.

Persistent passwords come only from `builtin_passwords.json`, including its `clipboard_history`. Add records with `value` to `passwords`; optional `scopes` lists absolute directories and applies to their descendants too. Omit `scopes` for global passwords. Runtime sources are explicit input (`-p`, `-P`, or the password prompt) and the current clipboard.

```json
{
  "passwords": [
    { "value": "global-password" },
    { "value": "scoped-password", "scopes": ["D:/Downloads", "E:/Archives"] }
  ],
  "clipboard_history": []
}
```

## Watch deduplication

Set `watch.deduplication` to `none`, `file_id`, or `hash` in configuration or the GUI. The shipped ordinary configuration enables hard-link deduplication; the advanced default and fallback remain `none`. Ordinary settings override advanced settings. Only confirmed archives with a determined logical layout enter this index; ordinary files and uncertain volume combinations do not. Ordered volume members and carrier ranges are part of the logical input. This does not compare extracted contents or affect CLI extraction.

`file_id` compares underlying file identities; `hash` uses streaming XXH3-128 content digests after a size check. Hash equality is probabilistic, not a cryptographic guarantee. A duplicate is skipped even when the original is pending or failed; it is not reported as an extraction success and its source is not cleaned. The original input can still retry. The GUI lists skips in the successful category with the green “Duplicate skipped” label; this is not an extraction success. Records remain valid only while their input files exist in the monitored scope.

Every mode change discards the old in-memory and persisted deduplication index. `none` stops there; `file_id` rescans confirmed inputs, and `hash` also reads their contents to build the new index. Rebuilding does not extract or clean files. Restarting without changing the mode reuses the independently persisted index after validation instead of hashing everything again.

`watch.deduplication_scope` defaults to `root` in both configuration files. Use `global` to compare across monitored roots: hash mode can identify equal logical input contents across roots or volumes, while hard-link mode uses the volume plus file ID (matching IDs on different volumes are not the same file). A pathname shared by nested monitored roots is still one input, not its own duplicate. Changing the scope discards and rebuilds the deduplication index just like changing its mode; with deduplication disabled, no index is built.
