# Configuration guide

**English** | [简体中文](zh-CN/configuration.md)

Edit `sunpack_config.json` to change everyday settings. When running from source, use the file in the project root. For an installed copy, use `%ProgramData%\SunPack\sunpack_config.json`. `sunpack_advanced_config.json` supplies the remaining defaults.

Ordinary configuration values take precedence over the same fields in the advanced file; `SUNPACK_CONFIG_OVERRIDES` remains the final explicit override layer. Objects are merged by field, and `filesystem.scan_filters` entries are merged by `name`. Other arrays are replaced as a whole. Watch reloads configuration changes automatically.

Check your changes and view the resulting configuration:

```powershell
python sunpack.py config validate
python sunpack.py config show
```

For an installed copy, replace `python sunpack.py` with `sunpack.exe`.

## Common settings

| Setting                                 | What to set                                                                                                                  |
| --------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `cli.language`                          | `zh` for Chinese or `en` for English.                                                                                        |
| `recursive_extract`                     | `"*"` to keep processing nested archives, a positive integer for a fixed number of rounds, or `"?"` to ask after each round. |
| `recursive_authorization.enabled`       | `true` to apply the nested archive selection policy; `false` to skip this policy.                                            |
| `post_extract.archive_cleanup_mode`     | `"r"` to recycle the original archive after complete success, `"k"` to keep it, or `"d"` to delete it.                                |
| `post_extract.flatten_single_directory` | `true` to lift the contents of a single top-level output folder.                                                             |
| `passwords.clipboard_passwords_enabled` | `true` (default) reads the current clipboard for CLI password candidates. |
| `watch.clipboard_monitor_enabled` | `true` (default) lets a running Watch save clipboard password history. |
| `watch.clipboard_builtin_max_entries` | Keep the newest 30 clipboard history entries by default, minimum 1. |
| `watch.toast_report_retention_days` | Keep failure reports for 30 days by default, minimum 1. |
| `extraction.content_requirement`        | `"complete"` to require a complete result, or `"allow_partial"` to accept partial recovery.                                  |

For example, add these fields to the main configuration to keep original archives:

```json
{
  "post_extract": { "archive_cleanup_mode": "k" }
}
```

CLI options such as `--recur`, `--cleanup`, and `--out-dir` let you set extraction behavior for one command. See the [CLI parameter reference](cli_parameters.md).

Directory discovery is shallow by default. Use `--recursive` with `scan` or `extract`; nested extraction continues to use `--recur`. Upgrades from installed versions below 1.4.0 reset managed runtime data and convert legacy scan-filter fields. Read the [upgrade warning](upgrade-v1.4.md) and back up your data first.

## Partial success and result verification

`extraction.content_requirement` in `sunpack_config.json` is the single partial-success setting. The GUI's “Required extraction result” edits the same field. The default, `"complete"`, accepts only complete results; `"allow_partial"` accepts recoverable partial results identified by verification. CLI, Watch and nested extraction share it. The `-k`, `--allow-partial` and `--ap` overrides have been removed. Partial acceptance does not turn authentication, execution or independent-input failures into success, and never authorizes recycling or deleting that partial result's source archive.

The same key in an older advanced configuration remains readable, with the ordinary configuration taking precedence. During an installation upgrade, a missing ordinary setting is filled from the old advanced value, or with `"complete"` if neither exists.

Complete acceptance retains the internal completeness condition of `0.999`, together with a complete assessment and compatible content integrity. There is no external threshold setting.

When complete acceptance does not apply, at least one actual file in the output inventory supports a partial recommendation, including a zero-byte file. No minimum recovered proportion, output-quality score, confidence or estimated recoverable upper bound is required. Empty directories and records of missing files do not count as output files. Password requests and explicit failure recommendations still take precedence.

Verification, coverage, quality scores and damage evidence still run normally. Only the terminal decision applies the ordinary partial-success setting; this does not introduce per-file damage filtering or repair.

`manifest_size_match` compares file counts and total unpacked bytes exactly, without absolute or ratio tolerances. Shortfalls produce failure issues and excesses produce warnings; per-file name, size and CRC checks still run independently.

`archive_test_crc` no longer caps missing-file, CRC-mismatch, size-mismatch or read-error details by item count. Rust encodes complete JSON streams during verification and reuses byte-based spill storage. Python retains immutable handles, while CLI and Watch reports stream the encoded data directly. Temporary storage is reclaimed when its last owning result or knowledge snapshot is released. Writing a complete report still costs disk IO proportional to its contents.

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
  "paths": [{"value": ".git", "regex": false}],
  "files": [{"value": "report*", "regex": false}],
  "extensions": [{"value": "zip", "regex": false}],
  "full_names": [
    {"value": "report[final]+.zip", "regex": false},
    {"value": "\\.(?:tmp|log|bak)\\z", "regex": true}
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

Monitored roots are stored in `sunpack_watch_roots.txt` and managed through the GUI or `watch add/remove`. Start and stop monitoring through the GUI or `watch start/stop`. The unused `watch.enabled`, `watch.roots`, `watch.max_folders`, and `performance.worker.priority_aging_quantum` settings have been removed.

Monitored input folders require NTFS. On startup or configuration reload, the backend removes confirmed non-NTFS paths from the watch list and displays a classic Windows error dialog in `cli.language`, listing the paths, filesystems, and removal result. Monitoring starts for the remaining folders without waiting for dialog acknowledgment. An empty list still allows the service to start and wait for new folders. Files and folders are not deleted, and temporarily offline paths are retained.

Analysis recognizes only the current archive layer. GZIP, BZIP2, XZ, Zstandard and LZ4 streams are extracted first; a resulting TAR is discovered and extracted by the normal recursive pipeline. The former `tar_*` analysis modules and all `max_probe_bytes` settings have been removed. Ordinary TAR analysis starts at offset zero; only the canonical embedded scanner can supply TAR candidates at other offsets. `watch.event_log_retention_days` controls task history and event retention shared by CLI and Watch.

Add a monitored directory with `python sunpack.py watch add C:\Downloads`. Use `-o E:\Output` to choose its output directory; leaving it empty writes beside each archive. `watch list` shows the configured roots. Watch monitors files directly in each root, not its subdirectories.

## Automatic runtime settings

Input planning runs whenever required, with no configuration switch. Its report cache has an internal limit of 512 entries; the shared analysis cache is 64 MiB and the worker job buffer budget is 32 MiB. Analysis views impose no artificial read concurrency limit; independent reads can overlap while retaining existing cache synchronization and resource lifecycle protection. The entire `input_planning` section, `analysis.shared_cache_mb`, `analysis.max_concurrent_reads`, and `performance.worker.job_buffer_budget_bytes` have been removed from the configuration and GUI. Installer upgrades remove old ordinary overrides and deploy the new advanced template; runtime code has no compatibility path for these controls.

Native worker and Python stage thread capacities always use their existing automatic strategies. Queue limits are internal (4096), with existing backpressure retained. Native memory reserve is automatic: 128 MiB plus 16 MiB per nominal CPU credit. Disk-space pause/retry and idle cache maintenance are always enabled. `watch.runtime_cache_cleanup_idle_seconds` remains configurable (default 10 seconds); maintenance is event/deadline driven, not periodic idle polling. The native worker internally uses 4 writer threads per volume.

The two clipboard switches and history limit are exposed in the ordinary configuration and remain in the advanced template. They are independent: disabling current clipboard use does not disable Watch history collection; disabling both does not erase saved history. Clipboard history is saved as plaintext in `builtin_passwords.json`.

Failure reports use only `watch.toast_report_retention_days`. Count and byte limits and detail truncation have been removed. Complete details are streamed to disk during a batch. Native encoding uses fixed-size buffers and lazy failure views rather than joining error text, building copied failure trees or allocating full escaped JSON strings. Report work runs through the existing work broker, releases the GIL during encoding/I/O, and does not hold the notification-state lock while writing. Cancellation drains the writer and removes incomplete output. This bounds additional report-encoding memory, not the extraction diagnostics and native inventories already held by their owners; traversal also needs space proportional to nesting depth. Expired reports and abandoned temporary reports are cleaned when a new report is written, not by a new timer.

State always lives in `.sunpack_watch` under the writable data directory (`%ProgramData%\SunPack` for installed copies). It is shared by CLI, Watch and the GUI. There is no state-directory setting or runtime directory-switch mechanism.

The installer and `scripts/upgrade_config.ps1` own upgrades. For installed numeric base versions below 1.4.0, the new ordinary template defines the retained fields: existing ordinary values (including `false`, `0`, empty values and `null`) take precedence, then old advanced values for fields promoted to ordinary settings, then new defaults. New fields are added and retired fields removed. Manually copied advanced-only fields and unknown extensions are not retained; the advanced file is replaced by the new template.

Only the ordinary settings, Watch roots and nonblank built-in passwords are retained from managed data. Watch root paths, outputs, `deep_detect`, `recursive` and comments are preserved, but `initial_scanned` resets to `false`. Other managed data, including recovery tasks, catalog, task/event history, caches and failure reports, is deleted rather than migrated. In a custom Watch state directory outside managed data, only known SunPack records are removed; unrelated contents are left untouched. An unknown installed version with existing data stops the destructive reset; versions 1.4.0 and newer do not receive this legacy reset. See the [bilingual upgrade notes](upgrade-v1.4.md) for backup and rescan warnings. Runtime code does not migrate or read retired controls.

Persistent passwords come only from `builtin_passwords.json`, including its `clipboard_history`. Add records with `value` to `passwords`; optional `scopes` lists absolute directories and applies to their descendants too. Omit `scopes` for global passwords. Runtime sources are explicit input (`-p`, `--pw-file`, or the password prompt) and the current clipboard.

```json
{
  "passwords": [
    { "value": "global-password" },
    { "value": "scoped-password", "scopes": ["D:/Downloads", "E:/Archives"] }
  ],
  "clipboard_history": []
}
```

