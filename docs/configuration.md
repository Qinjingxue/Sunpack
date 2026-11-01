# Configuration guide

**English** | [简体中文](zh-CN/configuration.md)

Edit `sunpack_config.json` to change everyday settings. When running from source, use the file in the project root. For an installed copy, use `%ProgramData%\SunPack\sunpack_config.json`. `sunpack_advanced_config.json` supplies the remaining defaults; you only need to add fields you want to change to the main file.

Objects are merged by field, and `filesystem.scan_filters` entries are merged by `name`. Other arrays are replaced as a whole. Watch reloads configuration changes automatically.

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
| `post_extract.archive_cleanup_mode`     | `"r"` to recycle the original archive after success, `"k"` to keep it, or `"d"` to delete it.                                |
| `post_extract.flatten_single_directory` | `true` to lift the contents of a single top-level output folder.                                                             |
| `extraction.content_requirement`        | `"complete"` to require a complete result, or `"allow_partial"` to accept partial recovery.                                  |

For example, add these fields to the main configuration to keep original archives:

```json
{
  "post_extract": { "archive_cleanup_mode": "k" }
}
```

CLI options such as `--recur`, `--cleanup`, and `--out-dir` let you set extraction behavior for one command. See the [CLI parameter reference](cli_parameters.md).

Directory discovery is shallow by default. Use `--recursive` with `scan`, `inspect`, or `extract`; nested extraction continues to use `--recur`. The configuration upgrade hook, atomic commit and failure rollback remain available from 1.3.0 onward. There are currently no migration rules, so upgrades do not rewrite user configuration.

## Scan filters

Set `filesystem.scan_filters_enabled` to `false` to turn off all scan filters. To change one filter, add an entry with its `name` under `filesystem.scan_filters`:

```json
{
  "filesystem": {
    "scan_filters": [{ "name": "size_range", "enabled": false }]
  }
}
```

Available filters are `directory_prune` (skip directories), `whitelist` (include selected paths, names, or extensions), `blacklist` (exclude them), `size_range`, and `mtime_range`. Edit their fields in `sunpack_config.json`; the shipped `sunpack_advanced_config.json` shows the expected shapes. Extension filters can hide archives with disguised names.

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

Analysis recognizes only the current archive layer. GZIP, BZIP2, XZ, Zstandard and LZ4 streams are extracted first; a resulting TAR is discovered and extracted by the normal recursive pipeline. The former `tar_*` analysis modules and all `max_probe_bytes` settings have been removed. Ordinary TAR analysis starts at offset zero; only the canonical embedded scanner can supply TAR candidates at other offsets. An empty `watch.state_dir` still selects the default state directory. A zero `memory_reserve_bytes` or `job_buffer_budget_bytes` still selects automatic sizing or the worker default. `watch.event_log_retention_days` controls task history and event retention shared by CLI and Watch. Installer upgrades update named filters, analysis modules, and verification methods while preserving user values, module order, and unknown extensions.

Add a monitored directory with `python sunpack.py watch add C:\Downloads`. Use `-o E:\Output` to choose its output directory; leaving it empty writes beside each archive. `watch list` shows the configured roots. Watch monitors files directly in each root, not its subdirectories.

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

For less common settings, inspect `sunpack_advanced_config.json` and run `config show`. `SUNPACK_CONFIG_OVERRIDES` accepts an inline JSON object or a JSON file path for temporary overrides.
