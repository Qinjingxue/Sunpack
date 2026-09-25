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

| Setting | What to set |
| --- | --- |
| `cli.language` | `zh` for Chinese or `en` for English. |
| `recursive_extract` | `"*"` to keep processing nested archives, a positive integer for a fixed number of rounds, or `"?"` to ask after each round. |
| `recursive_authorization.enabled` | `true` to apply the nested archive selection policy; `false` to skip this policy. |
| `post_extract.archive_cleanup_mode` | `"r"` to recycle the original archive after success, `"k"` to keep it, or `"d"` to delete it. |
| `post_extract.flatten_single_directory` | `true` to lift the contents of a single top-level output folder. |
| `filesystem.directory_scan_mode` | `"-"` for files directly in the selected directory, or `"*"` to scan its subdirectories too. |
| `extraction.content_requirement` | `"complete"` to require a complete result, or `"allow_partial"` to accept partial recovery. |
| `watch.out_dir` | Default output directory for Watch roots without their own output path; `"."` means beside the input. |

For example, add these fields to the main configuration to keep original archives and scan subdirectories:

```json
{
  "post_extract": {"archive_cleanup_mode": "k"},
  "filesystem": {"directory_scan_mode": "*"}
}
```

CLI options such as `--recur`, `--cleanup`, and `--out-dir` let you set extraction behavior for one command. See the [CLI parameter reference](cli_parameters.md).

## Scan filters

Set `filesystem.scan_filters_enabled` to `false` to turn off all scan filters. To change one filter, add an entry with its `name` under `filesystem.scan_filters`:

```json
{
  "filesystem": {
    "scan_filters": [
      {"name": "size_range", "enabled": false}
    ]
  }
}
```

Available filters are `directory_prune` (skip directories), `whitelist` (include selected paths, names, or extensions), `blacklist` (exclude them), `size_range`, and `mtime_range`. Edit their fields in `sunpack_config.json`; the shipped `sunpack_advanced_config.json` shows the expected shapes. Extension filters can hide archives with disguised names.

## Watch and passwords

Add a monitored directory with `python sunpack.py watch add C:\Downloads`. Use `-o E:\Output` to choose its output directory, or set `watch.out_dir` for roots without one. `watch list` shows the configured roots. Watch monitors files directly in each root, not its subdirectories.

Put `sunpack-passwords.txt` beside archives to supply passwords, one per line. Set `passwords.directory_passwords_enabled` to `false` to stop reading those files, or `watch.directory_password_file_auto_create` to `false` to stop Watch creating them. CLI passwords can also be supplied with `-p` or `--pw-file`.

For less common settings, inspect `sunpack_advanced_config.json` and run `config show`. `SUNPACK_CONFIG_OVERRIDES` accepts an inline JSON object or a JSON file path for temporary overrides.
