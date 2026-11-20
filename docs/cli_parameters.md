# CLI parameter reference

[简体中文](zh-CN/cli_parameters.md) | **English** | [繁體中文](zh-TW/cli_parameters.md) | [日本語](ja/cli_parameters.md) | [한국어](ko/cli_parameters.md)

```powershell
sunpack.exe <command> [options] [paths...]
```

Top-level commands:

| Command | Purpose |
| --- | --- |
| `extract`, `e` | Scan, identify, extract, verify, post-process, and clean up. |
| `watch`, `w` | Monitor directories and process files automatically once they are stable. |
| `scan`, `s` | Read-only archive discovery and password confirmation. |
| `passwords`, `pw` | Show a summary of the password sources available to the current command. |
| `config`, `cfg` | Show or validate the merged effective configuration. |
| `daemon`, `d` | Control the daemon and logon startup. |
| `doctor`, `doc` | Read-only check of configuration and runtime environment. |
| `version`, `ver` | Print the installed SunPack version. |

Full names and the listed aliases are both supported syntax. Options accept only the short forms listed below; long options are not supported. JSON `command` fields always use the full command name. `-p` supplies a password; `-P` supplies a password file. `-f` enables flattening; `-nf` disables it. Separate options from their values, for example `-r 3` and `-c r`.

Passwords must use `-p PASSWORD` with a separate value; attached forms are not supported. The next token is taken literally, even if it starts with `-`. `-pa` on its own controls the exit pause.

Short command examples:

```powershell
sunpack e D:\Downloads -o E:\Output -r "*" -c r -d -P D:\pw.txt -npa
sunpack s D:\Downloads -v -d -j
sunpack w add D:\Downloads -o E:\Output -R -d
sunpack w ls
sunpack w st
```

## Common output options

These options apply to `extract` and `scan`:

| Option | Description |
| --- | --- |
| `-R` | Discover input subdirectories; independent of nested extraction with `-r`. |
| `-j` | Output results as JSON; suitable for scripting. |
| `-v` | Output more detection and diagnostic detail. |
| `-pa` | Wait for a key press before exiting. |
| `-npa` | Do not pause after the command finishes. |

`extract` and `scan` use high process priority while any foreground archive request is active. After the last foreground request finishes, an active Watch retains foreground priority until its idle deadline; without Watch, the shared runtime and native worker immediately return to the configured `runtime.process_mode`. Watch cache cleanup follows `watch.runtime_cache_cleanup_idle_seconds`.

`passwords` supports only `-j` plus the password input options; `config` supports `-j`. JSON results use a unified outer set of fields: `command`, `inputs`, `summary`, `errors`, `items`, `tasks`, `logs`; each command fills `items` or `tasks` according to its own semantics.

For `extract` and `scan`, normal text goes to stdout and errors go to stderr. `[Scan error]` identifies filesystem scan failures; `[Extraction failed]` identifies archive processing failures. `[Scan incomplete]` means some paths could not be read and the discovered results may be incomplete. Readable inputs are still processed. `-j` emits the JSON result without these text messages.

JSON `summary.scan_error_count` counts distinct filesystem scan failures in the report. Each diagnostic records the affected path, filesystem operation, and error detail.

`extract -j` reports archive and input failures in `tasks[].failures`. `scan -j` reports a logical archive error as `items[].error` and `items[].error_kind`; it does not expose the internal worker evidence or recovery preview. Scan fields are sparse: byte ranges appear for range inputs or embedded extents, and volume fields only for actual volume layouts or confirmed missing volumes. Internal unknown completeness is omitted; unresolved volume attempt plans use `pending` (or `missing` when confirmed). Retained extraction outputs are listed in `summary.recovered_outputs`.

For `extract`, `summary.failed_count` and each attempt's `failed_count` count archive processing failures. `input_error_count` separately counts invalid inputs, such as an unsupported filesystem object. These use `[Input error]` in text output. Attempts also include `scan_error_count` and `input_error_count`. Filesystem diagnostic details are stored once in `summary.scan_failures`. Each attempt's `failures` contains archive and input failures. Classification uses structured failure kinds and target results. All error categories remain in `errors` and cause a nonzero exit code, even when other archives succeed.

## extract

Usage:

```powershell
sunpack.exe extract [options] <paths...>
```

`paths` may be one or more files or directories. Directories are scanned shallowly by default; `-R` includes their subdirectories.

Options:

| Option | Description |
| --- | --- |
| `-p PASSWORD` | Provide one extraction password; may be repeated. |
| `-P PASSWORD_FILE` | Read passwords from a text file, one per line. |
| `-a` | Prompt for passwords interactively in the terminal; an empty line ends input. |
| `-d` | Use Embedded as the sole archive discovery entry. The first round scans all input files without filesystem scan filters; nested rounds retain filesystem filtering, `embedded_scan.recursive_candidate_ratio`, recursion depth and authorization. Selected files receive full-file scanning. |
| `-r VALUE` | Override the number of nested extraction rounds; accepts a positive integer, `*`, or `?`. |
| `-c VALUE` | Override how the original archive is handled on success: `d` delete, `r` Recycle Bin, `k` keep. |
| `-o OUTPUT_DIR` | Set the output root; relative paths are resolved against the current command directory. |
| `-f` | Lift the contents of a single top-level directory after extraction. |
| `-nf` | Keep the extracted directory structure. |

When `-o` is given, results land under "output root / the input path relative to its common root / archive name"; when it is omitted, results land next to the archive. When a nested archive is produced inside the output root, the sub-archive still computes its own output location from where it sits.

Values for `-r`:

- A positive integer such as `1`, `2`, `3`: a fixed number of recursive rounds.
- `*`: keep recursing while each round produces new processable nested archives.
- `?`: ask whether to continue after each round that produces new processable nested archives.

Examples:

```powershell
sunpack.exe extract D:\Downloads
sunpack.exe extract D:\A.7z -p 123456 -p secret
sunpack.exe extract D:\Archives -P .\passwords.txt -c r
sunpack.exe extract D:\Nested -r * -nf
sunpack.exe extract -d D:\MaybeArchive.bin
sunpack.exe extract D:\Archives -o E:\Unpacked
```

Exit codes:

- `0`: all tasks succeeded completely.
- `1`: at least one task failed.
- `2`: argument, path, or configuration error.
- `3`: runtime exception.
- `4`: no task failed, but at least one task only partially succeeded.

Extraction displays a tree of logical task scopes. Each carrier segment and nested archive owns its status, progress, and errors. Redirected output prints each complete tree when its root finishes; the final summary is unchanged.

## scan

Usage:

```powershell
sunpack.exe scan [options] <paths...>
```

`scan` shares extract's discovery, input planning, and password confirmation. Results are grouped by physical file and logical segment, showing only obtained format, range, volume, password, and error facts. Ordinary archives omit ranges; carriers show `[start, end)`, with `?` for an unknown end and a tree for multiple segments. Known encryption without a confirmed password is shown as “Password: not in password list”, without a duplicate password error; confirmed passwords are printed directly.

Ambiguous volumes retain compact slot candidates and layouts, without expanding combinations, and remain pending actual extraction. A bounded password test does not establish archive integrity or validate an entire volume set. Scan does not extract, create output directories, inspect contents that require extraction, verify outputs, flatten directories, or clean source files.

The password input options are shared with extract. `-v` adds existing discovery sources without extra analysis; `-j` independently selects the output format.

`-d` uses full-file Embedded discovery instead of the normal Relations/Detection prepass and disables filesystem scan filters for this request. Embedded reuses the existing password and volume resolver after discovering anchors. `-R` determines the directory scope. Each CLI request uses its own arguments, even when it shares a runtime with deep monitoring of the same input directory.

Examples:

```powershell
sunpack.exe scan D:\Downloads
sunpack.exe scan D:\Downloads -d -j
sunpack.exe scan D:\Downloads -v
```

## watch

Usage:

```powershell
sunpack.exe watch <add|remove|list|enable|disable|reload|relog|status> [options]
```

Monitored roots are stored in `sunpack_watch_roots.txt` inside the program resource directory. The format is `input directory | output root | deep_detect | initial_scanned | recursive | enabled`. Set the final column to `true` to monitor the folder or `false` to keep it disabled.

```text
C:\Downloads | | false | false | false | true
E:\Archives | E:\Output | false | false | false | true
F:\Incoming | . | true | false | true | true
G:\Incoming | | true | false | false | false
```

With an empty output column, extraction writes beside each archive. With `-o`, a relative output path is resolved against that input directory and persisted as an absolute path. The output root may be on a different drive. `watch` only observes the direct files of each root and does not recursively watch subdirectories; the input root must be on an NTFS or ReFS volume with a readable USN Journal.

`deep_detect` accepts `true` or `false`; an empty value defaults to `false`. This mode belongs to the input directory. Different input roots may share an output root and use different modes. Nested extraction, password retries, and crash recovery retain the original input root and use its configured mode. Deep mode disables all filesystem scan filters for that root's requests. Editing the column triggers configuration reload; `watch reload` also applies it.

`initial_scanned` records completion of the first candidate scan and defaults to `false` when empty. Startup and live reload automatically scan roots marked `false` and write `true` after queuing candidates, without waiting for extraction success. New roots and changed input paths start at `false`; output or deep-mode edits preserve the flag. Existing roots still recover offline changes through USN. Scan-state-only edits, reordered roots, comments, and equivalent path spellings do not restart the scheduler.

Subcommands and options:

| Subcommand | Option | Description |
| --- | --- | --- |
| `enable`, `ea` | — | Enable monitoring without changing the daemon lifecycle. |
| `add PATH...` | `-o DIR` | Add a monitored root; only one path may be added at a time. |
| `add PATH...` | `-R` | Enable recursive discovery for the monitored root. |
| `add PATH...` | `-d` | Persist `deep_detect=true` for each input root; update already registered roots too. |
| `remove PATH...`, `rm PATH...` | — | Remove a monitored root by input directory. |
| `list`, `ls` | — | List the persisted input directories. |
| `reload`, `rl` | — | Re-read the configuration and monitored roots. |
| `relog`, `rlg` | — | Rebuild logs. |
| `disable`, `da` | — | Persistently pause monitoring; keep the daemon and tray running. |
| `status`, `st` | — | Show whether the watch service is running. JSON also includes pending counts, the last error, and root directories. |

`enable` resumes monitoring. `disable` persists across process restarts; resuming skips new changes made while paused. Restarting a daemon while monitoring is enabled still recovers offline changes. Writing, moving, or modifying a file triggers an active cycle. New candidates have no initial delay; subsequent content changes adapt the quiet window to observed write intervals, without a fixed minimum or maximum wait. Ready files are submitted for processing. The arrival of a new volume or a change in password sources reactivates the affected tasks.

`add`'s `-o` can only be used together with a single input directory. Adding the same input directory again does not change the existing output mapping; you must `remove` and then `add` to update the mapping. The output roots of different monitored roots must not be strict ancestors or descendants of one another; the same output root may be shared.

Adding a new root without `-d` leaves deep mode disabled. Re-adding an existing root without the flag preserves its mode; set the third column to `false` or leave it empty to disable deep mode.

```powershell
sunpack.exe watch add D:\Downloads -d
sunpack.exe daemon start
```

The directory and directory-background context menus offer direct extraction, recursive extraction, password-prompted extraction, watch, recursive watch, and unwatch. The two file extraction entries enable `-d` by default.

## daemon (alias d)

```powershell
sunpack.exe daemon <start|stop|startup>
sunpack.exe daemon startup <enable|disable|status>
```

`start` starts the daemon and restores the saved monitoring state. `stop` waits for daemon shutdown without changing that state. `start -nt` suppresses the tray for this daemon session. `startup` manages the current user's logon startup entry. `stop` accepts `-j` and `-h`.

“Watch this folder” runs `watch add` followed by `daemon start`; it does not override a saved pause.

## passwords

Usage:

```powershell
sunpack.exe passwords [options]
```

Options:

| Option | Description |
| --- | --- |
| `-j` | Output the password source summary as JSON. |
| `-p PASSWORD` | Provide a password; may be repeated. |
| `-P PASSWORD_FILE` | Read passwords from a text file, one per line. |
| `-a` | Prompt for passwords interactively in the terminal. |

`passwords` has no archive path and summarizes global candidates. Extraction tries eligible recent successes first, then matching JSON scopes, CLI input, the current clipboard, and JSON global passwords and clipboard history. Candidates are deduplicated, with an empty password tried first when necessary.

Examples:

```powershell
sunpack.exe passwords
sunpack.exe passwords -p 123456
sunpack.exe passwords -P .\passwords.txt -j
```

## config

Usage:

```powershell
sunpack.exe config [options] <show|validate>
```

| Subcommand | Description |
| --- | --- |
| `show` | Print the effective configuration currently loaded. |
| `validate` | Validate the JSON, field values, detection rule names, and rule configuration. |

Options:

| Option | Description |
| --- | --- |
| `-j` | Output the result as JSON. |

Examples:

```powershell
sunpack.exe config show
sunpack.exe config validate
sunpack.exe config validate -j
```

## doctor

Usage:

```powershell
sunpack.exe doctor [-j]
sunpack.exe doc [-j]
```

`doctor` performs a read-only check of the configuration, the native extension, `7z.dll`, the SevenZip worker, Windows notification capability, and the configured monitored roots. A monitored root that does not exist is reported as a warning; the command never starts continuous monitoring or a real extraction, and never modifies the registry. The exit code is `1` when any check fails, and `0` when there are only warnings or skipped items.

## version

Usage:

```powershell
sunpack.exe version
```

`version` reads `VERSION.txt` next to the running SunPack executable and prints the value after `version=`. The packaged executable can also be invoked as `sunpack.exe version`.

## Windows context menu

Manage the current user's Explorer context menu from SunPack GUI settings or run either command from the application directory.

```powershell
.\SunPackGUI.exe --context-menu enable
.\SunPackGUI.exe --context-menu disable
```

The command runs without opening a window. A process exit code of zero indicates success. For a development build, pass `--app-root` and `--cli` to specify the application directory and launcher.

The folder and folder-background menus offer "Extract files in this folder" and "Enter password to extract files in this folder", plus watch and unwatch actions. The menu for any file offers "Extract this file" and "Enter password to extract this file", equivalent to:

```text
extract "%1" -d -pa
extract "%1" -a -d -pa
```

Output lands next to the archive by default.

`watch add DIR -R` enables recursive discovery for that root. Omitted optional columns use their default values. Split volumes may span subdirectories within one scope; separate roots remain independent. Watch outputs go directly to the root’s mapped output directory. CLI outputs default beside each archive, or beside the entry volume for a split archive. Pipeline output subtrees are protected from Watch, including later files added there.
