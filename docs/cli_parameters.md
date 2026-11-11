# CLI parameter reference

**English** | [简体中文](zh-CN/cli_parameters.md)

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
| `doctor`, `d` | Read-only check of configuration and runtime environment. |
| `version`, `ver` | Print the installed SunPack version. |

Full names and the listed aliases are both supported syntax. Arbitrary long-option prefixes are rejected. JSON `command` fields always use the full command name. `-p` supplies a password; `-P` supplies a password file. `-f` enables flattening; `-F` disables it. Separate options from their values, for example `-r 3` and `-c r`.

Short command examples:

```powershell
sunpack e D:\Downloads -o E:\Output -r "*" -c r -d -P D:\pw.txt --no-pause
sunpack s D:\Downloads -v -d -j
sunpack w add D:\Downloads -o E:\Output -s -R -d
sunpack w ls
sunpack w st
```

## Common output options

These options apply to `extract` and `scan`:

| Option | Description |
| --- | --- |
| `-R/--recursive` | Discover input subdirectories; independent of nested extraction with `--recur`. |
| `-j`, `--json` | Output results as JSON; suitable for scripting. |
| `-v`, `--verbose` | Output more detection and diagnostic detail. |
| `--pause` | Wait for a key press before exiting. |
| `--no-pause` | Do not pause after the command finishes. |

`extract` and `scan` use high process priority. When the shared runtime reaches the Watch idle-maintenance deadline (`watch.runtime_cache_cleanup_idle_seconds`), it returns to the configured `runtime.process_mode`.

`passwords` supports only `--json` plus the password input options; `config` supports `--json`. JSON results use a unified outer set of fields: `command`, `inputs`, `summary`, `errors`, `items`, `tasks`, `logs`; each command fills `items` or `tasks` according to its own semantics.

For `extract` and `scan`, normal text goes to stdout and errors go to stderr. `[Scan error]` identifies filesystem scan failures; `[Extraction failed]` identifies archive processing failures. `[Scan incomplete]` means some paths could not be read and the discovered results may be incomplete. Readable inputs are still processed. `--json` emits the JSON result without these text messages.

JSON `summary.scan_error_count` counts filesystem scan errors, including errors whose individual details were omitted. Filesystem scan diagnostics retain at most 100 records per report, plus one total omission summary; the existing 20-detail limit per directory also applies. Above the report budget, only the omitted count is accumulated, without retaining each path or error identity. Archive task results remain available independently of this diagnostic budget.

When the native worker supplies archive failure evidence, `extract --json` lists it by logical archive in `summary.failure_details`; `scan --json` includes it in the corresponding `items[].failure`. The `evidence` can include the failure stage, missing volume name, last read location, and a recovery preview of up to 50 files. `recovery.omitted_files` counts files outside the preview. Per-file bytes describe the worker's write attempts; `summary.recovered_outputs` identifies the outputs retained by extraction.

For `extract`, `summary.failed_count` and each attempt's `failed_count` count archive processing failures. `input_error_count` separately counts invalid inputs, such as a directory passed to `--direct-file`; these use `[Input error]` in text output. Attempts also include `scan_error_count` and `input_error_count`. Bounded filesystem diagnostic details are stored once in `summary.scan_failures`; each attempt's `failures` contains archive and input failures. Classification uses structured failure kinds and target results. All error categories remain in `errors` and cause a nonzero exit code, even when other archives succeed.

## extract

Usage:

```powershell
sunpack.exe extract [options] <paths...>
```

`paths` may be one or more files or directories. Directories are scanned shallowly by default; `--recursive` includes their subdirectories.

Options:

| Option | Description |
| --- | --- |
| `-p PASSWORD`, `--password PASSWORD` | Provide one extraction password; may be repeated. |
| `-P PASSWORD_FILE`, `--pw-file PASSWORD_FILE` | Read passwords from a text file, one per line. |
| `-a`, `--ask-pw` | Prompt for passwords interactively in the terminal; an empty line ends input. |
| `--no-builtin-pw`, `--no-bpw` | Disable persistent JSON passwords, including clipboard history. |
| `-d`, `--deep-detect` | Enable a full embedded scan for unresolved candidates and disable all filesystem scan filters for this request. |
| `-r VALUE`, `--recur VALUE` | Override the number of nested extraction rounds; accepts a positive integer, `*`, or `?`. |
| `-c VALUE`, `--cleanup VALUE` | Override how the original archive is handled on success: `d` delete, `r` Recycle Bin, `k` keep. |
| `-o OUTPUT_DIR`, `--out-dir OUTPUT_DIR` | Set the output root; relative paths are resolved against the current command directory. |
| `-f`, `--flatten` | Lift the contents of a single top-level directory after extraction. |
| `-F`, `--no-flatten` | Keep the extracted directory structure. |
| `--direct-file`, `--direct` | Treat every input path directly as an archive, skipping directory scanning and automatic candidate discovery. |

When `--out-dir` is given, results land under "output root / the input path relative to its common root / archive name"; when it is omitted, results land next to the archive. When a nested archive is produced inside the output root, the sub-archive still computes its own output location from where it sits.

Values for `--recur`:

- A positive integer such as `1`, `2`, `3`: a fixed number of recursive rounds.
- `*`: keep recursing while each round produces new processable nested archives.
- `?`: ask whether to continue after each round that produces new processable nested archives.

Examples:

```powershell
sunpack.exe extract D:\Downloads
sunpack.exe extract D:\A.7z -p 123456 -p secret
sunpack.exe extract D:\Archives --pw-file .\passwords.txt --cleanup r
sunpack.exe extract D:\Nested --recur * --no-flatten
sunpack.exe extract --direct-file D:\MaybeArchive.bin
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

The password input options are shared with extract. `-v` adds existing discovery sources and damage facts without extra analysis; `--json` independently selects the output format.

`--deep-detect` performs a full embedded scan on candidates not resolved by normal detection and disables all filesystem scan filters for this request, for scan. `--recursive` determines the directory scope. Each CLI request uses its own arguments, even when it shares a runtime with deep monitoring of the same input directory.

Examples:

```powershell
sunpack.exe scan D:\Downloads
sunpack.exe scan D:\Downloads --deep-detect --json
sunpack.exe scan D:\Downloads -v
```

## watch

Usage:

```powershell
sunpack.exe watch <add|remove|list|start|stop|reload|rebuild-log|status|startup> [options]
```

Monitored roots are stored in `sunpack_watch_roots.txt` inside the program resource directory. The format is `input directory | output root | deep_detect | initial_scanned | recursive`; the last four columns are optional:

```text
C:\Downloads
E:\Archives | E:\Output
F:\Incoming | . | true
G:\Incoming | | true
```

When only the input directory is given, the output column remains empty and extraction writes beside each archive. With `--out-dir`, a relative output path is resolved against that input directory and persisted as an absolute path. The output root may be on a different drive. `watch` only observes the direct files of each root and does not recursively watch subdirectories; the input root must be on an NTFS volume with a readable USN Journal.

`deep_detect` accepts `true` or `false`; an omitted or empty value defaults to `false`. This mode belongs to the input directory. Different input roots may share an output root and use different modes. Nested extraction, password retries, and crash recovery retain the original input root and use its configured mode. Deep mode disables all filesystem scan filters for that root's requests. Editing the column triggers configuration reload; `watch reload` also applies it.

`initial_scanned` records completion of the first candidate scan and defaults to `false` when omitted or empty. Startup and live reload automatically scan roots marked `false` and write `true` after queuing candidates, without waiting for extraction success. New roots and changed input paths start at `false`; output or deep-mode edits preserve the flag. Existing roots still recover offline changes through USN. Scan-state-only edits, reordered roots, comments, and equivalent path spellings do not restart the scheduler.

Subcommands and options:

| Subcommand | Option | Description |
| --- | --- | --- |
| `start` | `--once` | Run a single monitoring scan, then exit. |
| `start` | `--no-tray` | Disable the tray entry point while running continuously. |
| `add PATH...` | `-o/--out-dir DIR` | Add a monitored root; only one path may be added at a time. |
| `add PATH...` | `-s`, `--start` | Start continuous monitoring after adding. |
| `add PATH...` | `-R/--recursive` | Enable recursive discovery for the monitored root. |
| `add PATH...` | `-d`, `--deep-detect` | Persist `deep_detect=true` for each input root; update already registered roots too. |
| `remove PATH...`, `rm PATH...` | — | Remove a monitored root by input directory. |
| `list`, `ls` | — | List the persisted input directories. |
| `reload` | — | Re-read the configuration and monitored roots. |
| `rebuild-log` | — | Clear display logs and rebuild from the watch snapshot/WAL. Completed history is discarded. Reports success or failure (exit code 1); automatic recovery still ignores failures and retries on later log operations. |
| `stop` | — | Stop continuous monitoring. |
| `status`, `st` | — | Show whether the watch service is running. JSON also includes pending counts, the last error, and root directories. |
| `startup enable\|disable\|status` | — | Manage the current user's logon startup entry. |

`start` keeps running until a stop request arrives; `start --once` completes one current scheduling pass and then exits. Writing, moving, or modifying a file triggers an active cycle. New candidates have no initial delay; subsequent content changes adapt the quiet window to observed write intervals, without a fixed minimum or maximum wait. Ready files are submitted for processing. The arrival of a new volume or a change in password sources reactivates the affected tasks.

`add`'s `-o/--out-dir` can only be used together with a single input directory. Adding the same input directory again does not change the existing output mapping; you must `remove` and then `add` to update the mapping. The output roots of different monitored roots must not be strict ancestors or descendants of one another; the same output root may be shared.

Adding a new root without `--deep-detect` leaves deep mode disabled. Re-adding an existing root without the flag preserves its mode; set the third column to `false` or leave it empty to disable deep mode.

```powershell
sunpack.exe watch add D:\Downloads --deep-detect --start
```

The directory and directory-background context menus contain four entries: "Extract files in this folder", "Enter password to extract files in this folder", "Watch this folder", and "Stop watching this folder". These entries do not add `--deep-detect`. The two file extraction entries enable `--deep-detect` by default. Re-run `scripts/register_context_menu.ps1` to rebuild the menus and remove obsolete entries.

## passwords

Usage:

```powershell
sunpack.exe passwords [options]
```

Options:

| Option | Description |
| --- | --- |
| `-j`, `--json` | Output the password source summary as JSON. |
| `-p PASSWORD`, `--password PASSWORD` | Provide a password; may be repeated. |
| `-P PASSWORD_FILE`, `--pw-file PASSWORD_FILE` | Read passwords from a text file, one per line. |
| `-a`, `--ask-pw` | Prompt for passwords interactively in the terminal. |
| `--no-builtin-pw`, `--no-bpw` | Do not use persistent JSON passwords or clipboard history. |

`passwords` has no archive path and summarizes global candidates. Extraction tries eligible recent successes first, then matching JSON scopes, CLI input, the current clipboard, and JSON global passwords and clipboard history. Candidates are deduplicated, with an empty password tried first when necessary.

Examples:

```powershell
sunpack.exe passwords
sunpack.exe passwords -p 123456 --no-builtin-pw
sunpack.exe passwords --pw-file .\passwords.txt --json
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
| `-j`, `--json` | Output the result as JSON. |

Examples:

```powershell
sunpack.exe config show
sunpack.exe config validate
sunpack.exe config validate --json
```

## doctor

Usage:

```powershell
sunpack.exe doctor [--json]
sunpack.exe d [-j]
```

`doctor` performs a read-only check of the configuration, the native extension, `7z.dll`, the SevenZip worker, Windows notification capability, and the configured monitored roots. A monitored root that does not exist is reported as a warning; the command never starts continuous monitoring or a real extraction, and never modifies the registry. The exit code is `1` when any check fails, and `0` when there are only warnings or skipped items.

## version

Usage:

```powershell
sunpack.exe version
```

`version` reads `VERSION.txt` next to the running SunPack executable and prints the value after `version=`. The packaged executable can also be invoked as `sunpack.exe version`.

## Windows context menu

Run these scripts in a regular PowerShell session to manage the current user's context menu.

```powershell
.\scripts\register_context_menu.ps1
.\scripts\unregister_context_menu.ps1
```

The registration script inside the distribution package uses the `sunpack.exe` in its own parent directory. When run from the source tree, the script detects the single unique `dist/sunpack-*/sunpack.exe`; when several build outputs exist, specify one explicitly with `-AppPath`.

The folder and folder-background menus offer "Extract files in this folder" and "Enter password to extract files in this folder", plus watch and unwatch actions. The menu for any file offers "Extract this file" and "Enter password to extract this file", equivalent to:

```text
extract "%1" --deep-detect --pause
extract "%1" --ask-pw --deep-detect --pause
```

Output lands next to the archive by default.

`watch add DIR --recursive` enables recursive discovery for that root. Omitted optional columns use their default values. Split volumes may span subdirectories within one scope; separate roots remain independent. Watch outputs go directly to the root’s mapped output directory. CLI outputs default beside each archive, or beside the entry volume for a split archive. Pipeline output subtrees are protected from Watch, including later files added there.
