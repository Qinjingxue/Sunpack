# CLI parameter reference

**English** | [简体中文](zh-CN/cli_parameters.md)

Entry script:

```powershell
python sunpack.py <command> [options] [paths...]
```

The packaged Windows program is usually invoked directly:

```powershell
sunpack.exe <command> [options] [paths...]
```

Top-level commands:

| Command | Purpose |
| --- | --- |
| `extract` | Scan, identify, extract, verify, post-process, and clean up. |
| `watch` | Monitor directories and process files automatically once they are stable. |
| `scan` | Only scan and list extractable tasks; does not modify files. |
| `inspect` | Print detection and structural analysis details; does not modify files. |
| `passwords` | Show a summary of the password sources available to the current command. |
| `config` | Show or validate the merged effective configuration. |
| `doctor` | Read-only check of configuration and runtime environment. |

## Common output options

These options apply to `extract`, `scan`, and `inspect`:

| Option | Description |
| --- | --- |
| `-j`, `--json` | Output results as JSON; suitable for scripting. |
| `-q`, `--quiet` | Reduce terminal output. |
| `-v`, `--verbose` | Output more detection and diagnostic detail. |
| `--pause` | Wait for a key press before exiting. |
| `--no-pause` | Do not pause after the command finishes. |
| `--process-mode {background,normal,high}` | Temporarily override the shared RuntimeHost/native-worker process mode for this workload. Defaults to `high`. |

For `extract`, `scan`, and `inspect`, the process-mode override remains effective after the command finishes and expires when the shared runtime reaches the existing Watch idle-maintenance deadline (`watch.runtime_cache_cleanup_idle_seconds`); it then returns to `runtime.process_mode`.

`passwords` supports only `--json` plus the password input options; `config` supports `--json` and `--quiet`. JSON results use a unified outer set of fields: `command`, `inputs`, `summary`, `errors`, `items`, `tasks`, `logs`; each command fills `items` or `tasks` according to its own semantics.

## extract

Usage:

```powershell
python sunpack.py extract [options] <paths...>
```

`paths` may be one or more files or directories. Directories are scanned according to the configuration and turned into extraction tasks.

Options:

| Option | Description |
| --- | --- |
| `-p PASSWORD`, `--password PASSWORD` | Provide one extraction password; may be repeated. |
| `--pw-file PASSWORD_FILE` | Read passwords from a text file, one per line. |
| `--ask-pw` | Prompt for passwords interactively in the terminal; an empty line ends input. |
| `--no-builtin-pw` | Disable the built-in password table. |
| `--no-dir-pw` | Disable `sunpack-passwords.txt` from the archive's own directory. |
| `--deep-detect` | Enable a full embedded scan for candidates that detection did not resolve. |
| `--recur VALUE` | Override the number of nested extraction rounds; accepts a positive integer, `*`, or `?`. |
| `--cleanup VALUE` | Override how the original archive is handled on success: `d` delete, `r` Recycle Bin, `k` keep. |
| `-o OUTPUT_DIR`, `--out-dir OUTPUT_DIR` | Set the output root; relative paths are resolved against the current command directory. |
| `--flatten` | Lift the contents of a single top-level directory after extraction. |
| `--no-flatten` | Keep the extracted directory structure. |
| `--write-manifest` | Write an extraction progress manifest into the output directory. |
| `--allow-partial`, `--ap` | Accept partial recovery results as acceptable results. |
| `--direct-file` | Treat every input path directly as an archive, skipping directory scanning and automatic candidate discovery. |

When `--out-dir` is given, results land under "output root / the input path relative to its common root / archive name"; when it is omitted, results land next to the archive. When a nested archive is produced inside the output root, the sub-archive still computes its own output location from where it sits.

Values for `--recur`:

- A positive integer such as `1`, `2`, `3`: a fixed number of recursive rounds.
- `*`: keep recursing while each round produces new processable nested archives.
- `?`: ask whether to continue after each round that produces new processable nested archives.

Examples:

```powershell
python sunpack.py extract D:\Downloads
python sunpack.py extract D:\A.7z -p 123456 -p secret
python sunpack.py extract D:\Archives --pw-file .\passwords.txt --cleanup r
python sunpack.py extract D:\Nested --recur * --no-flatten
python sunpack.py extract --direct-file D:\MaybeArchive.bin
python sunpack.py extract D:\Archives -o E:\Unpacked
```

Exit codes:

- `0`: all tasks succeeded completely.
- `1`: at least one task failed.
- `2`: argument, path, or configuration error.
- `3`: runtime exception.
- `4`: no task failed, but at least one task only partially succeeded.

## scan

Usage:

```powershell
python sunpack.py scan [options] <paths...>
```

`scan` outputs the identified extraction tasks, volume relationships, detected extensions, verdicts, and matched rules. It does not extract or clean up files.

`--deep-detect` performs a full embedded scan on candidates that qualify but were not resolved by normal detection. The directory scope is affected by `filesystem.directory_scan_mode`, `filesystem.scan_filters_enabled`, and `filesystem.scan_filters`.

Examples:

```powershell
python sunpack.py scan D:\Downloads
python sunpack.py scan D:\Downloads --deep-detect --json
python sunpack.py scan D:\Downloads -v
```

## inspect

Usage:

```powershell
python sunpack.py inspect [options] <paths...>
```

`inspect` is a read-only detection diagnostic command. It lists the verdicts, processing stages, stop reasons, and factual errors of candidate files.

Options:

| Option | Description |
| --- | --- |
| `--archives-only` | Show only items finally judged extractable. |
| `--analyze` | Attach format, fragment, damage markers, and candidate summaries to extractable or pending candidates. |
| `--deep-detect` | Enable a full embedded scan for candidates that detection did not resolve. |

`-v` additionally prints the effective configuration, matched rules, scoring details, and factual errors; JSON output keeps the corresponding structured fields.

Examples:

```powershell
python sunpack.py inspect D:\Downloads
python sunpack.py inspect D:\Downloads --archives-only --analyze
python sunpack.py inspect D:\Downloads --deep-detect --json
python sunpack.py inspect D:\Downloads -v
```

## watch

Usage:

```powershell
python sunpack.py watch <add|remove|list|start|stop|reload|status|startup> [options]
```

Monitored roots are stored in `sunpack_watch_roots.txt` inside the program resource directory. Each line may contain only an input directory, or may use `|` to specify an output root:

```text
C:\Downloads
E:\Archives | E:\Output
F:\Incoming | .
```

When only the input directory is given, `watch.out_dir` is used; a relative output path is resolved against that input directory and persisted as an absolute path. The output root may be on a different drive. `watch` only observes the direct files of each root and does not recursively watch subdirectories; the input root must be on an NTFS volume with a readable USN Journal.

Subcommands and options:

| Subcommand | Option | Description |
| --- | --- | --- |
| `start` | `--once` | Run a single monitoring scan, then exit. |
| `start` | `--no-tray` | Disable the tray entry point while running continuously. |
| `start` | `--initial-scan` | Process existing files at startup. |
| `add PATH...` | `-o/--out-dir DIR` | Add a monitored root; only one path may be added at a time. |
| `add PATH...` | `--start` | Start continuous monitoring after adding. |
| `add PATH...` | `--initial-scan` | Run an initial scan for the new root after adding. |
| `remove PATH...` | — | Remove a monitored root by input directory, and clean up that root's per-directory password file. |
| `list` | — | List the persisted input directories. |
| `reload` | — | Re-read the configuration and monitored roots. |
| `stop` | — | Stop continuous monitoring. |
| `status` | — | Show run status, pending counts, errors, and root directories. |
| `startup enable\|disable\|status` | — | Manage the current user's logon startup entry. |

`start` keeps running until a stop request arrives; `start --once` completes one current scheduling pass and then exits. Writing, moving, or modifying a file triggers an active cycle; once the file is ready it is submitted for processing according to the configured quiet policy. The arrival of a new volume or a change in password sources reactivates the affected tasks.

`add`'s `-o/--out-dir` can only be used together with a single input directory. Adding the same input directory again does not change the existing output mapping; you must `remove` and then `add` to update the mapping. The output roots of different monitored roots must not be strict ancestors or descendants of one another; the same output root may be shared.

## passwords

Usage:

```powershell
python sunpack.py passwords [options]
```

Options:

| Option | Description |
| --- | --- |
| `-j`, `--json` | Output the password source summary as JSON. |
| `-p PASSWORD`, `--password PASSWORD` | Provide a password; may be repeated. |
| `--pw-file PASSWORD_FILE` | Read passwords from a text file, one per line. |
| `--ask-pw` | Prompt for passwords interactively in the terminal. |
| `--no-builtin-pw` | Do not use the built-in password table. |
| `--no-dir-pw` | This command has no target archive and will not read a per-directory password file; in `extract` it disables per-directory passwords. |

Because `passwords` has no archive path, it outputs a summary of command-line input, the most recent successful password, clipboard passwords, and built-in passwords; it does not load `sunpack-passwords.txt` for any directory. During archive extraction, the candidate order is "most recent successful password → per-directory passwords → CLI arguments and password files → clipboard → built-in passwords". Duplicates are removed, and the empty password is tried first when necessary.

Examples:

```powershell
python sunpack.py passwords
python sunpack.py passwords -p 123456 --no-builtin-pw
python sunpack.py passwords --pw-file .\passwords.txt --json
```

## config

Usage:

```powershell
python sunpack.py config [options] <show|validate>
```

| Subcommand | Description |
| --- | --- |
| `show` | Print the effective configuration currently loaded. |
| `validate` | Validate the JSON, field values, detection rule names, and rule configuration. |

Options:

| Option | Description |
| --- | --- |
| `-j`, `--json` | Output the result as JSON. |
| `-q`, `--quiet` | Reduce plain-text output. |

Examples:

```powershell
python sunpack.py config show
python sunpack.py config validate
python sunpack.py config validate --json
```

## doctor

Usage:

```powershell
python sunpack.py doctor [--json] [--quiet]
```

`doctor` performs a read-only check of the configuration, the native extension, `7z.dll`, the SevenZip worker, Windows notification capability, and the configured monitored roots. A monitored root that does not exist is reported as a warning; the command never starts continuous monitoring or a real extraction, and never modifies the registry. The exit code is `1` when any check fails, and `0` when there are only warnings or skipped items.

## Windows context menu

Machine-wide context menu scripts (they require an elevated shell):

```powershell
.\scripts\register_context_menu.ps1
.\scripts\unregister_context_menu.ps1
```

The registration script inside the distribution package uses the `sunpack.exe` in its own parent directory. When run from the source tree, the script detects the single unique `dist/sunpack-*/sunpack.exe`; when several build outputs exist, specify one explicitly with `-AppPath`. When no packaged program is found, `python sunpack.py` is used.

The folder and folder-background menus offer extract, monitor, and unmonitor actions; the menu for any file offers direct extraction and interactive-password extraction, equivalent to:

```text
extract "%1" --pause
extract "%1" --ask-pw --pause
```

Output lands next to the archive by default.
