# SunPack

**English** | [简体中文](README.zh-CN.md)

**SunPack is a Windows-only automated archive processing tool that supports command-line, Watch monitoring, and Explorer context-menu invocation.**

It supports 7z, RAR, ZIP, and other formats, with experimental support for XZ, BZip2, Gzip, TAR, and Zstandard. It handles multi-volume archives, self-extracting archives, and archives embedded in invalid data.

SunPack identifies archives by binary signatures rather than file extensions, and tolerates messy extensions and incomplete file names.

---

## Contents

- [Installation](#installation)
- [Usage guide](#usage-guide)
  - [Command overview](#command-overview)
  - [Password management](#password-management)
- [Core capabilities](#core-capabilities)
  - [Recursive processing](#recursive-processing)
  - [Post-processing](#post-processing)
  - [Watch mode monitoring system](#watch-mode-monitoring-system)
  - [Robustness and WAL crash recovery](#robustness-and-wal-crash-recovery)
  - [High concurrency and speed optimization](#high-concurrency-and-speed-optimization)
  - [Low background resource usage](#low-background-resource-usage)
- [Configuration](#configuration)
- [Development and testing](#development-and-testing)
  - [Development](#development)
  - [Architecture at a glance](#architecture-at-a-glance)
  - [Testing](#testing)
  - [Reproducible worker vs. 7-Zip benchmark](#reproducible-worker-vs-7-zip-benchmark)
- [Notice](#notice)
- [License](#license)

## Installation

### System requirements

SunPack supports only Windows 10 version 1607 or later and Windows 11.

Download the latest `sunpack-windows-<arch>-<version>-setup.exe` from [GitHub Releases](https://github.com/Qinjingxue/Sunpack/releases/latest).

1. Pick the installer that matches your system architecture: `x64` for Intel/AMD 64-bit Windows, `arm64` for Windows on ARM.
2. Run the installer and accept the UAC elevation prompt. It installs to `C:\Program Files\SunPack` by default; installing the Watch Broker service requires administrator privileges.
3. Choose the optional items in the setup wizard as needed:
   - Add the installation directory to the machine `PATH`. Reopen PowerShell after the installation completes.
   - Register the Explorer context menu for folders and folder backgrounds.
   - Start SunPack Watch with Windows (disabled by default).

---

## Usage guide

### Command overview

| Command     | Description                                                          |
| ----------- | -------------------------------------------------------------------- |
| `extract`   | Extract files.                                                       |
| `watch`     | Monitor directories and extract archives automatically once found.   |
| `scan`      | Scan a directory for archives; useful for identifying archives.      |
| `inspect`   | Print detailed detection data; a debugging command with JSON output. |
| `passwords` | Show the password list that will be attempted in this run.           |
| `config`    | Show or validate the effective configuration.                        |
| `doctor`    | Non-destructive check of installation and runtime health.            |
| `version`   | Print the installed SunPack version.                                  |

> See [CLI parameter reference](docs/cli_parameters.md) for detailed options.

### Password management

For maximum convenience, SunPack gathers passwords from several sources at run time, tries all candidate passwords at high speed — with thousands of candidates it is nearly imperceptible — and automatically finds and uses the correct one. The password sources are:

- Built-in password file: used on every extraction. It can be opened and edited from the tray context menu in watch mode, and lives at `%ProgramData%\SunPack\builtin_passwords.txt` in the installed version. Watch mode automatically collects clipboard history into this file, with a default limit of 30 entries.
- User input: the context menu, and the interactive password prompt launched from the CLI.
- Clipboard: the clipboard text is read as a password before extraction.
- Per-directory password file: SunPack automatically looks for `sunpack-passwords.txt` in the directory and reads each line as one password; watch mode creates it automatically by default. Set `watch.directory_password_file_auto_create` to `false` to disable automatic creation.

---

## Core capabilities

### Recognition Capability

- Identifies potential archive files by analyzing their binary data, including disguised archives embedded within carrier files and multi-volume archives.

### Recursive processing

- Recursively searches for nested archives by default: after a successful extraction it checks whether the resulting folder contains archives that clearly should be extracted further, and processes them recursively. The algorithm is tuned so that, in most cases, it does not wrongly extract files that should not be extracted further.

### Post-processing

- Automatically flattens meaningless nested single-child directories after a successful extraction, keeping only the top-level folder, and moves the original archive to the Recycle Bin or deletes it (controlled by the `"archive_cleanup_mode": "r"` setting; the Recycle Bin is the default). If processing fails, it automatically cleans up the failed output and reports an error.

### Watch mode monitoring system

- The watch system is built on a carefully designed identification algorithm that monitors and processes archives. It quickly detects and identifies newly added archives in the relevant directories and ignores non-archive files.
- It can recognize situations with missing volumes or passwords, and automatically retries after the password sources or the volumes change. It uses Windows notifications to show progress while processing.
- Each monitored directory can be configured with its own output root. See [CLI parameter reference](docs/cli_parameters.md) for the exact commands and the persistence format.

### Robustness and WAL crash recovery

- Automatically pauses extraction tasks when disk space runs out, and resumes them once enough disk space is available again — no manual retry needed.
- Has a file verification system that allows partially damaged files to yield whatever usable files they can, instead of failing outright. When everything fails, it automatically cleans up the damaged files, leaving no leftovers that need manual cleanup.
- Adopts a database-like WAL design: an unexpected power loss or process crash during extraction leaves no half-finished or corrupted state; the program handles it correctly and completes the task after recovery.
- Has a test suite containing a rich set of complex cases that guarantee the correctness of the program's behavior.

### High concurrency and speed optimization

- Processes large numbers of archives concurrently, and has a concurrency algorithm that distributes work sensibly. In multi-file scenarios there is no need to extract files one by one — just drop them into a directory and they are all extracted quickly and automatically.
- Handles the high-performance computation and I/O paths in Rust and C++ native code, using overlapped I/O to overlap the read, compute, and output stages of 7z extraction. Resource utilization is good, the output path is tuned separately for mechanical and NVMe drives, and cross-drive writes are direct writes with no staging copy.

* For the 7-Zip backend decoders, zlib-ng was used to accelerate Deflate decompression, while parallel decoding was implemented to improve RAR and BZip2 decompression performance.

- Has a rich set of benchmark cases for various scenarios, and is optimized for those benchmarks close to the maintainability limit.

### Low background resource usage

- Manages cache lifetimes well and automatically releases useless caches after processing files.
- Uses purely event notifications while the system is idle; an idle background process consumes no CPU on polling.

---

## Configuration

The main configuration file is `sunpack_config.json`; `sunpack_advanced_config.json` supplies additional defaults. Watch automatically reloads configuration changes.

Add only the fields you want to change to the main configuration file.

Configuration validation command:

```powershell
python sunpack.py config validate
```

See the [configuration guide](docs/configuration.md) for common settings and examples.

---

## Development and testing

### Development

Prepare the development environment:

```powershell
.\scripts\setup_windows_dev.ps1
```

Build the project:

```powershell
.\scripts\build_windows.ps1
```

See [the documentation](docs/development_setup.md) for development environment and build instructions.
See [the documentation](docs/development_boundaries.md) for development boundaries.

### Architecture at a glance

```text
CLI / Watch / Explorer (runtime)
  -> pipeline coordinator
     -> filesystem routing
        +-- Relations (RAR / 7z / ZIP, including volumes)
        +-- Detection (TAR and compression streams)
        +-- Embedded discovery (unresolved files)
     -> recursive authorization -> password handling -> extraction
     -> verification -> post-processing
```

Rust provides low-level scanning and archive analysis; the C++ worker extracts with the integrated 7-Zip source code.

### Testing

Install the test dependencies and run the default tests:

```powershell
uv sync --locked --extra test
uv run --locked pytest
```

Acceptance tests:

```powershell
.\run_acceptance_tests.ps1
```

### Reproducible worker vs. 7-Zip benchmark

Detailed machine identity, archive construction, compression methods, and
reproduction instructions are in [the benchmark document](docs/benchmark_worker_vs_7z_300m.md).
These results use SunPack **v0.7.0**, five measured runs per case, and no warmups.
Times and sampled peak process-tree RSS are per-case medians; RSS is in MiB.

#### Wall time (median ms)

| Format / variant | SunPack worker | `7z.exe` | worker / 7-Zip |
| ---------------- | -------------: | -------: | -------------: |
| 7z split | 152.428 | 212.774 | 0.716 |
| 7z non-solid | 191.658 | 249.196 | 0.769 |
| 7z solid | 152.874 | 208.849 | 0.732 |
| BZip2 | 2,903.218 | 3,018.483 | 0.962 |
| Gzip | 85.065 | 210.524 | 0.404 |
| RAR5 split | 225.367 | 774.706 | 0.291 |
| RAR4 non-solid | 167.379 | 189.960 | 0.881 |
| RAR4 solid | 646.962 | 663.775 | 0.975 |
| RAR5 non-solid | 133.381 | 185.708 | 0.718 |
| RAR5 solid | 205.989 | 764.585 | 0.269 |
| TAR | 86.117 | 139.751 | 0.616 |
| TBZ2 | 2,795.495 | 2,952.648 | 0.947 |
| TGZ | 83.694 | 199.684 | 0.419 |
| TXZ | 176.999 | 179.940 | 0.984 |
| TZST | 90.564 | 167.695 | 0.540 |
| XZ | 172.809 | 180.811 | 0.956 |
| ZIP | 96.212 | 202.997 | 0.474 |
| ZST | 88.075 | 154.881 | 0.569 |

#### Peak RSS (median MiB)

| Format / variant | SunPack worker | `7z.exe` | worker / 7-Zip |
| ---------------- | -------------: | -------: | -------------: |
| 7z split | 474.410 | 458.383 | 1.035 |
| 7z non-solid | 323.938 | 308.055 | 1.052 |
| 7z solid | 474.148 | 458.312 | 1.035 |
| BZip2 | 146.871 | 12.637 | 11.622 |
| Gzip | 25.055 | 8.219 | 3.048 |
| RAR5 split | 52.145 | 40.516 | 1.287 |
| RAR4 non-solid | 24.320 | 11.613 | 2.094 |
| RAR4 solid | 25.027 | 12.359 | 2.025 |
| RAR5 non-solid | 52.008 | 39.613 | 1.313 |
| RAR5 solid | 53.043 | 40.480 | 1.310 |
| TAR | 24.074 | 7.305 | 3.296 |
| TBZ2 | 146.953 | 12.641 | 11.625 |
| TGZ | 25.051 | 8.227 | 3.045 |
| TXZ | 474.520 | 458.531 | 1.035 |
| TZST | 21.871 | 9.801 | 2.232 |
| XZ | 474.484 | 458.527 | 1.035 |
| ZIP | 23.090 | 7.992 | 2.889 |
| ZST | 21.500 | 9.793 | 2.195 |

Across 18 cases, the sum of per-case time medians is 8,454.286 ms for SunPack
and 10,656.967 ms for `7z.exe` (0.793x). Memory use varies by format; BZip2/TBZ2
are about 147 MiB for the worker versus 13 MiB for `7z.exe`. In the time table,
a ratio below 1 means the worker is faster; in the RSS table, it means the
worker uses less memory. RSS values are per-case medians, not sums across
independent cases.

---

## Notice

Normal embedded discovery does not scan files whose names end in `.exe`. Structurally confirmed self-extracting archives are still recognized by the relations stage, while `--deep-detect` explicitly opts executable carriers back into embedded scanning. This keeps ordinary application and installer executables out of the full-file embedded scan without maintaining runtime- or installer-specific exclusion rules.

SunPack is not yet mature, and its handling of uncontrolled inputs is limited. It is not guaranteed to be safe. If you have concerns, use it only in a trusted environment.

## License

SunPack-original source code is licensed under the MIT License; see [LICENSE](LICENSE).

The repository also vendors third-party source code, including 7-Zip 26.03 under `native/sevenzip_bridge/7z2603-src/` and zlib-ng 2.3.3 under `native/sevenzip_bridge/zlib-ng-2.3.3/`. Third-party source and binaries remain subject to their original licenses and are not relicensed under MIT. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), [licenses/](licenses/), and [docs/licensing.md](docs/licensing.md) for the exact license scope and release-compliance information.

The 7-Zip source license is copied at [licenses/7zip-source-license.txt](licenses/7zip-source-license.txt), the full GNU LGPL 2.1 text is available at [licenses/LGPL-2.1.txt](licenses/LGPL-2.1.txt), and the zlib-ng license is copied at [licenses/zlib-ng-license.txt](licenses/zlib-ng-license.txt).
