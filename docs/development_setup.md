# Development environment and build instructions

**English** | [简体中文](zh-CN/development_setup.md)

SunPack is a Windows-only project. Cargo builds the Rust runtime and Watch Broker. CMake builds the native worker, launcher, GUI, and toast DLL. `uv.lock` pins the Python test dependencies.

## Directories and build artifacts

See the [README development requirements](../README.en.md#development) for the toolchain needed to run setup.

Main project directories:

```text
sunpack/sunpack_runtime/      Rust orchestration and computation, CLI and Watch
sunpack/sunpack_usn_core/     Shared NTFS/ReFS USN Rust core
sunpack/sunpack_watch_broker/ Windows Watch Broker service
sunpack/sevenzip_bridge/      CLI launcher and embedded 7-Zip worker
sunpack/toast_host/           Windows toast DLL
tools/                        Shared external fixture tools
tools/arm64/                  ARM64 7-Zip fixture tools
.cache/rust-target/            Shared Cargo build tree
.cache/native/                 CMake trees for the launcher, worker and toast
.cache/gui-x64/                x64 GUI CMake tree
```

The development, release and CI scripts share these build locations. Cargo separates its artifacts by target triple and profile. The native CMake trees use `.cache/native/<arch>/<profile>/<component>/` so the diagnostic `ci` build and the LTO `release` build can coexist. Source launchers and tests use the selected build tree directly.

## Python dependencies

Installable extras:

| Extra | Purpose |
| --- | --- |
| `test` | pytest and test data generation dependencies |
| `build` | CMake |
| `dev` | Union of build and test |

Common install commands:

```powershell
uv sync --locked
uv sync --locked --extra test
uv sync --locked --extra dev
```

When creating `.venv`, the setup script asks uv for Python 3.11 on an x64 host or Python 3.12 on an ARM64 host. uv can download the interpreter on demand. Setup keeps the interpreter in an existing `.venv` and syncs its locked dependencies. It disables access to global site-packages if enabled.

## One-step development environment setup

```powershell
.\scripts\setup_windows_dev.ps1
```

The script will:

1. Add the selected Rust MSVC target with rustup and sync `.venv` with `uv sync --locked --extra dev`.
2. Prepare and check the acceptance fixture generators.
3. Build the Rust runtime, Watch Broker, native fixture generator, CLI launcher, worker, and toast DLL under `.cache`.
4. Run the worker and toast CTest suites for the `ci` profile when the build matches the current PowerShell process architecture.

Options:

```powershell
.\scripts\setup_windows_dev.ps1 -Clean
.\scripts\setup_windows_dev.ps1 -Arch arm64
.\scripts\setup_windows_dev.ps1 -SkipAcceptanceTestTools
.\scripts\setup_windows_dev.ps1 -Arch arm64 -SkipAcceptanceTestTools
```

Setup prepares 7-Zip for the selected architecture, using 26.04 for a fresh download and keeping `7z.exe`, `7z.dll`, and `7zCon.sfx`. Full acceptance on either architecture also uses WinRAR 6.22, zstd 1.5.7, and [7-Zip-Zstandard 25.01 / Zstandard 1.5.7 Release 4](https://github.com/mcmilk/7-Zip-zstd/releases/tag/v25.01-v1.5.7-R4), shared under `tools/`. Setup extracts only the two WinRAR writers, RAR SFX module, and license. It keeps the 7-Zip-Zstandard LZ4 writer, its companion DLL, and its license. These tools are for development and testing only.

On Windows 11 ARM64, run `.\run_acceptance_tests.ps1 -Arch arm64 -NoWait`. Windows runs the shared x64 generators under emulation. Use `-SkipAcceptanceTestTools` to skip preparing and checking the shared generators for a build-only run or an ARM64 cross-build on x64.

## USN Watch Broker

watch uses the NTFS/ReFS USN Journal to determine whether file contents have changed and whether a file has crossed a write boundary. Operations that need volume-level Journal access are concentrated in `sunpack/sunpack_usn_core` and `sunpack/sunpack_watch_broker`. Watch consumes the typed file observations and state directly.

### Components and lifecycle

- `sunpack/sunpack_usn_core` is a Windows-only Rust crate containing volume identification, Journal probing, bounded USN reason reads, and the named pipe client protocol.
- `sunpack/sunpack_watch_broker` compiles to `sunpack-watch-broker.exe` and runs as a Windows service, holding volume-level Journal access.
- At startup, watch acquires a process-level lease. The first lease starts the service on demand and establishes a local named pipe connection. Later leases in the same process reuse the connection. Releasing the last lease closes the connection.
- The service starts on demand. It exits if the first client has not connected within 5 seconds; after the last lease is released it waits 1 second before exiting. Each service keeps at most 64 clients and 64 volume contexts.

The standard identities are:

```text
Service: SunPackWatchBroker
Pipe:    \\.\pipe\SunPack.WatchBroker.v1
```

The service accepts only local named pipe clients. Installing the service requires administrator privileges; an installed service is used by ordinary watch instances through the client protocol.

### USN read boundaries

File observation reads file metadata and the current USN in Rust. When the current USN is greater than the last recorded one, the client asks the broker to read:

```text
previous_usn < usn <= current_usn
```

Each observation reads at most 1 MiB of reason data, supports USN record versions 2, 3, and 4, and distinguishes all reasons from the reasons with `CLOSE` removed. Content changes such as overwrite, extension, and truncation enter the watch content-change path; metadata-only changes are not treated as content writes.

Before a watch root starts, the path is verified to be on an NTFS or ReFS volume with a readable Journal. A missing Journal is created through the Broker before file observation. If creation or reading fails, the volume identity is invalid, or the broker cannot be reached, watch startup fails and reports the reason.

### Local manual build

x64:

```powershell
cargo build --locked --manifest-path sunpack\sunpack_watch_broker\Cargo.toml --release `
  --target x86_64-pc-windows-msvc --target-dir .cache\rust-target\watch-broker
```

For ARM64, use the target triple `aarch64-pc-windows-msvc`. The x64 output is:

```text
.cache\rust-target\watch-broker\x86_64-pc-windows-msvc\release\sunpack-watch-broker.exe
```

A development test service must use the test identity prefixes:

```text
Service: SunPackWatchBrokerTest_<id>
Pipe:    \\.\pipe\SunPack.WatchBroker.Test.<id>
```

Repository scripts can install or uninstall a temporary service; the scripts reject the standard service identity so that tests cannot overwrite the release service on a development machine:

```powershell
.\scripts\manage_test_watch_service.ps1 -Action Install `
  -ServiceName SunPackWatchBrokerTest_dev `
  -PipeName '\\.\pipe\SunPack.WatchBroker.Test.dev' `
  -BrokerPath '.cache\rust-target\watch-broker\x86_64-pc-windows-msvc\release\sunpack-watch-broker.exe'

.\scripts\manage_test_watch_service.ps1 -Action Uninstall `
  -ServiceName SunPackWatchBrokerTest_dev `
  -PipeName '\\.\pipe\SunPack.WatchBroker.Test.dev'
```

## Building native components manually

### Rust runtime

```powershell
cargo build --locked --manifest-path sunpack\Cargo.toml -p sunpack-runtime --bin sunpack-runtime --release --target x86_64-pc-windows-msvc
```

### C++ embedded 7-Zip worker

```powershell
.\.venv\Scripts\cmake.exe -S sunpack\sevenzip_bridge -B .cache\native\x64\release\sevenzip_bridge -A x64
.\.venv\Scripts\cmake.exe --build .cache\native\x64\release\sevenzip_bridge --config Release
.\.venv\Scripts\ctest.exe --test-dir .cache\native\x64\release\sevenzip_bridge -C Release --output-on-failure
```

The product worker embeds the retained 7-Zip sources and does not load `7z.dll` at run time.

### Windows toast

```powershell
.\.venv\Scripts\cmake.exe -S sunpack\toast_host -B .cache\native\x64\release\toast_host -A x64
.\.venv\Scripts\cmake.exe --build .cache\native\x64\release\toast_host --config Release
.\.venv\Scripts\ctest.exe --test-dir .cache\native\x64\release\toast_host -C Release --output-on-failure
```

A continuously running watch creates Windows notification capability according to `watch.toast_enabled` and sends progress, completion, and failure notifications as configured. Notification failure reports are written to `.sunpack_watch/failures` under the writable data directory.

## Smoke checks

```powershell
cargo test --locked --manifest-path sunpack\Cargo.toml --workspace --profile ci
```

## Testing

Run the CLI boundary tests after building the development artifacts:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\blackbox
```

When pytest is run directly, cases that need the Windows Watch Broker are skipped. Full acceptance is done through `run_acceptance_tests.ps1`, which prepares an isolated test service, runs Rust correctness tests and the CLI and Watch boundary tests, and automatically uninstalls the test service at the end:

```powershell
.\run_acceptance_tests.ps1 -NoWait
```

Acceptance runs use a randomized test service name, named pipe, and temporary environment variables, and never overwrite an installed release service. In a CI environment without elevation, service installation fails immediately instead of waiting for interactive UAC.

CI-style tests for the project:

```powershell
.\scripts\run_ci_tests.ps1
```

## Windows release build

The official build entry point:

```powershell
.\scripts\build_windows.ps1
```

Common parameters:

```powershell
.\scripts\build_windows.ps1 -Arch x64
.\scripts\build_windows.ps1 -Clean
.\scripts\build_windows.ps1 -SkipTests
.\scripts\build_windows.ps1 -Version 1.2.3
```

The release artifact is a Windows installer. The build environment must have Inno Setup 6 installed; when `ISCC.exe` is missing the build fails before it starts, and the compiler path can also be given with `-InnoCompilerPath`. The build runs packaged smoke checks and compiles the final installer with the real Inno Setup compiler; installer behavior is covered by static contract tests rather than a machine-state-dependent install/upgrade/uninstall E2E. `-SkipTests` skips the acceptance suite only.

The build process:

1. Build the Rust runtime and Watch Broker with Cargo
2. Build the CLI launcher, worker, GUI, and toast DLL with CMake
3. Stage configuration, password data, scripts, and license files
4. Check PE architecture and run packaged CLI smoke tests
5. Run the selected acceptance tests and create the installer with Inno Setup

### NTFS and ReFS USN contract

Both filesystems use the same Broker and recovery path. A missing journal
(`ERROR_JOURNAL_NOT_ACTIVE`) is created once with the existing 32 MiB / 8 MiB
settings before file observation; other errors retain their original failure.
No periodic journal polling or additional resident index is introduced.

The volume read uses [`READ_USN_JOURNAL_DATA_V1`](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-read_usn_journal_data_v1)
with versions 2–3. Per-file reads request the same range. V3 carries full
128-bit file and parent IDs; V2 IDs are zero-extended for matching. Directory
recovery accepts a zero initial cursor but still checks journal identity and
retained bounds. Existing `FileIdInfo` identities and compact catalog IDs
preserve all 128 bits ([Microsoft identity requirements](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/ns-fileapi-by_handle_file_information)).
V4 extent records lack filenames and are not requested.

ReFS regression coverage uses simulated V3 records with nonzero high 64-bit
file and parent IDs, plus the existing tests for journal creation, version
negotiation, zero cursors and paged recovery. These tests need neither a ReFS
volume nor permission to create one. Real-volume checks are temporary local
validation and are not part of the repository test suite or CI requirements.
