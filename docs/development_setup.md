# Development environment and build instructions

**English** | [简体中文](zh-CN/development_setup.md)

SunPack is a Windows-only project. Cargo builds the Rust runtime and Watch Broker. CMake builds the native worker, launcher, GUI, and toast DLL. `uv.lock` pins the Python test dependencies.

## Requirements

- Windows 10/11
- PowerShell 5.1 or newer
- Python 3.10 or newer for boundary tests and development scripts
- `uv` 0.12 or newer
- Rust MSVC toolchain, providing `cargo`
- Visual Studio Build Tools 2022, including a C++17 compiler
- ARM64 optimized builds additionally require the Visual Studio **C++ Clang tools for Windows** component (`clang-cl`), used only for upstream 7-Zip `LzmaDecOpt.S`
- Network access for the first dependency install and for preparing the 7-Zip test files

Main project directories:

```text
native/sunpack_native/      Rust orchestration and computation, CLI and Watch
native/sunpack_usn_core/    Shared NTFS/USN Rust core
native/sunpack_watch_broker/Windows Watch Broker service
native/sevenzip_bridge/     Windows 7z.dll bridge and worker
native/toast_host/          Windows toast DLL
tools/                      x64 external tools and native build outputs
tools-arm64/                ARM64 external tools and native build outputs
```

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

The development environment directory is `.venv`. If that environment has global site-packages enabled, the setup script disables that option.

## One-step development environment setup

```powershell
.\scripts\setup_windows_dev.ps1
```

The script will:

1. Prepare an isolated `.venv` with `uv sync --locked --extra dev`
2. Build the Rust runtime and native fixture generator
3. Build `sunpack-watch-broker.exe`
4. Prepare `7z.exe`, `7z.dll`, and the license for the matching architecture
5. Build `sunpack_sevenzip_worker.exe` and `sunpack_toast.dll`
6. Copy the native artifacts into the tools directory
7. Run the worker and toast CTest suites

Options:

```powershell
.\scripts\setup_windows_dev.ps1 -Clean
.\scripts\setup_windows_dev.ps1 -Arch arm64
.\scripts\setup_windows_dev.ps1 -SkipAcceptanceTestTools
```

On x64, setup also prepares the acceptance fixture generators under `.sunpack_test_tools/`: WinRAR 6.22, zstd 1.5.7, and [7-Zip-Zstandard 25.01 / Zstandard 1.5.7 Release 4](https://github.com/mcmilk/7-Zip-zstd/releases/tag/v25.01-v1.5.7-R4). The LZ4 writer is installed at `7zip-zstd/7z.exe` with its companion `7z.dll`; setup checks that it runs and exposes the LZ4 encoder. These tools are excluded from release packages. `-SkipAcceptanceTestTools` skips their preparation.

## USN Watch Broker

watch uses the NTFS USN Journal to determine whether file contents have changed and whether a file has crossed a write boundary. Operations that need volume-level Journal access are concentrated in `native/sunpack_usn_core` and `native/sunpack_watch_broker`. Watch consumes the typed file observations and state directly.

### Components and lifecycle

- `native/sunpack_usn_core` is a Windows-only Rust crate containing volume identification, Journal probing, bounded USN reason reads, and the named pipe client protocol.
- `native/sunpack_watch_broker` compiles to `sunpack-watch-broker.exe` and runs as a Windows service, holding volume-level Journal access.
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

Before a watch root starts, the path is verified to be on an NTFS volume with a readable Journal. If the Journal is unavailable, the volume identity is invalid, or the broker cannot be reached, watch startup fails and reports the reason.

### Local manual build

x64:

```powershell
cargo build --locked --manifest-path native\sunpack_watch_broker\Cargo.toml --release --target x86_64-pc-windows-msvc --target-dir .cache\rust-target\x64
```

For ARM64, replace the target triple and target directory with `aarch64-pc-windows-msvc` and `.cache\rust-target\arm64`. The output file is:

```text
.cache\rust-target\x64\x86_64-pc-windows-msvc\release\sunpack-watch-broker.exe
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
  -BrokerPath '.cache\rust-target\x64\x86_64-pc-windows-msvc\release\sunpack-watch-broker.exe'

.\scripts\manage_test_watch_service.ps1 -Action Uninstall `
  -ServiceName SunPackWatchBrokerTest_dev `
  -PipeName '\\.\pipe\SunPack.WatchBroker.Test.dev'
```

## Building native components manually

### Rust runtime

```powershell
cargo build --locked --manifest-path native\Cargo.toml -p sunpack-native --bin sunpack-runtime --release --target x86_64-pc-windows-msvc --target-dir .cache\rust-target\x64
```

### C++ embedded 7-Zip worker

```powershell
cmake -S native\sevenzip_bridge -B native\sevenzip_bridge\build-x64 -A x64
cmake --build native\sevenzip_bridge\build-x64 --config Release
ctest --test-dir native\sevenzip_bridge\build-x64 -C Release --output-on-failure
Copy-Item native\sevenzip_bridge\build-x64\Release\sunpack_sevenzip_worker.exe tools\sunpack_sevenzip_worker.exe -Force
```

The product worker embeds the retained 7-Zip sources and does not load `7z.dll` at run time.

### Windows toast

```powershell
cmake -S native\toast_host -B native\toast_host\build-x64 -A x64
cmake --build native\toast_host\build-x64 --config Release
ctest --test-dir native\toast_host\build-x64 -C Release --output-on-failure
Copy-Item native\toast_host\build-x64\Release\sunpack_toast.dll tools\sunpack_toast.dll -Force
```

A continuously running watch creates Windows notification capability according to `watch.toast_enabled` and sends progress, completion, and failure notifications as configured. Ordinary CLI requests and `watch start --once` do not create notification capability. Notification failure reports are written to `.sunpack_watch/failures` under the writable data directory.

## Smoke checks

```powershell
cargo test --locked --manifest-path native\Cargo.toml --workspace --profile ci
```

## Testing

Run the CLI boundary tests after building the development artifacts:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\blackbox
```

When pytest is run directly, cases that need the Windows NTFS Watch Broker are skipped. Full acceptance is done through `run_acceptance_tests.ps1`, which prepares an isolated test service, runs Rust correctness tests and the CLI and Watch boundary tests, and automatically uninstalls the test service at the end:

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
