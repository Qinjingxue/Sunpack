# Development environment and build instructions

**English** | [简体中文](zh-CN/development_setup.md)

SunPack is a Windows-only project. Python dependencies are declared uniformly in the root `pyproject.toml` and locked by `uv.lock`; Rust, C++, and the Windows service share the same build pipeline.

## Requirements

- Windows 10/11
- PowerShell 5.1 or newer
- Python 3.10 or newer, with an architecture matching the target distribution package
- `uv` 0.12 or newer
- Rust MSVC toolchain, providing `cargo`
- Visual Studio Build Tools 2022, including a C++17 compiler
- ARM64 optimized builds additionally require the Visual Studio **C++ Clang tools for Windows** component (`clang-cl`), used only for upstream 7-Zip `LzmaDecOpt.S`
- Network access for the first dependency install and for preparing the 7-Zip test files

Main project directories:

```text
sunpack/                    Product runtime code
native/sunpack_native/      Rust/PyO3 extension
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
| default | SunPack runtime dependencies |
| `test` | pytest and test data generation dependencies |
| `build` | Nuitka, maturin, CMake |
| `dev` | Union of build and test |

Common install commands:

```powershell
uv sync --locked
uv sync --locked --extra test
uv sync --locked --extra dev
```

The development environment directory is `.venv`. If that environment has global site-packages enabled, the setup script rebuilds it so that global packages cannot interfere with dependency resolution.

## One-step development environment setup

```powershell
.\scripts\setup_windows_dev.ps1
```

The script will:

1. Prepare an isolated `.venv` with `uv sync --locked --extra dev`
2. Build and install the Rust/PyO3 wheel for the current architecture
3. Build `sunpack-watch-broker.exe`
4. Prepare `7z.exe`, `7z.dll`, and the license for the matching architecture
5. Build `sunpack_sevenzip_worker.exe` and `sunpack_toast.dll`
6. Copy the native artifacts into the tools directory
7. Run Python, Rust, C++, and CLI smoke checks

Options:

```powershell
.\scripts\setup_windows_dev.ps1 -Clean
.\scripts\setup_windows_dev.ps1 -Arch arm64
.\scripts\setup_windows_dev.ps1 -SkipAcceptanceTestTools
```

The target architecture must match the architecture of the current Python process.

## USN Watch Broker

watch uses the NTFS USN Journal to determine whether file contents have changed and whether a file has crossed a write boundary. Operations that need volume-level Journal access are concentrated in `native/sunpack_usn_core` and `native/sunpack_watch_broker`; Python only consumes file observation results and watch state.

### Components and lifecycle

- `native/sunpack_usn_core` is a Windows-only Rust crate containing volume identification, Journal probing, bounded USN reason reads, and the named pipe client protocol.
- `native/sunpack_watch_broker` compiles to `sunpack-watch-broker.exe` and runs as a Windows service, holding volume-level Journal access.
- At startup, watch first acquires a process-level lease. The first lease starts the service on demand and establishes a local named pipe connection; later leases in the same process reuse the connection; when the last lease is released, a release request is sent to the service.
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

### Rust/PyO3

```powershell
uv sync --locked --extra build
.\.venv\Scripts\maturin.exe build --manifest-path native\sunpack_native\Cargo.toml --release --target-dir .cache\rust-target\x64 --out build\native-wheels-dev
$wheel = Get-ChildItem build\native-wheels-dev\sunpack_native-*.whl |
    Sort-Object LastWriteTimeUtc -Descending |
    Select-Object -First 1 -ExpandProperty FullName
uv pip uninstall --python .\.venv\Scripts\python.exe sunpack-native
uv pip install --python .\.venv\Scripts\python.exe --reinstall $wheel
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

A continuously running watch creates Windows notification capability according to `watch.toast_enabled` and sends progress, completion, and failure notifications as configured. Ordinary CLI requests and `watch start --once` do not create notification capability. Notification failure reports are written to the state directory managed by `watch.state_dir`.

## Smoke checks

```powershell
.\.venv\Scripts\python.exe -c "import sunpack_native as n; print(n.native_available())"
.\.venv\Scripts\python.exe -c "from sunpack.core.support.resources import get_sevenzip_bridge_worker_path; print(get_sevenzip_bridge_worker_path())"
.\.venv\Scripts\python.exe -m pytest tests\unit\test_config_loader.py
```

The first two commands verify the Rust extension and the C++ worker path respectively; the third verifies configuration loading.

## Testing

Plain pytest:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

When pytest is run directly, cases that need the Windows NTFS Watch Broker are skipped. Full acceptance is done through `run_acceptance_tests.ps1`, which prepares an isolated test service, runs unit, functional, integration, real-scenario, disk-space, and CLI smoke tests, and automatically uninstalls the test service at the end:

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

1. Create or reuse `.venv` (cleaned and recreated with `-Clean`)
2. Install the project `dev` extra
3. Build and install the Rust wheel
4. Build the Watch Broker
5. Build and test the C++ bridge/worker and the toast DLL
6. Optionally run acceptance tests
7. Build the console-less runtime and the CLI launcher
8. Copy the configuration, password table, tools, Watch Broker, third-party license files, and notices
9. Validate the architecture of the key PE files
10. Run packaged CLI, bridge, and worker smoke checks
11. Create the Windows installer with Inno Setup

Output:

```text
dist\sunpack-<arch>\
dist\sunpack-<arch>\service\sunpack-watch-broker.exe
dist\sunpack-<arch>\licenses\SunPack-MIT.txt
dist\sunpack-<arch>\licenses\7zip-license.txt
dist\sunpack-<arch>\licenses\7zip-source-license.txt
dist\sunpack-<arch>\licenses\LGPL-2.1.txt
dist\sunpack-<arch>\THIRD_PARTY_NOTICES.md
release\sunpack-windows-<arch>-<version>-setup.exe
```

ARM64 must be built on ARM64 Windows with an ARM64 Python environment. An existing directory can be validated independently:

```powershell
.\scripts\verify_windows_package_arch.ps1 -PackageRoot dist\sunpack-x64 -Arch x64
```

## Runtime native files

The x64 development environment uses the following by default:

```text
tools\7z.exe
tools\7z.dll
tools\sunpack_sevenzip_worker.exe
tools\sunpack_toast.dll
```

The installer package additionally contains:

```text
service\sunpack-watch-broker.exe
```

`sunpack_sevenzip_worker.exe` reads JSON jobs and extracts files, volumes, and virtual inputs through the embedded 7-Zip backend. `7z.exe` and its adjacent development `7z.dll` are used for fixtures, manual diagnostics, file provenance, and preparing release resources; they are not product extraction runtime dependencies.
