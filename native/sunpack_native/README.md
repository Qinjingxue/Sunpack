# sunpack_native

The Windows runtime shares typed archive inputs, directory snapshots, password
data, and output inventories across CLI, Watch, and the native computation
modules. `core` provides configuration and shared facilities, `pipeline` owns
archive orchestration, and `runtime` integrates the Windows entry points.

Discovery uses the existing analyzers and logical readers. The resulting facts
flow through password verification, extraction planning, and recovery. The
C++ worker embeds the 7-Zip backend and communicates over SPBF.

## Build and test

```powershell
.\scripts\setup_windows_dev.ps1
cargo test --locked --manifest-path native\Cargo.toml --workspace --profile ci
```

The packaging script stages `sunpack-runtime.exe` with the CLI launcher, worker,
GUI, toast DLL, configuration, and installer scripts. See the
[development setup](../../docs/development_setup.md) and
[module boundaries](../../docs/development_boundaries.md).
