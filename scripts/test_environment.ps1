# Shared development-artifact preflight. Read metadata only; no fingerprints or
# persistent manifest. Each invocation rescans inputs so the post-setup check
# also notices source edits made while setup was running.
function Set-DevelopmentArtifactBuildTime {
    param([Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][datetime]$BuildStartedUtc)
    # Incremental builds may succeed without relinking. Record when the build
    # verified its inputs, rather than preserving an old link timestamp.
    # Advance an old timestamp only to the START time, not completion time.
    # Never backdate a newly linked output: Cargo needs its original timestamp
    # relative to dependencies for subsequent incremental builds.
    $artifact = Get-Item -LiteralPath $Path
    if ($artifact.LastWriteTimeUtc -lt $BuildStartedUtc) {
        $artifact.LastWriteTimeUtc = $BuildStartedUtc
    }
}

function Get-RustBuildDirectory {
    param([string]$RepoRoot, [ValidateSet("x64", "arm64")][string]$Arch,
        [ValidateSet("release", "ci")][string]$BuildProfile = "ci")
    $target = if ($Arch -eq "arm64") { "aarch64-pc-windows-msvc" } else { "x86_64-pc-windows-msvc" }
    return Join-Path $RepoRoot ".cache\rust-target\$target\$BuildProfile"
}

function Get-NativeBuildDirectory {
    param([string]$RepoRoot, [ValidateSet("x64", "arm64")][string]$Arch,
        [ValidateSet("release", "ci")][string]$BuildProfile = "ci",
        [ValidateSet("sevenzip_bridge", "toast_host")][string]$Component)
    return Join-Path $RepoRoot ".cache\native\$Arch\$BuildProfile\$Component"
}

function Get-WatchBrokerBuildPath {
    param([string]$RepoRoot, [ValidateSet("x64", "arm64")][string]$Arch,
        [ValidateSet("release", "ci")][string]$BuildProfile = "ci")
    return Join-Path (Get-RustBuildDirectory -RepoRoot $RepoRoot -Arch $Arch -BuildProfile $BuildProfile) "sunpack-watch-broker.exe"
}

function Get-ArchiveFixtureBuildPath {
    param([string]$RepoRoot, [ValidateSet("x64", "arm64")][string]$Arch,
        [ValidateSet("release", "ci")][string]$BuildProfile = "ci")
    return Join-Path (Get-RustBuildDirectory -RepoRoot $RepoRoot -Arch $Arch -BuildProfile $BuildProfile) "examples\real_fixture.exe"
}

function Get-SunPackRuntimeBuildPath {
    param([string]$RepoRoot, [ValidateSet("x64", "arm64")][string]$Arch,
        [ValidateSet("release", "ci")][string]$BuildProfile = "ci")
    return Join-Path (Split-Path -Parent (Get-WatchBrokerBuildPath -RepoRoot $RepoRoot -Arch $Arch -BuildProfile $BuildProfile)) "sunpack-runtime.exe"
}

function Get-ArchiveFixtureToolRefreshReasons {
    param([string]$RepoRoot, [ValidateSet("x64", "arm64")][string]$Arch)
    $toolsRoot = Join-Path $RepoRoot $(if ($Arch -eq "arm64") { "tools\arm64" } else { "tools" })
    foreach ($name in @("7z.exe", "7z.dll", "7zCon.sfx")) {
        if (-not (Test-Path -LiteralPath (Join-Path $toolsRoot $name) -PathType Leaf)) {
            "Required archive fixture generator is missing: $name"
        }
    }
}

function Get-NewestSourceWriteTime {
    param([Parameter(Mandatory = $true)][string[]]$Paths)
    $newest = [datetime]::MinValue
    $pending = New-Object 'System.Collections.Generic.Stack[string]'
    foreach ($path in $Paths) { $pending.Push($path) }
    while ($pending.Count -gt 0) {
        $path = $pending.Pop()
        if (-not (Test-Path -LiteralPath $path)) {
            throw "Required native build input is missing: $path"
        }
        $item = Get-Item -LiteralPath $path -Force
        if (-not $item.PSIsContainer) {
            if ($item.LastWriteTimeUtc -gt $newest) { $newest = $item.LastWriteTimeUtc }
            continue
        }
        # Prune before descending: generated CMake/Cargo files are not inputs.
        foreach ($child in Get-ChildItem -LiteralPath $path -Force) {
            if ($child.PSIsContainer) {
                if ($child.Name -match '^(build($|[-_])|target$|\.git$|__pycache__$|\.cache$)' -or
                    ($child.Attributes -band [IO.FileAttributes]::ReparsePoint)) { continue }
                $pending.Push($child.FullName)
            } elseif ($child.Name -eq 'CMakeLists.txt' -or
                $child.Extension -match '^\.(rs|toml|lock|c|h|cpp|hpp|cxx|hxx|cmake|asm|s|inc|in|rc|manifest|def)$') {
                if ($child.LastWriteTimeUtc -gt $newest) { $newest = $child.LastWriteTimeUtc }
            }
        }
    }
    return $newest
}

function Get-NativeArtifactRefreshReasons {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [ValidateSet("x64", "arm64")][string]$Arch = "x64",
        [ValidateSet("release", "ci")][string]$BuildProfile = "ci"
    )
    $nativeRoot = Join-Path $RepoRoot "sunpack"
    $sevenZipOutputs = Join-Path (Get-NativeBuildDirectory -RepoRoot $RepoRoot -Arch $Arch -BuildProfile $BuildProfile -Component sevenzip_bridge) "Release"
    $toastOutputs = Join-Path (Get-NativeBuildDirectory -RepoRoot $RepoRoot -Arch $Arch -BuildProfile $BuildProfile -Component toast_host) "Release"
    $sharedRustTime = Get-NewestSourceWriteTime -Paths @(
        (Join-Path $RepoRoot ".cargo\config.toml"),
        (Join-Path $nativeRoot "Cargo.toml"), (Join-Path $nativeRoot "Cargo.lock"),
        (Join-Path $nativeRoot "sunpack_usn_core"),
        (Join-Path $RepoRoot "scripts\setup_windows_dev.ps1")
    )
    $lz4Time = Get-NewestSourceWriteTime -Paths @(
        (Join-Path $nativeRoot "lz4_stream"), (Join-Path $nativeRoot "third_party\lz4")
    )
    $sevenZipTime = Get-NewestSourceWriteTime -Paths @(
        (Join-Path $RepoRoot ".cargo\config.toml"),
        (Join-Path $nativeRoot "sevenzip_bridge"), (Join-Path $nativeRoot "cmake"),
        (Join-Path $nativeRoot "sunpack_enc"), (Join-Path $nativeRoot "Cargo.toml"),
        (Join-Path $nativeRoot "Cargo.lock"), (Join-Path $RepoRoot "scripts\setup_windows_dev.ps1"),
        (Join-Path $RepoRoot "sunpack.manifest")
    )
    $components = @(
        @{ Name = "SunPack runtime"; Artifact = (Get-SunPackRuntimeBuildPath -RepoRoot $RepoRoot -Arch $Arch -BuildProfile $BuildProfile); InputTime = @(
            $sharedRustTime, $lz4Time,
            (Get-NewestSourceWriteTime -Paths @(
                (Join-Path $RepoRoot "sunpack_advanced_config.json"),
                (Join-Path $RepoRoot "sunpack.manifest"),
                (Join-Path $RepoRoot "sunpack.ico")
            )),
            (Get-NewestSourceWriteTime -Paths (Join-Path $nativeRoot "sunpack_runtime")),
            (Get-NewestSourceWriteTime -Paths (Join-Path $nativeRoot "sunpack_enc"))
        ) },
        @{ Name = "Native test fixture"; Artifact = (Get-ArchiveFixtureBuildPath -RepoRoot $RepoRoot -Arch $Arch -BuildProfile $BuildProfile); InputTime = @(
            $sharedRustTime, $lz4Time,
            (Get-NewestSourceWriteTime -Paths (Join-Path $nativeRoot "sunpack_runtime")),
            (Get-NewestSourceWriteTime -Paths (Join-Path $nativeRoot "sunpack_enc"))
        ) },
        @{ Name = "Watch Broker"; Artifact = (Get-WatchBrokerBuildPath -RepoRoot $RepoRoot -Arch $Arch -BuildProfile $BuildProfile); InputTime = @(
            $sharedRustTime,
            (Get-NewestSourceWriteTime -Paths (Join-Path $nativeRoot "sunpack_watch_broker"))
        ) },
        @{ Name = "SunPack launcher"; Artifact = (Join-Path $sevenZipOutputs "sunpack_launcher.exe"); InputTime = @(
            $sevenZipTime
        ) },
        @{ Name = "7-Zip worker"; Artifact = (Join-Path $sevenZipOutputs "sunpack_sevenzip_worker.exe"); InputTime = @(
            $lz4Time, $sevenZipTime
        ) },
        @{ Name = "Toast library"; Artifact = (Join-Path $toastOutputs "sunpack_toast.dll"); InputTime = @(
            (Get-NewestSourceWriteTime -Paths @((Join-Path $nativeRoot "toast_host"),
                (Join-Path $nativeRoot "cmake"), (Join-Path $RepoRoot "scripts\setup_windows_dev.ps1")))
        ) }
    )
    foreach ($component in $components) {
        $artifact = $component.Artifact
        if (-not $artifact -or -not (Test-Path -LiteralPath $artifact -PathType Leaf)) {
            "$($component.Name) build artifact is missing: $artifact"
            continue
        }
        $artifactTime = (Get-Item -LiteralPath $artifact).LastWriteTimeUtc
        foreach ($inputTime in $component.InputTime) {
            if ($inputTime -gt $artifactTime) {
                "$($component.Name) build artifact is older than its inputs: $artifact"
                break
            }
        }
    }
}
