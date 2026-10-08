# Shared development-artifact preflight. Read metadata only; no fingerprints or
# persistent manifest. Each invocation rescans inputs so the post-setup check
# also notices source edits made while setup was running.
function Set-DevelopmentArtifactBuildTime {
    param([Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][datetime]$BuildStartedUtc)
    # Incremental builds may succeed without relinking. Record when the build
    # verified its inputs, rather than preserving an old link/wheel timestamp.
    # Advance an old timestamp only to the START time, not completion time.
    # Never backdate a newly linked output: Cargo needs its original timestamp
    # relative to dependencies for subsequent incremental builds.
    $artifact = Get-Item -LiteralPath $Path
    if ($artifact.LastWriteTimeUtc -lt $BuildStartedUtc) {
        $artifact.LastWriteTimeUtc = $BuildStartedUtc
    }
}

function Get-WatchBrokerBuildPath {
    param([string]$RepoRoot, [ValidateSet("x64", "arm64")][string]$Arch,
        [ValidateSet("release", "ci")][string]$BuildProfile = "ci")
    $target = if ($Arch -eq "arm64") { "aarch64-pc-windows-msvc" } else { "x86_64-pc-windows-msvc" }
    return Join-Path $RepoRoot (".cache\rust-target\{0}\{1}\{2}\sunpack-watch-broker.exe" -f $Arch, $target, $BuildProfile)
}

function Get-NativeExtensionPath {
    param([Parameter(Mandatory = $true)][string]$PythonPath)
    # Resolve the actual extension rather than picking the newest .pyd beside
    # a package wrapper (which might not be the binary Python loads).
    $code = @'
import importlib.util
from importlib.machinery import EXTENSION_SUFFIXES
spec = importlib.util.find_spec('sunpack_native')
if spec and spec.submodule_search_locations is not None:
    spec = importlib.util.find_spec('sunpack_native.sunpack_native')
origin = spec.origin if spec else ''
print(origin if origin and any(origin.endswith(s) for s in EXTENSION_SUFFIXES) else '')
'@
    try {
        $origin = & $PythonPath -c $code 2>$null
        if ($LASTEXITCODE -eq 0) { return (($origin | Out-String).Trim()) }
    } catch {
    }
    return ""
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
        [AllowEmptyString()][string]$NativeExtension = "",
        [ValidateSet("release", "ci")][string]$BuildProfile = "ci"
    )
    $nativeRoot = Join-Path $RepoRoot "native"
    $toolsRoot = if ($Arch -eq "arm64") { Join-Path $RepoRoot "tools-arm64" } else { Join-Path $RepoRoot "tools" }
    $sharedRustTime = Get-NewestSourceWriteTime -Paths @(
        (Join-Path $nativeRoot "Cargo.toml"), (Join-Path $nativeRoot "Cargo.lock"),
        (Join-Path $nativeRoot "sunpack_usn_core"),
        (Join-Path $RepoRoot "scripts\setup_windows_dev.ps1")
    )
    $lz4Time = Get-NewestSourceWriteTime -Paths @(
        (Join-Path $nativeRoot "lz4_stream"), (Join-Path $nativeRoot "third_party\lz4")
    )
    $components = @(
        @{ Name = "sunpack_native"; Artifact = $NativeExtension; InputTime = @(
            $sharedRustTime, $lz4Time,
            (Get-NewestSourceWriteTime -Paths (Join-Path $nativeRoot "sunpack_native")),
            (Get-NewestSourceWriteTime -Paths (Join-Path $nativeRoot "sunpack_enc"))
        ) },
        @{ Name = "Native test fixture"; Artifact = (Join-Path $toolsRoot "real_fixture.exe"); InputTime = @(
            $sharedRustTime, $lz4Time,
            (Get-NewestSourceWriteTime -Paths (Join-Path $nativeRoot "sunpack_native")),
            (Get-NewestSourceWriteTime -Paths (Join-Path $nativeRoot "sunpack_enc"))
        ) },
        @{ Name = "Watch Broker"; Artifact = (Get-WatchBrokerBuildPath -RepoRoot $RepoRoot -Arch $Arch -BuildProfile $BuildProfile); InputTime = @(
            $sharedRustTime,
            (Get-NewestSourceWriteTime -Paths (Join-Path $nativeRoot "sunpack_watch_broker"))
        ) },
        @{ Name = "7-Zip worker"; Artifact = (Join-Path $toolsRoot "sunpack_sevenzip_worker.exe"); InputTime = @(
            $lz4Time,
            (Get-NewestSourceWriteTime -Paths @((Join-Path $nativeRoot "sevenzip_bridge"),
                (Join-Path $nativeRoot "cmake"), (Join-Path $nativeRoot "sunpack_enc"),
                (Join-Path $nativeRoot "Cargo.toml"), (Join-Path $nativeRoot "Cargo.lock"),
                (Join-Path $RepoRoot "scripts\setup_windows_dev.ps1")))
        ) },
        @{ Name = "Toast library"; Artifact = (Join-Path $toolsRoot "sunpack_toast.dll"); InputTime = @(
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
        if ($component.Name -eq "sunpack_native") {
            $sitePackages = [IO.Path]::GetFullPath((Join-Path $RepoRoot ".venv\Lib\site-packages")) + '\'
            if (-not ([IO.Path]::GetFullPath($artifact)).StartsWith($sitePackages, [StringComparison]::OrdinalIgnoreCase)) {
                "sunpack_native is loaded outside the project .venv: $artifact"
                continue
            }
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
