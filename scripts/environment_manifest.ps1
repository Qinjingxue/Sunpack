[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RepoRoot,
    [Parameter(Mandatory = $true)][ValidateSet("x64", "arm64")][string]$Arch,
    [switch]$Check
)

$ErrorActionPreference = "Stop"
$RepoRoot = [IO.Path]::GetFullPath($RepoRoot)
$toolsRoot = if ($Arch -eq "arm64") { Join-Path $RepoRoot "tools-arm64" } else { Join-Path $RepoRoot "tools" }
$manifestRoot = Join-Path $RepoRoot ".sunpack_cache"
$manifestPath = Join-Path $manifestRoot ("environment-{0}.json" -f $Arch)

function Get-FileDigest([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return "missing" }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-TreeDigest([string]$Root, [string[]]$Patterns) {
    $items = @(Get-ChildItem -LiteralPath $Root -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object {
            $relative = $_.FullName.Substring($Root.Length).TrimStart('\','/')
            $segments = $relative -split '[\\/]'
            ($segments -notcontains "target") -and
            ($segments -notmatch '^build(-|$)') -and
            ($_.Name -in $Patterns -or $_.Extension -in $Patterns)
        }) |
        Sort-Object FullName
    $parts = foreach ($item in $items) {
        "{0}={1}" -f ($item.FullName.Substring($Root.Length).TrimStart('\','/')), (Get-FileDigest $item.FullName)
    }
    $bytes = [Text.Encoding]::UTF8.GetBytes(($parts -join "`n"))
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace("-", "").ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Get-ComponentDigest([string]$Root) {
    return Get-TreeDigest $Root @(".rs", ".toml", ".lock", ".cpp", ".h", ".hpp", ".cmake", "CMakeLists.txt", "pyproject.toml")
}

$nativeRoot = Join-Path $RepoRoot "native"
$nativeParts = @(
    (Get-ComponentDigest $nativeRoot),
    (Get-FileDigest (Join-Path $RepoRoot "pyproject.toml")),
    (Get-FileDigest (Join-Path $RepoRoot "uv.lock"))
)
$sourceHashInput = [Text.Encoding]::UTF8.GetBytes(($nativeParts -join "`n"))
$sha = [Security.Cryptography.SHA256]::Create()
try { $sourceHash = ([BitConverter]::ToString($sha.ComputeHash($sourceHashInput))).Replace("-", "").ToLowerInvariant() }
finally { $sha.Dispose() }

$rustTarget = if ($Arch -eq "arm64") { "aarch64-pc-windows-msvc" } else { "x86_64-pc-windows-msvc" }
$brokerCandidates = @(
    (Join-Path $RepoRoot (".cache\rust-target\{0}\{1}\release\sunpack-watch-broker.exe" -f $Arch, $rustTarget)),
    (Join-Path $RepoRoot "native\target\release\sunpack-watch-broker.exe")
)
$brokerPath = $brokerCandidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
$bridgeLauncherPath = Join-Path $RepoRoot ("native\sevenzip_bridge\build-{0}\Release\sunpack_launcher.exe" -f $Arch)
$pythonExtension = Get-ChildItem -LiteralPath (Join-Path $RepoRoot ".venv\Lib\site-packages\sunpack_native") -Filter "sunpack_native*.pyd" -File -ErrorAction SilentlyContinue |
    Select-Object -First 1
$artifacts = [ordered]@{
    native_extension = if ($pythonExtension) { Get-FileDigest $pythonExtension.FullName } else { "missing" }
    watch_broker = if ($brokerPath) { Get-FileDigest $brokerPath } else { "missing" }
    seven_zip_launcher = Get-FileDigest $bridgeLauncherPath
    seven_zip_exe = Get-FileDigest (Join-Path $toolsRoot "7z.exe")
    seven_zip_sfx = Get-FileDigest (Join-Path $toolsRoot "7zCon.sfx")
    seven_zip_dll = Get-FileDigest (Join-Path $toolsRoot "7z.dll")
    wrapper_dll = Get-FileDigest (Join-Path $toolsRoot "sunpack_sevenzip.dll")
    wrapper_worker = Get-FileDigest (Join-Path $toolsRoot "sunpack_sevenzip_worker.exe")
    toast_dll = Get-FileDigest (Join-Path $toolsRoot "sunpack_toast.dll")
}
$state = [ordered]@{
    project = "sunpack"
    native_workspace = "native/Cargo.toml"
    arch = $Arch
    source_hash = $sourceHash
    components = [ordered]@{
        rust_workspace = Get-ComponentDigest $nativeRoot
        sevenzip_bridge = Get-ComponentDigest (Join-Path $nativeRoot "sevenzip_bridge")
        toast_host = Get-ComponentDigest (Join-Path $nativeRoot "toast_host")
    }
    artifacts = $artifacts
}

if ($Check) {
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { exit 1 }
    $expected = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ($expected.source_hash -ne $state.source_hash) { exit 1 }
    foreach ($name in $artifacts.Keys) {
        if ($expected.artifacts.$name -ne $artifacts[$name] -or $artifacts[$name] -eq "missing") { exit 1 }
    }
    exit 0
}

New-Item -ItemType Directory -Path $manifestRoot -Force | Out-Null
$state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
