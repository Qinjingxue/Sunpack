[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$SourceKey,
    [ValidateSet("x64", "arm64")][string]$Arch = "x64",
    [ValidateSet("release", "ci")][string]$BuildProfile = "release",
    [ValidateSet("native", "gui")][string]$Scope = "native"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$statePath = Join-Path $repoRoot ".cache\$Scope-source-times-$Arch-$BuildProfile.json"
$saved = $null
if (Test-Path -LiteralPath $statePath) {
    try { $saved = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json -AsHashtable }
    catch { Write-Warning "Ignoring unreadable $Scope timestamp cache: $_" }
}

# Only each subsystem's actual build inputs may affect its cached timestamps.
# Git blob IDs let an unchanged source retain its timestamp even if another
# input changed (fallback cache); modified working-tree files never do.
$inputs = if ($Scope -eq "gui") {
    @("gui", "tests/gui", "scripts/build_gui.ps1",
      "scripts/restore_native_cache_times.ps1", "sunpack.manifest",
      "sunpack_advanced_config.json", "native/third_party/lz4")
} else {
    @("native", "scripts", ":(exclude)scripts/build_gui.ps1", "sunpack.manifest")
}
$tracked = @(& git -C $repoRoot -c core.quotepath=false ls-files --stage -- $inputs)
if ($LASTEXITCODE -ne 0) { throw "Cannot enumerate $Scope build inputs" }
$dirtyFiles = @(& git -C $repoRoot -c core.quotepath=false diff --name-only -- $inputs)
if ($LASTEXITCODE -ne 0) { throw "Cannot check modified $Scope build inputs" }
$dirty = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
foreach ($name in $dirtyFiles) { [void]$dirty.Add($name) }

$times = @{}
$blobs = @{}
$restored = 0
foreach ($line in $tracked) {
    if ($line -notmatch '^[0-7]{6} ([0-9a-f]{40,64}) 0\t(.+)$') { continue }
    $blob = $Matches[1]
    $relativePath = $Matches[2]
    $path = Join-Path $repoRoot $relativePath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
    $file = Get-Item -LiteralPath $path
    $sameBlob = $saved -and $saved.ContainsKey("Blobs") -and
        $saved.Blobs.ContainsKey($relativePath) -and $saved.Blobs[$relativePath] -eq $blob
    $sameSource = $saved -and $saved.ContainsKey("SourceKey") -and
        $saved.SourceKey -eq $SourceKey
    if ($saved -and $saved.ContainsKey("Times") -and
        $saved.Times.ContainsKey($relativePath) -and -not $dirty.Contains($relativePath) -and
        ($sameSource -or $sameBlob)) {
        $file.LastWriteTimeUtc = [datetime]::new([long]$saved.Times[$relativePath], [DateTimeKind]::Utc)
        $restored++
    }
    $times[$relativePath] = $file.LastWriteTimeUtc.Ticks
    $blobs[$relativePath] = $blob
}
New-Item -ItemType Directory -Path (Split-Path -Parent $statePath) -Force | Out-Null
@{ SourceKey = $SourceKey; Times = $times; Blobs = $blobs } | ConvertTo-Json -Depth 3 -Compress |
    Set-Content -LiteralPath $statePath -Encoding UTF8
Write-Host "Restored $restored unchanged $Scope input timestamps ($Arch/$BuildProfile)"
