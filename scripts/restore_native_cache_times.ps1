[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$SourceKey,
    [ValidateSet("x64", "arm64")][string]$Arch = "x64",
    [ValidateSet("release", "ci")][string]$BuildProfile = "release"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$statePath = Join-Path $repoRoot ".cache\native-source-times-$Arch-$BuildProfile.json"
$saved = $null
if (Test-Path -LiteralPath $statePath) {
    try { $saved = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json -AsHashtable }
    catch { Write-Warning "Ignoring unreadable native timestamp cache: $_" }
}

# The workflow fingerprint covers these inputs. Restore times only when their
# contents match; changed-source fallback caches retain checkout timestamps so
# Cargo and MSBuild invalidate stale objects. Operate on Git-tracked paths only.
$tracked = @(& git -C $repoRoot -c core.quotepath=false ls-files -- native scripts sunpack.manifest)
if ($LASTEXITCODE -ne 0) { throw "Cannot enumerate native build inputs" }
$times = @{}
$restored = 0
foreach ($relativePath in $tracked) {
    $path = Join-Path $repoRoot $relativePath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
    $file = Get-Item -LiteralPath $path
    if ($saved -and $saved.SourceKey -eq $SourceKey -and $saved.Times.ContainsKey($relativePath)) {
        $file.LastWriteTimeUtc = [datetime]::new([long]$saved.Times[$relativePath], [DateTimeKind]::Utc)
        $restored++
    }
    $times[$relativePath] = $file.LastWriteTimeUtc.Ticks
}
New-Item -ItemType Directory -Path (Split-Path -Parent $statePath) -Force | Out-Null
@{ SourceKey = $SourceKey; Times = $times } | ConvertTo-Json -Depth 3 -Compress |
    Set-Content -LiteralPath $statePath -Encoding UTF8
Write-Host "Restored $restored unchanged native input timestamps ($Arch/$BuildProfile)."
