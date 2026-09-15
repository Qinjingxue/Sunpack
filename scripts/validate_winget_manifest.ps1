[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ManifestRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$resolvedRoot = (Resolve-Path -LiteralPath $ManifestRoot).Path
if (-not (Test-Path -LiteralPath $resolvedRoot -PathType Container)) {
    throw "WinGet manifest root must be a directory: $ManifestRoot"
}
$packageIdentifier = "Qinjingxue.SunPack"
$requiredFiles = @(
    "$packageIdentifier.yaml",
    "$packageIdentifier.installer.yaml",
    "$packageIdentifier.locale.en-US.yaml"
)

foreach ($fileName in $requiredFiles) {
    $path = Join-Path $resolvedRoot $fileName
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "WinGet manifest set is missing ${fileName}: $resolvedRoot"
    }
}

$winget = Get-Command winget -ErrorAction Stop
& $winget.Source validate --manifest $resolvedRoot
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Write-Host "WinGet manifest validation passed: $resolvedRoot" -ForegroundColor Green
