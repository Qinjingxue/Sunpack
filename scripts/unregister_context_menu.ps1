param([switch]$Machine)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Setup uses -Machine to clear registrations from previous versions.
$classesKey = if ($Machine) { "HKLM:\Software\Classes" } else { "HKCU:\Software\Classes" }
$keys = @(
    "$classesKey\Directory\shell\SunPack",
    "$classesKey\Directory\Background\shell\SunPack",
    "$classesKey\*\shell\SunPack",
    "$classesKey\SunPack.FolderContextMenu",
    "$classesKey\SunPack.BackgroundContextMenu",
    "$classesKey\SunPack.FileContextMenu"
)

foreach ($key in $keys) {
    if (Test-Path -LiteralPath $key) {
        Remove-Item -LiteralPath $key -Recurse -Force
        Write-Host "Removed:" $key
    } else {
        Write-Host "Not found:" $key
    }
}

Write-Host "Context menu unregistration completed" -ForegroundColor Green
