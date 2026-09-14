Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$keys = @(
    "HKCU:\Software\Classes\Directory\shell\SunPack",
    "HKCU:\Software\Classes\Directory\Background\shell\SunPack",
    "HKCU:\Software\Classes\*\shell\SunPack",
    "HKCU:\Software\Classes\SunPack.FolderContextMenu",
    "HKCU:\Software\Classes\SunPack.BackgroundContextMenu",
    "HKCU:\Software\Classes\SunPack.FileContextMenu"
)

foreach ($key in $keys) {
    if (Test-Path -LiteralPath $key) {
        Remove-Item -LiteralPath $key -Recurse -Force
        Write-Host "Removed:" $key
    } else {
        Write-Host "Not found:" $key
    }
}

Write-Host "Context menu unregistration completed." -ForegroundColor Green
