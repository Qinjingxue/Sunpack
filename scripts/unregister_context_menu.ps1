Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$keys = @(
    "HKLM:\Software\Classes\Directory\shell\SunPack",
    "HKLM:\Software\Classes\Directory\Background\shell\SunPack",
    "HKLM:\Software\Classes\*\shell\SunPack",
    "HKLM:\Software\Classes\SunPack.FolderContextMenu",
    "HKLM:\Software\Classes\SunPack.BackgroundContextMenu",
    "HKLM:\Software\Classes\SunPack.FileContextMenu"
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
