[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$magick = (Get-Command magick -ErrorAction Stop).Source
$source = Join-Path $repoRoot 'sunpack.png'
$destination = Join-Path $repoRoot 'sunpack.ico'
# Render each size from the master, never from another ICO frame. Small frames
# need stronger edges to keep the box opening visible; retain full RGBA, including
# at 16px, where indexed colour previously lost much of the silhouette.
$sizes = @(16, 20, 24, 28, 32, 40, 48, 56, 64, 72, 80, 96, 128, 256)
$arguments = @()
foreach ($size in $sizes) {
    $arguments += @('(', $source, '-channel', 'A', '-level', '18%,85%', '+channel',
        '-filter', 'Lanczos', '-resize', "${size}x${size}",
        '-gravity', 'center', '-background', 'none', '-extent', "${size}x${size}")
    if ($size -le 48) {
        $arguments += @('-unsharp', '0x0.45+0.6+0.02',
            '-channel', 'A', '-level', '8%,92%', '+channel')
    }
    $arguments += @('-depth', '8', '-type', 'TrueColorAlpha', ')')
}
$arguments += $destination
& $magick @arguments
if ($LASTEXITCODE -ne 0) { throw 'SunPack icon generation failed' }
