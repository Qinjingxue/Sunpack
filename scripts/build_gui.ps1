[CmdletBinding()]
param(
    [ValidateSet('x64', 'arm64')][string]$Arch = 'x64',
    [string]$CMakeCommand = 'cmake',
    [string]$BuildDir,
    [int]$Jobs = [Environment]::ProcessorCount,
    [switch]$SkipTests,
    [switch]$ApplicationOnly,
    [switch]$SkipConfigure,
    [switch]$TestsOnly
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $BuildDir) { $BuildDir = Join-Path $repoRoot ".cache\gui-$Arch" }
$platform = if ($Arch -eq 'arm64') { 'ARM64' } else { 'x64' }
if ($TestsOnly -and ($ApplicationOnly -or $SkipTests -or $SkipConfigure)) {
    throw '-TestsOnly cannot be combined with build options'
}
if ($ApplicationOnly -and -not $SkipTests) {
    throw '-ApplicationOnly requires -SkipTests'
}
if (-not $TestsOnly) {
    if ($SkipConfigure) {
        if (-not (Test-Path -LiteralPath (Join-Path $BuildDir 'CMakeCache.txt'))) {
            throw 'GUI build directory is not configured'
        }
    } else {
        & $CMakeCommand -S (Join-Path $repoRoot 'gui') -B $BuildDir -A $platform
        if ($LASTEXITCODE -ne 0) { throw 'GUI CMake configuration failed' }
    }
    $target = if ($ApplicationOnly) { 'SunPackGUI' } else { 'sunpack_gui_checks' }
    & $CMakeCommand --build $BuildDir --config Release --target $target --parallel $Jobs
    if ($LASTEXITCODE -ne 0) { throw 'GUI compilation failed' }
} else {
    foreach ($name in @('SunPackGUI.exe', 'sunpack_gui_tests.exe', 'sunpack_gui_ui_tests.exe')) {
        if (-not (Test-Path -LiteralPath (Join-Path $BuildDir "Release\$name"))) {
            throw "GUI test-only mode requires a previously built $name"
        }
    }
}
$hostArch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
if (-not $SkipTests -and $hostArch -eq $Arch) {
    $ctest = Join-Path (Split-Path -Parent (Get-Command $CMakeCommand).Source) 'ctest.exe'
    & $ctest --test-dir $BuildDir -C Release --output-on-failure
    if ($LASTEXITCODE -ne 0) { throw 'GUI tests failed' }
    $python = Join-Path $repoRoot '.venv\Scripts\python.exe'
    if (Test-Path -LiteralPath $python) {
        $previousTestBinary = $env:SUNPACK_GUI_TEST_BINARY
        $env:SUNPACK_GUI_TEST_BINARY = Join-Path $BuildDir 'Release\sunpack_gui_tests.exe'
        try {
            & $python -m pytest (Join-Path $repoRoot 'tests\gui\test_integration.py') -q
            if ($LASTEXITCODE -ne 0) { throw 'GUI cross-language contracts failed' }
        } finally {
            if ($null -ne $previousTestBinary) { $env:SUNPACK_GUI_TEST_BINARY = $previousTestBinary }
            else { Remove-Item Env:SUNPACK_GUI_TEST_BINARY }
        }
    }
}
$binary = Get-Item -LiteralPath (Join-Path $BuildDir 'Release\SunPackGUI.exe')
Write-Host ('SunPackGUI ({0}): {1:N0} bytes ({2:N2} MiB)' -f $Arch, $binary.Length, ($binary.Length / 1MB))
