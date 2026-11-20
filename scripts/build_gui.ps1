[CmdletBinding()]
param(
    [ValidateSet('x64', 'arm64')][string]$Arch = 'x64',
    [string]$CMakeCommand,
    [string]$BuildDir,
    [int]$Jobs = [Environment]::ProcessorCount,
    [switch]$SkipTests,
    [switch]$ApplicationOnly,
    [switch]$SkipConfigure,
    [switch]$TestsOnly,
    [switch]$SkipPythonTests
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'build_native.ps1')
if (-not $CMakeCommand) {
    $CMakeCommand = Get-CMakeCommand -VenvScripts (Join-Path $repoRoot '.venv\Scripts')
}
if (-not $BuildDir) { $BuildDir = Join-Path $repoRoot ".cache\gui-$Arch" }
$platform = if ($Arch -eq 'arm64') { 'ARM64' } else { 'x64' }
if ($TestsOnly -and ($ApplicationOnly -or $SkipTests -or $SkipConfigure)) {
    throw '-TestsOnly cannot be combined with build options'
}
if ($ApplicationOnly -and -not $SkipTests) {
    throw '-ApplicationOnly requires -SkipTests'
}
if (-not $TestsOnly) {
    # CMake forwards UTF-8 MSBuild output even on consoles using a legacy code page.
    $previousOutputEncoding = [Console]::OutputEncoding
    try {
        [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
        if ($SkipConfigure) {
            if (-not (Test-Path -LiteralPath (Join-Path $BuildDir 'CMakeCache.txt'))) {
                throw 'GUI build directory is not configured'
            }
        } else {
            Invoke-Native -FilePath $CMakeCommand -Arguments @('-S', (Join-Path $repoRoot 'gui'), '-B', $BuildDir, '-A', $platform)
        }
        $target = if ($ApplicationOnly) { 'SunPackGUI' } else { 'sunpack_gui_checks' }
        Invoke-Native -FilePath $CMakeCommand -Arguments @('--build', $BuildDir, '--config', 'Release', '--target', $target, '--parallel', $Jobs)
    } finally {
        [Console]::OutputEncoding = $previousOutputEncoding
    }
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
    Invoke-Native -FilePath $ctest -Arguments @('--test-dir', $BuildDir, '-C', 'Release', '--output-on-failure')
    $python = Join-Path $repoRoot '.venv\Scripts\python.exe'
    if (-not $SkipPythonTests -and (Test-Path -LiteralPath $python)) {
        $previousTestBinary = $env:SUNPACK_GUI_TEST_BINARY
        $env:SUNPACK_GUI_TEST_BINARY = Join-Path $BuildDir 'Release\sunpack_gui_tests.exe'
        try {
            Invoke-Native -FilePath $python -Arguments @('-m', 'pytest', (Join-Path $repoRoot 'tests\gui\test_integration.py'), '-q')
        } finally {
            if ($null -ne $previousTestBinary) { $env:SUNPACK_GUI_TEST_BINARY = $previousTestBinary }
            else { Remove-Item Env:SUNPACK_GUI_TEST_BINARY }
        }
    }
}
$binary = Get-Item -LiteralPath (Join-Path $BuildDir 'Release\SunPackGUI.exe')
Write-Host ('SunPackGUI ({0}): {1:N0} bytes ({2:N2} MiB)' -f $Arch, $binary.Length, ($binary.Length / 1MB))
