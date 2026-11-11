[CmdletBinding()]
param(
    [ValidateSet("x64", "arm64")]
    [string]$Arch = "x64",
    [ValidateSet("release", "ci")]
    [string]$BuildProfile = "ci",
    [ValidateRange(0, 32)]
    [int]$ParallelWorkers = 0
)

$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "test_environment.ps1")

$repoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $repoRoot

if ($ParallelWorkers -le 0) {
    $ParallelWorkers = [math]::Max(1, [math]::Floor([Environment]::ProcessorCount / 4))
}

$script:StepResults = @()

function Invoke-TestStep {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Label,
        [Parameter(Mandatory = $true)]
        [string[]]$Command
    )

    Write-Host ""
    Write-Host "==> $Label" -ForegroundColor Cyan

    $argsList = @()
    if ($Command.Length -gt 1) {
        $argsList = $Command[1..($Command.Length - 1)]
    }

    $startTime = Get-Date
    & $Command[0] @argsList
    $exitCode = $LASTEXITCODE
    $duration = ((Get-Date) - $startTime).TotalSeconds

    $script:StepResults += [pscustomobject]@{
        Label = $Label
        ExitCode = $exitCode
        DurationSeconds = [math]::Round($duration, 2)
    }

    if ($exitCode -ne 0) {
        throw "Test step failed: $Label (exit code $exitCode)"
    }

    Write-Host ("    PASS ({0:N2}s)" -f $duration) -ForegroundColor Green
}

function Get-CiEnvironmentRefreshReasons {
    param([string]$RepoRoot, [string]$VenvPython, [string]$Arch)
    if (-not (Test-Path -LiteralPath $VenvPython -PathType Leaf)) {
        ".venv is missing"
        return
    }
    try {
        & $VenvPython -c "import pytest, xdist, psutil" *> $null
        if ($LASTEXITCODE -ne 0) { "Python test dependencies could not be imported" }
    } catch {
        "Python test dependencies could not be imported"
    }
    Get-NativeArtifactRefreshReasons -RepoRoot $RepoRoot -Arch $Arch -BuildProfile $BuildProfile
    Get-ArchiveFixtureToolRefreshReasons -RepoRoot $RepoRoot -Arch $Arch
}

$venvPython = Join-Path $repoRoot ".venv\Scripts\python.exe"
$env:PYTHONPATH = $repoRoot
$refreshReasons = @(Get-CiEnvironmentRefreshReasons -RepoRoot $repoRoot -VenvPython $venvPython -Arch $Arch)
if ($refreshReasons.Count -gt 0) {
    Write-Host ("Environment refresh required:`n  - " + ($refreshReasons -join "`n  - ")) -ForegroundColor Yellow
    Invoke-TestStep -Label "Refresh development environment" -Command @(
        [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName,
        "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
        "-File", (Join-Path $PSScriptRoot "setup_windows_dev.ps1"),
        "-Arch", $Arch, "-BuildProfile", $BuildProfile, "-SkipAcceptanceTestTools"
    )
    $remainingReasons = @(Get-CiEnvironmentRefreshReasons -RepoRoot $repoRoot -VenvPython $venvPython -Arch $Arch)
    if ($remainingReasons.Count -gt 0) {
        throw ("Environment refresh completed but the environment is still stale:`n  - " + ($remainingReasons -join "`n  - "))
    }
}
if (-not (Test-Path -LiteralPath $venvPython -PathType Leaf)) {
    throw "Development setup completed without creating the project virtual environment: $venvPython"
}
$python = $venvPython
$env:PYTHONPATH = $repoRoot

$testEnvironmentNames = @("SUNPACK_TEST_ARCH", "SUNPACK_TEST_BUILD_PROFILE")
$testEnvironmentBackup = @{}
foreach ($name in $testEnvironmentNames) {
    $testEnvironmentBackup[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
}
try {
    $env:SUNPACK_TEST_ARCH = $Arch.ToLowerInvariant()
    $env:SUNPACK_TEST_BUILD_PROFILE = $BuildProfile.ToLowerInvariant()
    $target = if ($Arch -eq "arm64") { "aarch64-pc-windows-msvc" } else { "x86_64-pc-windows-msvc" }
    Write-Host "Native test build: $Arch/$BuildProfile"
    Invoke-TestStep -Label "Rust correctness tests" -Command @(
        "cargo", "test", "--locked", "--manifest-path", (Join-Path $repoRoot "native\Cargo.toml"),
        "--workspace", "--profile", $BuildProfile, "--target", $target,
        "--target-dir", (Join-Path $repoRoot (".cache\rust-target\" + $Arch))
    )
    Invoke-TestStep -Label "CLI and script boundary tests" -Command @(
        $python, "-m", "pytest", "-q", "-n", [string]$ParallelWorkers,
        "--dist", "worksteal", "tests/blackbox", "tests/unit", "-m", "not requires_watch_broker"
    )
} finally {
    foreach ($name in $testEnvironmentNames) {
        [Environment]::SetEnvironmentVariable($name, $testEnvironmentBackup[$name], "Process")
    }
}

Write-Host ""
Write-Host "Summary" -ForegroundColor Cyan
foreach ($result in $script:StepResults) {
    Write-Host ("  PASS  {0,-36} {1,6:N2}s" -f $result.Label, $result.DurationSeconds) -ForegroundColor Green
}

Write-Host ""
Write-Host "V2 CI checks passed" -ForegroundColor Green
