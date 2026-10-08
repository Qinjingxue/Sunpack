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
    & $Command[0] $argsList
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
        & $VenvPython -c "import pytest, xdist, psutil, send2trash, watchdog, zstandard; import sunpack_native as n; assert n.native_available(); assert callable(n.inspect_pe_overlay_structure)" *> $null
        if ($LASTEXITCODE -ne 0) { "Runtime, test dependencies or native smoke check failed" }
    } catch {
        "Runtime, test dependencies or native smoke check failed"
    }
    Get-NativeArtifactRefreshReasons -RepoRoot $RepoRoot -Arch $Arch -NativeExtension (Get-NativeExtensionPath -PythonPath $VenvPython) -BuildProfile $BuildProfile
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

Invoke-TestStep -Label "Native extension smoke test" -Command @(
    $python,
    "-c",
    "import sunpack_native as n; assert n.native_available(); assert callable(n.inspect_pe_overlay_structure)"
)
Invoke-TestStep -Label "Parallel unit, functional, and CLI tests" -Command @(
    $python,
    "-m", "pytest", "-q",
    "-n", [string]$ParallelWorkers,
    "--dist", "worksteal",
    "tests/unit", "tests/functional", "tests/cli"
)
Invoke-TestStep -Label "CLI help smoke test" -Command @($python, "sunpack.py", "--help")
Invoke-TestStep -Label "CLI passwords smoke test" -Command @($python, "sunpack.py", "passwords", "--json")
Invoke-TestStep -Label "CLI scan smoke test" -Command @($python, "sunpack.py", "scan", (Join-Path $repoRoot "tests"), "--json")
Invoke-TestStep -Label "CLI inspect smoke test" -Command @($python, "sunpack.py", "inspect", (Join-Path $repoRoot "tests"), "--json")
Invoke-TestStep -Label "CLI config smoke test" -Command @($python, "sunpack.py", "config", "--json", "show")

Write-Host ""
Write-Host "Summary" -ForegroundColor Cyan
foreach ($result in $script:StepResults) {
    Write-Host ("  PASS  {0,-36} {1,6:N2}s" -f $result.Label, $result.DurationSeconds) -ForegroundColor Green
}

Write-Host ""
Write-Host "V2 CI checks passed." -ForegroundColor Green
