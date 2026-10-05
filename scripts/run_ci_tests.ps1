[CmdletBinding()]
param(
    [ValidateRange(0, 32)]
    [int]$ParallelWorkers = 0
)

$ErrorActionPreference = "Stop"

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

function Get-UvBootstrapPythonCommand {
    foreach ($candidate in @("python", "py")) {
        try {
            $resolvedPython = & $candidate -c "import sys; print(sys.executable)" 2>$null
            if ($LASTEXITCODE -eq 0) {
                $resolvedPython = @($resolvedPython | Where-Object { $_ }) | Select-Object -Last 1
                if ($resolvedPython) {
                    return ([string]$resolvedPython).Trim()
                }
            }
        } catch {
        }
    }
    throw "A base Python interpreter is required by uv to create .venv, but none was found in PATH."
}

$venvPython = Join-Path $repoRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $venvPython -PathType Leaf)) {
    $bootstrapPython = Get-UvBootstrapPythonCommand
    Invoke-TestStep -Label "Prepare .venv with uv" -Command @(
        "uv", "sync", "--locked", "--extra", "dev", "--python", $bootstrapPython
    )
}
if (-not (Test-Path -LiteralPath $venvPython -PathType Leaf)) {
    throw "uv sync completed without creating the project virtual environment: $venvPython"
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
