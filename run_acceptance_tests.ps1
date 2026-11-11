[CmdletBinding()]
param(
    [switch]$VerboseOutput,
    [switch]$NoWait,
    [switch]$SkipEnvironmentRefresh,
    [ValidateSet("x64", "arm64")]
    [string]$Arch = "x64",
    [ValidateSet("release", "ci")]
    [string]$BuildProfile = "ci",
    [ValidateRange(0, 32)]
    [int]$ParallelWorkers = 0,
    [int]$StepTimeoutSeconds = 900
)

$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "scripts\test_environment.ps1")

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$unelevatedRunner = Join-Path $repoRoot "scripts\run_unelevated_process.py"
$testArtifactCleanupScript = Join-Path $repoRoot "scripts\cleanup_test_artifacts.ps1"
Set-Location $repoRoot

if ($ParallelWorkers -le 0) {
    $ParallelWorkers = [math]::Max(1, [math]::Floor([Environment]::ProcessorCount / 4))
}

$script:StepResults = @()

function Test-CurrentProcessAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

$script:AcceptanceProcessIsAdministrator = Test-CurrentProcessAdministrator

function Invoke-TestArtifactCleanup {
    if (-not (Test-Path -LiteralPath $testArtifactCleanupScript -PathType Leaf)) {
        return
    }
    Write-Host "==> Cleaning stale SunPack test artifacts" -ForegroundColor Cyan
    try {
        & ([Diagnostics.Process]::GetCurrentProcess().MainModule.FileName) `
            -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $testArtifactCleanupScript
        if ($LASTEXITCODE -ne 0) {
            Write-Host ("    NOTE - stale artifact cleanup returned exit code {0}; continuing" -f $LASTEXITCODE) -ForegroundColor Yellow
        }
    } catch {
        Write-Host ("    NOTE - stale artifact cleanup could not run: " + $_.Exception.Message) -ForegroundColor Yellow
    }
}

Invoke-TestArtifactCleanup

function Initialize-ExitCodeProbe {
    if ("SunPack.ProcessExit" -as [type]) {
        return
    }
    Add-Type -Namespace SunPack -Name ProcessExit -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
public static extern bool GetExitCodeProcess(System.IntPtr hProcess, out uint lpExitCode);

public static bool TryGetExitCode(System.IntPtr hProcess, ref int exitCode) {
    uint code;
    if (!GetExitCodeProcess(hProcess, out code)) {
        return false;
    }
    exitCode = unchecked((int)code);
    return true;
}
'@
}

function Get-ChildExitCode {
    param(
        [Parameter(Mandatory = $true)][System.Diagnostics.Process]$Process,
        $ProcessHandle = $null
    )

    # Windows PowerShell 5.1 can leave Start-Process -PassThru ExitCode unset ($null), and
    # [int]$null silently becomes 0, which would report a failing pytest run as exit 0.
    if ($null -ne $Process.ExitCode) {
        return [int]$Process.ExitCode
    }
    if ($ProcessHandle -is [IntPtr] -and $ProcessHandle -ne [IntPtr]::Zero) {
        try {
            Initialize-ExitCodeProbe
            $code = 0
            # 259 is STILL_ACTIVE: the handle outlived the process without an exit code.
            if ([SunPack.ProcessExit]::TryGetExitCode($ProcessHandle, [ref]$code) -and $code -ne 259) {
                return [int]$code
            }
        } catch {
        }
    }
    return $null
}

function ConvertTo-WindowsCommandLineArgument {
    param([AllowEmptyString()][string]$Value)
    # Start-Process joins ArgumentList without quoting. Follow CommandLineToArgvW
    # escaping so spaces, embedded quotes and trailing backslashes survive.
    return '"' + (($Value -replace '(\\*)"', '$1$1\"') -replace '(\\+)$', '$1$1') + '"'
}

function Invoke-TestStep {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Label,
        [Parameter(Mandatory = $true)]
        [string[]]$Command,
        [int]$TimeoutSeconds = $StepTimeoutSeconds,
        [switch]$QuietOutput,
        [switch]$KeepElevationIfAdministrator,
        [switch]$RequireExecutedTests
    )

    Write-Host ""
    Write-Host "==> $Label" -ForegroundColor Cyan

    $argsList = @()
    if ($Command.Length -gt 1) {
        $argsList = $Command[1..($Command.Length - 1)]
    }

    $startTime = Get-Date
    $joinedCommand = $Command -join " "
    $junitReportPath = $null
    $diagnosticStep = $null
    $stdoutPath = $null
    $stderrPath = $null
    $retainOutput = $false

    if ($QuietOutput) {
        $stdoutPath = [System.IO.Path]::GetTempFileName()
        $stderrPath = [System.IO.Path]::GetTempFileName()
    }

    if ($Command.Length -ge 3 -and $Command[1] -eq "-m" -and $Command[2] -eq "pytest") {
        $junitReportPath = Join-Path ([System.IO.Path]::GetTempPath()) (
            "sunpack-acceptance-{0}-{1}.xml" -f $PID, [guid]::NewGuid().ToString("N")
        )
        $argsList += "--junitxml=$junitReportPath"
        if ($env:SUNPACK_ACCEPTANCE_DIAGNOSTICS_DIR) {
            $diagnosticStep = Join-Path $env:SUNPACK_ACCEPTANCE_DIAGNOSTICS_DIR ($Label -replace '[^a-zA-Z0-9]+', '-')
            New-Item -ItemType Directory -Force -Path $diagnosticStep | Out-Null
            $argsList += @(("--diagnostics-dir=$diagnosticStep"), "-o", "faulthandler_timeout=60")
        }
    }

    if ($VerboseOutput) {
        Write-Host ("    " + $joinedCommand) -ForegroundColor DarkGray
    }

    $runnerArguments = @()
    $runnerExecutable = $python
    if ($KeepElevationIfAdministrator -and $script:AcceptanceProcessIsAdministrator) {
        Write-Host "    Running this step with the acceptance process administrator token" -ForegroundColor DarkGray
        $runnerExecutable = $Command[0]
        $runnerArguments = $argsList
        if ($diagnosticStep) {
            $stdoutPath = Join-Path $diagnosticStep "stdout.bin"
            $stderrPath = Join-Path $diagnosticStep "stderr.bin"
            $retainOutput = $true
        }
    } else {
        # The acceptance script may itself require elevation to install the temporary
        # Watch Broker service. Keep ordinary test/smoke commands behind the existing
        # token-switching helper so pytest and its descendants use the normal token.
        $runnerArguments = @(
            $unelevatedRunner,
            "--cwd", $repoRoot,
            "--timeout-seconds", [string]$TimeoutSeconds
        )
        if ($diagnosticStep) { $runnerArguments += @("--output-directory", $diagnosticStep) }
        $runnerArguments += @("--", $Command[0])
        $runnerArguments += $argsList
    }

    $process = $null
    try {
        $startProcessArgs = @{
            FilePath = $runnerExecutable
            ArgumentList = @($runnerArguments | ForEach-Object { ConvertTo-WindowsCommandLineArgument $_ })
            NoNewWindow = $true
            PassThru = $true
        }
        if ($QuietOutput) {
            $startProcessArgs.RedirectStandardOutput = $stdoutPath
            $startProcessArgs.RedirectStandardError = $stderrPath
        }
        $process = Start-Process @startProcessArgs

        # Windows PowerShell 5.1 builds the -PassThru wrapper lazily and only binds a real
        # process handle while the child is still alive. Capture it now so the exit code stays
        # readable after the wait; without this the code below sees $null on a 5.1 host.
        $processHandle = $null
        try {
            $processHandle = $process.Handle
        } catch {
            $processHandle = $null
        }

        $timeoutMs = [Math]::Max(1, $TimeoutSeconds) * 1000
        if (-not $process.WaitForExit($timeoutMs)) {
            $terminated = $false
            try {
                # taskkill follows detached descendants that Process.Kill($true) can miss.
                & taskkill.exe /PID $process.Id /T /F *> $null
                $terminated = ($LASTEXITCODE -eq 0)
            } catch {
            }
            if (-not $terminated -and -not $process.HasExited) {
                try {
                    $process.Kill($true)
                } catch {
                    $process.Kill()
                }
            }
            $process.WaitForExit()
            $duration = ((Get-Date) - $startTime).TotalSeconds
            $script:StepResults += [pscustomobject]@{
                Label = $Label
                ExitCode = -1
                DurationSeconds = [math]::Round($duration, 2)
            }
            Write-Host ("    FAIL ({0:N2}s) - timed out after {1} seconds" -f $duration, $TimeoutSeconds) -ForegroundColor Red
            Write-Host ("    Command: " + $joinedCommand) -ForegroundColor DarkGray
            return
        }

        $exitCode = Get-ChildExitCode -Process $process -ProcessHandle $processHandle
        if ($junitReportPath) {
            if (-not (Test-Path -LiteralPath $junitReportPath)) {
                Write-Host "    FAIL - pytest did not produce its JUnit report" -ForegroundColor Red
                $exitCode = if ($null -eq $exitCode -or $exitCode -eq 0) { -2 } else { $exitCode }
            } else {
                try {
                    # pytest writes UTF-8 and skip messages may be non-ASCII. Get-Content without
                    # an explicit -Encoding decodes such a report as ANSI on Windows PowerShell,
                    # which corrupts the XML until it is no longer parseable.
                    [xml]$junitReport = [System.IO.File]::ReadAllText(
                        $junitReportPath, [System.Text.Encoding]::UTF8
                    )
                    $reportedFailures = @($junitReport.SelectNodes("//testcase/failure | //testcase/error")).Count
                    $reportedTests = @($junitReport.SelectNodes("//testcase")).Count
                    $reportedSkips = @($junitReport.SelectNodes("//testcase/skipped")).Count
                    if ($RequireExecutedTests -and ($reportedTests -eq 0 -or $reportedSkips -gt 0)) {
                        Write-Host "    FAIL - this required step must execute every test (tests=$reportedTests, skipped=$reportedSkips)" -ForegroundColor Red
                        $exitCode = 1
                    }
                    if ($reportedFailures -gt 0) {
                        Write-Host "    FAIL - pytest JUnit report contains $reportedFailures failure(s) or error(s)" -ForegroundColor Red
                        $exitCode = if ($null -eq $exitCode -or $exitCode -eq 0) { 1 } else { $exitCode }
                    } elseif ($null -eq $exitCode) {
                        # No exit code from the host, so the report is the only verdict available.
                        $reportedTests = @($junitReport.SelectNodes("//testcase")).Count
                        if ($reportedTests -eq 0) {
                            Write-Host "    FAIL - pytest JUnit report contains no test case" -ForegroundColor Red
                            $exitCode = -2
                        } else {
                            Write-Host "    NOTE - this PowerShell host did not expose the pytest exit code; the JUnit report is used" -ForegroundColor DarkGray
                            $exitCode = 0
                        }
                    }
                } catch {
                    Write-Host ("    FAIL - could not read pytest JUnit report: " + $_.Exception.Message) -ForegroundColor Red
                    $exitCode = if ($null -eq $exitCode -or $exitCode -eq 0) { -2 } else { $exitCode }
                }
            }
        } elseif ($null -eq $exitCode) {
            Write-Host "    FAIL - the process exit code is unavailable on this PowerShell host" -ForegroundColor Red
            $exitCode = -2
        }
        $duration = ((Get-Date) - $startTime).TotalSeconds
        $script:StepResults += [pscustomobject]@{
            Label = $Label
            ExitCode = $exitCode
            DurationSeconds = [math]::Round($duration, 2)
        }

        if ($exitCode -eq 0) {
            Write-Host ("    PASS ({0:N2}s)" -f $duration) -ForegroundColor Green
            return
        }

        Write-Host ("    FAIL ({0:N2}s)" -f $duration) -ForegroundColor Red
        Write-Host ("    Command: " + $joinedCommand) -ForegroundColor DarkGray
        return
    } catch {
        $duration = ((Get-Date) - $startTime).TotalSeconds
        $script:StepResults += [pscustomobject]@{
            Label = $Label
            ExitCode = -1
            DurationSeconds = [math]::Round($duration, 2)
        }
        Write-Host ("    FAIL ({0:N2}s) - could not start command" -f $duration) -ForegroundColor Red
        Write-Host ("    Command: " + $joinedCommand) -ForegroundColor DarkGray
        Write-Host ("    Error: " + $_.Exception.Message) -ForegroundColor DarkRed
        return
    } finally {
        if ($process) {
            $process.Dispose()
        }
        if ($junitReportPath -and (Test-Path -LiteralPath $junitReportPath)) {
            Remove-Item -LiteralPath $junitReportPath -Force
        }
        foreach ($outputPath in @($stdoutPath, $stderrPath)) {
            if ($outputPath -and (Test-Path -LiteralPath $outputPath)) {
                if ($retainOutput) {
                    Get-Content -LiteralPath $outputPath -Encoding UTF8 | ForEach-Object { Write-Host $_ }
                } else {
                    Remove-Item -LiteralPath $outputPath -Force
                }
            }
        }
    }
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

function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [string[]]$Arguments = @()
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        $joined = ($Arguments | ForEach-Object { $_ }) -join " "
        throw "Command failed with exit code ${LASTEXITCODE}: $FilePath $joined"
    }
}
function Test-PythonImports {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PythonPath,
        [Parameter(Mandatory = $true)]
        [string[]]$Modules
    )

    $importList = ($Modules | ForEach-Object { "'$_'" }) -join ", "
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        # Python warnings are written to stderr.  Do not let PowerShell promote
        # them to terminating errors; the interpreter exit code is authoritative.
        $ErrorActionPreference = "Continue"
        & $PythonPath -c "import importlib; modules = [$importList]; [importlib.import_module(name) for name in modules]" *> $null
        return ($LASTEXITCODE -eq 0)
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
}

function Get-EnvironmentRefreshReasons {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot,
        [Parameter(Mandatory = $true)]
        [string]$VenvPython
    )

    $reasons = New-Object System.Collections.Generic.List[string]
    if (-not (Test-Path -LiteralPath $VenvPython)) {
        $reasons.Add(".venv is missing")
        return $reasons
    }

    $requiredPythonModules = @(
        "pytest",
        "xdist",
        "psutil"
    )
    if (-not (Test-PythonImports -PythonPath $VenvPython -Modules $requiredPythonModules)) {
        $reasons.Add(".venv is missing or cannot import test modules")
    }

    foreach ($reason in @(Get-NativeArtifactRefreshReasons -RepoRoot $RepoRoot -Arch $Arch -BuildProfile $BuildProfile)) {
        $reasons.Add($reason)
    }

    foreach ($reason in @(Get-ArchiveFixtureToolRefreshReasons -RepoRoot $RepoRoot -Arch $Arch)) {
        $reasons.Add($reason)
    }
    return $reasons
}

function Ensure-AcceptanceEnvironment {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot,
        [Parameter(Mandatory = $true)]
        [string]$VenvPython
    )

    if ($SkipEnvironmentRefresh) {
        Write-Host "Skipping acceptance environment refresh by request" -ForegroundColor Yellow
        return
    }

    Write-Host ""
    Write-Host "==> Acceptance environment preflight" -ForegroundColor Cyan
    if ($env:OS -ne "Windows_NT") {
        throw "This acceptance script only supports Windows."
    }

    $reasons = @(Get-EnvironmentRefreshReasons -RepoRoot $RepoRoot -VenvPython $VenvPython)
    if ($reasons.Count -eq 0) {
        Write-Host "    Environment is current" -ForegroundColor Green
        return
    }

    Write-Host "    Environment refresh required:" -ForegroundColor Yellow
    foreach ($reason in $reasons) {
        Write-Host "      - $reason" -ForegroundColor Yellow
    }
    Invoke-Native -FilePath "powershell" -Arguments @(
        "-ExecutionPolicy", "Bypass",
        "-File", (Join-Path $RepoRoot "scripts\setup_windows_dev.ps1"),
        "-Arch", $Arch, "-BuildProfile", $BuildProfile
    )

    # Verify persistence immediately; a successful setup subprocess is not
    # sufficient evidence that every artifact was refreshed.
    $remainingReasons = @(Get-EnvironmentRefreshReasons -RepoRoot $RepoRoot -VenvPython $VenvPython)
    if ($remainingReasons.Count -gt 0) {
        throw ("Environment refresh completed but the environment is still stale:`n  - " + ($remainingReasons -join "`n  - "))
    }
}

function Wait-BeforeExit {
    param([string]$Message = "Press Enter to exit...")
    if ($NoWait) {
        return
    }
    Write-Host ""
    Write-Host $Message -ForegroundColor DarkGray
    $null = Read-Host
}

function Invoke-TestWatchServiceAction {
    param(
        [Parameter(Mandatory = $true)][string]$PowerShellHost,
        [Parameter(Mandatory = $true)][string]$ManagerScript,
        [Parameter(Mandatory = $true)][ValidateSet("Install", "Uninstall")][string]$Action,
        [Parameter(Mandatory = $true)][string]$ServiceName,
        [Parameter(Mandatory = $true)][string]$PipeName,
        [string]$BrokerPath = ""
    )

    $arguments = @(
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $ManagerScript,
        "-Action", $Action, "-ServiceName", $ServiceName, "-PipeName", $PipeName
    )
    if ($BrokerPath) {
        $arguments += @("-BrokerPath", $BrokerPath)
    }
    Invoke-Native -FilePath $PowerShellHost -Arguments $arguments
}

trap {
    Write-Host ("ERROR: " + $_.Exception.Message) -ForegroundColor Red
    Wait-BeforeExit
    throw
}

$venvPython = Join-Path $repoRoot ".venv\Scripts\python.exe"
Ensure-AcceptanceEnvironment -RepoRoot $repoRoot -VenvPython $venvPython
if (-not (Test-Path -LiteralPath $venvPython -PathType Leaf)) {
    $bootstrapPython = Get-UvBootstrapPythonCommand
    Write-Host "==> Preparing .venv with uv" -ForegroundColor Cyan
    Invoke-Native -FilePath "uv" -Arguments @(
        "sync", "--locked", "--extra", "dev", "--python", $bootstrapPython
    )
}
if (-not (Test-Path -LiteralPath $venvPython -PathType Leaf)) {
    throw "uv sync completed without creating the project virtual environment: $venvPython"
}
$python = $venvPython
$env:PYTHONPATH = $repoRoot

$brokerPath = Get-WatchBrokerBuildPath -RepoRoot $repoRoot -Arch $Arch -BuildProfile $BuildProfile
$brokerPath = [IO.Path]::GetFullPath($brokerPath)
if (-not (Test-Path -LiteralPath $brokerPath -PathType Leaf)) {
    throw "Watch Broker executable not found: $brokerPath"
}
$watchServiceManager = Join-Path $repoRoot "scripts\manage_test_watch_service.ps1"
$powerShellHost = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
$watchServiceRunId = [guid]::NewGuid().ToString("N")
$watchServiceName = "SunPackWatchBrokerTest_$watchServiceRunId"
$watchPipeName = "\\.\pipe\SunPack.WatchBroker.Test.$watchServiceRunId"
$watchEnvironmentNames = @(
    "SUNPACK_WATCH_BROKER_SERVICE_NAME",
    "SUNPACK_WATCH_BROKER_PIPE_NAME",
    "SUNPACK_WATCH_BROKER_BINARY_PATH",
    "SUNPACK_TEST_ARCH",
    "SUNPACK_TEST_BUILD_PROFILE"
)
$watchEnvironmentBackup = @{}
foreach ($name in $watchEnvironmentNames) {
    $watchEnvironmentBackup[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
}
$watchServiceInstalled = $false
$watchServiceCleanupFailed = $false

try {
    $env:SUNPACK_TEST_ARCH = $Arch.ToLowerInvariant()
    $env:SUNPACK_TEST_BUILD_PROFILE = $BuildProfile.ToLowerInvariant()
    $target = if ($Arch -eq "arm64") { "aarch64-pc-windows-msvc" } else { "x86_64-pc-windows-msvc" }
    Write-Host "Native test build: $Arch/$BuildProfile"
    $env:SUNPACK_WATCH_BROKER_SERVICE_NAME = $watchServiceName
    $env:SUNPACK_WATCH_BROKER_PIPE_NAME = $watchPipeName
    $env:SUNPACK_WATCH_BROKER_BINARY_PATH = $brokerPath

    Write-Host ""
    Write-Host "==> Installing temporary Watch Broker service" -ForegroundColor Cyan
    Invoke-TestWatchServiceAction `
        -PowerShellHost $powerShellHost `
        -ManagerScript $watchServiceManager `
        -Action Install `
        -ServiceName $watchServiceName `
        -PipeName $watchPipeName `
        -BrokerPath $brokerPath
    $watchServiceInstalled = $true

    Invoke-TestStep -Label "Rust correctness tests" -Command @(
        "cargo", "test", "--locked", "--manifest-path", (Join-Path $repoRoot "native\Cargo.toml"),
        "--workspace", "--profile", $BuildProfile, "--target", $target,
        "--target-dir", (Join-Path $repoRoot (".cache\rust-target\" + $Arch))
    )
    Invoke-TestStep -Label "CLI and Watch acceptance tests" -Command @(
        $python, "-m", "pytest", "-q", "-rs", "-n", [string]$ParallelWorkers,
        "--dist", "worksteal", "tests/blackbox", "tests/unit", "tests/integration", "tests/real",
        "--ignore=tests/integration/test_disk_full_pause_resume.py"
    )
    # DiskPart must retain elevation, unlike ordinary launcher/GUI tests.
    # Missing elevation or any prerequisite skip is an incomplete acceptance run.
    Invoke-TestStep -Label "Real disk-full recovery tests" -KeepElevationIfAdministrator -RequireExecutedTests -Command @(
        $python, "-m", "pytest", "-q", "-rs", "-n", "0",
        "tests/integration/test_disk_full_pause_resume.py"
    )
} finally {
    if ($watchServiceInstalled) {
        Write-Host ""
        Write-Host "==> Uninstalling temporary Watch Broker service" -ForegroundColor Cyan
        try {
            Invoke-TestWatchServiceAction `
                -PowerShellHost $powerShellHost `
                -ManagerScript $watchServiceManager `
                -Action Uninstall `
                -ServiceName $watchServiceName `
                -PipeName $watchPipeName
        } catch {
            $watchServiceCleanupFailed = $true
            Write-Host ("    FAIL - could not uninstall temporary Watch Broker service: " + $_.Exception.Message) -ForegroundColor Red
        }
    }
    foreach ($name in $watchEnvironmentNames) {
        $previousValue = $watchEnvironmentBackup[$name]
        if ($null -eq $previousValue) {
            Remove-Item -LiteralPath ("Env:" + $name) -ErrorAction SilentlyContinue
        } else {
            Set-Item -LiteralPath ("Env:" + $name) -Value $previousValue
        }
    }
}

Write-Host ""
Write-Host "Summary" -ForegroundColor Cyan
foreach ($result in $script:StepResults) {
    if ($result.ExitCode -eq 0) {
        Write-Host ("  PASS  {0,-40} {1,6:N2}s" -f $result.Label, $result.DurationSeconds) -ForegroundColor Green
    } else {
        Write-Host ("  FAIL  {0,-40} {1,6:N2}s (exit {2})" -f $result.Label, $result.DurationSeconds, $result.ExitCode) -ForegroundColor Red
    }
}

Write-Host ""
$failedResults = @($script:StepResults | Where-Object { $_.ExitCode -ne 0 })
if ($watchServiceCleanupFailed) {
    $failedResults += [pscustomobject]@{ Label = "Temporary Watch Broker service cleanup"; ExitCode = -1; DurationSeconds = 0 }
}
if ($failedResults.Count -gt 0) {
    Write-Host ("{0} acceptance test step(s) failed; all scheduled steps have completed" -f $failedResults.Count) -ForegroundColor Red
} else {
    Write-Host "All acceptance tests passed" -ForegroundColor Green
}
if (-not $NoWait) {
    if ($failedResults.Count -gt 0) {
        Wait-BeforeExit ("{0} acceptance test step(s) failed. Press Enter to exit..." -f $failedResults.Count)
    } else {
        Wait-BeforeExit
    }
}
if ($failedResults.Count -gt 0) {
    exit 1
}
