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
. (Join-Path $PSScriptRoot "scripts\test_elevation.ps1")

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
        [AllowEmptyString()]
        [string[]]$Command,
        [int]$TimeoutSeconds = $StepTimeoutSeconds,
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

    if ($Command.Length -ge 3 -and $Command[1] -eq "-m" -and $Command[2] -eq "pytest") {
        $junitReportPath = Join-Path ([System.IO.Path]::GetTempPath()) (
            "sunpack-acceptance-{0}-{1}.xml" -f $PID, [guid]::NewGuid().ToString("N")
        )
        $argsList = @("-u") + $argsList
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

    # The acceptance script needs elevation for the temporary Watch Broker.
    # Ordinary tests and their descendants still run with the interactive token.
    $captureOption = "--output-directory"
    if ($KeepElevationIfAdministrator -and $script:AcceptanceProcessIsAdministrator) {
        Write-Host "    Running this step with the acceptance process administrator token" -ForegroundColor DarkGray
        $captureOption = "--capture-directory"
    }

    $process = $null
    $outputDirectory = $diagnosticStep
    $outputPaths = @()
    try {
        if (-not $outputDirectory) {
            $outputDirectory = Join-Path ([IO.Path]::GetTempPath()) ("sunpack-test-" + [guid]::NewGuid().ToString("N"))
            $null = [IO.Directory]::CreateDirectory($outputDirectory)
        }
        $outputPaths = @("stdout.bin", "stderr.bin", "runner-stderr.bin" | ForEach-Object {
            Join-Path $outputDirectory $_
        })
        foreach ($outputPath in $outputPaths) {
            [IO.File]::WriteAllBytes($outputPath, [byte[]]@())
        }
        $runnerArguments = @(
            $unelevatedRunner, "--cwd", $repoRoot, "--timeout-seconds", [string]$TimeoutSeconds,
            $captureOption, $outputDirectory, "--", $Command[0]
        ) + $argsList
        $startProcessArgs = @{
            FilePath = $python
            ArgumentList = @($runnerArguments | ForEach-Object { ConvertTo-WindowsCommandLineArgument $_ })
            NoNewWindow = $true
            PassThru = $true
            RedirectStandardError = $outputPaths[2]
        }
        Initialize-TestProcessOutput
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

        $timeoutMs = [Math]::Min([int]::MaxValue, [Math]::Max(1, $TimeoutSeconds) * 1000)
        $finished = Receive-TestProcessOutput -Process $process -Paths $outputPaths -TimeoutMilliseconds $timeoutMs -OnTimeout {
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
        }
        if (-not $finished) {
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
        if (-not $diagnosticStep -and $outputDirectory -and [IO.Directory]::Exists($outputDirectory)) {
            foreach ($outputPath in $outputPaths) {
                [IO.File]::Delete($outputPath)
            }
            [IO.Directory]::Delete($outputDirectory)
        }
    }
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
    $generatorErrors = & $VenvPython -m tests.helpers.tool_config --arch $Arch.ToLowerInvariant() 2>&1
    if ($LASTEXITCODE -ne 0) {
        $reasons.Add(($generatorErrors | Out-String).Trim())
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
    $originalOutputEncoding = [Console]::OutputEncoding
    try {
        # Match the UTF-8 native build output forwarded by the setup subprocess.
        [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
        Invoke-Native -FilePath "powershell" -Arguments @(
            "-ExecutionPolicy", "Bypass",
            "-File", (Join-Path $RepoRoot "scripts\setup_windows_dev.ps1"),
            "-Arch", $Arch, "-BuildProfile", $BuildProfile
        )
    } finally {
        [Console]::OutputEncoding = $originalOutputEncoding
    }

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

$elevatedArguments = @{} + $PSBoundParameters
$elevatedArguments.NoWait = [System.Management.Automation.SwitchParameter]::Present
$elevatedExitCode = Invoke-TestScriptElevated -ScriptPath $PSCommandPath -BoundParameters $elevatedArguments -ShowOutput
if ($null -ne $elevatedExitCode) {
    Wait-BeforeExit
    exit $elevatedExitCode
}

Invoke-TestArtifactCleanup

trap {
    Write-Host ("ERROR: " + $_.Exception.Message) -ForegroundColor Red
    Wait-BeforeExit
    throw
}

$venvPython = Join-Path $repoRoot ".venv\Scripts\python.exe"
Ensure-AcceptanceEnvironment -RepoRoot $repoRoot -VenvPython $venvPython
if (-not (Test-Path -LiteralPath $venvPython -PathType Leaf)) {
    Invoke-Native -FilePath "powershell" -Arguments @(
        "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
        "-File", (Join-Path $repoRoot "scripts\setup_windows_dev.ps1"), "-Arch", $Arch, "-BootstrapOnly"
    )
}
if (-not (Test-Path -LiteralPath $venvPython -PathType Leaf)) {
    throw "uv sync completed without creating the project virtual environment: $venvPython"
}
$python = $venvPython
# Never let SkipEnvironmentRefresh turn a reduced real-format matrix into a pass.
# This is the same configured-tool capability check used by setup.
Invoke-Native -FilePath $python -Arguments @("-m", "tests.helpers.tool_config", "--arch", $Arch.ToLowerInvariant())
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

    # Use the optimized CI profile for the harness, even when the public CLI
    # and its fixtures below are tested from the release build.
    $rustTests = @(
        "cargo", "test", "--locked", "--manifest-path", (Join-Path $repoRoot "sunpack\Cargo.toml"),
        "--workspace", "--profile", "ci", "--target", $target
    )
    if (-not $VerboseOutput) { $rustTests += "--quiet" }
    Invoke-TestStep -Label "Rust correctness tests" -Command $rustTests

    $pytestVerbosity = if ($VerboseOutput) { "-v" } else { "-q" }
    Invoke-TestStep -Label "CLI and Watch acceptance tests" -Command @(
        $python, "-m", "pytest", $pytestVerbosity, "-rs", "-n", [string]$ParallelWorkers,
        "--dist", "worksteal", "tests/blackbox", "tests/unit", "tests/integration", "tests/real",
        "--ignore=tests/integration/test_disk_full_pause_resume.py"
    )
    # DiskPart must retain elevation, unlike ordinary launcher/GUI tests.
    # Missing elevation or any prerequisite skip is an incomplete acceptance run.
    $diskTestWorkers = if ($ParallelWorkers -gt 1) { [Math]::Min(3, $ParallelWorkers) } else { 0 }
    Invoke-TestStep -Label "Real disk-full recovery tests" -KeepElevationIfAdministrator -RequireExecutedTests -Command @(
        $python, "-m", "pytest", $pytestVerbosity, "-rs", "-n", [string]$diskTestWorkers,
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
exit 0
