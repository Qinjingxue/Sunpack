[CmdletBinding()]
param(
    [switch]$VerboseOutput,
    [switch]$NoWait,
    [switch]$SkipEnvironmentRefresh,
    [ValidateSet("x64", "arm64")]
    [string]$Arch = "x64",
    [ValidateSet("full", "lite")]
    [string]$RepairSystem = "full",
    [ValidateRange(0, 32)]
    [int]$ParallelWorkers = 0,
    [int]$StepTimeoutSeconds = 900
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$unelevatedRunner = Join-Path $repoRoot "scripts\run_unelevated_process.py"
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

function Invoke-TestStep {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Label,
        [Parameter(Mandatory = $true)]
        [string[]]$Command,
        [int]$TimeoutSeconds = $StepTimeoutSeconds,
        [switch]$QuietOutput,
        [switch]$KeepElevationIfAdministrator
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
    $stdoutPath = $null
    $stderrPath = $null

    if ($QuietOutput) {
        $stdoutPath = [System.IO.Path]::GetTempFileName()
        $stderrPath = [System.IO.Path]::GetTempFileName()
    }

    if ($Command.Length -ge 3 -and $Command[1] -eq "-m" -and $Command[2] -eq "pytest") {
        $junitReportPath = Join-Path ([System.IO.Path]::GetTempPath()) (
            "sunpack-acceptance-{0}-{1}.xml" -f $PID, [guid]::NewGuid().ToString("N")
        )
        $argsList += "--junitxml=$junitReportPath"
    }

    if ($VerboseOutput) {
        Write-Host ("    " + $joinedCommand) -ForegroundColor DarkGray
    }

    $runnerArguments = @()
    if ($KeepElevationIfAdministrator -and $script:AcceptanceProcessIsAdministrator) {
        Write-Host "    Running this step with the acceptance process administrator token." -ForegroundColor DarkGray
        $runnerArguments = $argsList
    } else {
        # The acceptance script may itself require elevation to install the temporary
        # Watch Broker service. Keep ordinary test/smoke commands behind the existing
        # token-switching helper so pytest and its descendants use the normal token.
        $runnerArguments = @(
            $unelevatedRunner,
            "--cwd", $repoRoot,
            "--timeout-seconds", [string]$TimeoutSeconds,
            "--",
            $Command[0]
        )
        $runnerArguments += $argsList
    }

    $process = $null
    try {
        $startProcessArgs = @{
            FilePath = $Command[0]
            ArgumentList = $runnerArguments
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
                    $exitCode = if ($null -eq $exitCode) { -2 } else { $exitCode }
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
                Remove-Item -LiteralPath $outputPath -Force
            }
        }
    }
}

function Get-PythonCommand {
    foreach ($candidate in @("python", "py")) {
        try {
            & $candidate --version *> $null
            if ($LASTEXITCODE -eq 0) {
                return $candidate
            }
        } catch {
        }
    }
    throw "Python interpreter not found in PATH."
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

function Get-NativeSmokeCode {
    return @"
import sunpack_native as n
required = [
    'native_available', 'scanner_version',
    'scan_directory_snapshot', 'scan_directory_snapshots',
    'directory_snapshot_from_columns', 'filter_inventory_file_indices',
    'batch_file_head_facts', 'authorize_nested_candidates',
    'relations_build_candidate_groups_from_snapshot',
    'profile_directory_scan', 'list_regular_files_in_directory',
    'scan_embedded_archives', 'scan_magics_anywhere',
    'scan_zip_central_directory_names', 'inspect_zip_eocd_structure',
    'inspect_pe_overlay_structure',
    'repair_read_file_range', 'repair_concat_ranges_to_bytes',
    'repair_write_candidate', 'repair_copy_range_to_file',
    'repair_concat_ranges_to_file', 'repair_patch_file',
    'archive_state_to_bytes_native', 'archive_state_size_native',
    'archive_state_write_to_file_native', 'archive_state_zip_manifest_native',
    'zip_deep_partial_recovery', 'zip_rebuild_from_local_headers',
    'zip_directory_field_repair', 'zip_conflict_resolver_rebuild',
    'gzip_footer_fix_repair', 'gzip_deflate_member_resync_repair',
    'zstd_frame_salvage_repair', 'tar_boundary_repair',
    'compression_stream_partial_recovery',
    'compression_stream_trailing_junk_trim', 'tar_compressed_partial_recovery',
    'archive_carrier_crop_recovery',
    'seven_zip_scan_source', 'seven_zip_atomic_repair',
    'archive_nested_payload_salvage',
    'rar_block_chain_trim_recovery', 'rar_end_block_repair',
    'watch_broker_acquire', 'watch_broker_release',
    'watch_broker_is_connected', 'watch_broker_ping_seconds',
]
assert n.native_available()
missing = [name for name in required if not callable(getattr(n, name, None))]
assert not missing, missing
"@
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

function Get-AcceptanceTestToolRequirements {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot
    )

    $testToolsRoot = Join-Path $RepoRoot ".sunpack_test_tools"
    $rarRoot = Join-Path $testToolsRoot "winrar"
    $zstdRoot = Join-Path $testToolsRoot "zstd"
    return @(
        [pscustomobject]@{
            Path = Join-Path $rarRoot "Rar.exe"
            Description = "RAR archive generator"
            Arguments = @()
        },
        [pscustomobject]@{
            Path = Join-Path $rarRoot "Default.SFX"
            Description = "RAR SFX module"
            Arguments = $null
        },
        [pscustomobject]@{
            Path = Join-Path $rarRoot "WinRAR.exe"
            Description = "WinRAR archive generator"
            Arguments = $null
        },
        [pscustomobject]@{
            Path = Join-Path $zstdRoot "zstd.exe"
            Description = "zstd stream generator"
            Arguments = @("--version")
        }
    )
}

function Test-AcceptanceTestToolRuns {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [string[]]$Arguments = @()
    )

    try {
        & $Path @Arguments *> $null
        return ($LASTEXITCODE -eq 0)
    } catch {
        return $false
    }
}

function Test-AcceptanceRarGeneratorVersion {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [string]$RequiredVersion = "6.22"
    )

    try {
        $output = (& $Path "iver" 2>&1 | Out-String)
        # Rar.exe returns exit code 7 for the informational iver command.
        return ($output -match ("RAR " + [regex]::Escape($RequiredVersion) + " x64"))
    } catch {
        return $false
    }
}

function Assert-AcceptanceTestTools {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot
    )

    $missing = New-Object System.Collections.Generic.List[string]
    foreach ($tool in @(Get-AcceptanceTestToolRequirements -RepoRoot $RepoRoot)) {
        if (-not (Test-Path -LiteralPath $tool.Path -PathType Leaf)) {
            $missing.Add("$($tool.Description): $($tool.Path)")
            continue
        }
        if ($tool.Description -eq "RAR archive generator" -and
            -not (Test-AcceptanceRarGeneratorVersion -Path $tool.Path)) {
            $missing.Add("$($tool.Description) must be WinRAR 6.22 x64 for RAR4 fixtures: $($tool.Path)")
        } elseif ($null -ne $tool.Arguments -and
            -not (Test-AcceptanceTestToolRuns -Path $tool.Path -Arguments $tool.Arguments)) {
            $missing.Add("$($tool.Description) is not executable: $($tool.Path)")
        }
    }
    if ($missing.Count -gt 0) {
        throw (
            "Acceptance test generator tools are incomplete:`n  - " +
            ($missing -join "`n  - ") +
            "`nRun scripts\setup_windows_dev.ps1 on a Windows x64 environment or configure the test tool paths."
        )
    }
    Write-Host "    Acceptance generator tools are present and executable." -ForegroundColor Green
}

function Get-ModuleOrigin {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PythonPath,
        [Parameter(Mandatory = $true)]
        [string]$ModuleName
    )

    try {
        $origin = & $PythonPath -c "import importlib.util; spec = importlib.util.find_spec('$ModuleName'); print(spec.origin if spec and spec.origin else '')" 2>$null
        if ($LASTEXITCODE -ne 0) {
            return ""
        }
        return (($origin | Out-String).Trim())
    } catch {
        return ""
    }
}

function Get-NewestSourceWriteTime {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Root,
        [Parameter(Mandatory = $true)]
        [string[]]$Include
    )

    $files = @()
    foreach ($pattern in $Include) {
        $files += Get-ChildItem -LiteralPath $Root -Filter $pattern -Recurse -File -ErrorAction SilentlyContinue
    }
    if (-not $files) {
        return [datetime]::MinValue
    }
    return ($files | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1).LastWriteTimeUtc
}

function Get-OldestExistingWriteTime {
    param([string[]]$Paths)

    $files = @($Paths | Where-Object { Test-Path -LiteralPath $_ } | ForEach-Object { Get-Item -LiteralPath $_ })
    if ($files.Count -eq 0) {
        return [datetime]::MinValue
    }
    return ($files | Sort-Object LastWriteTimeUtc | Select-Object -First 1).LastWriteTimeUtc
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
        "psutil",
        "send2trash",
        "watchdog",
        "zstandard",
        "numpy",
        "requests",
        "charset_normalizer"
    )
    if ($RepairSystem -eq "full") {
        $requiredPythonModules += @("torch", "torch_geometric")
    }
    if (-not (Test-PythonImports -PythonPath $VenvPython -Modules $requiredPythonModules)) {
        $reasons.Add(".venv is missing or cannot import runtime, test, or model modules")
    }

    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        & $VenvPython -c (Get-NativeSmokeCode) *> $null
        $nativeSmokeExitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    if ($nativeSmokeExitCode -ne 0) {
        $reasons.Add("sunpack_native is missing new native repair APIs")
    }

    $nativeExtension = Get-NativeExtensionPath -PythonPath $VenvPython
    if (-not $nativeExtension) {
        $reasons.Add("sunpack_native is not importable from .venv")
    }

    $toolsRoot = if ($Arch -eq "arm64") { Join-Path $RepoRoot "tools-arm64" } else { Join-Path $RepoRoot "tools" }
    $requiredTools = @(
        (Join-Path $toolsRoot "7z.exe"),
        (Join-Path $toolsRoot "7zCon.sfx"),
        (Join-Path $toolsRoot "7z.dll"),
        (Join-Path $toolsRoot "sunpack_sevenzip.dll"),
        (Join-Path $toolsRoot "sunpack_sevenzip_worker.exe")
    )
    foreach ($toolPath in $requiredTools) {
        if (-not (Test-Path -LiteralPath $toolPath)) {
            $reasons.Add("required runtime tool is missing: $toolPath")
        }
    }
    foreach ($tool in @(Get-AcceptanceTestToolRequirements -RepoRoot $RepoRoot)) {
        if (-not (Test-Path -LiteralPath $tool.Path -PathType Leaf)) {
            $reasons.Add("acceptance test generator is missing: $($tool.Path)")
        } elseif ($tool.Description -eq "RAR archive generator" -and
            -not (Test-AcceptanceRarGeneratorVersion -Path $tool.Path)) {
            $reasons.Add("acceptance RAR generator must be WinRAR 6.22 x64: $($tool.Path)")
        } elseif ($null -ne $tool.Arguments -and
            -not (Test-AcceptanceTestToolRuns -Path $tool.Path -Arguments $tool.Arguments)) {
            $reasons.Add("acceptance test generator cannot run: $($tool.Path)")
        }
    }
    if ($requiredTools | Where-Object { -not (Test-Path -LiteralPath $_) }) {
        return $reasons
    }

    if (-not (Test-EnvironmentManifest -RepoRoot $RepoRoot)) {
        $reasons.Add("environment manifest is missing or does not match current sources/artifacts")
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
        Write-Host "Skipping acceptance environment refresh by request." -ForegroundColor Yellow
        return
    }

    Write-Host ""
    Write-Host "==> Acceptance environment preflight" -ForegroundColor Cyan
    if ($env:OS -ne "Windows_NT") {
        throw "This acceptance script only supports Windows."
    }

    $reasons = @(Get-EnvironmentRefreshReasons -RepoRoot $RepoRoot -VenvPython $VenvPython)
    if ($reasons.Count -eq 0) {
        Write-Host "    Environment is current." -ForegroundColor Green
        return
    }

    Write-Host "    Environment refresh required:" -ForegroundColor Yellow
    foreach ($reason in $reasons) {
        Write-Host "      - $reason" -ForegroundColor Yellow
    }
    Invoke-Native -FilePath "powershell" -Arguments @(
        "-ExecutionPolicy", "Bypass",
        "-File", (Join-Path $RepoRoot "scripts\setup_windows_dev.ps1"),
        "-Arch", $Arch,
        "-RepairSystem", $RepairSystem
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

function Get-NativeExtensionPath {
    param([Parameter(Mandatory = $true)][string]$PythonPath)

    $origin = Get-ModuleOrigin -PythonPath $PythonPath -ModuleName "sunpack_native"
    if (-not $origin -or -not (Test-Path -LiteralPath $origin -PathType Leaf)) {
        return ""
    }
    $moduleRoot = Split-Path -Parent $origin
    $extension = Get-ChildItem -LiteralPath $moduleRoot -Filter "sunpack_native*.pyd" -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
    if ($null -eq $extension) {
        return ""
    }
    return $extension.FullName
}

function Test-EnvironmentManifest {
    param([Parameter(Mandatory = $true)][string]$RepoRoot)

    $manifestScript = Join-Path $RepoRoot "scripts\environment_manifest.ps1"
    & powershell -NoProfile -ExecutionPolicy Bypass -File $manifestScript `
        -RepoRoot $RepoRoot -Arch $Arch -RepairSystem $RepairSystem -Check *> $null
    return ($LASTEXITCODE -eq 0)
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
Assert-AcceptanceTestTools -RepoRoot $repoRoot
$python = if (Test-Path -LiteralPath $venvPython) { $venvPython } else { Get-PythonCommand }
$env:PYTHONPATH = $repoRoot

$rustTarget = if ($Arch -eq "arm64") { "aarch64-pc-windows-msvc" } else { "x86_64-pc-windows-msvc" }
$brokerPath = Join-Path $repoRoot (".cache\rust-target\{0}\{1}\release\sunpack-watch-broker.exe" -f $Arch, $rustTarget)
if (-not (Test-Path -LiteralPath $brokerPath -PathType Leaf)) {
    $brokerPath = Join-Path $repoRoot "native\target\release\sunpack-watch-broker.exe"
}
$brokerPath = [IO.Path]::GetFullPath($brokerPath)
if (-not (Test-Path -LiteralPath $brokerPath -PathType Leaf)) {
    throw "Watch Broker executable not found: $brokerPath"
}
$watchServiceManager = Join-Path $repoRoot "scripts\manage_test_watch_service.ps1"
$powerShellHost = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
$watchServiceRunId = [guid]::NewGuid().ToString("N")
$watchServiceName = "SunPackWatchBrokerTest_$watchServiceRunId"
$watchPipeName = "\\.\pipe\SunPack.WatchBroker.Test.$watchServiceRunId"
$watchBrokerSha256 = (Get-FileHash -LiteralPath $brokerPath -Algorithm SHA256).Hash.ToLowerInvariant()
$watchEnvironmentNames = @(
    "SUNPACK_WATCH_BROKER_SERVICE_NAME",
    "SUNPACK_WATCH_BROKER_PIPE_NAME",
    "SUNPACK_WATCH_BROKER_BINARY_PATH",
    "SUNPACK_WATCH_BROKER_BINARY_SHA256"
)
$watchEnvironmentBackup = @{}
foreach ($name in $watchEnvironmentNames) {
    $watchEnvironmentBackup[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
}
$watchServiceInstalled = $false
$watchServiceCleanupFailed = $false

try {
    $env:SUNPACK_WATCH_BROKER_SERVICE_NAME = $watchServiceName
    $env:SUNPACK_WATCH_BROKER_PIPE_NAME = $watchPipeName
    $env:SUNPACK_WATCH_BROKER_BINARY_PATH = $brokerPath
    $env:SUNPACK_WATCH_BROKER_BINARY_SHA256 = $watchBrokerSha256

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

    Invoke-TestStep -Label "Parallel CLI, unit, and functional tests" -Command @(
        $python,
        "-m", "pytest", "-q",
        "-n", [string]$ParallelWorkers,
        "--dist", "worksteal",
        "tests/cli", "tests/unit", "tests/functional",
        "--durations=20"
    )
    Invoke-TestStep -Label "Parallel integration and real tests" -Command @(
        $python,
        "-m", "pytest", "-q",
        "-n", [string]$ParallelWorkers,
        "--dist", "worksteal",
        "tests/integration", "tests/real",
        "--ignore", "tests/integration/test_disk_full_pause_resume.py",
        "--durations=20"
    )
    Invoke-TestStep -Label "Parallel administrator VHD disk-full tests" -KeepElevationIfAdministrator -Command @(
        $python,
        "-m", "pytest", "-q",
        "-n", [string]$ParallelWorkers,
        "--dist", "worksteal",
        "tests/integration/test_disk_full_pause_resume.py",
        "--durations=20"
    )
    Invoke-TestStep -Label "CLI help smoke test" -Command @($python, "sunpack.py", "--help") -QuietOutput
    Invoke-TestStep -Label "CLI passwords smoke test" -Command @($python, "sunpack.py", "passwords", "--json") -QuietOutput
    Invoke-TestStep -Label "CLI scan smoke test" -Command @($python, "sunpack.py", "scan", (Join-Path $repoRoot "tests"), "--json") -QuietOutput
    Invoke-TestStep -Label "CLI inspect smoke test" -Command @($python, "sunpack.py", "inspect", (Join-Path $repoRoot "tests"), "--json") -QuietOutput
    Invoke-TestStep -Label "CLI config smoke test" -Command @($python, "sunpack.py", "config", "--json", "show") -QuietOutput
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
    Write-Host ("{0} acceptance test step(s) failed; all scheduled steps have completed." -f $failedResults.Count) -ForegroundColor Red
} else {
    Write-Host "All acceptance tests passed." -ForegroundColor Green
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
