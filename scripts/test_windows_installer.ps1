[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$InstallerPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot

. (Join-Path $PSScriptRoot "test_elevation.ps1")
$elevatedExitCode = Invoke-TestScriptElevated -ScriptPath $PSCommandPath -BoundParameters $PSBoundParameters
if ($null -ne $elevatedExitCode) {
    exit $elevatedExitCode
}

function Write-SmokePhase {
    param(
        [Parameter(Mandatory = $true)][string]$State,
        [Parameter(Mandatory = $true)][string]$Label,
        [string]$Detail = ""
    )
    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    $suffix = if ($Detail) { " :: $Detail" } else { "" }
    Write-Host "[installer-smoke][$timestamp][$State] $Label$suffix"
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$Arguments = @(),
        [int]$TimeoutSeconds = 120,
        [string]$Label = ""
    )
    if (-not $Label) {
        $Label = Split-Path -Leaf $FilePath
    }
    $commandText = "$FilePath $($Arguments -join ' ')".Trim()
    Write-SmokePhase -State "BEGIN" -Label $Label -Detail $commandText

    # Do not use Start-Process -Wait here. Windows PowerShell can wait for
    # descendants too; after #23 an upgrade intentionally restores a persistent
    # Watch runtime, so waiting for the process tree turns success into a hang.
    $startedAt = Get-Date
    $process = Start-Process `
        -FilePath $FilePath `
        -ArgumentList $Arguments `
        -PassThru `
        -NoNewWindow
    if (-not $process.WaitForExit([Math]::Max(1, $TimeoutSeconds) * 1000)) {
        $elapsed = ((Get-Date) - $startedAt).TotalSeconds
        Write-SmokePhase -State "TIMEOUT" -Label $Label -Detail ("PID={0} elapsed={1:N1}s" -f $process.Id, $elapsed)
        try {
            & taskkill.exe /PID $process.Id /T /F 2>&1 | ForEach-Object { Write-Host $_ }
        } catch {
        }
        throw "Command timed out after $TimeoutSeconds seconds: $commandText"
    }
    $process.WaitForExit()
    $exitCode = $process.ExitCode
    $elapsed = ((Get-Date) - $startedAt).TotalSeconds
    Write-SmokePhase -State "END" -Label $Label -Detail ("PID={0} exit={1} elapsed={2:N2}s" -f $process.Id, $exitCode, $elapsed)
    if ($exitCode -ne 0) {
        throw "Command failed with exit code ${exitCode}: $commandText"
    }
}
function Invoke-UninstallerChecked {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$Arguments = @(),
        [int]$TimeoutSeconds = 300
    )
    $commandText = "$FilePath $($Arguments -join ' ')".Trim()
    Write-SmokePhase -State "BEGIN" -Label "uninstall" -Detail $commandText
    # Do not use Start-Process -Wait here. PowerShell 5.1 waits for the
    # uninstaller's entire descendant tree, which includes the replacement
    # Explorer process started after unregistering shell integrations.
    $startedAt = Get-Date
    $process = Start-Process `
        -FilePath $FilePath `
        -ArgumentList $Arguments `
        -PassThru `
        -NoNewWindow
    if (-not $process.WaitForExit([Math]::Max(1, $TimeoutSeconds) * 1000)) {
        $elapsed = ((Get-Date) - $startedAt).TotalSeconds
        Write-SmokePhase -State "TIMEOUT" -Label "uninstall" -Detail ("PID={0} elapsed={1:N1}s" -f $process.Id, $elapsed)
        try {
            $process.Kill()
        } catch {
        }
        throw "Uninstaller timed out after $TimeoutSeconds seconds: $commandText"
    }
    $process.WaitForExit()
    $exitCode = $process.ExitCode
    $elapsed = ((Get-Date) - $startedAt).TotalSeconds
    Write-SmokePhase -State "END" -Label "uninstall" -Detail ("PID={0} exit={1} elapsed={2:N2}s" -f $process.Id, $exitCode, $elapsed)
    if ($null -ne $exitCode -and $exitCode -ne 0) {
        throw "Uninstaller failed with exit code ${exitCode}: $commandText"
    }
}
function Wait-UninstallCompletion {
    param(
        [Parameter(Mandatory = $true)][string]$InstallRoot,
        [Parameter(Mandatory = $true)][string]$ServiceName,
        [int]$TimeoutSeconds = 30
    )
    $deadline = (Get-Date).AddSeconds([Math]::Max(1, $TimeoutSeconds))
    do {
        $rootExists = Test-Path -LiteralPath $InstallRoot
        $serviceExists = $null -ne (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)
        if (-not $rootExists -and -not $serviceExists) {
            return
        }
        Start-Sleep -Milliseconds 100
    } while ((Get-Date) -lt $deadline)
    throw "Uninstaller did not remove the application directory and service within $TimeoutSeconds seconds. RootExists=$rootExists ServiceExists=$serviceExists"
}

function Invoke-UnelevatedChecked {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$Arguments = @(),
        [int]$TimeoutSeconds = 120
    )
    $pythonPath = Join-Path $repoRoot ".venv\Scripts\python.exe"
    $runnerPath = Join-Path $repoRoot "scripts\run_unelevated_process.py"
    if (-not (Test-Path -LiteralPath $pythonPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $runnerPath -PathType Leaf)) {
        throw "Unelevated installer test runner is unavailable under: $repoRoot"
    }
    $runnerArguments = @(
        $runnerPath,
        "--cwd", (Split-Path -Parent $FilePath),
        "--timeout-seconds", [string]$TimeoutSeconds,
        "--",
        $FilePath
    ) + $Arguments
    & $pythonPath @runnerArguments
    if ($LASTEXITCODE -ne 0) {
        throw "Unelevated command failed with exit code ${LASTEXITCODE}: $FilePath $($Arguments -join ' ')"
    }
}

function Invoke-UnelevatedJson {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$Arguments = @(),
        [int]$TimeoutSeconds = 120
    )
    $pythonPath = Join-Path $repoRoot ".venv\Scripts\python.exe"
    $runnerPath = Join-Path $repoRoot "scripts\run_unelevated_process.py"
    if (-not (Test-Path -LiteralPath $pythonPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $runnerPath -PathType Leaf)) {
        throw "Unelevated installer test runner is unavailable under: $repoRoot"
    }
    $runnerArguments = @(
        $runnerPath,
        "--cwd", (Split-Path -Parent $FilePath),
        "--timeout-seconds", [string]$TimeoutSeconds,
        "--",
        $FilePath
    ) + $Arguments
    $output = & $pythonPath @runnerArguments
    if ($LASTEXITCODE -ne 0) {
        throw "Unelevated command failed with exit code ${LASTEXITCODE}: $FilePath $($Arguments -join ' ')"
    }
    try {
        return (($output | Out-String) | ConvertFrom-Json)
    } catch {
        throw "Unelevated command did not return valid JSON: $FilePath $($Arguments -join ' ')"
    }
}


function Write-DiagnosticLogTail {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$Path,
        [int]$Tail = 200
    )
    Write-Host "::group::SunPack diagnostic: $Label"
    try {
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            Write-Host "Path: $Path"
            Get-Content -LiteralPath $Path -Tail $Tail -ErrorAction Stop
        } else {
            Write-Host "Diagnostic log was not found: $Path"
        }
    } catch {
        Write-Host "Failed to read diagnostic log '$Path': $($_.Exception.Message)"
    } finally {
        Write-Host "::endgroup::"
    }
}

function Test-PathEntry {
    param([string]$PathValue, [string]$Expected)
    $expectedPath = [System.IO.Path]::GetFullPath($Expected).TrimEnd('\')
    foreach ($entry in ([string]$PathValue -split ';')) {
        if (-not $entry.Trim()) {
            continue
        }
        try {
            $candidate = [System.IO.Path]::GetFullPath($entry.Trim().Trim('"')).TrimEnd('\')
        } catch {
            continue
        }
        if ($candidate.Equals($expectedPath, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

function Get-MachinePath {
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
        "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
    )
    if ($null -eq $key) {
        return ""
    }
    try {
        return [string]$key.GetValue("Path", "", [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    } finally {
        $key.Close()
    }
}

$resolvedInstaller = (Resolve-Path -LiteralPath $InstallerPath).Path
$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("sunpack-installer-smoke-" + $PID)
$installRoot = Join-Path $testRoot "SunPack"
$installLog = Join-Path $testRoot "install.log"
$uninstallLog = Join-Path $testRoot "uninstall.log"
$folderMenuKey = "HKLM:\Software\Classes\Directory\shell\SunPack"
$backgroundMenuKey = "HKLM:\Software\Classes\Directory\Background\shell\SunPack"
$startupRunKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
$systemEnvironmentKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
$startupValueName = "SunPackWatchService"
$toastClsidKey = "HKLM:\Software\Classes\CLSID\{C5A6B4E9-3184-44E2-9F15-6A71804F7A36}\LocalServer32"
$serviceName = "SunPackWatchBroker"
$userDataRoot = Join-Path $env:ProgramData "SunPack"
$userDataBackup = $null
$uninstaller = $null
$startMenuRoots = @(
    [Environment]::GetFolderPath([Environment+SpecialFolder]::Programs),
    [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonPrograms)
) | Where-Object { $_ } | Select-Object -Unique

function Get-StartMenuShortcutPaths {
    param([Parameter(Mandatory = $true)][string]$Name)

    foreach ($root in $startMenuRoots) {
        Join-Path (Join-Path $root "SunPack") $Name
        Join-Path $root $Name
    }
}

function Get-SunPackStartMenuEntries {
    foreach ($root in $startMenuRoots) {
        $directory = Join-Path $root "SunPack"
        if (Test-Path -LiteralPath $directory -PathType Container) {
            Get-ChildItem -LiteralPath $directory -Force -File -Filter "*.lnk" -ErrorAction SilentlyContinue
        }
    }
}

function Assert-SunPackStartMenu {
    $entries = @(Get-SunPackStartMenuEntries)
    $installerNames = @($entries | Select-Object -ExpandProperty Name)
    if ($installerNames.Count -ne 1 -or $installerNames[0] -ne "Uninstall SunPack.lnk") {
        throw "Installer Start menu entries should contain only the uninstaller. Entries: $($installerNames -join ', ')"
    }
}

function Assert-ToastMachineRegistration {
    param([Parameter(Mandatory = $true)][string]$RuntimePath)

    $activationCommand = [string](Get-Item -LiteralPath $toastClsidKey -ErrorAction Stop).GetValue("")
    if ($activationCommand -ne ('"{0}" --toast-activated' -f $RuntimePath)) {
        throw "Toast COM activation command is incorrect: $activationCommand"
    }
}

if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    throw "Installer smoke test requires the service to be absent: $serviceName"
}
if (Get-ItemProperty -LiteralPath $startupRunKey -Name $startupValueName -ErrorAction SilentlyContinue) {
    throw "Installer smoke test requires a clean startup state and will not overwrite an existing Run value: $startupValueName"
}
foreach ($key in @($toastClsidKey)) {
    if (Test-Path -LiteralPath $key) {
        throw "Installer smoke test requires a clean Toast registration state and will not overwrite: $key"
    }
}

foreach ($key in @(
    $folderMenuKey,
    $backgroundMenuKey,
    "HKLM:\Software\Classes\SunPack.FolderContextMenu",
    "HKLM:\Software\Classes\SunPack.BackgroundContextMenu"
)) {
    if (Test-Path -LiteralPath $key) {
        throw "Installer smoke test requires a clean context-menu state and will not overwrite an existing key: $key"
    }
}

New-Item -ItemType Directory -Path $testRoot -Force | Out-Null
try {
    if (Test-Path -LiteralPath $userDataRoot) {
        $userDataBackup = Join-Path $env:ProgramData ("SunPack.installer-test-backup-" + [guid]::NewGuid().ToString("N"))
        $resolvedDataRoot = [System.IO.Path]::GetFullPath($userDataRoot)
        $resolvedBackup = [System.IO.Path]::GetFullPath($userDataBackup)
        $programDataRoot = [System.IO.Path]::GetFullPath($env:ProgramData).TrimEnd('\') + '\'
        if (-not $resolvedDataRoot.StartsWith($programDataRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
            -not $resolvedBackup.StartsWith($programDataRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to move user data outside ProgramData."
        }
        Move-Item -LiteralPath $userDataRoot -Destination $userDataBackup
    }

    Invoke-Checked -Label "initial install" -TimeoutSeconds 180 -FilePath $resolvedInstaller -Arguments @(
        "/VERYSILENT",
        "/SUPPRESSMSGBOXES",
        "/NORESTART",
        "/SP-",
        "/TASKS=addtopath,contextmenu,autostart",
        "/DIR=$installRoot",
        "/LOG=$installLog"
    )

    $appPath = Join-Path $installRoot "sunpack.exe"
    $runtimeAppPath = Join-Path $installRoot "sunpack-runtime.exe"
    $configPath = Join-Path $userDataRoot "sunpack_config.json"
    $builtinPasswordsPath = Join-Path $userDataRoot "builtin_passwords.txt"
    $watchRootsPath = Join-Path $userDataRoot "sunpack_watch_roots.txt"
    $brokerPath = Join-Path $installRoot "service\sunpack-watch-broker.exe"
    if (-not (Test-Path -LiteralPath $appPath)) {
        throw "Installed executable was not found: $appPath"
    }
    if (-not (Test-Path -LiteralPath $runtimeAppPath)) {
        throw "Installed shared runtime executable was not found: $runtimeAppPath"
    }
    if (Test-Path -LiteralPath (Join-Path $installRoot "sunpack-watch.exe")) {
        throw "Retired duplicate watch executable was installed."
    }
    foreach ($persistentName in @("sunpack_config.json", "sunpack_watch_roots.txt", "builtin_passwords.txt")) {
        if (Test-Path -LiteralPath (Join-Path $installRoot $persistentName)) {
            throw "Installer must not write user data into the application directory: $persistentName"
        }
    }
    if (-not (Test-Path -LiteralPath $configPath)) {
        throw "Installed sunpack_config.json was not found in ProgramData: $configPath"
    }
    if (-not (Test-Path -LiteralPath $builtinPasswordsPath)) {
        throw "Installed builtin password file was not found: $builtinPasswordsPath"
    }
    $programDataAcl = Get-Acl -LiteralPath $userDataRoot
    $usersModify = @(
        $programDataAcl.Access |
            Where-Object {
                $_.IdentityReference.Value -in @("BUILTIN\Users", "Users") -and
                $_.AccessControlType -eq "Allow" -and
                ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Modify) -eq
                    [System.Security.AccessControl.FileSystemRights]::Modify
            }
    )
    if ($usersModify.Count -eq 0) {
        throw "ProgramData\SunPack does not grant the Users group modify rights: $userDataRoot"
    }
    if (-not (Test-Path -LiteralPath $brokerPath)) {
        throw "Installed Watch Broker executable was not found: $brokerPath"
    }
    Assert-ToastMachineRegistration -RuntimePath $runtimeAppPath
    Assert-SunPackStartMenu
    $service = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    if ($null -eq $service) {
        throw "Installer did not create the Watch Broker service: $serviceName"
    }
    if ($service.StartMode -ne "Manual" -or $service.StartName -ne "LocalSystem") {
        throw "Watch Broker service configuration is incorrect: StartMode=$($service.StartMode), StartName=$($service.StartName)"
    }
    $expectedImagePath = '"{0}"' -f $brokerPath
    if ($service.PathName -ne $expectedImagePath) {
        throw "Watch Broker ImagePath is incorrect. Expected '$expectedImagePath', got '$($service.PathName)'."
    }
    $serviceDacl = (& sc.exe sdshow $serviceName 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $serviceDacl -notmatch '\(A;;LCRP;;;IU\)') {
        throw "Watch Broker service DACL does not grant only start/query rights to interactive users: $serviceDacl"
    }
    Invoke-Checked -Label "installed launcher help" -TimeoutSeconds 30 -FilePath $appPath -Arguments @("--help")

    $userPath = Get-MachinePath
    if (-not (Test-PathEntry -PathValue $userPath -Expected $installRoot)) {
        throw "Installer did not add the application directory to the machine PATH."
    }
    foreach ($key in @($folderMenuKey, $backgroundMenuKey)) {
        if (-not (Test-Path -LiteralPath $key)) {
            throw "Installer did not register the expected context menu key: $key"
        }
    }
    $directCommandKey = "HKLM:\Software\Classes\SunPack.FolderContextMenu\shell\DirectExtract\command"
    $directCommand = [string](Get-Item -LiteralPath $directCommandKey).GetValue("")
    if ($directCommand -notlike "*$appPath*") {
        throw "Context menu command does not reference the installed executable: $directCommand"
    }
    $startupCommand = [string](Get-ItemProperty -LiteralPath $startupRunKey -Name $startupValueName).$startupValueName
    $expectedRuntime = if ($runtimeAppPath -match '[ \t]') {
        '"' + $runtimeAppPath + '"'
    } else {
        $runtimeAppPath
    }
    $escapedRuntime = [regex]::Escape($expectedRuntime)
    $startupMatch = [regex]::Match($startupCommand, (
        '^' + $escapedRuntime +
        ' (?<RuntimeIdentity>--_sunpack-runtime-id=v2-[0-9a-f]{16}) watch start$'
    ))
    if (-not $startupMatch.Success) {
        throw "Startup Run value is incorrect: $startupCommand"
    }
    $runtimeIdentity = $startupMatch.Groups["RuntimeIdentity"].Value

    Invoke-Checked -Label "initial persistent shutdown" -TimeoutSeconds 45 -FilePath $appPath -Arguments @("--persistent-shutdown")
    $runtimeExitDeadline = (Get-Date).AddSeconds(20)
    do {
        $installedRuntimeProcesses = @(
            Get-CimInstance Win32_Process -Filter "Name='sunpack-runtime.exe'" |
                Where-Object { $_.ExecutablePath -eq $runtimeAppPath }
        )
        if ($installedRuntimeProcesses.Count -eq 0) {
            break
        }
        Start-Sleep -Milliseconds 100
    } while ((Get-Date) -lt $runtimeExitDeadline)
    if ($installedRuntimeProcesses.Count -ne 0) {
        throw "Packaged runtime did not exit before the startup cold-start test: $runtimeAppPath"
    }
    Write-SmokePhase -State "STAGE" -Label "start Watch before running-state upgrade"
    try {
        Invoke-UnelevatedChecked -FilePath $runtimeAppPath -Arguments @($runtimeIdentity, "watch", "start")
    } catch {
        $runtimeIdValue = $runtimeIdentity.Substring($runtimeIdentity.IndexOf("=") + 1)
        Write-DiagnosticLogTail `
            -Label "persistent runtime events" `
            -Path (Join-Path $userDataRoot "runtime-$runtimeIdValue.state.events.jsonl")
        Write-DiagnosticLogTail `
            -Label "watch service events" `
            -Path (Join-Path $userDataRoot ".sunpack_watch\events.jsonl")
        throw
    }

    $watchRoot = Join-Path $testRoot "watch-root"
    New-Item -ItemType Directory -Path $watchRoot -Force | Out-Null
    $watchRootsContent = "$watchRoot`n"
    Set-Content -LiteralPath $watchRootsPath -Value $watchRootsContent -Encoding UTF8 -NoNewline
    $unicodePassword = "installer-smoke-unicode-" + [char]0x5BC6 + [char]0x7801 + "-" + [char]0x03A9
    $builtinPasswordsContent = "installer-smoke-user-password`n$unicodePassword`n"
    Set-Content -LiteralPath $builtinPasswordsPath -Value $builtinPasswordsContent -Encoding UTF8 -NoNewline
    $configContent = "{`"cli`": {`"language`": `"en`"}}`n"
    Set-Content -LiteralPath $configPath -Value $configContent -Encoding UTF8 -NoNewline
    $watchStateDir = Join-Path $userDataRoot ".sunpack_watch"
    New-Item -ItemType Directory -Path $watchStateDir -Force | Out-Null
    $upgradeWatchStateMarker = Join-Path $watchStateDir "upgrade-preserve.marker"
    Set-Content -LiteralPath $upgradeWatchStateMarker -Value "preserve" -Encoding UTF8

    $staleUpgradeMarker = Join-Path $installRoot "stale-upgrade-marker.json"
    Set-Content -LiteralPath $staleUpgradeMarker -Value "stale" -Encoding UTF8
    $staleConfigDir = Join-Path $installRoot "config"
    New-Item -ItemType Directory -Path $staleConfigDir -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $staleConfigDir "old-settings.json") -Value "stale" -Encoding UTF8
    $staleDataMarker = Join-Path $userDataRoot "stale-runtime-state.json"
    Set-Content -LiteralPath $staleDataMarker -Value "stale" -Encoding UTF8
    $staleDataDir = Join-Path $userDataRoot "runtime-cwd"
    $staleRuntimeMarker = Join-Path $staleDataDir "stale.json"
    New-Item -ItemType Directory -Path $staleDataDir -Force | Out-Null
    Set-Content -LiteralPath $staleRuntimeMarker -Value "stale" -Encoding UTF8
    Write-SmokePhase -State "STAGE" -Label "prepare running-Watch upgrade"
    $watchStatusBeforeUpgrade = Invoke-UnelevatedJson -FilePath $appPath -Arguments @("watch", "status", "--json")
    if (-not [bool]$watchStatusBeforeUpgrade.summary.running) {
        throw "Installer smoke precondition failed: Watch is not running before the upgrade."
    }
    Invoke-Checked -Label "running-Watch upgrade install" -TimeoutSeconds 180 -FilePath $resolvedInstaller -Arguments @(
        "/VERYSILENT",
        "/SUPPRESSMSGBOXES",
        "/NORESTART",
        "/SP-",
        "/TASKS=addtopath,contextmenu,autostart",
        "/DIR=$installRoot",
        "/LOG=$installLog"
    )
    $watchRootsAfterUpgrade = Get-Content -LiteralPath $watchRootsPath -Raw -Encoding UTF8
    if ($watchRootsAfterUpgrade -ne $watchRootsContent) {
        throw "Upgrade install overwrote the existing watch roots file: $watchRootsPath"
    }
    $builtinPasswordsAfterUpgrade = Get-Content -LiteralPath $builtinPasswordsPath -Raw -Encoding UTF8
    $builtinPasswordLinesAfterUpgrade = @($builtinPasswordsAfterUpgrade -split '\r?\n')
    if ($builtinPasswordLinesAfterUpgrade -notcontains "installer-smoke-user-password") {
        throw "Upgrade install lost the existing builtin password entry: $builtinPasswordsPath"
    }
    if ($builtinPasswordLinesAfterUpgrade -notcontains $unicodePassword) {
        throw "Upgrade install corrupted the existing Unicode builtin password entry: $builtinPasswordsPath"
    }
    if ($builtinPasswordsAfterUpgrade -notmatch '#!SUNPACK-WATCH-CLIPBOARD-BEGIN' -or
        $builtinPasswordsAfterUpgrade -notmatch '#!SUNPACK-WATCH-CLIPBOARD-END') {
        throw "Upgrade install did not migrate the builtin password Watch block: $builtinPasswordsPath"
    }
    $configAfterUpgrade = Get-Content -LiteralPath $configPath -Raw -Encoding UTF8
    if ($configAfterUpgrade -ne $configContent) {
        throw "Upgrade install overwrote the existing program data config file: $configPath"
    }
    if (Test-Path -LiteralPath $staleUpgradeMarker) {
        throw "Upgrade install left stale application data behind: $staleUpgradeMarker"
    }
    if (Test-Path -LiteralPath $staleConfigDir) {
        throw "Upgrade install left stale configuration data behind: $staleConfigDir"
    }
    if (Test-Path -LiteralPath $staleDataMarker) {
        throw "Upgrade install left stale runtime state behind: $staleDataMarker"
    }
    # A successfully restored Watch recreates runtime-cwd/<runtime-id> by design.
    # Only the stale marker seeded before upgrade must be gone.
    if (Test-Path -LiteralPath $staleRuntimeMarker) {
        throw "Upgrade install left stale runtime state behind: $staleRuntimeMarker"
    }
    if (-not (Test-Path -LiteralPath $upgradeWatchStateMarker -PathType Leaf)) {
        throw "Upgrade install removed the durable Watch state directory: $watchStateDir"
    }
    Write-SmokePhase -State "STAGE" -Label "validate running-Watch upgrade"
    $watchStatusAfterUpgrade = Invoke-UnelevatedJson -FilePath $appPath -Arguments @("watch", "status", "--json")
    if (-not [bool]$watchStatusAfterUpgrade.summary.running) {
        throw "Upgrade install did not restore the Watch instance that was running before upgrade."
    }
    $machinePathAfterUpgrade = Get-MachinePath
    if (-not (Test-PathEntry -PathValue $machinePathAfterUpgrade -Expected $installRoot)) {
        throw "Upgrade install removed the machine PATH entry."
    }
    foreach ($key in @($folderMenuKey, $backgroundMenuKey)) {
        if (-not (Test-Path -LiteralPath $key)) {
            throw "Upgrade install removed a context menu key: $key"
        }
    }
    $directCommandAfterUpgrade = [string](Get-Item -LiteralPath $directCommandKey).GetValue("")
    if ($directCommandAfterUpgrade -ne $directCommand) {
        throw "Upgrade install changed the context menu command: $directCommandAfterUpgrade"
    }
    $startupCommandAfterUpgrade = [string](Get-ItemProperty -LiteralPath $startupRunKey -Name $startupValueName).$startupValueName
    if ($startupCommandAfterUpgrade -ne $startupCommand) {
        throw "Upgrade install changed the startup Run value: $startupCommandAfterUpgrade"
    }
    Assert-ToastMachineRegistration -RuntimePath $runtimeAppPath
    Assert-SunPackStartMenu

    Write-SmokePhase -State "STAGE" -Label "prepare stopped-Watch upgrade"
    Invoke-UnelevatedChecked -FilePath $appPath -Arguments @("watch", "stop")
    $watchStatusBeforeStoppedUpgrade = Invoke-UnelevatedJson -FilePath $appPath -Arguments @("watch", "status", "--json")
    if ([bool]$watchStatusBeforeStoppedUpgrade.summary.running) {
        throw "Watch did not stop before the stopped-state upgrade test."
    }
    Invoke-Checked -Label "stopped-Watch upgrade install" -TimeoutSeconds 180 -FilePath $resolvedInstaller -Arguments @(
        "/VERYSILENT",
        "/SUPPRESSMSGBOXES",
        "/NORESTART",
        "/SP-",
        "/TASKS=addtopath,contextmenu,autostart",
        "/DIR=$installRoot",
        "/LOG=$installLog"
    )
    $watchStatusAfterStoppedUpgrade = Invoke-UnelevatedJson -FilePath $appPath -Arguments @("watch", "status", "--json")
    if ([bool]$watchStatusAfterStoppedUpgrade.summary.running) {
        throw "Upgrade install restarted Watch even though it was stopped before upgrade."
    }
    $startupCommandAfterStoppedUpgrade = [string](Get-ItemProperty -LiteralPath $startupRunKey -Name $startupValueName).$startupValueName
    if ($startupCommandAfterStoppedUpgrade -ne $startupCommand) {
        throw "Stopped-state upgrade changed the startup Run value: $startupCommandAfterStoppedUpgrade"
    }

    Write-SmokePhase -State "STAGE" -Label "validate one-shot Watch lifecycle"
    Invoke-UnelevatedChecked -FilePath $appPath -Arguments @("watch", "start", "--once", "--no-tray")
    $stopDeadline = (Get-Date).AddSeconds(10)
    do {
        $brokerService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($null -ne $brokerService -and $brokerService.Status -eq "Stopped") {
            break
        }
        Start-Sleep -Milliseconds 100
    } while ((Get-Date) -lt $stopDeadline)
    if ($null -eq $brokerService -or $brokerService.Status -ne "Stopped") {
        throw "Watch Broker did not stop after the one-shot Watch client released its lease."
    }
    Set-Content -LiteralPath $watchRootsPath -Value "$watchRoot`n" -Encoding UTF8
    Set-Content -LiteralPath $builtinPasswordsPath -Value "uninstall-delete`n" -Encoding UTF8
    Set-Content -LiteralPath $configPath -Value $configContent -Encoding UTF8
    New-Item -ItemType Directory -Path $watchStateDir -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $watchStateDir "watch.stop") -Value "installer-smoke" -Encoding UTF8
    $runtimeStateDir = Join-Path $userDataRoot "runtime-cwd"
    New-Item -ItemType Directory -Path $runtimeStateDir -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $runtimeStateDir "stale.json") -Value "{}" -Encoding UTF8
    Set-ItemProperty -LiteralPath $startupRunKey -Name $startupValueName -Value ('"{0}" watch start' -f $appPath)

    $uninstaller = Get-ChildItem -LiteralPath $installRoot -Filter "unins*.exe" -File | Select-Object -First 1
    if ($null -eq $uninstaller) {
        throw "Inno Setup uninstaller was not created under: $installRoot"
    }
    Invoke-UninstallerChecked -FilePath $uninstaller.FullName -Arguments @(
        "/VERYSILENT",
        "/SUPPRESSMSGBOXES",
        "/NORESTART",
        "/LOG=$uninstallLog"
    )
    $uninstaller = $null
    Wait-UninstallCompletion -InstallRoot $installRoot -ServiceName $serviceName

    $userPathAfter = Get-MachinePath
    if (Test-PathEntry -PathValue $userPathAfter -Expected $installRoot) {
        throw "Uninstaller left the application directory in the machine PATH."
    }
    foreach ($key in @($folderMenuKey, $backgroundMenuKey)) {
        if (Test-Path -LiteralPath $key) {
            throw "Uninstaller left a context menu key behind: $key"
        }
    }
    if (Get-ItemProperty -LiteralPath $startupRunKey -Name $startupValueName -ErrorAction SilentlyContinue) {
        throw "Uninstaller left the startup Run value behind: $startupValueName"
    }
    if (Test-Path -LiteralPath $userDataRoot) {
        throw "Uninstaller left ProgramData behind: $userDataRoot"
    }
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        throw "Uninstaller left the Watch Broker service installed: $serviceName"
    }
    if (Test-Path -LiteralPath $installRoot) {
        throw "Uninstaller left the application directory behind: $installRoot"
    }
    foreach ($key in @($toastClsidKey)) {
        if (Test-Path -LiteralPath $key) {
            throw "Uninstaller left Toast registration behind: $key"
        }
    }
    foreach ($name in @("Uninstall SunPack.lnk")) {
        foreach ($path in @(Get-StartMenuShortcutPaths -Name $name)) {
            if (Test-Path -LiteralPath $path) {
                throw "Uninstaller left a Start menu shortcut behind: $path"
            }
        }
    }
    foreach ($root in $startMenuRoots) {
        $directory = Join-Path $root "SunPack"
        if ((Test-Path -LiteralPath $directory -PathType Container) -and
            @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction SilentlyContinue).Count -gt 0) {
            throw "Uninstaller left Start menu entries behind: $directory"
        }
    }

    Write-Host "Windows installer smoke test passed." -ForegroundColor Green
} finally {
    if ($null -ne $uninstaller -and (Test-Path -LiteralPath $uninstaller.FullName)) {
        try {
            & $uninstaller.FullName /VERYSILENT /SUPPRESSMSGBOXES /NORESTART | Out-Null
        } catch {
        }
    }
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
        & sc.exe delete $serviceName | Out-Null
    }
    Remove-Item -LiteralPath $userDataRoot -Recurse -Force -ErrorAction SilentlyContinue
    Remove-ItemProperty -LiteralPath $startupRunKey -Name $startupValueName -ErrorAction SilentlyContinue
    $machinePathAfterCleanup = Get-MachinePath
    if (Test-PathEntry -PathValue $machinePathAfterCleanup -Expected $installRoot) {
        $cleanedPath = @(
            ([string]$machinePathAfterCleanup -split ';') |
                Where-Object { $_.Trim() -and -not $_.Trim().Equals($installRoot, [System.StringComparison]::OrdinalIgnoreCase) }
        ) -join ';'
        Set-ItemProperty -LiteralPath $systemEnvironmentKey -Name "Path" -Value $cleanedPath
    }
    Remove-ItemProperty -LiteralPath "HKLM:\Software\SunPack" -Name "PathAddedByInstaller" -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath "HKLM:\Software\SunPack" -Force -ErrorAction SilentlyContinue
    foreach ($key in @(
        $folderMenuKey,
        $backgroundMenuKey,
        "HKLM:\Software\Classes\SunPack.FolderContextMenu",
        "HKLM:\Software\Classes\SunPack.BackgroundContextMenu",
        (Split-Path -Parent $toastClsidKey)
    )) {
        Remove-Item -LiteralPath $key -Recurse -Force -ErrorAction SilentlyContinue
    }
    if ($null -ne $userDataBackup -and (Test-Path -LiteralPath $userDataBackup)) {
        Remove-Item -LiteralPath $userDataRoot -Recurse -Force -ErrorAction SilentlyContinue
        Move-Item -LiteralPath $userDataBackup -Destination $userDataRoot
    }
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}