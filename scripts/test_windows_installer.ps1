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

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$Arguments = @()
    )
    $process = Start-Process `
        -FilePath $FilePath `
        -ArgumentList $Arguments `
        -Wait `
        -PassThru `
        -NoNewWindow
    if ($process.ExitCode -ne 0) {
        throw "Command failed with exit code $($process.ExitCode): $FilePath $($Arguments -join ' ')"
    }
}

function Invoke-UninstallerChecked {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$Arguments = @(),
        [int]$TimeoutSeconds = 300
    )
    # Do not use Start-Process -Wait here. PowerShell 5.1 waits for the
    # uninstaller's entire descendant tree, which includes the replacement
    # Explorer process started after unregistering shell integrations.
    $process = Start-Process `
        -FilePath $FilePath `
        -ArgumentList $Arguments `
        -PassThru `
        -NoNewWindow
    if (-not $process.WaitForExit([Math]::Max(1, $TimeoutSeconds) * 1000)) {
        try {
            $process.Kill()
        } catch {
        }
        throw "Uninstaller timed out after $TimeoutSeconds seconds: $FilePath $($Arguments -join ' ')"
    }
    $process.WaitForExit()
    $exitCode = $process.ExitCode
    if ($null -ne $exitCode -and $exitCode -ne 0) {
        throw "Uninstaller failed with exit code ${exitCode}: $FilePath $($Arguments -join ' ')"
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

$resolvedInstaller = (Resolve-Path -LiteralPath $InstallerPath).Path
$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("sunpack-installer-smoke-" + $PID)
$installRoot = Join-Path $testRoot "SunPack"
$installLog = Join-Path $testRoot "install.log"
$uninstallLog = Join-Path $testRoot "uninstall.log"
$folderMenuKey = "HKCU:\Software\Classes\Directory\shell\SunPack"
$backgroundMenuKey = "HKCU:\Software\Classes\Directory\Background\shell\SunPack"
$startupRunKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$startupValueName = "SunPackWatchService"
$serviceName = "SunPackWatchBroker"
$userDataRoot = Join-Path $env:LOCALAPPDATA "SunPack"
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
    $installerNames = @(
        $entries |
            Where-Object { $_.Name -ine "SunPack Watch Notifications.lnk" } |
            Select-Object -ExpandProperty Name
    )
    if ($installerNames.Count -ne 1 -or $installerNames[0] -ne "Uninstall SunPack.lnk") {
        throw "Installer Start menu entries should contain only the uninstaller. Entries: $($installerNames -join ', ')"
    }
    foreach ($name in @("SunPack Command Prompt.lnk", "sunpack.exe.lnk")) {
        foreach ($path in @(Get-StartMenuShortcutPaths -Name $name)) {
            if (Test-Path -LiteralPath $path) {
                throw "Obsolete Start menu shortcut remains: $path"
            }
        }
    }
}

if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    throw "Installer smoke test requires the service to be absent: $serviceName"
}
if (Get-ItemProperty -LiteralPath $startupRunKey -Name $startupValueName -ErrorAction SilentlyContinue) {
    throw "Installer smoke test requires a clean startup state and will not overwrite an existing Run value: $startupValueName"
}

foreach ($key in @(
    $folderMenuKey,
    $backgroundMenuKey,
    "HKCU:\Software\Classes\SunPack.FolderContextMenu",
    "HKCU:\Software\Classes\SunPack.BackgroundContextMenu"
)) {
    if (Test-Path -LiteralPath $key) {
        throw "Installer smoke test requires a clean context-menu state and will not overwrite an existing key: $key"
    }
}

New-Item -ItemType Directory -Path $testRoot -Force | Out-Null
try {
    if (Test-Path -LiteralPath $userDataRoot) {
        $userDataBackup = Join-Path $env:LOCALAPPDATA ("SunPack.installer-test-backup-" + [guid]::NewGuid().ToString("N"))
        $resolvedDataRoot = [System.IO.Path]::GetFullPath($userDataRoot)
        $resolvedBackup = [System.IO.Path]::GetFullPath($userDataBackup)
        $localAppDataRoot = [System.IO.Path]::GetFullPath($env:LOCALAPPDATA).TrimEnd('\') + '\'
        if (-not $resolvedDataRoot.StartsWith($localAppDataRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
            -not $resolvedBackup.StartsWith($localAppDataRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to move user data outside LocalAppData."
        }
        Move-Item -LiteralPath $userDataRoot -Destination $userDataBackup
    }

    Invoke-Checked -FilePath $resolvedInstaller -Arguments @(
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
    if (-not (Test-Path -LiteralPath $builtinPasswordsPath)) {
        throw "Installed builtin password file was not found: $builtinPasswordsPath"
    }
    if (-not (Test-Path -LiteralPath $brokerPath)) {
        throw "Installed Watch Broker executable was not found: $brokerPath"
    }
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
    Invoke-Checked -FilePath $appPath -Arguments @("--help")

    $userPath = [string](Get-ItemProperty -LiteralPath "HKCU:\Environment" -Name "Path" -ErrorAction SilentlyContinue).Path
    if (-not (Test-PathEntry -PathValue $userPath -Expected $installRoot)) {
        throw "Installer did not add the application directory to the current user's PATH."
    }
    foreach ($key in @($folderMenuKey, $backgroundMenuKey)) {
        if (-not (Test-Path -LiteralPath $key)) {
            throw "Installer did not register the expected context menu key: $key"
        }
    }
    $directCommandKey = "HKCU:\Software\Classes\SunPack.FolderContextMenu\shell\DirectExtract\command"
    $directCommand = [string](Get-Item -LiteralPath $directCommandKey).GetValue("")
    if ($directCommand -notlike "*$appPath*") {
        throw "Context menu command does not reference the installed executable: $directCommand"
    }
    $startupCommand = [string](Get-ItemProperty -LiteralPath $startupRunKey -Name $startupValueName).$startupValueName
    # The runtime serializes the Run value through subprocess.list2cmdline, which quotes an
    # argument only when it contains a space or a tab. The smoke-test install root lives under
    # %TEMP% and carries no whitespace, so the executable stays unquoted there, while an
    # install root such as "C:\Program Files\SunPack" is quoted.
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

    Invoke-Checked -FilePath $appPath -Arguments @("--persistent-shutdown")
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
    Invoke-UnelevatedChecked -FilePath $runtimeAppPath -Arguments @($runtimeIdentity, "watch", "start")

    $watchRoot = Join-Path $testRoot "watch-root"
    New-Item -ItemType Directory -Path $watchRoot -Force | Out-Null
    $watchRootsContent = "$watchRoot`n"
    Set-Content -LiteralPath $watchRootsPath -Value $watchRootsContent -Encoding UTF8 -NoNewline
    $builtinPasswordsContent = "installer-smoke-user-password`n"
    Set-Content -LiteralPath $builtinPasswordsPath -Value $builtinPasswordsContent -Encoding UTF8 -NoNewline
    $staleUpgradeMarker = Join-Path $installRoot "stale-upgrade-marker.json"
    Set-Content -LiteralPath $staleUpgradeMarker -Value "stale" -Encoding UTF8
    $staleConfigDir = Join-Path $installRoot "config"
    New-Item -ItemType Directory -Path $staleConfigDir -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $staleConfigDir "old-settings.json") -Value "stale" -Encoding UTF8
    Invoke-Checked -FilePath $resolvedInstaller -Arguments @(
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
    if ($builtinPasswordsAfterUpgrade -ne $builtinPasswordsContent) {
        throw "Upgrade install overwrote the existing builtin password file: $builtinPasswordsPath"
    }
    if (Test-Path -LiteralPath $staleUpgradeMarker) {
        throw "Upgrade install left stale application data behind: $staleUpgradeMarker"
    }
    if (Test-Path -LiteralPath $staleConfigDir) {
        throw "Upgrade install left stale configuration data behind: $staleConfigDir"
    }
    Assert-SunPackStartMenu
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
    Remove-Item -LiteralPath $watchRootsPath -Force
    Remove-Item -LiteralPath $builtinPasswordsPath -Force
    $watchStateDir = Join-Path $userDataRoot ".sunpack_watch"
    New-Item -ItemType Directory -Path $watchStateDir -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $watchStateDir "watch.stop") -Value "installer-smoke" -Encoding UTF8
    $localSunPackCache = Join-Path $env:LOCALAPPDATA "SunPack\cache"
    New-Item -ItemType Directory -Path $localSunPackCache -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $localSunPackCache "machine_probe.json") -Value "{}" -Encoding UTF8
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

    $userPathAfter = [string](Get-ItemProperty -LiteralPath "HKCU:\Environment" -Name "Path" -ErrorAction SilentlyContinue).Path
    if (Test-PathEntry -PathValue $userPathAfter -Expected $installRoot) {
        throw "Uninstaller left the application directory in the current user's PATH."
    }
    foreach ($key in @($folderMenuKey, $backgroundMenuKey)) {
        if (Test-Path -LiteralPath $key) {
            throw "Uninstaller left a context menu key behind: $key"
        }
    }
    if (Get-ItemProperty -LiteralPath $startupRunKey -Name $startupValueName -ErrorAction SilentlyContinue) {
        throw "Uninstaller left the startup Run value behind: $startupValueName"
    }
    if (Test-Path -LiteralPath $watchStateDir) {
        throw "Uninstaller left the watch state directory behind: $watchStateDir"
    }
    if (Test-Path -LiteralPath $localSunPackCache) {
        throw "Uninstaller left the local SunPack cache behind: $localSunPackCache"
    }
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        throw "Uninstaller left the Watch Broker service installed: $serviceName"
    }
    if (Test-Path -LiteralPath $installRoot) {
        throw "Uninstaller left the application directory behind: $installRoot"
    }
    foreach ($name in @(
        "SunPack Watch Notifications.lnk",
        "SunPack Command Prompt.lnk",
        "Uninstall SunPack.lnk",
        "sunpack.exe.lnk"
    )) {
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
    foreach ($key in @(
        $folderMenuKey,
        $backgroundMenuKey,
        "HKCU:\Software\Classes\SunPack.FolderContextMenu",
        "HKCU:\Software\Classes\SunPack.BackgroundContextMenu"
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
