param(
    [string]$AppPath,
    [string]$PythonPath,
    [string]$MenuText,
    [string]$IconPath,
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-Launcher {
    param(
        [string]$RepoRoot,
        [string]$PreferredAppPath,
        [string]$PreferredPythonPath
    )

    if ($PreferredAppPath) {
        $resolvedApp = (Resolve-Path -LiteralPath $PreferredAppPath).Path
        $appIcon = Resolve-SunPackIcon -RepoRoot $RepoRoot -FallbackPath $resolvedApp
        return @{
            Mode = "app"
            AppPath = $resolvedApp
            IconPath = $appIcon
        }
    }

    $exeCandidates = @(
        (Join-Path $RepoRoot "bin\sunpack.exe"),
        (Join-Path $RepoRoot "sunpack.exe"),
        (Join-Path $RepoRoot "dist\sunpack\sunpack.exe"),
        (Join-Path $RepoRoot "dist\sunpack.exe")
    )
    foreach ($candidate in $exeCandidates) {
        if (Test-Path -LiteralPath $candidate) {
            $resolvedExe = (Resolve-Path -LiteralPath $candidate).Path
            $appIcon = Resolve-SunPackIcon -RepoRoot $RepoRoot -FallbackPath $resolvedExe
            return @{
                Mode = "app"
                AppPath = $resolvedExe
                IconPath = $appIcon
            }
        }
    }

    $distRoot = Join-Path $RepoRoot "dist"
    $packagedCandidates = @()
    if (Test-Path -LiteralPath $distRoot) {
        $packagedCandidates = @(
            Get-ChildItem -LiteralPath $distRoot -Directory -Filter "sunpack-*" -ErrorAction SilentlyContinue |
                ForEach-Object { Join-Path $_.FullName "sunpack.exe" } |
                Where-Object { Test-Path -LiteralPath $_ }
        )
    }
    if ($packagedCandidates.Count -gt 1) {
        $listed = $packagedCandidates -join "`n  "
        throw "Multiple packaged SunPack executables were found. Pass -AppPath explicitly:`n  $listed"
    }
    if ($packagedCandidates.Count -eq 1) {
        $resolvedExe = (Resolve-Path -LiteralPath $packagedCandidates[0]).Path
        $appIcon = Resolve-SunPackIcon -RepoRoot $RepoRoot -FallbackPath $resolvedExe
        return @{
            Mode = "app"
            AppPath = $resolvedExe
            IconPath = $appIcon
        }
    }

    $defaultScript = Join-Path $RepoRoot "sunpack.py"
    if (-not (Test-Path -LiteralPath $defaultScript)) {
        throw "No usable script entry was found. Expected sunpack.py at the repository root."
    }
    $resolvedScript = (Resolve-Path -LiteralPath $defaultScript).Path

    $pythonCandidates = @()
    if ($PreferredPythonPath) {
        $pythonCandidates += $PreferredPythonPath
    }
    foreach ($commandName in @("python", "py")) {
        $command = Get-Command $commandName -ErrorAction SilentlyContinue
        if ($command) {
            $pythonCandidates += $command.Source
        }
    }
    $pythonCandidates = $pythonCandidates | Select-Object -Unique

    foreach ($candidate in $pythonCandidates) {
        if (Test-Path -LiteralPath $candidate) {
            $resolvedPython = (Resolve-Path -LiteralPath $candidate).Path
            $appIcon = Resolve-SunPackIcon -RepoRoot $RepoRoot -FallbackPath $resolvedPython
            return @{
                Mode = "python"
                AppPath = $resolvedPython
                ScriptPath = $resolvedScript
                IconPath = $appIcon
            }
        }
    }

    throw "No usable Python interpreter was found. Please pass -PythonPath explicitly."
}

function Resolve-SunPackIcon {
    param(
        [string]$RepoRoot,
        [string]$FallbackPath
    )

    $iconPath = Join-Path $RepoRoot "sunpack.ico"
    if (Test-Path -LiteralPath $iconPath) {
        return (Resolve-Path -LiteralPath $iconPath).Path
    }
    return $FallbackPath
}

function New-CommandString {
    param(
        [hashtable]$Launcher,
        [string]$TargetToken,
        [string]$OutDirToken,
        [bool]$PromptPasswords,
        [switch]$Recursive
    )

    $extractArgs = if ($PromptPasswords) { " --ask-pw" } else { "" }
    if ($Recursive) { $extractArgs += " --recursive" }
    if ($Launcher.Mode -eq "app") {
        return ('"{0}" extract "{1}" --out-dir "{2}"{3} --pause' -f $Launcher.AppPath, $TargetToken, $OutDirToken, $extractArgs)
    }

    return ('"{0}" "{1}" extract "{2}" --out-dir "{3}"{4} --pause' -f $Launcher.AppPath, $Launcher.ScriptPath, $TargetToken, $OutDirToken, $extractArgs)
}

function New-FileCommandString {
    param(
        [hashtable]$Launcher,
        [string]$TargetToken,
        [bool]$PromptPasswords
    )

    $passwordArg = if ($PromptPasswords) { " --ask-pw --deep-detect" } else { " --deep-detect" }
    if ($Launcher.Mode -eq "app") {
        return ('"{0}" extract "{1}"{2} --pause' -f $Launcher.AppPath, $TargetToken, $passwordArg)
    }

    return ('"{0}" "{1}" extract "{2}"{3} --pause' -f $Launcher.AppPath, $Launcher.ScriptPath, $TargetToken, $passwordArg)
}

function New-WatchCommandString {
    param(
        [hashtable]$Launcher,
        [string]$TargetToken,
        [switch]$Recursive
    )

    $watchArguments = @("watch", "add", $TargetToken, "--start")
    if ($Recursive) { $watchArguments += "--recursive" }
    if ($Launcher.Mode -ne "app") { $watchArguments = @($Launcher.ScriptPath) + $watchArguments }
    return New-HiddenStartProcessCommand -FilePath $Launcher.AppPath -ArgumentList $watchArguments
}

function New-WatchRemoveCommandString {
    param(
        [hashtable]$Launcher,
        [string]$TargetToken
    )

    if ($Launcher.Mode -eq "app") {
        return New-HiddenStartProcessCommand -FilePath $Launcher.AppPath -ArgumentList @("watch", "remove", $TargetToken)
    }

    return New-HiddenStartProcessCommand -FilePath $Launcher.AppPath -ArgumentList @($Launcher.ScriptPath, "watch", "remove", $TargetToken)
}

function New-HiddenStartProcessCommand {
    param(
        [string]$FilePath,
        [string[]]$ArgumentList
    )

    $quotedFilePath = ConvertTo-PowerShellSingleQuotedString -Value $FilePath
    $quotedArgs = ($ArgumentList | ForEach-Object { ConvertTo-PowerShellSingleQuotedString -Value $_ }) -join ","
    $command = "Start-Process -WindowStyle Hidden -FilePath $quotedFilePath -ArgumentList @($quotedArgs)"
    return ('"powershell.exe" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "{0}"' -f $command)
}

function ConvertTo-PowerShellSingleQuotedString {
    param([string]$Value)

    return "'" + ($Value -replace "'", "''") + "'"
}

function ConvertTo-RootSafeDirectoryToken {
    param([Parameter(Mandatory = $true)][string]$Token)

    # Explorer expands a drive root to a value ending in "\".  Quoting that
    # value directly ("D:\") makes the trailing slash escape the closing
    # quote under Windows argv rules.  Appending "\." preserves the directory
    # identity while ensuring the quoted argument never ends in a slash.  It
    # also works for normal directories and UNC share roots.
    return "$Token\."
}

function Set-ContextMenuParent {
    param(
        [string]$KeyPath,
        [string]$MenuLabel,
        [string]$IconValue,
        [string]$SubCommandsKey
    )

    $null = New-Item -Path $KeyPath -Force
    Set-Item -LiteralPath $KeyPath -Value $MenuLabel
    Set-ItemProperty -LiteralPath $KeyPath -Name "MUIVerb" -Value $MenuLabel
    Set-ItemProperty -LiteralPath $KeyPath -Name "Icon" -Value $IconValue
    Set-ItemProperty -LiteralPath $KeyPath -Name "ExtendedSubCommandsKey" -Value $SubCommandsKey
    Remove-ItemProperty -LiteralPath $KeyPath -Name "SubCommands" -ErrorAction SilentlyContinue
    # Rebuild our menus so re-registration cannot retain removed commands.
    foreach ($shellKey in @(
        (Join-Path $KeyPath "shell"),
        "HKLM:\Software\Classes\$SubCommandsKey\shell"
    )) {
        if (Test-Path -LiteralPath $shellKey) {
            Remove-Item -LiteralPath $shellKey -Recurse -Force
        }
    }
}

function Set-ContextMenuCommand {
    param(
        [string]$ParentKeyPath,
        [string]$CommandName,
        [string]$MenuLabel,
        [string]$CommandLine,
        [string]$IconValue
    )

    $keyPath = Join-Path (Join-Path $ParentKeyPath "shell") $CommandName
    $null = New-Item -Path $keyPath -Force
    Set-Item -LiteralPath $keyPath -Value $MenuLabel
    Set-ItemProperty -LiteralPath $keyPath -Name "MUIVerb" -Value $MenuLabel
    Set-ItemProperty -LiteralPath $keyPath -Name "Icon" -Value $IconValue
    $commandKey = Join-Path $keyPath "command"
    $null = New-Item -Path $commandKey -Force
    Set-Item -LiteralPath $commandKey -Value $CommandLine
}

function Get-MenuLanguage {
    param([string]$RepoRoot)

    $configPath = if ((Test-Path -LiteralPath (Join-Path $RepoRoot "bin\sunpack.exe") -PathType Leaf) -or
                      (Test-Path -LiteralPath (Join-Path $RepoRoot "sunpack.exe") -PathType Leaf)) {
        Join-Path $env:ProgramData "SunPack\sunpack_config.json"
    } else {
        Join-Path $RepoRoot "sunpack_config.json"
    }
    if (-not (Test-Path -LiteralPath $configPath)) {
        return "en"
    }

    try {
        $payload = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
        $language = [string]$payload.cli.language
        if ($language.Trim().ToLower().StartsWith("zh")) {
            return "zh"
        }
    } catch {
    }
    return "en"
}

function New-ChineseText {
    param([int[]]$CodePoints)

    return -join ($CodePoints | ForEach-Object { [char]$_ })
}

function Get-SubMenuTexts {
    param(
        [string]$Language,
        [ValidateSet("folder", "background", "file")][string]$Context
    )

    if ($Language -eq "zh") {
        $subject = switch ($Context) {
            "folder" { New-ChineseText @(0x8BE5, 0x76EE, 0x5F55, 0x4E0B, 0x6587, 0x4EF6) }
            "background" { New-ChineseText @(0x76EE, 0x5F55, 0x4E0B, 0x6587, 0x4EF6) }
            "file" { New-ChineseText @(0x8BE5, 0x6587, 0x4EF6) }
        }
        $directVerb = New-ChineseText @(0x89E3, 0x538B)
        $promptVerb = New-ChineseText @(0x8F93, 0x5165, 0x5BC6, 0x7801, 0x89E3, 0x538B)
        return @{
            Prompt = "$promptVerb$subject"
            Direct = "$directVerb$subject"
            RecursiveExtract = (New-ChineseText @(0x9012, 0x5F52)) + "$directVerb$subject"
            RecursiveWatch = New-ChineseText @(0x9012, 0x5F52, 0x76D1, 0x63A7, 0x6B64, 0x76EE, 0x5F55)
            Watch = New-ChineseText @(0x76D1, 0x63A7, 0x6B64, 0x76EE, 0x5F55)
            Unwatch = New-ChineseText @(0x53D6, 0x6D88, 0x76D1, 0x63A7, 0x6B64, 0x76EE, 0x5F55)
        }
    }

    $subject = if ($Context -eq "file") { "this file" } else { "files in this folder" }
    return @{
        Prompt = "Enter password to extract $subject"
        Direct = "Extract $subject"
        RecursiveExtract = "Recursively extract $subject"
        RecursiveWatch = "Watch this folder recursively"
        Watch = "Watch this folder"
        Unwatch = "Stop watching this folder"
    }
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$launcher = Resolve-Launcher -RepoRoot $repoRoot -PreferredAppPath $AppPath -PreferredPythonPath $PythonPath
$resolvedIconPath = if ($IconPath) { (Resolve-Path -LiteralPath $IconPath).Path } else { $launcher.IconPath }
$menuLanguage = Get-MenuLanguage -RepoRoot $repoRoot
$resolvedMenuText = if ($MenuText) { $MenuText } else { "sunpack" }

$folderKey = "HKLM:\Software\Classes\Directory\shell\SunPack"
$backgroundKey = "HKLM:\Software\Classes\Directory\Background\shell\SunPack"
$fileKey = "HKLM:\Software\Classes\*\shell\SunPack"
$folderSubCommandsName = "SunPack.FolderContextMenu"
$backgroundSubCommandsName = "SunPack.BackgroundContextMenu"
$fileSubCommandsName = "SunPack.FileContextMenu"
$folderSubCommandsKey = "HKLM:\Software\Classes\$folderSubCommandsName"
$backgroundSubCommandsKey = "HKLM:\Software\Classes\$backgroundSubCommandsName"
$fileSubCommandsKey = "HKLM:\Software\Classes\$fileSubCommandsName"
$folderMenuTexts = Get-SubMenuTexts -Language $menuLanguage -Context "folder"
$backgroundMenuTexts = Get-SubMenuTexts -Language $menuLanguage -Context "background"
$fileMenuTexts = Get-SubMenuTexts -Language $menuLanguage -Context "file"

$folderToken = ConvertTo-RootSafeDirectoryToken -Token "%1"
$backgroundToken = ConvertTo-RootSafeDirectoryToken -Token "%V"
$folderPromptCommand = New-CommandString -Launcher $launcher -TargetToken $folderToken -OutDirToken $folderToken -PromptPasswords $true
$folderDirectCommand = New-CommandString -Launcher $launcher -TargetToken $folderToken -OutDirToken $folderToken -PromptPasswords $false
$folderRecursiveExtractCommand = New-CommandString -Launcher $launcher -TargetToken $folderToken -OutDirToken $folderToken -PromptPasswords $false -Recursive
$folderWatchCommand = New-WatchCommandString -Launcher $launcher -TargetToken $folderToken
$folderRecursiveWatchCommand = New-WatchCommandString -Launcher $launcher -TargetToken $folderToken -Recursive
$folderUnwatchCommand = New-WatchRemoveCommandString -Launcher $launcher -TargetToken $folderToken
$backgroundPromptCommand = New-CommandString -Launcher $launcher -TargetToken $backgroundToken -OutDirToken $backgroundToken -PromptPasswords $true
$backgroundDirectCommand = New-CommandString -Launcher $launcher -TargetToken $backgroundToken -OutDirToken $backgroundToken -PromptPasswords $false
$backgroundRecursiveExtractCommand = New-CommandString -Launcher $launcher -TargetToken $backgroundToken -OutDirToken $backgroundToken -PromptPasswords $false -Recursive
$backgroundWatchCommand = New-WatchCommandString -Launcher $launcher -TargetToken $backgroundToken
$backgroundRecursiveWatchCommand = New-WatchCommandString -Launcher $launcher -TargetToken $backgroundToken -Recursive
$backgroundUnwatchCommand = New-WatchRemoveCommandString -Launcher $launcher -TargetToken $backgroundToken
$filePromptCommand = New-FileCommandString -Launcher $launcher -TargetToken "%1" -PromptPasswords $true
$fileDirectCommand = New-FileCommandString -Launcher $launcher -TargetToken "%1" -PromptPasswords $false

if ($DryRun) {
    $json = [pscustomobject]@{
        menu_text = $resolvedMenuText
        folder_prompt = $folderPromptCommand
        folder_direct = $folderDirectCommand
        folder_recursive_extract = $folderRecursiveExtractCommand
        folder_watch = $folderWatchCommand
        folder_recursive_watch = $folderRecursiveWatchCommand
        folder_unwatch = $folderUnwatchCommand
        background_prompt = $backgroundPromptCommand
        background_direct = $backgroundDirectCommand
        background_recursive_extract = $backgroundRecursiveExtractCommand
        background_watch = $backgroundWatchCommand
        background_recursive_watch = $backgroundRecursiveWatchCommand
        background_unwatch = $backgroundUnwatchCommand
        file_prompt = $filePromptCommand
        file_direct = $fileDirectCommand
        menu_labels = @{
            folder = @{ direct = $folderMenuTexts.Direct; prompt = $folderMenuTexts.Prompt; recursive_extract = $folderMenuTexts.RecursiveExtract; recursive_watch = $folderMenuTexts.RecursiveWatch }
            background = @{ direct = $backgroundMenuTexts.Direct; prompt = $backgroundMenuTexts.Prompt; recursive_extract = $backgroundMenuTexts.RecursiveExtract; recursive_watch = $backgroundMenuTexts.RecursiveWatch }
            file = @{ direct = $fileMenuTexts.Direct; prompt = $fileMenuTexts.Prompt }
        }
    } | ConvertTo-Json -Depth 5 -Compress
    # Windows PowerShell 5.1 may write redirected stdout using a legacy code page.
    # Emit ASCII-only JSON so localized menu labels survive without replacement.
    $json = [regex]::Replace($json, '[^\x00-\x7F]', [System.Text.RegularExpressions.MatchEvaluator]{
        param($match)
        '\u{0:X4}' -f [int][char]$match.Value
    })
    Write-Output $json
    return
}

Set-ContextMenuParent -KeyPath $folderKey -MenuLabel $resolvedMenuText -IconValue $resolvedIconPath -SubCommandsKey $folderSubCommandsName
Set-ContextMenuCommand -ParentKeyPath $folderSubCommandsKey -CommandName "DirectExtract" -MenuLabel $folderMenuTexts.Direct -CommandLine $folderDirectCommand -IconValue $resolvedIconPath
Set-ContextMenuCommand -ParentKeyPath $folderSubCommandsKey -CommandName "RecursiveExtract" -MenuLabel $folderMenuTexts.RecursiveExtract -CommandLine $folderRecursiveExtractCommand -IconValue $resolvedIconPath
Set-ContextMenuCommand -ParentKeyPath $folderSubCommandsKey -CommandName "PromptPassword" -MenuLabel $folderMenuTexts.Prompt -CommandLine $folderPromptCommand -IconValue $resolvedIconPath
Set-ContextMenuCommand -ParentKeyPath $folderSubCommandsKey -CommandName "WatchFolderRecursive" -MenuLabel $folderMenuTexts.RecursiveWatch -CommandLine $folderRecursiveWatchCommand -IconValue $resolvedIconPath
Set-ContextMenuCommand -ParentKeyPath $folderSubCommandsKey -CommandName "WatchFolder" -MenuLabel $folderMenuTexts.Watch -CommandLine $folderWatchCommand -IconValue $resolvedIconPath
Set-ContextMenuCommand -ParentKeyPath $folderSubCommandsKey -CommandName "UnwatchFolder" -MenuLabel $folderMenuTexts.Unwatch -CommandLine $folderUnwatchCommand -IconValue $resolvedIconPath
Set-ContextMenuParent -KeyPath $backgroundKey -MenuLabel $resolvedMenuText -IconValue $resolvedIconPath -SubCommandsKey $backgroundSubCommandsName
Set-ContextMenuCommand -ParentKeyPath $backgroundSubCommandsKey -CommandName "DirectExtract" -MenuLabel $backgroundMenuTexts.Direct -CommandLine $backgroundDirectCommand -IconValue $resolvedIconPath
Set-ContextMenuCommand -ParentKeyPath $backgroundSubCommandsKey -CommandName "RecursiveExtract" -MenuLabel $backgroundMenuTexts.RecursiveExtract -CommandLine $backgroundRecursiveExtractCommand -IconValue $resolvedIconPath
Set-ContextMenuCommand -ParentKeyPath $backgroundSubCommandsKey -CommandName "PromptPassword" -MenuLabel $backgroundMenuTexts.Prompt -CommandLine $backgroundPromptCommand -IconValue $resolvedIconPath
Set-ContextMenuCommand -ParentKeyPath $backgroundSubCommandsKey -CommandName "WatchFolder" -MenuLabel $backgroundMenuTexts.Watch -CommandLine $backgroundWatchCommand -IconValue $resolvedIconPath
Set-ContextMenuCommand -ParentKeyPath $backgroundSubCommandsKey -CommandName "WatchFolderRecursive" -MenuLabel $backgroundMenuTexts.RecursiveWatch -CommandLine $backgroundRecursiveWatchCommand -IconValue $resolvedIconPath
Set-ContextMenuCommand -ParentKeyPath $backgroundSubCommandsKey -CommandName "UnwatchFolder" -MenuLabel $backgroundMenuTexts.Unwatch -CommandLine $backgroundUnwatchCommand -IconValue $resolvedIconPath
Set-ContextMenuParent -KeyPath $fileKey -MenuLabel $resolvedMenuText -IconValue $resolvedIconPath -SubCommandsKey $fileSubCommandsName
Set-ContextMenuCommand -ParentKeyPath $fileSubCommandsKey -CommandName "PromptPassword" -MenuLabel $fileMenuTexts.Prompt -CommandLine $filePromptCommand -IconValue $resolvedIconPath
Set-ContextMenuCommand -ParentKeyPath $fileSubCommandsKey -CommandName "DirectExtract" -MenuLabel $fileMenuTexts.Direct -CommandLine $fileDirectCommand -IconValue $resolvedIconPath

Write-Host "Context menu registration completed" -ForegroundColor Green
Write-Host "Folder menu key:" $folderKey
Write-Host "Directory background key:" $backgroundKey
Write-Host "Folder submenu key:" $folderSubCommandsKey
Write-Host "Directory background submenu key:" $backgroundSubCommandsKey
Write-Host "Launch mode:" $launcher.Mode
if ($launcher.Mode -eq "app") {
    Write-Host "App path:" $launcher.AppPath
} else {
    Write-Host "Python path:" $launcher.AppPath
    Write-Host "Script path:" $launcher.ScriptPath
}
Write-Host ""
Write-Host ('You can now right-click a file, folder or directory background and choose the "{0}" submenu' -f $resolvedMenuText)
