[CmdletBinding()]
param(
    [switch]$SkipTests,
    [switch]$Clean,
    [switch]$NoPause,
    # Manual build verification only; tagged releases keep Cargo LTO enabled.
    [switch]$FastBuild,
    [ValidateRange(1, 64)]
    [int]$BuildJobs = 4,
    [string]$Version,
    [string]$InnoCompilerPath,
    [ValidateSet("x64", "arm64")]
    [string]$Arch = "x64"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$interactivePrompting = -not $NoPause -and -not [Console]::IsInputRedirected
$promptForAcceptanceTests = ($PSBoundParameters.Count -eq 0) -and $interactivePrompting

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Wait-BeforeBuildExit {
    if ($NoPause) {
        return
    }
    Write-Host ""
    Write-Host "Press Enter to exit..." -ForegroundColor Cyan
    try {
        $null = Read-Host
    } catch {
        # Never let the pause path hide the original build failure.
    }
}

function Remove-IfExists {
    param([string]$LiteralPath)
    if (Test-Path -LiteralPath $LiteralPath) {
        Remove-Item -LiteralPath $LiteralPath -Recurse -Force
    }
}

function Wait-ExecutableExit {
    param(
        [Parameter(Mandatory = $true)][string]$ExecutablePath,
        [int]$TimeoutSeconds = 15
    )

    $expectedPath = ConvertTo-NormalizedFullPath -Path $ExecutablePath
    $executableName = [System.IO.Path]::GetFileName($ExecutablePath).Replace("'", "''")
    $deadline = (Get-Date).AddSeconds([Math]::Max(1, $TimeoutSeconds))
    do {
        $matching = @(
            Get-CimInstance Win32_Process -Filter "Name='$executableName'" -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.ExecutablePath -and
                    (ConvertTo-NormalizedFullPath -Path $_.ExecutablePath) -eq $expectedPath
                }
        )
        if ($matching.Count -eq 0) {
            return
        }
        Start-Sleep -Milliseconds 100
    } while ((Get-Date) -lt $deadline)

    $processIds = ($matching | ForEach-Object ProcessId) -join ", "
    throw "Executable did not exit within $TimeoutSeconds seconds: $ExecutablePath (PID: $processIds)"
}

function Wait-FileReadyForPromotion {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [int]$TimeoutSeconds = 15
    )

    $deadline = (Get-Date).AddSeconds([Math]::Max(1, $TimeoutSeconds))
    do {
        $stream = $null
        try {
            $stream = [System.IO.File]::Open(
                $LiteralPath,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::ReadWrite,
                [System.IO.FileShare]::None
            )
            return
        } catch [System.IO.IOException] {
        } catch [System.UnauthorizedAccessException] {
        } finally {
            if ($null -ne $stream) {
                $stream.Dispose()
            }
        }
        Start-Sleep -Milliseconds 100
    } while ((Get-Date) -lt $deadline)

    throw "Compiled installer remained locked for $TimeoutSeconds seconds: $LiteralPath"
}

function Assert-PathExists {
    param(
        [string]$LiteralPath,
        [string]$Description
    )
    if (-not (Test-Path -LiteralPath $LiteralPath)) {
        throw "$Description not found: $LiteralPath"
    }
}

function Assert-PathMissing {
    param(
        [string]$LiteralPath,
        [string]$Description
    )
    if (Test-Path -LiteralPath $LiteralPath) {
        throw "$Description should not exist: $LiteralPath"
    }
}


function Assert-CommandExists {
    param(
        [string]$Command,
        [string]$Description
    )
    if (-not (Get-Command $Command -ErrorAction SilentlyContinue)) {
        throw "$Description not found in PATH: $Command"
    }
}

function Get-ProcessBuildArch {
    $arch = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString().ToLowerInvariant()
    switch ($arch) {
        "x64" { return "x64" }
        "arm64" { return "arm64" }
        default { return $arch }
    }
}

function Get-CMakePlatform {
    param([string]$BuildArch)
    switch ($BuildArch) {
        "x64" { return "x64" }
        "arm64" { return "ARM64" }
    }
    throw "Unsupported build architecture: $BuildArch"
}

function Get-RustTarget {
    param([string]$BuildArch)
    switch ($BuildArch) {
        "x64" { return "x86_64-pc-windows-msvc" }
        "arm64" { return "aarch64-pc-windows-msvc" }
    }
    throw "Unsupported build architecture: $BuildArch"
}

function Get-ExpectedPeMachine {
    param([string]$BuildArch)
    switch ($BuildArch) {
        "x64" { return 0x8664 }
        "arm64" { return 0xAA64 }
    }
    throw "Unsupported build architecture: $BuildArch"
}

function Get-PeMachine {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    $stream = [System.IO.File]::Open($LiteralPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        if ($stream.Length -lt 0x40) {
            throw "File is too small to be a PE image: $LiteralPath"
        }
        $reader = [System.IO.BinaryReader]::new($stream)
        try {
            if ($reader.ReadUInt16() -ne 0x5A4D) {
                throw "Missing MZ signature: $LiteralPath"
            }
            $stream.Seek(0x3C, [System.IO.SeekOrigin]::Begin) | Out-Null
            $peOffset = $reader.ReadUInt32()
            if ($peOffset + 6 -gt $stream.Length) {
                throw "Invalid PE header offset: $LiteralPath"
            }
            $stream.Seek([int64]$peOffset, [System.IO.SeekOrigin]::Begin) | Out-Null
            if ($reader.ReadUInt32() -ne 0x00004550) {
                throw "Missing PE signature: $LiteralPath"
            }
            return [int]$reader.ReadUInt16()
        } finally {
            $reader.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
}

function Get-PeMachineName {
    param([int]$Machine)
    switch ($Machine) {
        0x014C { return "x86" }
        0x8664 { return "x64" }
        0xAA64 { return "arm64" }
        default { return ("0x{0:X4}" -f $Machine) }
    }
}

function Assert-PeMachine {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)][string]$BuildArch,
        [string]$Description = "PE image"
    )

    Assert-PathExists -LiteralPath $LiteralPath -Description $Description
    $expected = Get-ExpectedPeMachine -BuildArch $BuildArch
    $actual = Get-PeMachine -LiteralPath $LiteralPath
    if ($actual -ne $expected) {
        throw ("{0} architecture mismatch: expected {1}, got {2}: {3}" -f $Description, $BuildArch, (Get-PeMachineName -Machine $actual), $LiteralPath)
    }
    Write-Host ("{0} architecture: {1} ({2})" -f $Description, $BuildArch, $LiteralPath) -ForegroundColor Green
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

function Get-PeSubsystem {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    $stream = [System.IO.File]::Open($LiteralPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        $reader = [System.IO.BinaryReader]::new($stream)
        try {
            $stream.Seek(0x3C, [System.IO.SeekOrigin]::Begin) | Out-Null
            $peOffset = $reader.ReadUInt32()
            $stream.Seek([int64]$peOffset + 24 + 68, [System.IO.SeekOrigin]::Begin) | Out-Null
            return [int]$reader.ReadUInt16()
        } finally {
            $reader.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
}

function Assert-PeSubsystem {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)][int]$Expected,
        [string]$Description = "PE image"
    )

    $actual = Get-PeSubsystem -LiteralPath $LiteralPath
    if ($actual -ne $Expected) {
        throw ("{0} subsystem mismatch: expected {1}, got {2}: {3}" -f $Description, $Expected, $actual, $LiteralPath)
    }
}

function Get-InnoSetupCompiler {
    param([string]$PreferredPath)

    $candidates = @()
    if ($PreferredPath) {
        $candidates += $PreferredPath
    }
    $command = Get-Command "ISCC.exe" -ErrorAction SilentlyContinue
    if ($command) {
        $candidates += $command.Source
    }
    foreach ($root in @(${env:ProgramFiles(x86)}, $env:ProgramFiles, $env:LOCALAPPDATA)) {
        if ($root) {
            $candidates += (Join-Path $root "Inno Setup 6\ISCC.exe")
            $candidates += (Join-Path $root "Programs\Inno Setup 6\ISCC.exe")
        }
    }
    foreach ($candidate in ($candidates | Select-Object -Unique)) {
        if ($candidate -and (Test-Path -LiteralPath $candidate)) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    throw "Inno Setup 6 compiler (ISCC.exe) was not found. Install JRSoftware.InnoSetup or pass -InnoCompilerPath."
}


function Invoke-WithRetry {
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,
        [string]$Description = "operation",
        [int]$MaxAttempts = 5,
        [int]$DelaySeconds = 2
    )

    $attempt = 0
    while ($true) {
        $attempt += 1
        try {
            & $ScriptBlock
            return
        } catch {
            if ($attempt -ge $MaxAttempts) {
                throw
            }
            Write-Warning ("{0} failed on attempt {1}/{2}: {3}" -f $Description, $attempt, $MaxAttempts, $_.Exception.Message)
            $retryDelaySeconds = [Math]::Min(30, [Math]::Max(1, $DelaySeconds) * $attempt)
            Start-Sleep -Seconds $retryDelaySeconds
        }
    }
}

function Get-ReleaseVersion {
    param(
        [string]$ExplicitVersion,
        [string]$RepoRoot
    )

    if ($ExplicitVersion) {
        return $ExplicitVersion
    }

    try {
        $gitOutput = & git -C $RepoRoot describe --tags --always 2>$null
        $gitVersion = (($gitOutput | Out-String).Trim())
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($gitVersion)) {
            return $gitVersion
        }
    } catch {
    }

    return (Get-Date -Format "yyyyMMdd-HHmmss")
}

function Get-GitCommit {
    param([string]$RepoRoot)
    try {
        $gitOutput = & git -C $RepoRoot rev-parse --short HEAD 2>$null
        $commit = (($gitOutput | Out-String).Trim())
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($commit)) {
            return $commit
        }
    } catch {
    }
    return "unknown"
}

function Confirm-AcceptanceTests {
    while ($true) {
        $rawAnswer = Read-Host "Run acceptance tests before building? [Y/n]"
        $answer = if ($null -eq $rawAnswer) { "" } else { $rawAnswer.Trim() }
        if ($answer -eq "" -or $answer -match "^(?i:y|yes)$") {
            return $true
        }
        if ($answer -match "^(?i:n|no)$") {
            return $false
        }
        Write-Host "Please answer Y or N" -ForegroundColor Yellow
    }
}


function Copy-IfExists {
    param(
        [string]$Source,
        [string]$Destination
    )
    if (Test-Path -LiteralPath $Source) {
        Copy-Item -LiteralPath $Source -Destination $Destination -Force
    }
}

function Get-PackagedRuntimeToolNames {
    return @(
        "sunpack_sevenzip_worker.exe",
        "sunpack_toast.dll"
    )
}

function Assert-PackagedRuntimeTools {
    param([Parameter(Mandatory = $true)][string]$PackageRoot)

    $toolsPath = Join-Path $PackageRoot "tools"
    Assert-PathExists -LiteralPath $toolsPath -Description "Packaged runtime tools directory"
    $expected = @(Get-PackagedRuntimeToolNames)
    $entries = @(Get-ChildItem -LiteralPath $toolsPath -Force)
    $unexpected = @($entries | Where-Object { $_.Name -notin $expected })
    if ($unexpected.Count -gt 0) {
        throw ("Unexpected files in the packaged runtime tools directory: " + (($unexpected | ForEach-Object FullName) -join ", "))
    }
    foreach ($name in $expected) {
        Assert-PathExists -LiteralPath (Join-Path $toolsPath $name) -Description "Packaged runtime tool $name"
    }
}

try {
. (Join-Path $PSScriptRoot "build_native.ps1")
$repoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $repoRoot
$buildArch = $Arch.ToLowerInvariant()
$processArch = Get-ProcessBuildArch
$rustTarget = Get-RustTarget -BuildArch $buildArch

Write-Step "Environment preflight"
if ($env:OS -ne "Windows_NT") {
    throw "This build script only supports Windows."
}
Write-Host "Requested architecture: $buildArch"
Write-Host "Build system: Cargo and CMake"
$venvPath = Join-Path $repoRoot ".venv"
$venvScripts = Join-Path $venvPath "Scripts"
$installerScriptPath = Join-Path $repoRoot "installer\SunPack.iss"
$iconPath = Join-Path $repoRoot "sunpack.ico"
$applicationManifestPath = Join-Path $repoRoot "sunpack.manifest"
$nativeCrateRoot = Join-Path $repoRoot "sunpack\sunpack_runtime"
$nativeCargoToml = Join-Path $nativeCrateRoot "Cargo.toml"
$nativeWorkspaceLock = Join-Path $repoRoot "sunpack\Cargo.lock"
$watchBrokerCargoToml = Join-Path $repoRoot "sunpack\sunpack_watch_broker\Cargo.toml"
$watchBrokerBuildPath = Get-WatchBrokerBuildPath -RepoRoot $repoRoot -Arch $buildArch -BuildProfile release
$sevenZipWrapperRoot = Join-Path $repoRoot "sunpack\sevenzip_bridge"
$sevenZipWrapperBuildDir = Get-NativeBuildDirectory -RepoRoot $repoRoot -Arch $buildArch -BuildProfile release -Component sevenzip_bridge
$toastHostRoot = Join-Path $repoRoot "sunpack\toast_host"
$toastHostBuildDir = Get-NativeBuildDirectory -RepoRoot $repoRoot -Arch $buildArch -BuildProfile release -Component toast_host
$sevenZipWorkerPath = Join-Path $sevenZipWrapperBuildDir "Release\sunpack_sevenzip_worker.exe"
$toastHostPath = Join-Path $toastHostBuildDir "Release\sunpack_toast.dll"
$launcherBuildPath = Join-Path $sevenZipWrapperBuildDir "Release\sunpack_launcher.exe"
$distRoot = Join-Path $repoRoot "dist"
$buildRoot = Join-Path $repoRoot "build"
$releaseRoot = Join-Path $repoRoot "release"
$distFolderName = "sunpack-" + $buildArch
$appExeName = "sunpack.exe"
$runtimeExeName = "sunpack-runtime.exe"
$distAppRoot = Join-Path $distRoot $distFolderName
$distExePath = Join-Path $distAppRoot $appExeName
$distRuntimeExePath = Join-Path $distAppRoot $runtimeExeName
$distToolsRoot = Join-Path $distAppRoot "tools"
$distServiceRoot = Join-Path $distAppRoot "service"
$distWatchBrokerPath = Join-Path $distServiceRoot "sunpack-watch-broker.exe"
$distLicenseBundlePath = Join-Path $distAppRoot "THIRD_PARTY_LICENSES.txt"
$versionValue = Get-ReleaseVersion -ExplicitVersion $Version -RepoRoot $repoRoot
$releaseInstallerName = "sunpack-windows-{0}-{1}-setup.exe" -f $buildArch, $versionValue
$releaseInstallerPath = Join-Path $releaseRoot $releaseInstallerName
$runAcceptanceTests = -not $SkipTests

if ($promptForAcceptanceTests) {
    $runAcceptanceTests = Confirm-AcceptanceTests
}
$runAcceptanceTests = $runAcceptanceTests -and $processArch -eq $buildArch

Assert-PathExists -LiteralPath $installerScriptPath -Description "Inno Setup installer script"
$innoCompiler = Get-InnoSetupCompiler -PreferredPath $InnoCompilerPath
Assert-PathExists -LiteralPath $iconPath -Description "SunPack icon"
Assert-PathExists -LiteralPath $applicationManifestPath -Description "Windows application manifest"
Assert-PathExists -LiteralPath $nativeCargoToml -Description "sunpack_runtime Cargo manifest"
Assert-PathExists -LiteralPath $nativeWorkspaceLock -Description "native Rust workspace lockfile"
Assert-PathExists -LiteralPath $watchBrokerCargoToml -Description "SunPack Watch Broker Cargo manifest"
Assert-PathExists -LiteralPath (Join-Path $sevenZipWrapperRoot "CMakeLists.txt") -Description "7z wrapper CMake project"
Assert-PathExists -LiteralPath (Join-Path $toastHostRoot "CMakeLists.txt") -Description "toast CMake project"
Assert-CommandExists -Command "cargo" -Description "Rust toolchain"

if ($Clean) {
    Write-Step "Cleaning native build outputs"
    $rustBuildDir = Get-RustBuildDirectory -RepoRoot $repoRoot -Arch $buildArch -BuildProfile release
    foreach ($output in @($rustBuildDir, $sevenZipWrapperBuildDir, $toastHostBuildDir)) {
        $fullOutput = [IO.Path]::GetFullPath($output)
        if (-not $fullOutput.StartsWith(([IO.Path]::GetFullPath($repoRoot) + "\"), [StringComparison]::OrdinalIgnoreCase)) {
            throw "Build output is outside the repository: $output"
        }
        Remove-IfExists -LiteralPath $fullOutput
    }
}

$cmakeCommand = Get-CMakeCommand -VenvScripts $venvScripts
$ctestCommand = Get-CTestCommand -VenvScripts $venvScripts

Write-Step "Cleaning previous build outputs"
$resolvedDistApp = [IO.Path]::GetFullPath($distAppRoot)
$resolvedDistRoot = [IO.Path]::GetFullPath($distRoot) + "\"
if (-not $resolvedDistApp.StartsWith($resolvedDistRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Package output is outside its distribution directory: $resolvedDistApp"
}
Remove-IfExists -LiteralPath $resolvedDistApp
New-Item -ItemType Directory -Path $distAppRoot -Force | Out-Null
New-Item -ItemType Directory -Path $releaseRoot -Force | Out-Null

Write-Step "Building Rust runtime and Windows Watch Broker"
$cargoArgs = @(
    "build", "--locked", "--manifest-path", (Join-Path $repoRoot "sunpack\Cargo.toml"),
    "--release", "--target", $rustTarget, "--jobs", [string]$BuildJobs,
    "-p", "sunpack-runtime", "-p", "sunpack-watch-broker",
    "--bin", "sunpack-runtime", "--bin", "sunpack-watch-broker"
)
if ($runAcceptanceTests) {
    $cargoArgs += @("--example", "real_fixture")
}
if ($FastBuild) {
    $cargoArgs += @("--config", "profile.release.lto=false", "--config", "profile.release.codegen-units=16")
}
Invoke-Native -FilePath "cargo" -Arguments $cargoArgs
$runtimeBuildPath = Get-SunPackRuntimeBuildPath -RepoRoot $repoRoot -Arch $buildArch -BuildProfile release
Assert-PathExists -LiteralPath $runtimeBuildPath -Description "SunPack runtime executable"
Assert-PathExists -LiteralPath $watchBrokerBuildPath -Description "SunPack Watch Broker executable"
Assert-PeMachine -LiteralPath $watchBrokerBuildPath -BuildArch $buildArch -Description "SunPack Watch Broker executable"

Build-SevenZipWorker -CMakeCommand $cmakeCommand -CTestCommand $ctestCommand -WrapperRoot $sevenZipWrapperRoot -BuildDir $sevenZipWrapperBuildDir -BuildArch $buildArch -BuildProfile release
$nativeLinkerEntry = @(Get-Content -LiteralPath (Join-Path $sevenZipWrapperBuildDir "CMakeCache.txt") |
    Where-Object { $_ -like "CMAKE_LINKER:FILEPATH=*" })
if ($nativeLinkerEntry.Count -ne 1) {
    throw "Cannot locate the native linker for the Watch Broker CRT dependency check."
}
$nativeLinker = $nativeLinkerEntry[0].Substring("CMAKE_LINKER:FILEPATH=".Length)
foreach ($executable in @($runtimeBuildPath, $watchBrokerBuildPath)) {
    Invoke-Native -FilePath $cmakeCommand -Arguments @(
        "-DLINKER=$nativeLinker", "-DBINARY=$executable",
        "-P", (Join-Path $sevenZipWrapperRoot "tests\static_runtime.cmake")
    )
}
Build-ToastLibrary -CMakeCommand $cmakeCommand -CTestCommand $ctestCommand -SourceRoot $toastHostRoot -BuildDir $toastHostBuildDir -BuildArch $buildArch -BuildProfile release
Assert-PathExists -LiteralPath $sevenZipWorkerPath -Description "Bundled 7z worker executable"
Assert-PeMachine -LiteralPath $sevenZipWorkerPath -BuildArch $buildArch -Description "Built 7z worker executable"
Assert-PeMachine -LiteralPath $launcherBuildPath -BuildArch $buildArch -Description "Built SunPack launcher executable"
Assert-PeMachine -LiteralPath $toastHostPath -BuildArch $buildArch -Description "Built toast DLL"
Write-Step "Building Core UI management panel"
$guiBuildDir = Join-Path $repoRoot (".cache\gui-" + $buildArch)
& (Join-Path $repoRoot "scripts\build_gui.ps1") -Arch $buildArch -CMakeCommand $cmakeCommand -BuildDir $guiBuildDir -Jobs $BuildJobs -SkipTests:$SkipTests -ApplicationOnly:$SkipTests

Write-Step "Staging native executables"
Copy-Item -LiteralPath $runtimeBuildPath -Destination $distRuntimeExePath -Force
Copy-Item -LiteralPath (Join-Path $guiBuildDir "Release\SunPackGUI.exe") -Destination (Join-Path $distAppRoot "SunPackGUI.exe") -Force
Assert-PeMachine -LiteralPath (Join-Path $distAppRoot "SunPackGUI.exe") -BuildArch $buildArch -Description "Packaged GUI manager"
Assert-PeSubsystem -LiteralPath (Join-Path $distAppRoot "SunPackGUI.exe") -Expected 2 -Description "Packaged GUI manager"
Copy-Item -LiteralPath $launcherBuildPath -Destination $distExePath -Force
New-Item -ItemType Directory -Path $distServiceRoot -Force | Out-Null
Copy-Item -LiteralPath $watchBrokerBuildPath -Destination $distWatchBrokerPath -Force

Write-Step "Validating packaged outputs"
Assert-PathExists -LiteralPath $distExePath -Description "Packaged sunpack executable"
Assert-PathExists -LiteralPath $distRuntimeExePath -Description "Packaged SunPack runtime executable"
Assert-PathExists -LiteralPath $distWatchBrokerPath -Description "Packaged SunPack Watch Broker service"
Assert-PeMachine -LiteralPath $distExePath -BuildArch $buildArch -Description "Packaged sunpack executable"
Assert-PeMachine -LiteralPath $distRuntimeExePath -BuildArch $buildArch -Description "Packaged SunPack runtime executable"
Assert-PeMachine -LiteralPath $distWatchBrokerPath -BuildArch $buildArch -Description "Packaged SunPack Watch Broker service"
Assert-PeSubsystem -LiteralPath $distExePath -Expected 3 -Description "Packaged sunpack executable"
Assert-PeSubsystem -LiteralPath $distRuntimeExePath -Expected 2 -Description "Packaged shared SunPack runtime executable"
Assert-PathMissing -LiteralPath (Join-Path $distAppRoot "sunpack-watch.exe") -Description "Retired duplicate watch executable"

Write-Step "Adding release metadata and helper scripts"
$distPasswordPath = Join-Path $distAppRoot "builtin_passwords.json"
$distConfigPath = Join-Path $distAppRoot "sunpack_config.json"
$distWatchRootsPath = Join-Path $distAppRoot "sunpack_watch_roots.txt"
$distAdvancedConfigPath = Join-Path $distAppRoot "sunpack_advanced_config.json"
$distIconPath = Join-Path $distAppRoot "sunpack.ico"
Copy-Item -LiteralPath (Join-Path $repoRoot "builtin_passwords.json") -Destination $distPasswordPath -Force
Copy-Item -LiteralPath (Join-Path $repoRoot "sunpack_config.json") -Destination $distConfigPath -Force
Copy-IfExists -Source (Join-Path $repoRoot "sunpack_watch_roots.txt") -Destination $distWatchRootsPath
Copy-Item -LiteralPath $iconPath -Destination $distIconPath -Force
Copy-IfExists -Source (Join-Path $repoRoot "sunpack_advanced_config.json") -Destination $distAdvancedConfigPath
New-Item -ItemType Directory -Path $distToolsRoot | Out-Null
Copy-Item -LiteralPath $sevenZipWorkerPath, $toastHostPath -Destination $distToolsRoot -Force

& (Join-Path $repoRoot "scripts\generate_license_bundle.ps1") -RepoRoot $repoRoot `
    -GuiLicenseRoot (Join-Path $guiBuildDir "licenses") -OutputPath $distLicenseBundlePath -Target $rustTarget

$distScriptsRoot = Join-Path $distAppRoot "scripts"
New-Item -ItemType Directory -Path $distScriptsRoot -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $repoRoot "scripts\upgrade_config.ps1") -Destination (Join-Path $distScriptsRoot "upgrade_config.ps1") -Force
Copy-Item -LiteralPath (Join-Path $repoRoot "scripts\initialize_config_language.ps1") -Destination (Join-Path $distScriptsRoot "initialize_config_language.ps1") -Force
Copy-Item -LiteralPath (Join-Path $repoRoot "scripts\register_context_menu.ps1") -Destination (Join-Path $distScriptsRoot "register_context_menu.ps1") -Force
Copy-Item -LiteralPath (Join-Path $repoRoot "scripts\unregister_context_menu.ps1") -Destination (Join-Path $distScriptsRoot "unregister_context_menu.ps1") -Force
Copy-Item -LiteralPath (Join-Path $repoRoot "scripts\wait_sunpack_runtime_exit.ps1") -Destination (Join-Path $distScriptsRoot "wait_sunpack_runtime_exit.ps1") -Force

Assert-PathExists -LiteralPath $distPasswordPath -Description "External password file"
Assert-PathExists -LiteralPath $distConfigPath -Description "External config file"
Assert-PathExists -LiteralPath $distIconPath -Description "External icon file"
Assert-PackagedRuntimeTools -PackageRoot $distAppRoot
Assert-PathExists -LiteralPath $distLicenseBundlePath -Description "Consolidated license and third-party notices"
Assert-PathMissing -LiteralPath (Join-Path $distToolsRoot "7z.dll") -Description "Legacy standalone tools/7z.dll (the 7-Zip backend is embedded)"
Assert-PeMachine -LiteralPath (Join-Path $distToolsRoot "sunpack_sevenzip_worker.exe") -BuildArch $buildArch -Description "Packaged tools/sunpack_sevenzip_worker.exe"

$versionFilePath = Join-Path $distAppRoot "VERSION.txt"
$gitCommit = Get-GitCommit -RepoRoot $repoRoot
$rustVersion = (& rustc --version).Trim()
$metadata = @(
    "product=SunPack"
    "version=$versionValue"
    "arch=$buildArch"
    "git_commit=$gitCommit"
    "rustc=$rustVersion"
    "built_at_utc=$([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
)
[System.IO.File]::WriteAllLines($versionFilePath, $metadata)

if ($processArch -eq $buildArch) {
    # Packaged smoke tests must not inherit a developer machine's persistent
    # %ProgramData%\SunPack configuration. In particular, an older config can
    # legitimately contain schema fields removed by the current build and must
    # not turn a valid package into a false build failure.
    $originalProgramData = $env:ProgramData
    $originalConfigOverrides = $env:SUNPACK_CONFIG_OVERRIDES
    $smokeProgramDataRoot = Join-Path $buildRoot ("smoke-program-data-" + [guid]::NewGuid().ToString("N"))
    $env:ProgramData = $smokeProgramDataRoot
    $env:SUNPACK_CONFIG_OVERRIDES = '{"passwords":{"clipboard_passwords_enabled":false}}'
    try {
        $packagedDataRoot = Join-Path $env:ProgramData "SunPack"
        New-Item -ItemType Directory -Path $packagedDataRoot -Force | Out-Null
        foreach ($seedPath in @($distConfigPath, $distPasswordPath)) {
            $dataPath = Join-Path $packagedDataRoot (Split-Path -Leaf $seedPath)
            Copy-Item -LiteralPath $seedPath -Destination $dataPath -Force
        }

        Write-Step "Running packaged smoke tests"
        try {
            $smokeInput = Join-Path $smokeProgramDataRoot "probe.txt"
            $smokeArchive = Join-Path $smokeProgramDataRoot "probe.zip"
            $smokeOutput = Join-Path $smokeProgramDataRoot "output"
            [IO.File]::WriteAllText($smokeInput, "SunPack archive smoke test")
            Compress-Archive -LiteralPath $smokeInput -DestinationPath $smokeArchive
            Invoke-Native -FilePath $distExePath -Arguments @("--help")
            Invoke-Native -FilePath $distExePath -Arguments @("passwords", "--json") | Out-Null
            Invoke-Native -FilePath $distExePath -Arguments @("scan", $smokeArchive, "--json") | Out-Null
            Invoke-Native -FilePath $distExePath -Arguments @("extract", $smokeArchive, "--cleanup", "k", "--out-dir", $smokeOutput, "--json") | Out-Null
            Assert-PathExists -LiteralPath (Join-Path $smokeOutput "probe\probe.txt") -Description "Extracted smoke fixture"
            Invoke-Native -FilePath $distExePath -Arguments @("config", "validate", "--json")
        } finally {
            # Every launcher request may start the packaged persistent runtime.
            # Shut it down while PROGRAMDATA still points at the smoke sandbox.
            Invoke-Native -FilePath $distExePath -Arguments @("--persistent-shutdown")
            Wait-ExecutableExit -ExecutablePath $distRuntimeExePath
        }
    } finally {
        $env:ProgramData = $originalProgramData
        $env:SUNPACK_CONFIG_OVERRIDES = $originalConfigOverrides
        Remove-Item -LiteralPath $smokeProgramDataRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
} else {
    Write-Step "Skipping packaged smoke tests"
    Write-Host "Packaged executable is $buildArch and cannot run under the current $processArch process" -ForegroundColor Yellow
}

if ($runAcceptanceTests) {
    # The release build already supplied the native artifacts for acceptance.
    Write-Step "Preparing acceptance test dependencies"
    Invoke-Native -FilePath "powershell" -Arguments @(
        "-ExecutionPolicy", "Bypass",
        "-File", (Join-Path $PSScriptRoot "setup_windows_dev.ps1"),
        "-Arch", $buildArch, "-AcceptanceTestDependenciesOnly"
    )
    $fixtureBuildPath = Get-ArchiveFixtureBuildPath -RepoRoot $repoRoot -Arch $buildArch -BuildProfile release
    Assert-PathExists -LiteralPath $fixtureBuildPath -Description "Native test fixture executable"

    Write-Step "Running acceptance tests"
    Invoke-Native -FilePath "powershell" -Arguments @(
        "-ExecutionPolicy", "Bypass",
        "-File", (Join-Path $repoRoot "run_acceptance_tests.ps1"),
        "-NoWait", "-Arch", $buildArch, "-BuildProfile", "release", "-SkipEnvironmentRefresh"
    )
}

Write-Step "Creating Windows installer"
$installerBaseName = [System.IO.Path]::GetFileNameWithoutExtension($releaseInstallerName)
$installerStagingBase = Join-Path $buildRoot "inno-staging"
$installerStagingRoot = Join-Path $installerStagingBase ([guid]::NewGuid().ToString("N"))
$normalizedStagingBase = (ConvertTo-NormalizedFullPath -Path $installerStagingBase) + "\"
$normalizedStagingRoot = ConvertTo-NormalizedFullPath -Path $installerStagingRoot
if (-not $normalizedStagingRoot.StartsWith($normalizedStagingBase, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to use installer staging directory outside its expected root: $installerStagingRoot"
}
New-Item -ItemType Directory -Path $installerStagingRoot -Force | Out-Null
try {
    Invoke-WithRetry -Description "Inno Setup installer compilation" -ScriptBlock {
        # Never retry against the same output file. EndUpdateResource can leave a
        # failed output briefly locked by the filesystem indexer or shell.
        $attemptBaseName = "{0}-attempt-{1}" -f $installerBaseName, [guid]::NewGuid().ToString("N")
        $attemptInstallerPath = Join-Path $installerStagingRoot ($attemptBaseName + ".exe")
        Invoke-Native -FilePath $innoCompiler -Arguments @(
            "/Qp",
            "/DAppVersion=$versionValue",
            "/DSourceDir=$distAppRoot",
            "/DOutputDir=$installerStagingRoot",
            "/DOutputBaseFilename=$attemptBaseName",
            "/DTargetArch=$buildArch",
            $installerScriptPath
        )
        Assert-PathExists -LiteralPath $attemptInstallerPath -Description "Staged Windows installer"
        Wait-FileReadyForPromotion -LiteralPath $attemptInstallerPath
        Move-Item -LiteralPath $attemptInstallerPath -Destination $releaseInstallerPath -Force
    }
} finally {
    Remove-Item -LiteralPath $installerStagingRoot -Recurse -Force -ErrorAction SilentlyContinue
}
Assert-PathExists -LiteralPath $releaseInstallerPath -Description "Windows installer"

Write-Host ""
Write-Host "Build completed successfully" -ForegroundColor Green
Write-Host "Version: $versionValue"
Write-Host "App directory: $distAppRoot"
Write-Host "Windows installer: $releaseInstallerPath"
} catch {
    Write-Host ""
    Write-Host ("Build failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
    Wait-BeforeBuildExit
    exit 1
}

Wait-BeforeBuildExit
