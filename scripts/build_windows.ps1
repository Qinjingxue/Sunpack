[CmdletBinding()]
param(
    [switch]$SkipTests,
    [switch]$Clean,
    [switch]$NoPause,
    # Nuitka currently warns that C-level PGO is unsupported for standalone builds.
    # Keep it opt-in for local experiments only; release builds use LTO by default.
    [switch]$ExperimentalCProfileGuidedOptimization,
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

function Remove-IfExists {
    param([string]$LiteralPath)
    if (Test-Path -LiteralPath $LiteralPath) {
        Remove-Item -LiteralPath $LiteralPath -Recurse -Force
    }
}

function ConvertTo-NormalizedFullPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    return ([System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/') -replace '/', '\').ToLowerInvariant()
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
    throw "Packaged runtime did not exit within $TimeoutSeconds seconds: $ExecutablePath (PID: $processIds)"
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

function Reset-StaleCMakeBuildDir {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourceDir,
        [Parameter(Mandatory = $true)]
        [string]$BuildDir,
        [Parameter(Mandatory = $true)]
        [string]$CMakePlatform
    )

    $cachePath = Join-Path $BuildDir "CMakeCache.txt"
    if (-not (Test-Path -LiteralPath $cachePath)) {
        return
    }

    $expectedSource = ConvertTo-NormalizedFullPath -Path $SourceDir
    $actualSource = ""
    $actualPlatform = ""
    foreach ($line in Get-Content -LiteralPath $cachePath) {
        if ($line -like "CMAKE_HOME_DIRECTORY:INTERNAL=*") {
            $actualSource = ConvertTo-NormalizedFullPath -Path ($line.Substring("CMAKE_HOME_DIRECTORY:INTERNAL=".Length))
        } elseif ($line -like "CMAKE_GENERATOR_PLATFORM:INTERNAL=*") {
            $actualPlatform = $line.Substring("CMAKE_GENERATOR_PLATFORM:INTERNAL=".Length)
        }
    }

    if ($actualSource -and $actualSource -ne $expectedSource) {
        Write-Host "CMake build cache points at a different source tree; recreating $BuildDir" -ForegroundColor Yellow
        Remove-IfExists -LiteralPath $BuildDir
        return
    }

    if ($actualPlatform -ne $CMakePlatform) {
        Write-Host "CMake build cache uses platform '$actualPlatform' instead of '$CMakePlatform'; resetting CMake metadata in $BuildDir" -ForegroundColor Yellow
        Remove-IfExists -LiteralPath $cachePath
        Remove-IfExists -LiteralPath (Join-Path $BuildDir "CMakeFiles")
    }
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


function Remove-PreviousNativeExtension {
    param(
        [Parameter(Mandatory = $true)][string]$PythonPath,
        [Parameter(Mandatory = $true)][string]$VenvPath
    )

    $sitePackages = Join-Path $VenvPath "Lib\site-packages"
    if (-not (Test-Path -LiteralPath $sitePackages)) {
        return
    }

    # Keep exactly one extension: remove the registered distribution and every
    # stale module/dist-info residue before installing this build's wheel.
    Invoke-Native -FilePath "uv" -Arguments @("pip", "uninstall", "--python", $PythonPath, "sunpack-native")
    $leftovers = Get-ChildItem -LiteralPath $sitePackages -Force |
        Where-Object {
            $_.Name -eq "sunpack_native" -or
            $_.Name -match "^sunpack_native-.*\.dist-info$" -or
            $_.Name -match "^[~].*npack_native$"
        }
    foreach ($leftover in $leftovers) {
        Remove-Item -LiteralPath $leftover.FullName -Recurse -Force
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

function Get-LatestWheel {
    param([string]$WheelRoot)
    $wheel = Get-ChildItem -LiteralPath $WheelRoot -Filter "*.whl" -File |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
    if ($null -eq $wheel) {
        throw "Native wheel was not produced under: $WheelRoot"
    }
    return $wheel.FullName
}

function Get-MaturinCommand {
    param([string]$VenvScripts)

    $venvMaturin = Join-Path $VenvScripts "maturin.exe"
    if (Test-Path -LiteralPath $venvMaturin) {
        return $venvMaturin
    }

    $globalMaturin = Get-Command "maturin" -ErrorAction SilentlyContinue
    if ($globalMaturin) {
        return $globalMaturin.Source
    }

    throw "maturin executable not found. Install the project build extra or make maturin available in PATH."
}

function Test-CommandRuns {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [string[]]$Arguments = @("--version")
    )

    if (-not (Test-Path -LiteralPath $FilePath) -and -not (Get-Command $FilePath -ErrorAction SilentlyContinue)) {
        return $false
    }
    try {
        & $FilePath @Arguments *> $null
        return ($LASTEXITCODE -eq 0)
    } catch {
        return $false
    }
}

function Get-CMakeCommand {
    param([string]$VenvScripts)

    $venvCMake = Join-Path $VenvScripts "cmake.exe"
    if ((Test-Path -LiteralPath $venvCMake) -and (Test-CommandRuns -FilePath $venvCMake)) {
        return $venvCMake
    } elseif (Test-Path -LiteralPath $venvCMake) {
        Write-Host "Ignoring unusable venv CMake executable: $venvCMake" -ForegroundColor Yellow
    }

    foreach ($globalCMake in @(Get-Command "cmake" -All -ErrorAction SilentlyContinue)) {
        if ($globalCMake.Source -and (Test-CommandRuns -FilePath $globalCMake.Source)) {
            return $globalCMake.Source
        }
    }

    throw "cmake executable not found. Install the project build extra or make CMake available in PATH."
}

function Get-CTestCommand {
    param([string]$VenvScripts)

    $venvCTest = Join-Path $VenvScripts "ctest.exe"
    if ((Test-Path -LiteralPath $venvCTest) -and (Test-CommandRuns -FilePath $venvCTest)) {
        return $venvCTest
    } elseif (Test-Path -LiteralPath $venvCTest) {
        Write-Host "Ignoring unusable venv CTest executable: $venvCTest" -ForegroundColor Yellow
    }

    foreach ($globalCTest in @(Get-Command "ctest" -All -ErrorAction SilentlyContinue)) {
        if ($globalCTest.Source -and (Test-CommandRuns -FilePath $globalCTest.Source)) {
            return $globalCTest.Source
        }
    }

    throw "ctest executable not found. Install CMake or make CTest available in PATH."
}

function Test-NativeImport {
    param([string]$PythonPath)

    $code = @"
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
    'watch_broker_acquire', 'watch_broker_release',
    'watch_broker_is_connected', 'watch_broker_ping_seconds'
]
assert n.native_available()
missing = [name for name in required if not callable(getattr(n, name, None))]
assert not missing, missing
"@
    Invoke-Native -FilePath $PythonPath -Arguments @(
        "-c",
        $code
    )
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


function Test-SevenZipWrapper {
    param([string]$PythonPath)

    Invoke-Native -FilePath $PythonPath -Arguments @(
        "-c",
        "from sunpack.support.sevenzip_bridge import NativePasswordTester; tester = NativePasswordTester(); assert tester.available(), (tester.wrapper_path, tester.seven_zip_dll_path)"
    )
}

function Test-SevenZipWorker {
    param([string]$PythonPath)

    Invoke-Native -FilePath $PythonPath -Arguments @(
        "-c",
        "from sunpack.support.resources import get_7z_dll_path, get_sevenzip_bridge_worker_path; import os; assert os.path.exists(get_sevenzip_bridge_worker_path()); assert os.path.exists(get_7z_dll_path())"
    )
}

function Build-SevenZipWrapper {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CMakeCommand,
        [Parameter(Mandatory = $true)]
        [string]$CTestCommand,
        [Parameter(Mandatory = $true)]
        [string]$WrapperRoot,
        [Parameter(Mandatory = $true)]
        [string]$BuildDir,
        [Parameter(Mandatory = $true)]
        [string]$ToolsRoot,
        [Parameter(Mandatory = $true)]
        [string]$SevenZipDllPath,
        [Parameter(Mandatory = $true)]
        [string]$BuildArch
    )

    Write-Step "Building 7z.dll C++ wrapper"
    Assert-PathExists -LiteralPath (Join-Path $WrapperRoot "CMakeLists.txt") -Description "7z wrapper CMake project"
    Assert-PathExists -LiteralPath $SevenZipDllPath -Description "Bundled 7z.dll"
    $cmakePlatform = Get-CMakePlatform -BuildArch $BuildArch
    Reset-StaleCMakeBuildDir -SourceDir $WrapperRoot -BuildDir $BuildDir -CMakePlatform $cmakePlatform
    Invoke-Native -FilePath $CMakeCommand -Arguments @("-S", $WrapperRoot, "-B", $BuildDir, "-A", $cmakePlatform, "-DCMAKE_BUILD_TYPE=Release")
    Invoke-Native -FilePath $CMakeCommand -Arguments @("--build", $BuildDir, "--config", "Release")
    if ((Get-ProcessBuildArch) -eq $BuildArch) {
        Invoke-Native -FilePath $CTestCommand -Arguments @("--test-dir", $BuildDir, "-C", "Release", "--output-on-failure")
    } else {
        Write-Host "Skipping C++ smoke test because $BuildArch binaries cannot run in the current process architecture." -ForegroundColor Yellow
    }

    $wrapperDll = Join-Path $BuildDir "Release\sunpack_sevenzip.dll"
    $workerExe = Join-Path $BuildDir "Release\sunpack_sevenzip_worker.exe"
    $launcherExe = Join-Path $BuildDir "Release\sunpack_launcher.exe"
    Assert-PathExists -LiteralPath $wrapperDll -Description "Built 7z wrapper DLL"
    Assert-PathExists -LiteralPath $workerExe -Description "Built 7z worker executable"
    Assert-PathExists -LiteralPath $launcherExe -Description "Built SunPack launcher executable"
    Assert-PeMachine -LiteralPath $wrapperDll -BuildArch $BuildArch -Description "Built 7z wrapper DLL"
    Assert-PeMachine -LiteralPath $workerExe -BuildArch $BuildArch -Description "Built 7z worker executable"
    Assert-PeMachine -LiteralPath $launcherExe -BuildArch $BuildArch -Description "Built SunPack launcher executable"
    Copy-Item -LiteralPath $wrapperDll -Destination (Join-Path $ToolsRoot "sunpack_sevenzip.dll") -Force
    Copy-Item -LiteralPath $workerExe -Destination (Join-Path $ToolsRoot "sunpack_sevenzip_worker.exe") -Force
}

function Build-ToastLibrary {
    param(
        [Parameter(Mandatory = $true)][string]$CMakeCommand,
        [Parameter(Mandatory = $true)][string]$CTestCommand,
        [Parameter(Mandatory = $true)][string]$SourceRoot,
        [Parameter(Mandatory = $true)][string]$BuildDir,
        [Parameter(Mandatory = $true)][string]$ToolsRoot,
        [Parameter(Mandatory = $true)][string]$BuildArch
    )

    Write-Step "Building in-process Windows toast library"
    Assert-PathExists -LiteralPath (Join-Path $SourceRoot "CMakeLists.txt") -Description "toast CMake project"
    $cmakePlatform = Get-CMakePlatform -BuildArch $BuildArch
    Reset-StaleCMakeBuildDir -SourceDir $SourceRoot -BuildDir $BuildDir -CMakePlatform $cmakePlatform
    Invoke-Native -FilePath $CMakeCommand -Arguments @("-S", $SourceRoot, "-B", $BuildDir, "-A", $cmakePlatform, "-DCMAKE_BUILD_TYPE=Release")
    Invoke-Native -FilePath $CMakeCommand -Arguments @("--build", $BuildDir, "--config", "Release")
    if ((Get-ProcessBuildArch) -eq $BuildArch) {
        Invoke-Native -FilePath $CTestCommand -Arguments @("--test-dir", $BuildDir, "-C", "Release", "--output-on-failure")
    } else {
        Write-Host "Skipping toast library self-test because $BuildArch binaries cannot run in the current process architecture." -ForegroundColor Yellow
    }

    $toastDll = Join-Path $BuildDir "Release\sunpack_toast.dll"
    Assert-PathExists -LiteralPath $toastDll -Description "Built toast DLL"
    Assert-PeMachine -LiteralPath $toastDll -BuildArch $BuildArch -Description "Built toast DLL"
    Copy-Item -LiteralPath $toastDll -Destination (Join-Path $ToolsRoot "sunpack_toast.dll") -Force
}

function Assert-PackagedNativeExtension {
    param(
        [string]$PackageRoot,
        [string]$BuildArch
    )

    $nativeExtension = Get-ChildItem -LiteralPath $PackageRoot -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -like "sunpack_native*.pyd" -or
            $_.Name -like "sunpack_native*.dll"
        } |
        Select-Object -First 1

    if ($null -eq $nativeExtension) {
        throw "Packaged sunpack_native extension not found under: $PackageRoot"
    }

    Write-Host ("Packaged native extension: {0}" -f $nativeExtension.FullName) -ForegroundColor Green
    Assert-PeMachine -LiteralPath $nativeExtension.FullName -BuildArch $BuildArch -Description "Packaged sunpack_native extension"
}

function Test-PythonImports {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PythonPath,
        [Parameter(Mandatory = $true)]
        [string[]]$Modules
    )

    $importList = ($Modules | ForEach-Object { "'$_'" }) -join ", "
    & $PythonPath -c "import importlib.util, sys; modules = [$importList]; missing = [name for name in modules if importlib.util.find_spec(name) is None]; sys.exit(0 if not missing else 1)"
    return ($LASTEXITCODE -eq 0)
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
        Write-Host "Please answer Y or N." -ForegroundColor Yellow
    }
}


function New-NuitkaEntrypoint {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $content = @(
        "from sunpack.support.entrypoint import main",
        "raise SystemExit(main())",
        ""
    )
    [System.IO.File]::WriteAllText($Path, ($content -join [Environment]::NewLine), [System.Text.UTF8Encoding]::new($false))
}

function Embed-WindowsApplicationManifest {
    param(
        [Parameter(Mandatory = $true)][string]$PythonPath,
        [Parameter(Mandatory = $true)][string]$EmbeddingScriptPath,
        [Parameter(Mandatory = $true)][string]$ManifestPath,
        [Parameter(Mandatory = $true)][string[]]$ExecutablePaths
    )

    Assert-PathExists -LiteralPath $EmbeddingScriptPath -Description "Manifest resource embedding script"
    Assert-PathExists -LiteralPath $ManifestPath -Description "Windows application manifest"
    $arguments = @($EmbeddingScriptPath, "--manifest", $ManifestPath)
    foreach ($executablePath in $ExecutablePaths) {
        Assert-PathExists -LiteralPath $executablePath -Description "Nuitka executable for manifest embedding"
        $arguments += @("--executable", $executablePath)
    }
    Invoke-Native -FilePath $PythonPath -Arguments $arguments
}

function Invoke-NuitkaStandaloneBuild {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PythonPath,
        [Parameter(Mandatory = $true)]
        [string]$EntryPath,
        [Parameter(Mandatory = $true)]
        [string]$OutputRoot,
        [Parameter(Mandatory = $true)]
        [string]$ExecutableName,
        [Parameter(Mandatory = $true)]
        [ValidateSet("force", "disable")]
        [string]$ConsoleMode,
        [Parameter(Mandatory = $true)]
        [string]$IconPath,
        [Parameter(Mandatory = $true)]
        [string[]]$DynamicPackages,
        [string]$PgoArgs,
        [switch]$EnableExperimentalCProfileGuidedOptimization,
        [Parameter(Mandatory = $true)]
        [string]$ReportPath
    )

    $arguments = @(
        "-m", "nuitka",
        "--standalone",
        "--assume-yes-for-downloads",
        "--lto=yes",
        "--output-dir=$OutputRoot",
        "--output-filename=$ExecutableName",
        "--windows-console-mode=$ConsoleMode",
        "--windows-icon-from-ico=$IconPath",
        "--include-module=sunpack_native",
        "--report=$ReportPath"
    )
    if ($EnableExperimentalCProfileGuidedOptimization) {
        Write-Warning "C-level PGO is experimental and unsupported by Nuitka for standalone builds; do not publish this output without independent validation."
        $arguments += "--pgo-c"
        if ($PgoArgs) {
            $arguments += "--pgo-args=$PgoArgs"
        }
    }
    foreach ($package in $DynamicPackages) {
        $arguments += "--include-package=$package"
    }

    foreach ($module in @("ssl", "_ssl")) {
        $arguments += "--nofollow-import-to=$module"
    }

    $arguments += $EntryPath
    Invoke-Native -FilePath $PythonPath -Arguments $arguments
}

function Copy-NuitkaDistContents {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Source,
        [Parameter(Mandatory = $true)]
        [string]$Destination
    )

    Assert-PathExists -LiteralPath $Source -Description "Nuitka standalone output"
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    foreach ($item in Get-ChildItem -LiteralPath $Source -Force) {
        Copy-Item -LiteralPath $item.FullName -Destination $Destination -Recurse -Force
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
        "7z.dll",
        "sunpack_sevenzip.dll",
        "sunpack_sevenzip_worker.exe",
        "sunpack_toast.dll"
    )
}

function Copy-PackagedRuntimeTools {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    foreach ($name in @(Get-PackagedRuntimeToolNames)) {
        $sourcePath = Join-Path $Source $name
        Assert-PathExists -LiteralPath $sourcePath -Description "Runtime tool source"
        Copy-Item -LiteralPath $sourcePath -Destination (Join-Path $Destination $name) -Force
    }
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
Write-Host "Build system: Nuitka"
Write-Host "Build Python/process architecture: $processArch"
if ($processArch -ne $buildArch) {
    throw "Windows Nuitka/PyO3 final executable builds must run under a target-architecture Python. This machine/process is '$processArch', so it cannot produce a real '$buildArch' sunpack.exe. Use an ARM64 Windows Python environment for -Arch arm64; use static PE validation on the resulting package."
}

$pythonCommand = Get-PythonCommand
$venvPath = Join-Path $repoRoot ".venv"
$venvPython = Join-Path $venvPath "Scripts\python.exe"
$venvScripts = Join-Path $venvPath "Scripts"
$sunpackEntryPath = Join-Path $repoRoot "sunpack.py"
$installerScriptPath = Join-Path $repoRoot "installer\SunPack.iss"
$projectPath = Join-Path $repoRoot "pyproject.toml"
$iconPath = Join-Path $repoRoot "sunpack.ico"
$applicationManifestPath = Join-Path $repoRoot "sunpack.manifest"
$manifestEmbeddingScriptPath = Join-Path $repoRoot "scripts\embed_windows_manifest.py"
$nativeCrateRoot = Join-Path $repoRoot "native\sunpack_native"
$nativeCargoToml = Join-Path $nativeCrateRoot "Cargo.toml"
$nativeWorkspaceLock = Join-Path $repoRoot "native\Cargo.lock"
$watchBrokerCargoToml = Join-Path $repoRoot "native\sunpack_watch_broker\Cargo.toml"
$rustTargetDir = Join-Path $repoRoot (".cache\rust-target\" + $buildArch)
$watchBrokerBuildPath = Join-Path $rustTargetDir ("$rustTarget\release\sunpack-watch-broker.exe")
$sevenZipWrapperRoot = Join-Path $repoRoot "native\sevenzip_bridge"
$sevenZipWrapperBuildDir = Join-Path $sevenZipWrapperRoot ("build-" + $buildArch)
$toastHostRoot = Join-Path $repoRoot "native\toast_host"
$toastHostBuildDir = Join-Path $toastHostRoot ("build-" + $buildArch)
$toolsRoot = if ($buildArch -eq "x64") { Join-Path $repoRoot "tools" } else { Join-Path $repoRoot ("tools-" + $buildArch) }
$sevenZipPath = Join-Path $toolsRoot "7z.exe"
$sevenZipDllPath = Join-Path $toolsRoot "7z.dll"
$sevenZipWrapperDllPath = Join-Path $toolsRoot "sunpack_sevenzip.dll"
$sevenZipWorkerPath = Join-Path $toolsRoot "sunpack_sevenzip_worker.exe"
$toastHostPath = Join-Path $toolsRoot "sunpack_toast.dll"
$launcherBuildPath = Join-Path $sevenZipWrapperBuildDir "Release\sunpack_launcher.exe"
$sevenZipLicensePath = Join-Path $repoRoot "licenses\7zip-license.txt"
$distRoot = Join-Path $repoRoot "dist"
$buildRoot = Join-Path $repoRoot "build"
$nativeWheelRoot = Join-Path $buildRoot ("native-wheels-" + $buildArch)
$releaseRoot = Join-Path $repoRoot "release"
$distFolderName = "sunpack-" + $buildArch
$appExeName = "sunpack.exe"
$runtimeExeName = "sunpack-runtime.exe"
$distAppRoot = Join-Path $distRoot $distFolderName
$distExePath = Join-Path $distAppRoot $appExeName
$distRuntimeExePath = Join-Path $distAppRoot $runtimeExeName
$nuitkaBuildRoot = Join-Path $buildRoot ("nuitka-" + $distFolderName)
$distToolsRoot = Join-Path $distAppRoot "tools"
$distServiceRoot = Join-Path $distAppRoot "service"
$distWatchBrokerPath = Join-Path $distServiceRoot "sunpack-watch-broker.exe"
$distLicensesRoot = Join-Path $distAppRoot "licenses"
$versionValue = Get-ReleaseVersion -ExplicitVersion $Version -RepoRoot $repoRoot
$releaseInstallerName = "sunpack-windows-{0}-{1}-setup.exe" -f $buildArch, $versionValue
$releaseInstallerPath = Join-Path $releaseRoot $releaseInstallerName
$runAcceptanceTests = -not $SkipTests

if ($promptForAcceptanceTests) {
    $runAcceptanceTests = Confirm-AcceptanceTests
}

Assert-PathExists -LiteralPath $projectPath -Description "pyproject.toml"
Assert-PathExists -LiteralPath $sunpackEntryPath -Description "SunPack entry point"
Assert-PathExists -LiteralPath $installerScriptPath -Description "Inno Setup installer script"
$innoCompiler = Get-InnoSetupCompiler -PreferredPath $InnoCompilerPath
Assert-PathExists -LiteralPath $iconPath -Description "SunPack icon"
Assert-PathExists -LiteralPath $applicationManifestPath -Description "Windows application manifest"
Assert-PathExists -LiteralPath $manifestEmbeddingScriptPath -Description "Manifest resource embedding script"
Assert-PathExists -LiteralPath $nativeCargoToml -Description "sunpack_native Cargo manifest"
Assert-PathExists -LiteralPath $nativeWorkspaceLock -Description "native Rust workspace lockfile"
Assert-PathExists -LiteralPath $watchBrokerCargoToml -Description "SunPack Watch Broker Cargo manifest"
Assert-PathExists -LiteralPath (Join-Path $sevenZipWrapperRoot "CMakeLists.txt") -Description "7z wrapper CMake project"
Assert-PathExists -LiteralPath (Join-Path $toastHostRoot "CMakeLists.txt") -Description "toast CMake project"
Assert-PathExists -LiteralPath $sevenZipPath -Description "Bundled 7-Zip executable"
Assert-PathExists -LiteralPath $sevenZipDllPath -Description "Bundled 7-Zip runtime DLL"
Assert-PathExists -LiteralPath $sevenZipLicensePath -Description "7-Zip license file"
Assert-CommandExists -Command "cargo" -Description "Rust toolchain"
Assert-CommandExists -Command "uv" -Description "uv dependency manager"
Assert-PeMachine -LiteralPath $sevenZipPath -BuildArch $buildArch -Description "Bundled 7-Zip executable"
Assert-PeMachine -LiteralPath $sevenZipDllPath -BuildArch $buildArch -Description "Bundled 7-Zip runtime DLL"

if ($Clean) {
    Write-Step "Cleaning build virtual environment"
    Remove-IfExists -LiteralPath $venvPath
}

Write-Step "Preparing build virtual environment"
if (Test-Path -LiteralPath (Join-Path $venvPath "pyvenv.cfg")) {
    $venvConfig = Get-Content -LiteralPath (Join-Path $venvPath "pyvenv.cfg") -Raw
    if ($venvConfig -match "include-system-site-packages\\s*=\\s*true") {
        Write-Host "Recreating build environment without global site-packages." -ForegroundColor Yellow
        Remove-IfExists -LiteralPath $venvPath
    }
}
Invoke-Native -FilePath "uv" -Arguments @("sync", "--locked", "--extra", "dev", "--python", $pythonCommand)
Invoke-Native -FilePath "uv" -Arguments @("pip", "check", "--python", $venvPython)
$maturinCommand = Get-MaturinCommand -VenvScripts $venvScripts
$cmakeCommand = Get-CMakeCommand -VenvScripts $venvScripts
$ctestCommand = Get-CTestCommand -VenvScripts $venvScripts

$env:Path = "$venvScripts;$env:Path"
$env:PYTHONPATH = if ($env:PYTHONPATH) { "$repoRoot;$env:PYTHONPATH" } else { $repoRoot }

Write-Step "Cleaning previous build outputs"
Remove-IfExists -LiteralPath $buildRoot
Remove-IfExists -LiteralPath $distRoot
Remove-IfExists -LiteralPath $releaseRoot
New-Item -ItemType Directory -Path $releaseRoot -Force | Out-Null

Write-Step "Building and installing Rust native extension"
Remove-PreviousNativeExtension -PythonPath $venvPython -VenvPath $venvPath
New-Item -ItemType Directory -Path $nativeWheelRoot -Force | Out-Null
Invoke-Native -FilePath "cargo" -Arguments @("--version")
Invoke-Native -FilePath $maturinCommand -Arguments @(
    "build",
    "--locked",
    "--manifest-path", $nativeCargoToml,
    "--release",
    "--target", $rustTarget,
    "--target-dir", $rustTargetDir,
    "--out", $nativeWheelRoot
)
$nativeWheelPath = Get-LatestWheel -WheelRoot $nativeWheelRoot
Invoke-Native -FilePath "uv" -Arguments @("pip", "install", "--python", $venvPython, "--reinstall", $nativeWheelPath)
Test-NativeImport -PythonPath $venvPython

Write-Step "Building minimal Windows Watch Broker service"
Invoke-Native -FilePath "cargo" -Arguments @(
    "build",
    "--locked",
    "--manifest-path", $watchBrokerCargoToml,
    "--release",
    "--target", $rustTarget,
    "--target-dir", $rustTargetDir
)
Assert-PathExists -LiteralPath $watchBrokerBuildPath -Description "SunPack Watch Broker executable"
Assert-PeMachine -LiteralPath $watchBrokerBuildPath -BuildArch $buildArch -Description "SunPack Watch Broker executable"

Build-SevenZipWrapper -CMakeCommand $cmakeCommand -CTestCommand $ctestCommand -WrapperRoot $sevenZipWrapperRoot -BuildDir $sevenZipWrapperBuildDir -ToolsRoot $toolsRoot -SevenZipDllPath $sevenZipDllPath -BuildArch $buildArch
Build-ToastLibrary -CMakeCommand $cmakeCommand -CTestCommand $ctestCommand -SourceRoot $toastHostRoot -BuildDir $toastHostBuildDir -ToolsRoot $toolsRoot -BuildArch $buildArch
Assert-PathExists -LiteralPath $sevenZipWrapperDllPath -Description "Bundled 7z wrapper DLL"
Assert-PathExists -LiteralPath $sevenZipWorkerPath -Description "Bundled 7z worker executable"
Assert-PathExists -LiteralPath $toastHostPath -Description "Bundled toast DLL"
Test-SevenZipWrapper -PythonPath $venvPython
Test-SevenZipWorker -PythonPath $venvPython
Invoke-Native -FilePath $venvPython -Arguments @(
    "-c",
    "from sunpack.support.resources import get_toast_library_path; import os; assert os.path.exists(get_toast_library_path())"
)

Write-Step "Writing environment manifest"
Invoke-Native -FilePath "powershell" -Arguments @(
    "-NoProfile", "-ExecutionPolicy", "Bypass",
    "-File", (Join-Path $repoRoot "scripts\environment_manifest.ps1"),
    "-RepoRoot", $repoRoot, "-Arch", $buildArch
)

if ($runAcceptanceTests) {
    Write-Step "Running acceptance tests"
    Invoke-Native -FilePath "powershell" -Arguments @(
        "-ExecutionPolicy", "Bypass",
        "-File", (Join-Path $repoRoot "run_acceptance_tests.ps1"),
        "-NoWait",
        "-SkipEnvironmentRefresh",
        "-Arch", $buildArch
    )
} else {
    Write-Host "Skipping acceptance tests by request." -ForegroundColor Yellow
}

Write-Step "Building Windows release with Nuitka"
    $nuitkaEntryRoot = Join-Path $nuitkaBuildRoot "entries"
    $nuitkaRuntimeEntryPath = Join-Path $nuitkaEntryRoot "sunpack-runtime.py"
    $nuitkaRuntimeDist = Join-Path $nuitkaBuildRoot ([System.IO.Path]::GetFileNameWithoutExtension($runtimeExeName) + ".dist")
    $nuitkaDynamicPackages = @(
    "watchdog",
        "sunpack.cli.commands",
        "sunpack.config.fields",
        "sunpack.filesystem.filters.modules",
        "sunpack.detection.pipeline.facts.collectors",
    "sunpack.detection.pipeline.processors.modules",
    "sunpack.detection.pipeline.rules.precheck",
    "sunpack.analysis.structure_pipeline.modules",
    "sunpack.analysis.fuzzy_pipeline.modules",
    "sunpack.passwords.candidates",
        "sunpack.extraction.internal",
        "sunpack.rename.internal",
        "sunpack.relations.internal",
        "sunpack.postprocess.internal",
        "sunpack.verification.methods"
    )

    New-Item -ItemType Directory -Path $nuitkaEntryRoot -Force | Out-Null
    New-NuitkaEntrypoint -Path $nuitkaRuntimeEntryPath
    Invoke-NuitkaStandaloneBuild -PythonPath $venvPython -EntryPath $nuitkaRuntimeEntryPath -OutputRoot $nuitkaBuildRoot -ExecutableName $runtimeExeName -ConsoleMode "disable" -IconPath $iconPath -DynamicPackages $nuitkaDynamicPackages -PgoArgs "--help" -EnableExperimentalCProfileGuidedOptimization:$ExperimentalCProfileGuidedOptimization -ReportPath (Join-Path $nuitkaBuildRoot "sunpack-runtime-report.xml")
    Embed-WindowsApplicationManifest -PythonPath $venvPython -EmbeddingScriptPath $manifestEmbeddingScriptPath -ManifestPath $applicationManifestPath -ExecutablePaths @(
        (Join-Path $nuitkaRuntimeDist $runtimeExeName)
    )
    Copy-NuitkaDistContents -Source $nuitkaRuntimeDist -Destination $distAppRoot
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
Assert-PackagedNativeExtension -PackageRoot $distAppRoot -BuildArch $buildArch

Write-Step "Adding release metadata and helper scripts"
$distPasswordPath = Join-Path $distAppRoot "builtin_passwords.txt"
$distConfigPath = Join-Path $distAppRoot "sunpack_config.json"
$distAdvancedConfigPath = Join-Path $distAppRoot "sunpack_advanced_config.json"
$distIconPath = Join-Path $distAppRoot "sunpack.ico"
Copy-Item -LiteralPath (Join-Path $repoRoot "builtin_passwords.txt") -Destination $distPasswordPath -Force
Copy-Item -LiteralPath (Join-Path $repoRoot "sunpack_config.json") -Destination $distConfigPath -Force
Copy-Item -LiteralPath $iconPath -Destination $distIconPath -Force
Copy-IfExists -Source (Join-Path $repoRoot "sunpack_advanced_config.json") -Destination $distAdvancedConfigPath
Copy-PackagedRuntimeTools -Source $toolsRoot -Destination $distToolsRoot

New-Item -ItemType Directory -Path $distLicensesRoot -Force | Out-Null
Copy-Item -LiteralPath $sevenZipLicensePath -Destination (Join-Path $distLicensesRoot "7zip-license.txt") -Force

$distScriptsRoot = Join-Path $distAppRoot "scripts"
New-Item -ItemType Directory -Path $distScriptsRoot -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $repoRoot "scripts\register_context_menu.ps1") -Destination (Join-Path $distScriptsRoot "register_context_menu.ps1") -Force
Copy-Item -LiteralPath (Join-Path $repoRoot "scripts\unregister_context_menu.ps1") -Destination (Join-Path $distScriptsRoot "unregister_context_menu.ps1") -Force

Assert-PathExists -LiteralPath $distPasswordPath -Description "External password file"
Assert-PathExists -LiteralPath $distConfigPath -Description "External config file"
Assert-PathExists -LiteralPath $distIconPath -Description "External icon file"
Assert-PackagedRuntimeTools -PackageRoot $distAppRoot
Assert-PathExists -LiteralPath (Join-Path $distLicensesRoot "7zip-license.txt") -Description "External 7-Zip license file"
Assert-PeMachine -LiteralPath (Join-Path $distToolsRoot "7z.dll") -BuildArch $buildArch -Description "Packaged tools/7z.dll"
Assert-PeMachine -LiteralPath (Join-Path $distToolsRoot "sunpack_sevenzip.dll") -BuildArch $buildArch -Description "Packaged tools/sunpack_sevenzip.dll"
Assert-PeMachine -LiteralPath (Join-Path $distToolsRoot "sunpack_sevenzip_worker.exe") -BuildArch $buildArch -Description "Packaged tools/sunpack_sevenzip_worker.exe"

$versionFilePath = Join-Path $distAppRoot "VERSION.txt"
$gitCommit = Get-GitCommit -RepoRoot $repoRoot
$pythonVersion = (& $venvPython --version).Trim()
$metadata = @(
    "product=SunPack"
    "version=$versionValue"
    "arch=$buildArch"
    "git_commit=$gitCommit"
    "python=$pythonVersion"
    "built_at_utc=$([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
)
[System.IO.File]::WriteAllLines($versionFilePath, $metadata)

if ($processArch -eq $buildArch) {
    Write-Step "Running packaged smoke tests"
    try {
        Invoke-Native -FilePath $distExePath -Arguments @("--help")
        Invoke-Native -FilePath $distExePath -Arguments @("passwords", "--json")
        Invoke-Native -FilePath $distExePath -Arguments @("inspect", (Join-Path $repoRoot "tests"), "--json")
        Invoke-Native -FilePath $distExePath -Arguments @("config", "validate", "--json")
    } finally {
        # Every launcher request may start the packaged persistent runtime. It
        # uses %LOCALAPPDATA%\SunPack\runtime-cwd, so leaving it alive pins the
        # user-data directory and breaks the installer smoke test that follows.
        Invoke-Native -FilePath $distExePath -Arguments @("--persistent-shutdown")
        Wait-ExecutableExit -ExecutablePath $distRuntimeExePath
    }
} else {
    Write-Step "Skipping packaged smoke tests"
    Write-Host "Packaged executable is $buildArch and cannot run under the current $processArch process." -ForegroundColor Yellow
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
Write-Host "Build completed successfully." -ForegroundColor Green
Write-Host "Version: $versionValue"
Write-Host "App directory: $distAppRoot"
Write-Host "Windows installer: $releaseInstallerPath"

if (-not $NoPause -and -not [Console]::IsInputRedirected -and -not [Console]::IsOutputRedirected) {
    Write-Host ""
    Write-Host "Press Enter to exit..." -ForegroundColor Cyan
    $null = Read-Host
}

