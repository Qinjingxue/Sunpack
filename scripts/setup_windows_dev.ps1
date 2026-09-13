[CmdletBinding()]
param(
    [switch]$Clean,
    [ValidateSet("x64", "arm64")]
    [string]$Arch = "x64",
    [switch]$SkipAcceptanceTestTools
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

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

function Resolve-Uri {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BaseUri,
        [Parameter(Mandatory = $true)]
        [string]$Reference
    )

    $base = [System.Uri]$BaseUri
    $resolved = [System.Uri]::new($base, $Reference)
    return $resolved.AbsoluteUri
}

function Invoke-FileDownload {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        [Parameter(Mandatory = $true)]
        [string]$DestinationPath,
        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    $destinationDir = Split-Path -Parent $DestinationPath
    if ($destinationDir) {
        New-Item -ItemType Directory -Path $destinationDir -Force | Out-Null
    }

    Write-Host "Downloading $Description from $Uri" -ForegroundColor Yellow
    $client = New-Object System.Net.WebClient
    try {
        $client.Headers["User-Agent"] = "SunPack dev bootstrap"
        $client.DownloadFile($Uri, $DestinationPath)
    } finally {
        $client.Dispose()
    }
}

function Get-7ZipWindowsDownloadInfo {
    param([string]$BuildArch = "x64")

    $downloadPageUri = "https://www.7-zip.org/download.html"
    $client = New-Object System.Net.WebClient
    try {
        $client.Headers["User-Agent"] = "SunPack dev bootstrap"
        $html = $client.DownloadString($downloadPageUri)
    } finally {
        $client.Dispose()
    }

    $sevenZipArch = if ($BuildArch -eq "arm64") { "arm64" } else { "x64" }
    $installerPattern = 'href="([^"]*7z\d+-' + [regex]::Escape($sevenZipArch) + '\.exe)"'
    $installerMatch = [regex]::Match($html, $installerPattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if (-not $installerMatch.Success) {
        throw "Could not locate the latest 7-Zip $sevenZipArch installer link on $downloadPageUri"
    }

    return @{
        DownloadPageUri = $downloadPageUri
        InstallerUri = Resolve-Uri -BaseUri $downloadPageUri -Reference $installerMatch.Groups[1].Value
    }
}

function Ensure-Bundled7ZipAssets {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ToolsRoot,
        [Parameter(Mandatory = $true)]
        [string]$LicenseDestinationPath,
        [Parameter(Mandatory = $true)]
        [string]$BuildArch
    )

    $requiredToolFiles = @(
        "7z.exe",
        "7z.dll",
        "7z.sfx",
        "7zCon.sfx",
        "7-zip.dll"
    )
    if ($BuildArch -eq "x64") {
        $requiredToolFiles += "7-zip32.dll"
    }

    $missingToolFiles = @(
        $requiredToolFiles | Where-Object {
            -not (Test-Path -LiteralPath (Join-Path $ToolsRoot $_))
        }
    )

    $licenseMissing = -not (Test-Path -LiteralPath $LicenseDestinationPath)
    if ($missingToolFiles.Count -eq 0 -and -not $licenseMissing) {
        Write-Host "Bundled 7-Zip files are already present." -ForegroundColor Green
        return
    }

    Write-Step "Bootstrapping bundled 7-Zip files"
    if ($missingToolFiles.Count -gt 0) {
        Write-Host ("Missing bundled 7-Zip files: {0}" -f ($missingToolFiles -join ", ")) -ForegroundColor Yellow
    }
    if ($licenseMissing) {
        Write-Host "Missing 7-Zip license file." -ForegroundColor Yellow
    }

    $downloadInfo = Get-7ZipWindowsDownloadInfo -BuildArch $BuildArch
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("sunpack-dev-7zip-" + [guid]::NewGuid().ToString("N"))
    $installerPath = Join-Path $tempRoot ("7zip-" + $BuildArch + "-installer.exe")
    $installRoot = Join-Path $tempRoot "installed"

    try {
        New-Item -ItemType Directory -Path $installRoot -Force | Out-Null
        Invoke-FileDownload -Uri $downloadInfo.InstallerUri -DestinationPath $installerPath -Description "7-Zip $BuildArch installer"

        Write-Host "Installing 7-Zip into temporary workspace $installRoot" -ForegroundColor Yellow
        $process = Start-Process -FilePath $installerPath -ArgumentList @("/S", "/D=$installRoot") -Wait -PassThru
        if ($process.ExitCode -ne 0) {
            throw "7-Zip installer exited with code $($process.ExitCode)"
        }

        New-Item -ItemType Directory -Path $ToolsRoot -Force | Out-Null
        foreach ($fileName in $requiredToolFiles) {
            $sourcePath = Join-Path $installRoot $fileName
            Assert-PathExists -LiteralPath $sourcePath -Description "Downloaded 7-Zip component $fileName"
            Copy-Item -LiteralPath $sourcePath -Destination (Join-Path $ToolsRoot $fileName) -Force
        }

        $optionalFiles = @("descript.ion")
        foreach ($fileName in $optionalFiles) {
            $sourcePath = Join-Path $installRoot $fileName
            if (Test-Path -LiteralPath $sourcePath) {
                Copy-Item -LiteralPath $sourcePath -Destination (Join-Path $ToolsRoot $fileName) -Force
            }
        }

        $licenseSourcePath = Join-Path $installRoot "License.txt"
        Assert-PathExists -LiteralPath $licenseSourcePath -Description "Downloaded 7-Zip license file"
        New-Item -ItemType Directory -Path (Split-Path -Parent $LicenseDestinationPath) -Force | Out-Null
        Copy-Item -LiteralPath $licenseSourcePath -Destination $LicenseDestinationPath -Force
    } finally {
        Remove-IfExists -LiteralPath $tempRoot
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

function Invoke-VerifiedFileDownload {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        [Parameter(Mandatory = $true)]
        [string]$DestinationPath,
        [Parameter(Mandatory = $true)]
        [string]$Description,
        [Parameter(Mandatory = $true)]
        [string]$Sha256
    )

    $expectedHash = $Sha256.Trim().ToUpperInvariant()
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            Remove-IfExists -LiteralPath $DestinationPath
            Invoke-FileDownload -Uri $Uri -DestinationPath $DestinationPath -Description $Description
            $actualHash = (Get-FileHash -LiteralPath $DestinationPath -Algorithm SHA256).Hash.ToUpperInvariant()
            if ($actualHash -ne $expectedHash) {
                throw "SHA-256 mismatch for $Description. Expected $expectedHash, got $actualHash."
            }
            return
        } catch {
            if ($attempt -eq 3) {
                throw
            }
            Write-Warning ("Download attempt {0} for {1} failed: {2}. Retrying." -f $attempt, $Description, $_.Exception.Message)
        }
    }
}

function Ensure-AcceptanceTestTools {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot,
        [Parameter(Mandatory = $true)]
        [string]$ToolsRoot
    )

    # Keep these generator binaries outside tools/. build_windows.ps1 copies
    # tools/ into release packages, while these are test-only dependencies.
    $testToolsRoot = Join-Path $RepoRoot ".sunpack_test_tools"
    $rarRoot = Join-Path $testToolsRoot "winrar"
    $rarPath = Join-Path $rarRoot "Rar.exe"
    $rarSfxPath = Join-Path $rarRoot "Default.SFX"
    $winrarPath = Join-Path $rarRoot "WinRAR.exe"
    $requiredRarVersion = "6.22"
    $zstdRoot = Join-Path $testToolsRoot "zstd"
    $zstdPath = Join-Path $zstdRoot "zstd.exe"
    New-Item -ItemType Directory -Path $testToolsRoot -Force | Out-Null

    $rarReady = (Test-Path -LiteralPath $rarPath) -and
        (Test-Path -LiteralPath $rarSfxPath) -and
        (Test-Path -LiteralPath $winrarPath) -and
        (Test-RarGeneratorVersion -FilePath $rarPath -RequiredVersion $requiredRarVersion)
    $zstdReady = (Test-Path -LiteralPath $zstdPath) -and
        (Test-CommandRuns -FilePath $zstdPath -Arguments @("--version"))
    if ($rarReady -and $zstdReady) {
        Write-Host "Acceptance archive generator tools are already present." -ForegroundColor Green
        return
    }

    Write-Step "Bootstrapping acceptance archive generator tools"
    $rarInstallerUri = if ($env:SUNPACK_TEST_RAR_INSTALLER_URI) {
        $env:SUNPACK_TEST_RAR_INSTALLER_URI
    } else {
        # Official RARLAB WinRAR x64 release. 6.22 is pinned because Plan 7
        # must generate RAR4 fixtures with the -ma4 switch.
        "https://www.rarlab.com/rar/winrar-x64-622.exe"
    }
    $rarInstallerSha256 = if ($env:SUNPACK_TEST_RAR_INSTALLER_SHA256) {
        $env:SUNPACK_TEST_RAR_INSTALLER_SHA256
    } else {
        "BC6440121C023A5068C558BEE72EAE5C2B2EEA1580C95EF7FBA354780C689F7F"
    }
    $zstdArchiveUri = if ($env:SUNPACK_TEST_ZSTD_URI) {
        $env:SUNPACK_TEST_ZSTD_URI
    } else {
        # Official facebook/zstd release artifact for Windows x64.
        "https://github.com/facebook/zstd/releases/download/v1.5.7/zstd-v1.5.7-win64.zip"
    }
    $zstdArchiveSha256 = if ($env:SUNPACK_TEST_ZSTD_SHA256) {
        $env:SUNPACK_TEST_ZSTD_SHA256
    } else {
        "ACB4E8111511749DC7A3EBEDCA9B04190E37A17AFEB73F55D4425DBF0B90FAD9"
    }

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("sunpack-test-tools-" + [guid]::NewGuid().ToString("N"))
    $rarInstallerPath = Join-Path $tempRoot "winrar-x64-installer.exe"
    $zstdArchivePath = Join-Path $tempRoot "zstd-win64.zip"
    $rarInstallRoot = Join-Path $tempRoot "winrar"
    $zstdExtractRoot = Join-Path $tempRoot "zstd"
    try {
        New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null

    if (-not $rarReady) {
            Invoke-VerifiedFileDownload `
                -Uri $rarInstallerUri `
                -DestinationPath $rarInstallerPath `
                -Description "WinRAR x64 test generator" `
                -Sha256 $rarInstallerSha256

            Remove-IfExists -LiteralPath $rarRoot
            New-Item -ItemType Directory -Path $rarInstallRoot -Force | Out-Null
            Write-Host "Installing WinRAR test generator into temporary workspace $rarInstallRoot" -ForegroundColor Yellow
            $installer = Start-Process `
                -FilePath $rarInstallerPath `
                -ArgumentList @("/s", ("/d" + $rarInstallRoot)) `
                -WindowStyle Hidden `
                -Wait `
                -PassThru
            if ($installer.ExitCode -ne 0) {
                throw "WinRAR installer exited with code $($installer.ExitCode)"
            }
            Assert-PathExists -LiteralPath (Join-Path $rarInstallRoot "Rar.exe") -Description "Installed Rar.exe"
            Assert-PathExists -LiteralPath (Join-Path $rarInstallRoot "Default.SFX") -Description "Installed Default.SFX"
            Assert-PathExists -LiteralPath (Join-Path $rarInstallRoot "WinRAR.exe") -Description "Installed WinRAR.exe"
            Move-Item -LiteralPath $rarInstallRoot -Destination $rarRoot -Force
        }

        if (-not $zstdReady) {
            Invoke-VerifiedFileDownload `
                -Uri $zstdArchiveUri `
                -DestinationPath $zstdArchivePath `
                -Description "zstd Windows x64 test generator" `
                -Sha256 $zstdArchiveSha256

            $sevenZipPath = Join-Path $ToolsRoot "7z.exe"
            Assert-PathExists -LiteralPath $sevenZipPath -Description "7-Zip extractor for acceptance test tools"
            Remove-IfExists -LiteralPath $zstdRoot
            New-Item -ItemType Directory -Path $zstdExtractRoot -Force | Out-Null
            Invoke-Native -FilePath $sevenZipPath -Arguments @(
                "x",
                $zstdArchivePath,
                ("-o" + $zstdExtractRoot),
                "-y"
            )
            $zstdSource = Get-ChildItem -LiteralPath $zstdExtractRoot -Filter "zstd.exe" -File -Recurse |
                Select-Object -First 1
            if ($null -eq $zstdSource) {
                throw "Downloaded zstd archive does not contain zstd.exe."
            }
            New-Item -ItemType Directory -Path $zstdRoot -Force | Out-Null
            Copy-Item -LiteralPath $zstdSource.FullName -Destination $zstdPath -Force
        }
    } finally {
        Remove-IfExists -LiteralPath $tempRoot
    }

    if (-not (Test-Path -LiteralPath $rarPath) -or
        -not (Test-Path -LiteralPath $rarSfxPath) -or
        -not (Test-Path -LiteralPath $winrarPath) -or
        -not (Test-RarGeneratorVersion -FilePath $rarPath -RequiredVersion $requiredRarVersion)) {
        throw "Acceptance RAR generator installation is incomplete under $rarRoot"
    }
    if (-not (Test-Path -LiteralPath $zstdPath) -or
        -not (Test-CommandRuns -FilePath $zstdPath -Arguments @("--version"))) {
        throw "Acceptance zstd generator installation is incomplete under $zstdRoot"
    }
    Write-Host "Acceptance archive generator tools are ready: $rarPath, $zstdPath" -ForegroundColor Green
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

    throw "maturin executable not found. Install maturin or make it available in PATH."
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

function Test-RarGeneratorVersion {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [Parameter(Mandatory = $true)]
        [string]$RequiredVersion
    )

    if (-not (Test-Path -LiteralPath $FilePath)) {
        return $false
    }
    try {
        $output = (& $FilePath "iver" 2>&1 | Out-String)
        # Rar.exe uses exit code 7 for the informational iver command even
        # though the version output is valid.
        return ($output -match ("RAR " + [regex]::Escape($RequiredVersion) + " x64"))
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

    throw "cmake executable not found. Install CMake or make it available in PATH."
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
    Assert-PathExists -LiteralPath $wrapperDll -Description "Built 7z wrapper DLL"
    Assert-PathExists -LiteralPath $workerExe -Description "Built 7z worker executable"
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
    }
    $toastDll = Join-Path $BuildDir "Release\sunpack_toast.dll"
    Assert-PathExists -LiteralPath $toastDll -Description "Built toast DLL"
    Copy-Item -LiteralPath $toastDll -Destination (Join-Path $ToolsRoot "sunpack_toast.dll") -Force
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
    'watch_broker_is_connected', 'watch_broker_ping_seconds',
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

$repoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $repoRoot
$buildArch = $Arch.ToLowerInvariant()
$processArch = Get-ProcessBuildArch
$rustTarget = Get-RustTarget -BuildArch $buildArch

Write-Step "Environment preflight"
if ($env:OS -ne "Windows_NT") {
    throw "This setup script only supports Windows."
}
Write-Host "Requested architecture: $buildArch"
Write-Host "Python/process architecture: $processArch"
if ($processArch -ne $buildArch) {
    throw "Development setup for native Python extensions must run under a target-architecture Python. This process is '$processArch', so it cannot prepare a real '$buildArch' environment."
}

$pythonCommand = Get-PythonCommand
$venvPath = Join-Path $repoRoot ".venv"
$venvPython = Join-Path $venvPath "Scripts\python.exe"
$venvScripts = Join-Path $venvPath "Scripts"
$projectPath = Join-Path $repoRoot "pyproject.toml"
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
$buildRoot = Join-Path $repoRoot "build"
$nativeWheelRoot = Join-Path $buildRoot ("native-wheels-dev-" + $buildArch)
$toolsRoot = if ($buildArch -eq "x64") { Join-Path $repoRoot "tools" } else { Join-Path $repoRoot ("tools-" + $buildArch) }
$sevenZipDllPath = Join-Path $toolsRoot "7z.dll"
$sevenZipLicensePath = Join-Path $repoRoot "licenses\7zip-license.txt"

Assert-PathExists -LiteralPath $projectPath -Description "pyproject.toml"
Assert-PathExists -LiteralPath $nativeCargoToml -Description "sunpack_native Cargo manifest"
Assert-PathExists -LiteralPath $nativeWorkspaceLock -Description "native Rust workspace lockfile"
Assert-PathExists -LiteralPath $watchBrokerCargoToml -Description "SunPack Watch Broker Cargo manifest"
Assert-CommandExists -Command "cargo" -Description "Rust toolchain"
Assert-CommandExists -Command "uv" -Description "uv dependency manager"
if ($Clean) {
    Write-Step "Cleaning local virtual environment"
    Remove-IfExists -LiteralPath $venvPath
}

Write-Step "Preparing local virtual environment"
$venvConfigPath = Join-Path $venvPath "pyvenv.cfg"
if (Test-Path -LiteralPath $venvConfigPath) {
    $venvConfig = Get-Content -LiteralPath $venvConfigPath -Raw
    if ($venvConfig -match "include-system-site-packages\s*=\s*true") {
        Write-Host "Recreating local virtual environment without global site-packages." -ForegroundColor Yellow
        Remove-IfExists -LiteralPath $venvPath
    }
}
Invoke-Native -FilePath "uv" -Arguments @("sync", "--locked", "--extra", "dev", "--python", $pythonCommand)

$env:Path = "$venvScripts;$env:Path"
$env:PYTHONPATH = $repoRoot
$env:VIRTUAL_ENV = $venvPath

Write-Step "Building and installing Rust native extension"
$maturinCommand = Get-MaturinCommand -VenvScripts $venvScripts
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

Ensure-Bundled7ZipAssets -ToolsRoot $toolsRoot -LicenseDestinationPath $sevenZipLicensePath -BuildArch $buildArch
if ($buildArch -eq "x64" -and -not $SkipAcceptanceTestTools) {
    Ensure-AcceptanceTestTools -RepoRoot $repoRoot -ToolsRoot $toolsRoot
}
$cmakeCommand = Get-CMakeCommand -VenvScripts $venvScripts
$ctestCommand = Get-CTestCommand -VenvScripts $venvScripts
Build-SevenZipWrapper -CMakeCommand $cmakeCommand -CTestCommand $ctestCommand -WrapperRoot $sevenZipWrapperRoot -BuildDir $sevenZipWrapperBuildDir -ToolsRoot $toolsRoot -SevenZipDllPath $sevenZipDllPath -BuildArch $buildArch
Build-ToastLibrary -CMakeCommand $cmakeCommand -CTestCommand $ctestCommand -SourceRoot $toastHostRoot -BuildDir $toastHostBuildDir -ToolsRoot $toolsRoot -BuildArch $buildArch
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

Write-Step "Verifying local source execution"
Invoke-Native -FilePath $venvPython -Arguments @("sunpack.py", "--help")
Invoke-Native -FilePath $venvPython -Arguments @("-m", "pytest", "--version")

Write-Host ""
Write-Host "Local development environment is ready." -ForegroundColor Green
Write-Host "Virtual env: $venvPath"
Write-Host "Activate: $venvPath\\Scripts\\Activate.ps1"
