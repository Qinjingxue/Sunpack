. (Join-Path $PSScriptRoot "sevenzip_asm_check.ps1")
. (Join-Path $PSScriptRoot "test_environment.ps1")

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Remove-IfExists {
    param([string]$LiteralPath)
    if (Test-Path -LiteralPath $LiteralPath) {
        Remove-Item -LiteralPath $LiteralPath -Recurse -Force
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

function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [string[]]$Arguments = @()
    )

    if ($PSVersionTable.PSVersion.Major -eq 5) {
        # Windows PowerShell reports redirected stderr as PowerShell errors.
        # Cargo writes progress there even on success.
        $command = Get-Command -Name $FilePath -CommandType Application -ErrorAction Stop
        $ErrorActionPreference = "Continue"
        & $command @Arguments 2>&1 | ForEach-Object {
            if ($_ -is [System.Management.Automation.ErrorRecord]) {
                if ($_.FullyQualifiedErrorId -notin @("NativeCommandError", "NativeCommandErrorMessage")) {
                    throw $_
                }
                Write-Host $_.ToString()
            } else {
                $_
            }
        }
    } else {
        & $FilePath @Arguments
    }
    if ($LASTEXITCODE -ne 0) {
        $joined = ($Arguments | ForEach-Object { $_ }) -join " "
        throw "Command failed with exit code ${LASTEXITCODE}: $FilePath $joined"
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

function Build-SevenZipWorker {
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
        [string]$BuildArch,
        [ValidateSet("ci", "release")][string]$BuildProfile
    )

    Write-Step "Building embedded 7-Zip worker"
    $buildStartedUtc = [datetime]::UtcNow
    Assert-PathExists -LiteralPath (Join-Path $WrapperRoot "CMakeLists.txt") -Description "7z wrapper CMake project"
    $cmakePlatform = Get-CMakePlatform -BuildArch $BuildArch
    Reset-StaleCMakeBuildDir -SourceDir $WrapperRoot -BuildDir $BuildDir -CMakePlatform $cmakePlatform
    $workerDebug = if ($BuildProfile -eq "ci") { "ON" } else { "OFF" }
    Invoke-Native -FilePath $CMakeCommand -Arguments @("-S", $WrapperRoot, "-B", $BuildDir, "-A", $cmakePlatform, "-DSUP7Z_DEBUG=$workerDebug", "-DSUNPACK_BUILD_JOBS=$BuildJobs")
    Remove-Item -LiteralPath (Join-Path $BuildDir "Release\sunpack_sevenzip.dll") -Force -ErrorAction SilentlyContinue
    Invoke-Native -FilePath $CMakeCommand -Arguments @("--build", $BuildDir, "--config", "Release", "--parallel", [string]$BuildJobs)
    if ($BuildProfile -eq "ci") {
        if ((Get-ProcessBuildArch) -eq $BuildArch) {
            Invoke-Native -FilePath $CTestCommand -Arguments @("--test-dir", $BuildDir, "-C", "Release", "--output-on-failure")
        } else {
            Write-Host "Skipping C++ tests because $BuildArch binaries cannot run in the current process architecture" -ForegroundColor Yellow
        }
    }

    $workerExe = Join-Path $BuildDir "Release\sunpack_sevenzip_worker.exe"
    $launcherExe = Join-Path $BuildDir "Release\sunpack_launcher.exe"
    Assert-PathExists -LiteralPath $workerExe -Description "Built 7z worker executable"
    Assert-PathExists -LiteralPath $launcherExe -Description "Built SunPack launcher executable"

    Assert-SevenZipAsmSelection -BuildDir $BuildDir -BuildArch $BuildArch -ArtifactPaths @($workerExe)
    Set-DevelopmentArtifactBuildTime -Path $launcherExe -BuildStartedUtc $buildStartedUtc
    Set-DevelopmentArtifactBuildTime -Path $workerExe -BuildStartedUtc $buildStartedUtc
}

function Build-ToastLibrary {
    param(
        [Parameter(Mandatory = $true)][string]$CMakeCommand,
        [Parameter(Mandatory = $true)][string]$CTestCommand,
        [Parameter(Mandatory = $true)][string]$SourceRoot,
        [Parameter(Mandatory = $true)][string]$BuildDir,
        [Parameter(Mandatory = $true)][string]$BuildArch,
        [ValidateSet("ci", "release")][string]$BuildProfile
    )

    Write-Step "Building in-process Windows toast library"
    $buildStartedUtc = [datetime]::UtcNow
    Assert-PathExists -LiteralPath (Join-Path $SourceRoot "CMakeLists.txt") -Description "toast CMake project"
    $cmakePlatform = Get-CMakePlatform -BuildArch $BuildArch
    Reset-StaleCMakeBuildDir -SourceDir $SourceRoot -BuildDir $BuildDir -CMakePlatform $cmakePlatform
    $lto = if ($BuildProfile -eq "ci") { "OFF" } else { "ON" }
    Invoke-Native -FilePath $CMakeCommand -Arguments @("-S", $SourceRoot, "-B", $BuildDir, "-A", $cmakePlatform, "-DCMAKE_BUILD_TYPE=Release", "-DSUNPACK_TOAST_ENABLE_LTO=$lto", "-DSUNPACK_BUILD_JOBS=$BuildJobs")
    $toastBuildArgs = @("--build", $BuildDir, "--config", "Release", "--parallel", [string]$BuildJobs)
    if ($BuildProfile -eq "release") { $toastBuildArgs += @("--target", "sunpack_toast") }
    Invoke-Native -FilePath $CMakeCommand -Arguments $toastBuildArgs
    if ($BuildProfile -eq "ci" -and (Get-ProcessBuildArch) -eq $BuildArch) {
        Invoke-Native -FilePath $CTestCommand -Arguments @("--test-dir", $BuildDir, "-C", "Release", "--output-on-failure")
    }
    $toastDll = Join-Path $BuildDir "Release\sunpack_toast.dll"
    Assert-PathExists -LiteralPath $toastDll -Description "Built toast DLL"
    Set-DevelopmentArtifactBuildTime -Path $toastDll -BuildStartedUtc $buildStartedUtc
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
