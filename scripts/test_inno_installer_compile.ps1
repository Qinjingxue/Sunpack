[CmdletBinding()]
param(
    [string]$InnoCompilerPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$installerScript = Join-Path $repoRoot "installer\SunPack.iss"
$iconPath = Join-Path $repoRoot "sunpack.ico"

function Resolve-InnoCompiler {
    param([string]$ExplicitPath)

    if ($ExplicitPath) {
        if (-not (Test-Path -LiteralPath $ExplicitPath -PathType Leaf)) {
            throw "Inno Setup compiler not found: $ExplicitPath"
        }
        return (Resolve-Path -LiteralPath $ExplicitPath).Path
    }

    $command = Get-Command "ISCC.exe" -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    $candidates = @(
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
        "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
    )
    $resolved = $candidates | Where-Object {
        $_ -and (Test-Path -LiteralPath $_ -PathType Leaf)
    } | Select-Object -First 1

    if (-not $resolved) {
        throw "ISCC.exe was not found. Install Inno Setup 6.3 or newer, or pass -InnoCompilerPath."
    }
    return (Resolve-Path -LiteralPath $resolved).Path
}

$iscc = Resolve-InnoCompiler -ExplicitPath $InnoCompilerPath
if (-not (Test-Path -LiteralPath $installerScript -PathType Leaf)) {
    throw "Installer script not found: $installerScript"
}
if (-not (Test-Path -LiteralPath $iconPath -PathType Leaf)) {
    throw "Installer icon not found: $iconPath"
}

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("sunpack-inno-compile-" + [Guid]::NewGuid().ToString("N"))
$sourceDir = Join-Path $tempRoot "source"
$outputDir = Join-Path $tempRoot "output"
New-Item -ItemType Directory -Path $sourceDir, $outputDir -Force | Out-Null

try {
    Copy-Item -LiteralPath $iconPath -Destination (Join-Path $sourceDir "sunpack.ico") -Force
    [System.IO.File]::WriteAllText(
        (Join-Path $sourceDir "sunpack_config.json"),
        "{}",
        [System.Text.UTF8Encoding]::new($false)
    )

    foreach ($arch in @("x64", "arm64")) {
        $arguments = @(
            "/Qp",
            "/DAppVersion=compile-test",
            "/DSourceDir=$sourceDir",
            "/DOutputDir=$outputDir",
            "/DOutputBaseFilename=sunpack-installer-compile-test-$arch",
            "/DTargetArch=$arch",
            $installerScript
        )
        & $iscc @arguments
        if ($LASTEXITCODE -ne 0) {
            throw "Inno Setup installer compilation failed for $arch with exit code $LASTEXITCODE."
        }

        $outputPath = Join-Path $outputDir "sunpack-installer-compile-test-$arch.exe"
        if (-not (Test-Path -LiteralPath $outputPath -PathType Leaf)) {
            throw "Inno Setup reported success but did not create: $outputPath"
        }
    }
} finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
