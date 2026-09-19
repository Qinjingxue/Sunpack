[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PackageRoot,
    [ValidateSet("x64", "arm64")]
    [string]$Arch = "x64"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

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
    Write-Host ("PASS  {0,-42} absent" -f $Description) -ForegroundColor Green
}

function Get-PackagedRuntimeToolNames {
    return @(
        "sunpack_sevenzip.dll",
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

function Get-ExpectedPeMachine {
    param([string]$BuildArch)
    switch ($BuildArch) {
        "x64" { return 0x8664 }
        "arm64" { return 0xAA64 }
    }
    throw "Unsupported architecture: $BuildArch"
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
    Write-Host ("PASS  {0,-42} {1}" -f $Description, $LiteralPath) -ForegroundColor Green
}

$root = (Resolve-Path -LiteralPath $PackageRoot).Path
$nativeExtension = Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Name -like "sunpack_native*.pyd" -or
        $_.Name -like "sunpack_native*.dll"
    } |
    Select-Object -First 1

if ($null -eq $nativeExtension) {
    throw "sunpack_native extension not found under: $root"
}

Assert-PeMachine -LiteralPath (Join-Path $root "sunpack.exe") -BuildArch $Arch -Description "sunpack.exe"
Assert-PeMachine -LiteralPath (Join-Path $root "sunpack-runtime.exe") -BuildArch $Arch -Description "sunpack-runtime.exe"
Assert-PeSubsystem -LiteralPath (Join-Path $root "sunpack.exe") -Expected 3 -Description "sunpack.exe"
Assert-PeSubsystem -LiteralPath (Join-Path $root "sunpack-runtime.exe") -Expected 2 -Description "sunpack-runtime.exe"
Assert-PathMissing -LiteralPath (Join-Path $root "sunpack-watch.exe") -Description "retired duplicate watch executable"
Assert-PeMachine -LiteralPath $nativeExtension.FullName -BuildArch $Arch -Description "sunpack_native extension"
Assert-PackagedRuntimeTools -PackageRoot $root
# The 7-Zip backend is compiled into sunpack_sevenzip.dll and
# sunpack_sevenzip_worker.exe. A leftover standalone 7z.dll would silently
# re-introduce the external backend dependency this migration removed.
Assert-PathMissing -LiteralPath (Join-Path $root "tools\7z.dll") -Description "retired standalone tools\7z.dll"
Assert-PeMachine -LiteralPath (Join-Path $root "tools\sunpack_sevenzip.dll") -BuildArch $Arch -Description "tools\sunpack_sevenzip.dll"
Assert-PeMachine -LiteralPath (Join-Path $root "tools\sunpack_sevenzip_worker.exe") -BuildArch $Arch -Description "tools\sunpack_sevenzip_worker.exe"
Assert-PeMachine -LiteralPath (Join-Path $root "tools\sunpack_toast.dll") -BuildArch $Arch -Description "tools\sunpack_toast.dll"

Write-Host ""
Write-Host "Package architecture validation passed: $Arch" -ForegroundColor Green
