[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$testTempRoot = [IO.Path]::GetFullPath((Join-Path $repoRoot ".sunpack-test-tmp"))
$testServicePrefix = "SunPackWatchBrokerTest_"
$testServicePattern = '^SunPackWatchBrokerTest_[0-9a-fA-F]{32}$'
$script:CleanupFailures = 0

. (Join-Path $PSScriptRoot "test_elevation.ps1")
$elevatedExitCode = Invoke-TestScriptElevated -ScriptPath $PSCommandPath -BoundParameters $PSBoundParameters
if ($null -ne $elevatedExitCode) {
    exit $elevatedExitCode
}

function Remove-StaleWatchBrokerServices {
    $services = @(Get-Service -Name ("{0}*" -f $testServicePrefix) -ErrorAction SilentlyContinue)
    foreach ($service in $services) {
        if ($service.Name -notmatch $testServicePattern) {
            continue
        }
        try {
            Stop-Service -InputObject $service -Force -ErrorAction SilentlyContinue
            & sc.exe delete $service.Name | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw "sc.exe delete returned exit code $LASTEXITCODE"
            }
            Write-Host ("    Removed stale Watch Broker service: " + $service.Name)
        } catch {
            $script:CleanupFailures++
            Write-Warning ("Could not remove stale Watch Broker service {0}: {1}" -f $service.Name, $_.Exception.Message)
        }
    }
}

function Remove-StaleTestVhds {
    $roots = @($testTempRoot)
    if ($env:SUNPACK_SPACE_TEST_VHD_DIR) {
        $roots += [IO.Path]::GetFullPath($env:SUNPACK_SPACE_TEST_VHD_DIR)
    }

    foreach ($root in ($roots | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $root -PathType Container)) {
            continue
        }
        $vhdFiles = @(Get-ChildItem -LiteralPath $root -Filter "space-*.vhdx" -File -Recurse -ErrorAction SilentlyContinue)
        foreach ($vhdFile in $vhdFiles) {
            try {
                if (Get-Command Dismount-DiskImage -ErrorAction SilentlyContinue) {
                    Dismount-DiskImage -ImagePath $vhdFile.FullName -ErrorAction SilentlyContinue | Out-Null
                }
                Remove-Item -LiteralPath $vhdFile.FullName -Force -ErrorAction Stop
                Write-Host ("    Removed stale test VHD: " + $vhdFile.FullName)
            } catch {
                $script:CleanupFailures++
                Write-Warning ("Could not remove stale test VHD {0}: {1}" -f $vhdFile.FullName, $_.Exception.Message)
            }
        }
    }
}

Remove-StaleWatchBrokerServices
Remove-StaleTestVhds

if ($script:CleanupFailures -gt 0) {
    Write-Warning ("SunPack test artifact cleanup completed with {0} failure(s)." -f $script:CleanupFailures)
    exit 1
}
Write-Host "SunPack test artifact cleanup completed."
