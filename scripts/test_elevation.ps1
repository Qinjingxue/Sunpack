function ConvertTo-PowerShellSingleQuotedLiteral {
    param([Parameter(Mandatory = $true)][string]$Value)

    return "'" + $Value.Replace("'", "''") + "'"
}

function ConvertTo-PowerShellValueLiteral {
    param($Value)

    if ($null -eq $Value) {
        return '$null'
    }
    if ($Value -is [string]) {
        return ConvertTo-PowerShellSingleQuotedLiteral -Value $Value
    }
    if ($Value -is [bool]) {
        if ($Value) { return '$true' }
        return '$false'
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $items = @($Value | ForEach-Object { ConvertTo-PowerShellValueLiteral -Value $_ })
        return '@(' + ($items -join ', ') + ')'
    }
    if ($Value -is [byte] -or $Value -is [sbyte] -or
        $Value -is [int16] -or $Value -is [uint16] -or
        $Value -is [int32] -or $Value -is [uint32] -or
        $Value -is [int64] -or $Value -is [uint64] -or
        $Value -is [single] -or $Value -is [double] -or $Value -is [decimal]) {
        return [Convert]::ToString($Value, [Globalization.CultureInfo]::InvariantCulture)
    }
    return ConvertTo-PowerShellSingleQuotedLiteral -Value ([string]$Value)
}

function Invoke-TestScriptElevated {
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$BoundParameters,
        [switch]$ShowOutput
    )

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        return $null
    }

    $runningInCi =
        [string]::Equals($env:CI, "true", [StringComparison]::OrdinalIgnoreCase) -or
        [string]::Equals($env:GITHUB_ACTIONS, "true", [StringComparison]::OrdinalIgnoreCase)
    if ($runningInCi) {
        throw "This test requires an elevated CI runner; interactive UAC relaunch is disabled in CI."
    }

    $commandParts = @("& " + (ConvertTo-PowerShellSingleQuotedLiteral -Value $ScriptPath))
    foreach ($entry in $BoundParameters.GetEnumerator()) {
        $parameterName = [string]$entry.Key
        $parameterValue = $entry.Value
        if ($parameterValue -is [System.Management.Automation.SwitchParameter]) {
            if ($parameterValue.IsPresent) {
                $commandParts += "-$parameterName"
            }
            continue
        }
        $commandParts += "-$parameterName"
        $commandParts += ConvertTo-PowerShellValueLiteral -Value $parameterValue
    }

    $diagnosticPath = Join-Path ([IO.Path]::GetTempPath()) (
        "sunpack-elevated-test-{0}-{1}.log" -f $PID, [guid]::NewGuid().ToString("N")
    )
    $diagnosticLiteral = ConvertTo-PowerShellSingleQuotedLiteral -Value $diagnosticPath
    $elevatedCommand = (
        '$ErrorActionPreference = ''Stop''; ' +
        'try { ' +
        ($commandParts -join " ") + ' *>&1 | Out-File -LiteralPath ' + $diagnosticLiteral + ' -Encoding UTF8; ' +
        'if (-not $?) { exit 1 } ' +
        '} catch { ($_ | Format-List * -Force | Out-String) | Out-File -LiteralPath ' +
        $diagnosticLiteral + ' -Append -Encoding UTF8; exit 1 }; ' +
        '; exit 0'
    )
    $encodedCommand = [Convert]::ToBase64String(
        [Text.Encoding]::Unicode.GetBytes($elevatedCommand)
    )
    $hostPath = (Get-Process -Id $PID).Path
    $process = $null
    try {
        if ($ShowOutput) {
            Write-Host "Running acceptance with elevation for the temporary Broker and disk-full tests."
        }
        $process = Start-Process `
            -FilePath $hostPath `
            -ArgumentList @("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", $encodedCommand) `
            -WorkingDirectory (Split-Path -Parent $ScriptPath) `
            -Verb RunAs `
            -WindowStyle Hidden `
            -Wait `
            -PassThru
        $exitCode = [int]$process.ExitCode
        if ($exitCode -ne 0) {
            [Console]::Error.WriteLine("Elevated test process failed. Diagnostic log: {0}", $diagnosticPath)
            if (Test-Path -LiteralPath $diagnosticPath -PathType Leaf) {
                foreach ($line in Get-Content -LiteralPath $diagnosticPath) {
                    [Console]::Error.WriteLine([string]$line)
                }
            } else {
                [Console]::Error.WriteLine("The elevated process did not produce its diagnostic log.")
            }
        } elseif (Test-Path -LiteralPath $diagnosticPath) {
            if ($ShowOutput) {
                Get-Content -LiteralPath $diagnosticPath | ForEach-Object { Write-Host $_ }
            }
            Remove-Item -LiteralPath $diagnosticPath -Force
        }
        return $exitCode
    } catch {
        [Console]::Error.WriteLine("Failed to launch or wait for elevated test process: {0}", $_.Exception.Message)
        if (Test-Path -LiteralPath $diagnosticPath -PathType Leaf) {
            foreach ($line in Get-Content -LiteralPath $diagnosticPath) {
                [Console]::Error.WriteLine([string]$line)
            }
        }
        throw
    } finally {
        if ($null -ne $process) {
            $process.Dispose()
        }
    }
}
