# Final uninstall barrier: explicit --persistent-shutdown is issued before this
# script runs. This only waits for the already-requested runtime teardown.
param(
    [Parameter(Mandatory = $true)]
    [string]$CliAppPath,

    [Parameter(Mandatory = $true)]
    [string]$RuntimeAppPath,

    [ValidateRange(1, 300)]
    [int]$TimeoutSeconds = 20
)

$targets = @(
    [System.IO.Path]::GetFullPath($CliAppPath),
    [System.IO.Path]::GetFullPath($RuntimeAppPath)
)
$deadline = (Get-Date).AddSeconds($TimeoutSeconds)

do {
    $running = @(
        Get-Process -ErrorAction SilentlyContinue | Where-Object {
            try {
                $processPath = [System.IO.Path]::GetFullPath($_.Path)
                @(
                    $targets | Where-Object {
                        $_.Equals($processPath, [System.StringComparison]::OrdinalIgnoreCase)
                    }
                ).Count -gt 0
            } catch {
                $false
            }
        }
    )

    if ($running.Count -eq 0) {
        exit 0
    }

    Start-Sleep -Milliseconds 250
} while ((Get-Date) -lt $deadline)

exit 1
