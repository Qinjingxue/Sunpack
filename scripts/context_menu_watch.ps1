param(
    [Parameter(Mandatory = $true)][string]$AppPath,
    [Parameter(Mandatory = $true)][ValidateSet("add", "remove")][string]$WatchAction,
    [Parameter(Mandatory = $true)][string]$TargetPath,
    [string]$ScriptPath,
    [switch]$Recursive
)

$ErrorActionPreference = "Stop"

# -File receives Explorer's quoted path as one argument, including whitespace
# and apostrophes. Native invocation preserves that boundary without rebuilding
# a command line using Start-Process -ArgumentList.
$watchArgs = @()
if ($ScriptPath) { $watchArgs += $ScriptPath }
$watchArgs += @("watch", $WatchAction, $TargetPath)
if ($WatchAction -eq "add") {
    $watchArgs += "--start"
    if ($Recursive) { $watchArgs += "--recursive" }
}

& $AppPath @watchArgs
exit $LASTEXITCODE
