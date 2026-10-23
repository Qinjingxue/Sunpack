[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$DataRoot,
    [Parameter(Mandatory = $true)][string]$AdvancedConfig,
    [string]$OldAdvancedConfig,
    [string]$UserConfig
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# The installer calls this only after stopping the runtime and deploying files.
# Never recurse into a state directory or remove configuration/password files.
$dataDirectory = [IO.Path]::GetFullPath($DataRoot)
$directories = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
[void]$directories.Add((Join-Path $dataDirectory '.sunpack_watch'))
$state = ''
foreach ($configPath in @($AdvancedConfig, $OldAdvancedConfig, $UserConfig)) {
    if (-not $configPath -or -not (Test-Path -LiteralPath $configPath -PathType Leaf)) { continue }
    $config = Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($config.PSObject.Properties['watch'] -and $config.watch.PSObject.Properties['state_dir']) {
        $state = ([string]$config.watch.state_dir).Trim()
    }
    if (-not $state) { continue }
    if ($state -eq '~') { $state = $env:USERPROFILE }
    elseif ($state.StartsWith('~\') -or $state.StartsWith('~/')) {
        $state = Join-Path $env:USERPROFILE $state.Substring(2)
    }
    if (-not [IO.Path]::IsPathRooted($state)) { $state = Join-Path $dataDirectory $state }
    [void]$directories.Add([IO.Path]::GetFullPath($state))
}
$removed = $false
foreach ($directory in $directories) {
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) { continue }
    $taskStateReset = $false
    foreach ($file in Get-ChildItem -LiteralPath $directory -File -Force) {
        if ($file.Name -notin @('state.json', 'catalog.snapshot', 'catalog.snapshot.tmp', 'catalog.wal') -and
            $file.Name -notmatch '^state\.journal\.[0-9]+\.jsonl$' -and
            $file.Name -notmatch '^\.state\.json\.[0-9a-f]{32}\.tmp$') { continue }
        $isTaskState = ($file.Name -eq 'state.json') -or
            ($file.Name -match '^state\.journal\.[0-9]+\.jsonl$')
        Remove-Item -LiteralPath $file.FullName -Force
        $removed = $true
        if ($isTaskState) { $taskStateReset = $true }
    }
    # A task-state reset also invalidates the GUI's event-based task projection.
    if ($taskStateReset) {
        $eventLog = Join-Path $directory 'events.jsonl'
        if (Test-Path -LiteralPath $eventLog -PathType Leaf) {
            Remove-Item -LiteralPath $eventLog -Force
            $removed = $true
        }
    }
}
if ($removed) { exit 10 }
exit 0
