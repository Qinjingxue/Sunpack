param(
    [Parameter(Mandatory=$true)][string]$OldAdvanced,
    [Parameter(Mandatory=$true)][string]$NewAdvanced,
    [Parameter(Mandatory=$true)][string]$Template,
    [Parameter(Mandatory=$true)][string]$UserConfig
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:Changed = $false

function Read-Object([string]$Path) {
    $value = [IO.File]::ReadAllText($Path) | ConvertFrom-Json
    if ($null -eq $value -or $value -isnot [pscustomobject]) { throw "Expected a JSON object: $Path" }
    return $value
}
function Update-Configuration($Old, $New, $User, $Defaults) {
    # Migrations are shape-based and idempotent. The installer owns backup/rollback.
    if (-not $User.PSObject.Properties['filesystem']) { return }
    $filesystem = $User.filesystem
    if (-not $filesystem.PSObject.Properties['scan_filters']) { return }
    $filters = @($filesystem.scan_filters)
    $merged = [Collections.Generic.List[object]]::new()
    foreach ($filter in $filters) {
        if ($filter.name -eq 'directory_prune') {
            $paths = @()
            foreach ($field in @('prune_dir_globs', 'path_globs')) {
                if ($filter.PSObject.Properties[$field]) { $paths += @($filter.$field) }
            }
            $enabled = $filter.PSObject.Properties['enabled'] -and $filter.enabled
            # Different enabled states must stay independent. Only merge rules
            # with the same switch; never activate a disabled file blacklist.
            $target = $filters | Where-Object {
                $_.name -eq 'blacklist' -and
                [bool]($_.PSObject.Properties['enabled'] -and $_.enabled) -eq [bool]$enabled
            } | Select-Object -First 1
            if ($null -eq $target) {
                $filter.name = 'blacklist'
                $target = $filter
                $merged.Add($filter)
            }
            $existing = @()
            if ($target.PSObject.Properties['path_globs']) { $existing = @($target.path_globs) }
            $target | Add-Member -NotePropertyName path_globs -NotePropertyValue @(Merge-PathGlobs ($existing + $paths)) -Force
            $filter.PSObject.Properties.Remove('prune_dir_globs')
            $script:Changed = $true
        } else {
            if ($filter.name -eq 'whitelist' -and $filter.PSObject.Properties['prune_dir_globs']) {
                $paths = @($filter.prune_dir_globs)
                if ($filter.PSObject.Properties['path_globs']) { $paths += @($filter.path_globs) }
                $filter | Add-Member -NotePropertyName path_globs -NotePropertyValue @(Merge-PathGlobs $paths) -Force
                $filter.PSObject.Properties.Remove('prune_dir_globs')
                $script:Changed = $true
            }
            $merged.Add($filter)
        }
    }
    if ($script:Changed) { $filesystem.scan_filters = @($merged.ToArray()) }
}

function Merge-PathGlobs($Values) {
    $unique = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $ordered = [Collections.Generic.List[string]]::new()
    foreach ($value in $Values) {
        $normalized = ([string]$value).Trim().Replace('\', '/').Trim('/')
        if ($normalized -and $unique.Add($normalized)) { $ordered.Add($normalized) }
    }
    foreach ($value in $ordered) {
        # A bare name already covers the same name and subtree at every depth.
        $base = $value
        if ($value.EndsWith('/**')) { $base = $value.Substring(0, $value.Length - 3) }
        if ($base -ne $value -and -not $base.Contains('/') -and $unique.Contains($base)) { continue }
        $value
    }
}

$old = Read-Object $OldAdvanced
$new = Read-Object $NewAdvanced
$defaults = Read-Object $Template
$user = Read-Object $UserConfig
Update-Configuration $old $new $user $defaults
if (-not $script:Changed) { exit 0 }

$target = [IO.Path]::GetFullPath($UserConfig)
$parent = [IO.Path]::GetDirectoryName($target)
for ($path = $target; $path; $path = [IO.Path]::GetDirectoryName($path)) {
    if ([IO.File]::GetAttributes($path) -band [IO.FileAttributes]::ReparsePoint) {
        throw "Refusing a reparse point in the installer configuration target: $path"
    }
}
$temporary = [IO.Path]::Combine($parent, '.sunpack-config-' + [Guid]::NewGuid().ToString('N') + '.tmp')
try {
    $text = ($user | ConvertTo-Json -Depth 100) + [Environment]::NewLine
    $null = $text | ConvertFrom-Json
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($text)
    $stream = New-Object IO.FileStream($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    [IO.File]::Replace($temporary, $target, [System.Management.Automation.Language.NullString]::Value, $false)
} finally {
    if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
}
