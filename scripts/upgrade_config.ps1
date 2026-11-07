param(
    [Parameter(Mandatory=$true)][string]$UserConfig,
    [string]$AdvancedConfig = ''
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Escape-RuleLiteral([string]$Value) {
    $builder = [Text.StringBuilder]::new()
    foreach ($c in $Value.ToCharArray()) {
        if ('\.^$|?*+()[]{}'.Contains([string]$c)) { $null = $builder.Append('\') }
        $null = $builder.Append($c)
    }
    $builder.ToString()
}

function Convert-LiteralRule([string]$Value) {
    # v1.3.4 filenames and extensions were literal, even when containing * or ?.
    if ($Value.Contains('*') -or $Value.Contains('?')) {
        [pscustomobject]@{ value = ('\A(?:' + (Escape-RuleLiteral $Value) + ')\z'); regex = $true }
    } else { [pscustomobject]@{ value = $Value; regex = $false } }
}

function Convert-PathRule([string]$Value, [bool]$DirectoryName) {
    $value = $Value.Trim().Replace('\', '/').Trim('/')
    if (-not $value) { return }
    if ($DirectoryName) {
        # v1.3.4 prune_dir_globs were matched against a single directory name.
        if ($value.Contains('/')) { [pscustomobject]@{ value = '\b\B'; regex = $true } }
        else { [pscustomobject]@{ value = $value; regex = $false } }
        return
    }
    # v1.3.4 path_globs matched at any component boundary, including below
    # the scan root. Its ** crossed separators; ordinary * and ? did not.
    if ($value.EndsWith('/**')) { $value = $value.Substring(0, $value.Length - 3).TrimEnd('/') }
    if (-not $value) { return }
    if (-not $value.Contains('/') -and -not $value.Contains('**')) {
        [pscustomobject]@{ value = $value; regex = $false }
        return
    }
    $body = [Text.StringBuilder]::new()
    for ($index = 0; $index -lt $value.Length; $index++) {
        $c = $value[$index]
        if ($c -eq '*' -and $index + 1 -lt $value.Length -and $value[$index + 1] -eq '*') {
            $index++; $null = $body.Append('.*')
        } elseif ($c -eq '*') { $null = $body.Append('[^/]*') }
        elseif ($c -eq '?') { $null = $body.Append('[^/]') }
        else { $null = $body.Append((Escape-RuleLiteral ([string]$c))) }
    }
    [pscustomobject]@{ value = ('(?:\A|/)(?:' + $body.ToString() + ')(?:/|\z)'); regex = $true }
}

function Unique-Rules($Rules) {
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($rule in $Rules) {
        if ($seen.Add(([string]$rule.regex + ':' + $rule.value))) { $rule }
    }
}

$user = [IO.File]::ReadAllText($UserConfig) | ConvertFrom-Json
if ($null -eq $user -or $user -isnot [pscustomobject]) { throw "Expected a JSON object: $UserConfig" }

# Expose the single content policy in the ordinary configuration. Preserve an
# explicit user value, then the previous advanced value, then the safe default.
$changed = $false
if (-not $user.PSObject.Properties['extraction'] -or $null -eq $user.extraction) {
    $user | Add-Member -NotePropertyName extraction -NotePropertyValue ([pscustomobject]@{}) -Force
}
if ($user.extraction -isnot [pscustomobject]) { throw 'extraction must be an object' }
if (-not $user.extraction.PSObject.Properties['content_requirement']) {
    $requirement = 'complete'
    if ($AdvancedConfig -and (Test-Path -LiteralPath $AdvancedConfig -PathType Leaf)) {
        $advanced = [IO.File]::ReadAllText($AdvancedConfig) | ConvertFrom-Json
        if ($advanced.PSObject.Properties['extraction'] -and $null -ne $advanced.extraction -and
            $advanced.extraction.PSObject.Properties['content_requirement']) {
            $requirement = $advanced.extraction.content_requirement
        }
    }
    $user.extraction | Add-Member -NotePropertyName content_requirement -NotePropertyValue $requirement
    $changed = $true
}

# The logical-input checkpoint replaces the former carrier continuation. Reset
# only its native snapshot/WAL; passwords, roots, outputs and configuration stay
# user-owned. A marker makes subsequent installations preserve current records.
$dataDirectory = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($UserConfig))
$stateDirectory = Join-Path $dataDirectory '.sunpack_watch'
foreach ($configuration in @($AdvancedConfig, $UserConfig)) {
    if (-not $configuration -or -not (Test-Path -LiteralPath $configuration -PathType Leaf)) { continue }
    $settings = [IO.File]::ReadAllText($configuration) | ConvertFrom-Json
    if ($settings.PSObject.Properties['watch'] -and $null -ne $settings.watch -and $settings.watch.PSObject.Properties['state_dir']) {
        $configured = ([string]$settings.watch.state_dir).Trim()
        $stateDirectory = if ($configured) { $configured } else { Join-Path $dataDirectory '.sunpack_watch' }
    }
}
if ($stateDirectory -eq '~') { $stateDirectory = $env:USERPROFILE }
elseif ($stateDirectory.StartsWith('~\') -or $stateDirectory.StartsWith('~/')) {
    $stateDirectory = Join-Path $env:USERPROFILE $stateDirectory.Substring(2)
}
if (-not [IO.Path]::IsPathRooted($stateDirectory)) { $stateDirectory = Join-Path $dataDirectory $stateDirectory }
$stateDirectory = [IO.Path]::GetFullPath($stateDirectory)
$marker = Join-Path $stateDirectory 'logical-input-recovery'
if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) {
    if (Test-Path -LiteralPath $stateDirectory) {
        if ((Get-Item -LiteralPath $stateDirectory -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Refusing a reparse point for Watch recovery reset: $stateDirectory"
        }
        foreach ($record in Get-ChildItem -LiteralPath $stateDirectory -File -Force) {
            if ($record.Name -notmatch '^state\.(?:snapshot|journal\.\d{20}\.wal)$') { continue }
            if ([IO.Path]::GetFullPath($record.DirectoryName) -ne $stateDirectory) { throw 'Watch recovery reset escaped its directory' }
            Remove-Item -LiteralPath $record.FullName -Force
        }
    } else { $null = New-Item -ItemType Directory -Path $stateDirectory -Force }
    [IO.File]::WriteAllText($marker, '')
}
$hasFilters = $user.PSObject.Properties['filesystem'] -and $null -ne $user.filesystem -and $user.filesystem.PSObject.Properties['scan_filters']
$filters = @()
if ($hasFilters) { $filters = @($user.filesystem.scan_filters) }
$converted = [Collections.Generic.List[object]]::new()
$pruned = [Collections.Generic.List[object]]::new()
foreach ($filter in $filters) {
    $enabled = [bool]($filter.PSObject.Properties['enabled'] -and $filter.enabled)
    if ($filter.name -eq 'directory_prune') {
        $paths = @()
        if ($filter.PSObject.Properties['prune_dir_globs']) {
            $paths += @(foreach ($value in $filter.prune_dir_globs) { Convert-PathRule ([string]$value) $true })
        }
        if ($filter.PSObject.Properties['path_globs']) {
            $paths += @(foreach ($value in $filter.path_globs) { Convert-PathRule ([string]$value) $false })
        }
        $pruned.Add([pscustomobject]@{ name = 'blacklist'; enabled = $enabled; paths = @(Unique-Rules $paths); full_names = @(); files = @(); extensions = @() })
        $changed = $true
        continue
    }
    # Only the released v1.3.4 schema is migrated. Current records are a no-op;
    # intermediate untagged development schemas have no compatibility path.
    $prefix = if ($filter.name -eq 'blacklist') { 'blocked' } elseif ($filter.name -eq 'whitelist') { 'allowed' } else { '' }
    if (-not $prefix -or $filter.PSObject.Properties['paths'] -or $filter.PSObject.Properties['files'] -or
        $filter.PSObject.Properties['extensions'] -or $filter.PSObject.Properties['full_names']) {
        $converted.Add($filter)
        continue
    }
    $paths = @(); $directories = @(); $names = @(); $extensions = @()
    if ($filter.name -eq 'whitelist') {
        if ($filter.PSObject.Properties['path_globs']) {
            $paths = @(foreach ($value in $filter.path_globs) { Convert-PathRule ([string]$value) $false })
        }
        if ($filter.PSObject.Properties['prune_dir_globs']) {
            $directories = @(foreach ($value in $filter.prune_dir_globs) { Convert-PathRule ([string]$value) $true })
        }
    }
    $fileField = $prefix + '_files'; $extField = $prefix + '_extensions'
    if ($filter.PSObject.Properties[$fileField]) {
        $names = @(foreach ($value in $filter.$fileField) {
            $name = (([string]$value).Trim().Replace('\', '/') -split '/')[-1]
            if ($name) { Convert-LiteralRule $name }
        })
    }
    if ($filter.PSObject.Properties[$extField]) {
        $extensions = @(foreach ($value in $filter.$extField) {
            $ext = ([string]$value).Trim()
            if (-not $ext) { continue }
            if ($ext.StartsWith('.')) { $ext = $ext.Substring(1) }
            if ($ext) { Convert-LiteralRule $ext }
            else { [pscustomobject]@{ value = '\A\z'; regex = $true } }
        })
    }
    # Combine the released whitelist path groups as one field (OR within paths).
    $paths = @(Unique-Rules (@($paths) + @($directories)))
    foreach ($field in @('path_globs', 'prune_dir_globs', $fileField, $extField)) { $filter.PSObject.Properties.Remove($field) }
    $filter | Add-Member -NotePropertyName enabled -NotePropertyValue $enabled -Force
    $filter | Add-Member -NotePropertyName paths -NotePropertyValue @(Unique-Rules $paths) -Force
    $filter | Add-Member -NotePropertyName full_names -NotePropertyValue @(Unique-Rules $names) -Force
    $filter | Add-Member -NotePropertyName files -NotePropertyValue @() -Force
    $filter | Add-Member -NotePropertyName extensions -NotePropertyValue @(Unique-Rules $extensions) -Force
    $converted.Add($filter)
    $changed = $true
}
foreach ($prune in $pruned) {
    # One blacklist owns both legacy filters; any enabled source enables it.
    $target = $converted | Where-Object { $_.name -eq 'blacklist' } | Select-Object -First 1
    if ($null -eq $target) { $converted.Insert(0, $prune) }
    else {
        $existing = @()
        if ($target.PSObject.Properties['paths']) { $existing = @($target.paths) }
        $target | Add-Member -NotePropertyName paths -NotePropertyValue @(Unique-Rules (@($prune.paths) + $existing)) -Force
        $target | Add-Member -NotePropertyName enabled -NotePropertyValue ([bool]($target.enabled -or $prune.enabled)) -Force
    }
}
if (-not $changed) { exit 0 }
if ($hasFilters) { $user.filesystem.scan_filters = @($converted.ToArray()) }

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
