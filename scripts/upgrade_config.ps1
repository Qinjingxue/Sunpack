param(
    [Parameter(Mandatory=$true)][string]$UserConfig,
    [Parameter(Mandatory=$true)][string]$TemplateConfig,
    [string]$AdvancedConfig = '',
    [AllowEmptyString()][string]$PreviousVersion = ''
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-PlainPath([string]$Path) {
    for ($part = $Path; $part; $part = [IO.Path]::GetDirectoryName($part)) {
        if ((Test-Path -LiteralPath $part) -and
            ((Get-Item -LiteralPath $part -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Refusing a reparse point during SunPack upgrade: $part"
        }
    }
}

function Assert-PlainTree([string]$Path) {
    Assert-PlainPath $Path
    if (Test-Path -LiteralPath $Path -PathType Container) {
        foreach ($child in Get-ChildItem -LiteralPath $Path -Force) {
            Assert-PlainTree $child.FullName
        }
    }
}

function Read-Config([string]$Path) {
    Assert-PlainPath $Path
    $value = [IO.File]::ReadAllText($Path) | ConvertFrom-Json
    if ($null -eq $value -or $value -isnot [pscustomobject]) { throw "Expected a JSON object: $Path" }
    $value
}

function Assert-PrivateDirectory([string]$Directory) {
    # Never allow a bad caller path to designate a drive or shared parent folder.
    foreach ($protected in @([IO.Path]::GetPathRoot($Directory), $env:ProgramData, $env:USERPROFILE, $env:WINDIR)) {
        if ($protected -and $Directory.TrimEnd('\', '/') -eq $protected.TrimEnd('\', '/')) {
            throw "Refusing to reset a shared directory: $Directory"
        }
    }
}

# This script is the entire pre-1.4 boundary. Current installs never repair,
# migrate or clear data merely because a marker file is absent.
$dataDirectory = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($UserConfig))
Assert-PlainPath $dataDirectory
Assert-PrivateDirectory $dataDirectory
$version = $null
$versionText = $PreviousVersion.Trim() -replace '^v', ''
if ($versionText -match '^(\d+\.\d+\.\d+(?:\.\d+)?)(?:-[0-9A-Za-z.-]+)?$') {
    [void][Version]::TryParse($Matches[1], [ref]$version)
}
if ($null -eq $version) {
    if ((Test-Path -LiteralPath $dataDirectory) -and
        @(Get-ChildItem -LiteralPath $dataDirectory -Force).Count -gt 0) {
        throw "Unknown installed version '$PreviousVersion'; refusing to reset existing SunPack data."
    }
    exit 0
}
if ($version -ge [Version]'1.4.0') { exit 0 }

Assert-PlainTree $dataDirectory
$template = Read-Config $TemplateConfig
$user = [pscustomobject]@{}
if (Test-Path -LiteralPath $UserConfig -PathType Leaf) { $user = Read-Config $UserConfig }
$advanced = [pscustomobject]@{}
if ($AdvancedConfig -and (Test-Path -LiteralPath $AdvancedConfig -PathType Leaf)) {
    $advanced = Read-Config $AdvancedConfig
}

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

$hasFilters = $user.PSObject.Properties['filesystem'] -and $null -ne $user.filesystem -and $user.filesystem.PSObject.Properties['scan_filters']
$filters = @()
if ($hasFilters -and $null -ne $user.filesystem.scan_filters) { $filters = @($user.filesystem.scan_filters) }
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
        continue
    }
    # v1.3.0-v1.3.4 share the legacy schema; v1.3.5 already uses current rules.
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
}
foreach ($prune in $pruned) {
    $target = $converted | Where-Object { $_.name -eq 'blacklist' } | Select-Object -First 1
    if ($null -eq $target) { $converted.Insert(0, $prune); continue }
    # There is one current blacklist switch. Never activate rules from a
    # disabled old module merely because the other module was enabled.
    if ($prune.enabled -and -not $target.enabled) {
        foreach ($name in @('paths', 'full_names', 'files', 'extensions')) {
            $target | Add-Member -NotePropertyName $name -NotePropertyValue @() -Force
        }
    }
    if ($prune.enabled -or -not $target.enabled) {
        $existing = @()
        if ($target.PSObject.Properties['paths']) { $existing = @($target.paths) }
        $target | Add-Member -NotePropertyName paths -NotePropertyValue @(Unique-Rules (@($prune.paths) + $existing)) -Force
    }
    $target | Add-Member -NotePropertyName enabled -NotePropertyValue ([bool]($target.enabled -or $prune.enabled)) -Force
}
if ($hasFilters -and $null -ne $user.filesystem.scan_filters) {
    $user.filesystem.scan_filters = @($converted.ToArray())
}

# Only the seven fields moved into the ordinary UI have an advanced fallback.
# Do not copy arbitrary advanced overrides into the ordinary configuration.
foreach ($field in @(
    @('watch', 'tray_enabled'), @('watch', 'toast_enabled'),
    @('watch', 'clipboard_monitor_enabled'), @('watch', 'clipboard_builtin_max_entries'),
    @('watch', 'toast_report_retention_days'), @('passwords', 'clipboard_passwords_enabled'),
    @('extraction', 'content_requirement')
)) {
    $section = $field[0]; $name = $field[1]
    if (-not $user.PSObject.Properties[$section]) {
        $user | Add-Member -NotePropertyName $section -NotePropertyValue ([pscustomobject]@{})
    }
    if ($user.$section -isnot [pscustomobject] -or $user.$section.PSObject.Properties[$name]) { continue }
    if ($advanced.PSObject.Properties[$section] -and $advanced.$section -is [pscustomobject] -and
        $advanced.$section.PSObject.Properties[$name]) {
        $user.$section | Add-Member -NotePropertyName $name -NotePropertyValue $advanced.$section.$name
    }
}

# The current ordinary template is the schema: new keys get their default and
# retired keys disappear. Test presence, never truthiness; null/false/0/""/[]
# are explicit values. Only scan_filters is a named-record array.
function Merge-OrdinaryConfig($Defaults, $Previous, [string]$Key = '') {
    if ($Defaults -is [pscustomobject] -and $Previous -is [pscustomobject]) {
        $result = [ordered]@{}
        foreach ($property in $Defaults.PSObject.Properties) {
            $old = $Previous.PSObject.Properties[$property.Name]
            if ($null -ne $old) {
                $result[$property.Name] = Merge-OrdinaryConfig $property.Value $old.Value $property.Name
            } else { $result[$property.Name] = $property.Value }
        }
        return [pscustomobject]$result
    }
    if ($Key -eq 'scan_filters' -and $Previous -is [array]) {
        $result = @(foreach ($filter in $Previous) {
            $current = $Defaults | Where-Object { $_.name -eq $filter.name } | Select-Object -First 1
            if ($null -ne $current) { Merge-OrdinaryConfig $current $filter }
        })
        return ,$result
    }
    return ,$Previous
}
$user = Merge-OrdinaryConfig $template $user

# A custom state directory is not owned by SunPack. Remove only named records,
# never recurse through arbitrary user content or delete the directory itself.
$customRecords = @()
if ($advanced.PSObject.Properties['watch'] -and $advanced.watch -is [pscustomobject] -and
    $advanced.watch.PSObject.Properties['state_dir']) {
    $custom = ([string]$advanced.watch.state_dir).Trim()
    if ($custom) {
        if ($custom -eq '~') { $custom = $env:USERPROFILE }
        elseif ($custom.StartsWith('~\') -or $custom.StartsWith('~/')) {
            $custom = Join-Path $env:USERPROFILE $custom.Substring(2)
        }
        if (-not [IO.Path]::IsPathRooted($custom)) { $custom = Join-Path $dataDirectory $custom }
        $custom = [IO.Path]::GetFullPath($custom)
        Assert-PlainPath $custom
        Assert-PrivateDirectory $custom
        if ($custom -ne $dataDirectory -and (Test-Path -LiteralPath $custom -PathType Container)) {
            $customRecords = @(foreach ($record in Get-ChildItem -LiteralPath $custom -Force) {
                $owned = if ($record.PSIsContainer) {
                    $record.Name -in @('events.json.store', 'bootstrap.events.json.store', 'failures')
                } else {
                    $record.Name -match '^(?:state\.(?:json|snapshot|journal\.\d{20}\.(?:wal|jsonl))|catalog\.(?:snapshot|wal)\.bin|(?:bootstrap\.)?events\.jsonl?|toast_host_events\.jsonl|logical-input-recovery|fixed-state-directory)$'
                }
                if (-not $owned) { continue }
                if (($dataDirectory + [IO.Path]::DirectorySeparatorChar).StartsWith(
                    $record.FullName.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
                    throw "Custom state record contains the managed data directory: $($record.FullName)"
                }
                Assert-PlainTree $record.FullName
                $record
            })
        }
    }
}

# Prepare all retained content before changing anything. A one-byte mapping
# preserves the BOM and every nonblank password byte, including whitespace in
# JSON string values. Do not deserialize/reserialize the password file.
$byteEncoding = [Text.Encoding]::GetEncoding(28591)
$contents = [ordered]@{}
$text = ($user | ConvertTo-Json -Depth 100) + [Environment]::NewLine
$null = $text | ConvertFrom-Json
$contents['sunpack_config.json'] = [Text.UTF8Encoding]::new($false).GetBytes($text)
$passwordFile = Join-Path $dataDirectory 'builtin_passwords.json'
if (Test-Path -LiteralPath $passwordFile -PathType Leaf) {
    $original = $byteEncoding.GetString([IO.File]::ReadAllBytes($passwordFile))
    $repaired = [regex]::Replace($original, '([^\r\n]*)(\r+\n|\r|\n|\z)', {
        param($match)
        $line = $match.Groups[1].Value
        if ([string]::IsNullOrWhiteSpace($line)) { return '' }
        $ending = $match.Groups[2].Value
        if ($ending.StartsWith("`r`r")) { $ending = "`r`n" }
        return $line + $ending
    })
    $contents['builtin_passwords.json'] = $byteEncoding.GetBytes($repaired)
}
$rootsFile = Join-Path $dataDirectory 'sunpack_watch_roots.txt'
if (Test-Path -LiteralPath $rootsFile -PathType Leaf) {
    $roots = $byteEncoding.GetString([IO.File]::ReadAllBytes($rootsFile))
    # Only the fourth column is persisted scan state. Preserve comments, paths,
    # output mappings, deep_detect and recursive flags byte for byte.
    $roots = [regex]::Replace($roots, '(?:(?<=\r)|(?<=\n)|\A)(?![ \t]*(?:\xEF\xBB\xBF)?[ \t]*#)([^|\r\n]+\|[^|\r\n]*\|[^|\r\n]*\|)([ \t]*)(?:true|false)?([ \t]*)(?=\||\r|\n|\z)', '${1}${2}false${3}', [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $contents['sunpack_watch_roots.txt'] = $byteEncoding.GetBytes($roots)
}

$null = [IO.Directory]::CreateDirectory($dataDirectory)
$staging = Join-Path $dataDirectory ('.sunpack-upgrade-' + [Guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($staging)
try {
    foreach ($name in $contents.Keys) {
        $path = Join-Path $staging $name
        $stream = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $stream.Write($contents[$name], 0, $contents[$name].Length); $stream.Flush($true) }
        finally { $stream.Dispose() }
    }
    # Commit retained files before clearing anything else. If a commit fails,
    # old state is intact and the same idempotent conversion can be retried.
    foreach ($name in $contents.Keys) {
        $path = Join-Path $dataDirectory $name
        Assert-PlainPath $path
        if ([IO.File]::Exists($path)) {
            [IO.File]::Replace((Join-Path $staging $name), $path, [System.Management.Automation.Language.NullString]::Value, $false)
        } else { [IO.File]::Move((Join-Path $staging $name), $path) }
    }
} finally {
    if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force }
}
foreach ($record in $customRecords) {
    if (Test-Path -LiteralPath $record.FullName) {
        Assert-PlainTree $record.FullName
        Remove-Item -LiteralPath $record.FullName -Recurse -Force
    }
}
foreach ($record in Get-ChildItem -LiteralPath $dataDirectory -Force) {
    if (-not $record.PSIsContainer -and $record.Name -in @('sunpack_config.json', 'sunpack_watch_roots.txt', 'builtin_passwords.json')) { continue }
    Assert-PlainTree $record.FullName
    Remove-Item -LiteralPath $record.FullName -Recurse -Force
}
