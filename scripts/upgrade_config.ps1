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
function Has-Key($Object, [string]$Name) {
    return $null -ne $Object -and $Object -is [pscustomobject] -and $null -ne $Object.PSObject.Properties[$Name]
}
function Add-Key($Object, [string]$Name, $Value) {
    $Object | Add-Member -MemberType NoteProperty -Name $Name -Value $Value
    $script:Changed = $true
}
function Named-Index($Items) {
    $index = New-Object 'Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
    foreach ($item in @($Items)) {
        if ((Has-Key $item 'name') -and $item.name -is [string]) { $index[$item.name] = $item }
    }
    return ,$index
}
function Update-Modules($Old, $New, $User, $Defaults, [string]$Path) {
    $oldIndex = Named-Index $Old
    $newIndex = Named-Index $New
    $defaultIndex = Named-Index $Defaults
    $userIndex = Named-Index $User
    $updated = New-Object 'Collections.Generic.List[object]'
    foreach ($item in $User) {
        if ((Has-Key $item 'name') -and $item.name -is [string] -and $oldIndex.ContainsKey($item.name)) {
            if (-not $newIndex.ContainsKey($item.name)) { $script:Changed = $true; continue }
            $default = $null
            if ($defaultIndex.ContainsKey($item.name)) { $default = $defaultIndex[$item.name] }
            Update-Fields $oldIndex[$item.name] $newIndex[$item.name] $item $default "$Path/@$($item.name)"
        }
        $updated.Add($item)
    }
    foreach ($item in @($New)) {
        if (-not (Has-Key $item 'name') -or $item.name -isnot [string]) { continue }
        if (-not $oldIndex.ContainsKey($item.name) -and -not $userIndex.ContainsKey($item.name) -and $defaultIndex.ContainsKey($item.name)) {
            $updated.Add($defaultIndex[$item.name])
            $script:Changed = $true
        }
    }
    return ,$updated.ToArray()
}
function Update-Fields($Old, $New, $User, $Defaults, [string]$Path = '') {
    if ($User -isnot [pscustomobject]) { return }
    foreach ($field in @($Old.PSObject.Properties)) {
        if (-not (Has-Key $New $field.Name) -and (Has-Key $User $field.Name)) {
            $User.PSObject.Properties.Remove($field.Name)
            $script:Changed = $true
        }
    }
    foreach ($field in @($New.PSObject.Properties)) {
        $name = $field.Name
        $fieldPath = "$Path/$name"
        if (-not (Has-Key $Old $name)) {
            if (-not (Has-Key $User $name) -and (Has-Key $Defaults $name)) {
                Add-Key $User $name $Defaults.$name
            }
            continue
        }
        $default = $null
        if (Has-Key $Defaults $name) { $default = $Defaults.$name }
        if (-not (Has-Key $User $name)) {
            if ($field.Value -is [pscustomobject] -and $Old.$name -is [pscustomobject]) {
                # Materialize only added fields, not the old defaults of an
                # object the user never wrote into the ordinary configuration.
                $added = [pscustomobject]@{}
                Update-Fields $Old.$name $field.Value $added $default $fieldPath
                if (@($added.PSObject.Properties).Count -gt 0) { Add-Key $User $name $added }
            }
            continue
        }
        if ($field.Value -is [pscustomobject] -and $Old.$name -is [pscustomobject]) {
            Update-Fields $Old.$name $field.Value $User.$name $default $fieldPath
        } elseif ($fieldPath -in @('/filesystem/scan_filters', '/analysis/modules', '/verification/methods') -and
                  $Old.$name -is [array] -and $field.Value -is [array] -and $User.$name -is [array]) {
            $User.$name = Update-Modules $Old.$name $field.Value $User.$name $default $fieldPath
        }
    }
}

$old = Read-Object $OldAdvanced
$new = Read-Object $NewAdvanced
$defaults = Read-Object $Template
$user = Read-Object $UserConfig
Update-Fields $old $new $user $defaults
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
