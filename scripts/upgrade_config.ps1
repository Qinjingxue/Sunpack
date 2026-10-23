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
function Update-Fields($Old, $New, $User, $Defaults, [string]$Path) {
    if ($User -isnot [pscustomobject]) { return }
    foreach ($field in @($Old.PSObject.Properties)) {
        if (-not (Has-Key $New $field.Name) -and (Has-Key $User $field.Name)) {
            $User.PSObject.Properties.Remove($field.Name)
            $script:Changed = $true
        }
    }
    foreach ($field in @($New.PSObject.Properties)) {
        $name = $field.Name
        $location = "$Path/$name"
        if (-not (Has-Key $Old $name)) {
            if (-not (Has-Key $User $name) -and (Has-Key $Defaults $name)) {
                Add-Key $User $name $Defaults.$name
            }
            continue
        }
        if (-not (Has-Key $User $name)) { continue }
        $default = $null
        if (Has-Key $Defaults $name) { $default = $Defaults.$name }
        if ($location -eq '/filesystem/scan_filters' -and $User.$name -is [array]) {
            $oldModules = @{}; $newModules = @{}; $templates = @{}
            foreach ($item in @($Old.$name)) { if (Has-Key $item 'name') { $oldModules[$item.name] = $item } }
            foreach ($item in @($New.$name)) { if (Has-Key $item 'name') { $newModules[$item.name] = $item } }
            foreach ($item in @($default)) { if (Has-Key $item 'name') { $templates[$item.name] = $item } }
            $kept = New-Object 'System.Collections.Generic.List[object]'
            $present = @{}
            foreach ($item in @($User.$name)) {
                if (-not (Has-Key $item 'name')) { $kept.Add($item); continue }
                $identity = $item.name
                if ($oldModules.ContainsKey($identity) -and -not $newModules.ContainsKey($identity)) {
                    $script:Changed = $true
                    continue
                }
                $present[$identity] = $true
                if ($oldModules.ContainsKey($identity) -and $newModules.ContainsKey($identity)) {
                    Update-Fields $oldModules[$identity] $newModules[$identity] $item $templates[$identity] "$location/$identity"
                }
                $kept.Add($item)
            }
            foreach ($item in @($default)) {
                if ((Has-Key $item 'name') -and -not $oldModules.ContainsKey($item.name) -and
                    $newModules.ContainsKey($item.name) -and -not $present.ContainsKey($item.name)) {
                    $kept.Add($item)
                    $script:Changed = $true
                }
            }
            $User.$name = $kept.ToArray()
        } elseif ($field.Value -is [pscustomobject] -and $Old.$name -is [pscustomobject]) {
            Update-Fields $Old.$name $field.Value $User.$name $default $location
        }
    }
}

$old = Read-Object $OldAdvanced
$new = Read-Object $NewAdvanced
$defaults = Read-Object $Template
$user = Read-Object $UserConfig
Update-Fields $old $new $user $defaults ''
if (-not $script:Changed) { exit 0 }

$target = [IO.Path]::GetFullPath($UserConfig)
$parent = [IO.Path]::GetDirectoryName($target)
for ($path = $target; $path; $path = [IO.Path]::GetDirectoryName($path)) {
    if ([IO.File]::GetAttributes($path) -band [IO.FileAttributes]::ReparsePoint) {
        throw "Refusing a reparse point in the installer configuration target: $path"
    }
}
$acl = [IO.File]::GetAccessControl($target)
$temporary = [IO.Path]::Combine($parent, '.sunpack-config-' + [Guid]::NewGuid().ToString('N') + '.tmp')
try {
    $text = ($user | ConvertTo-Json -Depth 100) + [Environment]::NewLine
    $null = $text | ConvertFrom-Json
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($text)
    $stream = New-Object IO.FileStream($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    [IO.File]::SetAccessControl($temporary, $acl)
    [IO.File]::Replace($temporary, $target, $null, $false)
} finally {
    if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
}
