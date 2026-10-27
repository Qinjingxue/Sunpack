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
    # Future post-1.3.0 migrations belong here. Set $script:Changed only when
    # a migration modifies $User; the installer owns backup and rollback.
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
