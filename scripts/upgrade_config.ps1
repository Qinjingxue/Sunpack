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
function Update-Fields($Old, $New, $User, $Defaults) {
    if ($User -isnot [pscustomobject]) { return }
    foreach ($field in @($Old.PSObject.Properties)) {
        if (-not (Has-Key $New $field.Name) -and (Has-Key $User $field.Name)) {
            $User.PSObject.Properties.Remove($field.Name)
            $script:Changed = $true
        }
    }
    foreach ($field in @($New.PSObject.Properties)) {
        $name = $field.Name
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
                Update-Fields $Old.$name $field.Value $added $default
                if (@($added.PSObject.Properties).Count -gt 0) { Add-Key $User $name $added }
            }
            continue
        }
        if ($field.Value -is [pscustomobject] -and $Old.$name -is [pscustomobject]) {
            Update-Fields $Old.$name $field.Value $User.$name $default
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
$acl = [IO.File]::GetAccessControl($target)
$privilege = $null
# A different elevated administrator must be able to retain the original owner.
if ($acl.GetOwner([Security.Principal.SecurityIdentifier]) -ne [Security.Principal.WindowsIdentity]::GetCurrent().User) {
    if (-not ('SunPackConfigRestorePrivilege' -as [type])) {
        Add-Type @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public sealed class SunPackConfigRestorePrivilege : IDisposable {
    [StructLayout(LayoutKind.Sequential, Pack=4)] struct Privilege { public uint Count; public long Luid; public uint Attributes; }
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool LookupPrivilegeValue(string system, string name, out long luid);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr token, bool disable, ref Privilege value, uint size, out Privilege previous, out uint needed);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    IntPtr token; Privilege previous;
    public SunPackConfigRestorePrivilege() {
        try {
            if (!OpenProcessToken(GetCurrentProcess(), 0x28, out token)) throw new Win32Exception();
            Privilege value = new Privilege { Count=1, Attributes=2 };
            if (!LookupPrivilegeValue(null, "SeRestorePrivilege", out value.Luid)) throw new Win32Exception();
            uint needed;
            if (!AdjustTokenPrivileges(token, false, ref value, (uint)Marshal.SizeOf(typeof(Privilege)), out previous, out needed)) throw new Win32Exception();
            int error = Marshal.GetLastWin32Error();
            if (error != 0) throw new Win32Exception(error);
        } catch { Dispose(); throw; }
    }
    public void Dispose() {
        if (token == IntPtr.Zero) return;
        Privilege ignored; uint needed;
        if (previous.Count != 0) AdjustTokenPrivileges(token, false, ref previous, (uint)Marshal.SizeOf(typeof(Privilege)), out ignored, out needed);
        CloseHandle(token); token = IntPtr.Zero;
    }
}
'@
    }
    $privilege = New-Object SunPackConfigRestorePrivilege
}
$temporary = [IO.Path]::Combine($parent, '.sunpack-config-' + [Guid]::NewGuid().ToString('N') + '.tmp')
try {
    $text = ($user | ConvertTo-Json -Depth 100) + [Environment]::NewLine
    $null = $text | ConvertFrom-Json
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($text)
    $stream = New-Object IO.FileStream($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    $preserved = New-Object Security.AccessControl.FileSecurity
    $preserved.SetSecurityDescriptorSddlForm($acl.Sddl, ([Security.AccessControl.AccessControlSections]::Access -bor
        [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group))
    [IO.File]::SetAccessControl($temporary, $preserved)
    [IO.File]::Replace($temporary, $target, [System.Management.Automation.Language.NullString]::Value, $false)
} finally {
    try { if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) } }
    finally { if ($null -ne $privilege) { $privilege.Dispose() } }
}
