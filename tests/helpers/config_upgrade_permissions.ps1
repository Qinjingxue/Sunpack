param([string]$RepoRoot, [string]$Fixture)
$ErrorActionPreference = 'Stop'
. (Join-Path $RepoRoot 'scripts/test_elevation.ps1')
$exitCode = Invoke-TestScriptElevated -ScriptPath $PSCommandPath -BoundParameters $PSBoundParameters
if ($null -ne $exitCode) { exit $exitCode }
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class ConfigTestLogon {
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool LogonUser(string user, string domain, string password, int type, int provider, out IntPtr token);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr handle);
}
'@
$name = 'spcfg_' + [Guid]::NewGuid().ToString('N').Substring(0,8)
$password = [Guid]::NewGuid().ToString('N') + 'aA1!'
$account = $null
$token = [IntPtr]::Zero
try {
    $account = New-LocalUser -Name $name -Password (ConvertTo-SecureString $password -AsPlainText -Force) -AccountNeverExpires
    Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $account
    $null = New-Item -ItemType Directory -Path $Fixture -Force
    $acl = Get-Acl -LiteralPath $Fixture
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($account.SID, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    Set-Acl -LiteralPath $Fixture -AclObject $acl
    $target = Join-Path $Fixture 'user.json'
    if (-not [ConfigTestLogon]::LogonUser($name, $env:COMPUTERNAME, $password, 2, 0, [ref]$token)) {
        throw [ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error())
    }
    $impersonation = [Security.Principal.WindowsIdentity]::Impersonate($token)
    try { [IO.File]::WriteAllText($target, '{"keep":0,"removed":9}', [Text.UTF8Encoding]::new($false)) }
    finally { $impersonation.Dispose() }
    $before = [IO.File]::GetAccessControl($target)
    if ($before.GetOwner([Security.Principal.SecurityIdentifier]) -ne $account.SID) { throw 'Fixture owner is not the ordinary user' }
    if ([Security.Principal.WindowsIdentity]::GetCurrent().User -eq $account.SID) { throw 'Upgrade must run as a different administrator' }
    foreach ($pair in @(@('old','{"keep":1,"removed":2}'), @('new','{"keep":1,"added":3}'), @('template','{"added":7}'))) {
        [IO.File]::WriteAllText((Join-Path $Fixture ($pair[0]+'.json')), $pair[1])
    }
    & (Join-Path $RepoRoot 'scripts/upgrade_config.ps1') -OldAdvanced (Join-Path $Fixture 'old.json') -NewAdvanced (Join-Path $Fixture 'new.json') -Template (Join-Path $Fixture 'template.json') -UserConfig $target
    $after = [IO.File]::GetAccessControl($target)
    if ($before.Sddl -ne $after.Sddl) { throw ("Upgrade changed owner or ACL: " + $before.Sddl + " -> " + $after.Sddl) }
    $result = [IO.File]::ReadAllText($target) | ConvertFrom-Json
    if ($result.keep -ne 0 -or $result.added -ne 7 -or $result.PSObject.Properties['removed']) { throw 'Configuration values changed' }
    [IO.File]::WriteAllText((Join-Path $Fixture 'verified'), 'ok')
} finally {
    if ($token -ne [IntPtr]::Zero) { $null = [ConfigTestLogon]::CloseHandle($token) }
    if ($null -ne $account) { Remove-LocalUser -SID $account.SID }
}
