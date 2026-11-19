param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('RegisterToast', 'EnableContextMenu', 'DisableContextMenu', 'EnableStartup',
        'DisableStartup', 'StartDaemon', 'UninstallToast', 'RemoveGuiPreferences')]
    [string]$Action,
    [switch]$ShellUser
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$app = Split-Path -Parent $PSScriptRoot
$launcher = Join-Path $app 'bin\sunpack.exe'
$toastClsid = '{C5A6B4E9-3184-44E2-9F15-6A71804F7A36}'
$toastClass = "HKLM:\Software\Classes\CLSID\$toastClsid"
$toastAppId = 'HKCU:\Software\Classes\AppUserModelId\SunPack.Watch.Toast'

function Remove-Registration([string]$Path) {
    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Recurse -Force }
}

function Invoke-Daemon([string[]]$Arguments) {
    & $launcher daemon @Arguments
    if ($LASTEXITCODE -ne 0) { throw "SunPack daemon exited with code $LASTEXITCODE" }
}

function Invoke-AsShellUser([string]$UserAction) {
    # The installer may have been elevated with another account's credentials.
    # Start under the desktop shell token and wait for the actual script result.
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

public static class SunPackSetupShell {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct StartupInfo {
        public int Size;
        public string Reserved, Desktop, Title;
        public int X, Y, XSize, YSize, XChars, YChars, Fill, Flags;
        public short ShowWindow, ReservedSize;
        public IntPtr ReservedData, Input, Output, Error;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct ProcessInfo {
        public IntPtr Process, Thread;
        public int ProcessId, ThreadId;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct Privilege {
        public int Count;
        public uint LuidLow;
        public int LuidHigh;
        public int Attributes;
    }

    [DllImport("user32.dll")] static extern IntPtr GetShellWindow();
    [DllImport("user32.dll", SetLastError = true)]
    static extern uint GetWindowThreadProcessId(IntPtr window, out uint pid);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetExitCodeProcess(IntPtr handle, out int code);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool DuplicateTokenEx(IntPtr token, uint access, IntPtr attributes,
        int impersonationLevel, int tokenType, out IntPtr primaryToken);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool LookupPrivilegeValue(string system, string name, out long luid);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll,
        ref Privilege state, uint size, IntPtr previous, IntPtr returned);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    static extern bool CreateProcessWithTokenW(IntPtr token, uint logonFlags, string application,
        StringBuilder command, uint flags, IntPtr environment, string directory,
        ref StartupInfo startup, out ProcessInfo process);

    static void EnablePrivilege(string name) {
        using (var identity = WindowsIdentity.GetCurrent(TokenAccessLevels.AdjustPrivileges | TokenAccessLevels.Query)) {
            long luid;
            if (!LookupPrivilegeValue(null, name, out luid)) throw new Win32Exception();
            var privilege = new Privilege { Count = 1, LuidLow = (uint)luid, LuidHigh = (int)(luid >> 32), Attributes = 2 };
            if (!AdjustTokenPrivileges(identity.Token, false, ref privilege, 0, IntPtr.Zero, IntPtr.Zero))
                throw new Win32Exception();
            int error = Marshal.GetLastWin32Error();
            if (error != 0) throw new Win32Exception(error);
        }
    }

    static IntPtr OpenShellToken(uint pid) {
        IntPtr shell = OpenProcess(0x1000, false, pid); // PROCESS_QUERY_LIMITED_INFORMATION
        if (shell == IntPtr.Zero) throw new Win32Exception();
        try {
            IntPtr token;
            if (!OpenProcessToken(shell, 0x000A, out token)) throw new Win32Exception(); // TOKEN_QUERY | TOKEN_DUPLICATE
            return token;
        } finally {
            CloseHandle(shell);
        }
    }

    public static int Run(string executable, string arguments, string directory) {
        IntPtr window = GetShellWindow();
        if (window == IntPtr.Zero) throw new InvalidOperationException("The interactive Windows shell is unavailable.");
        uint pid;
        if (GetWindowThreadProcessId(window, out pid) == 0) throw new Win32Exception();
        EnablePrivilege("SeImpersonatePrivilege");

        IntPtr shellToken;
        try {
            shellToken = OpenShellToken(pid);
        } catch (Win32Exception error) {
            if (error.NativeErrorCode != 5) throw; // ERROR_ACCESS_DENIED
            // Over-the-shoulder elevation can put Explorer and Setup under different accounts.
            EnablePrivilege("SeDebugPrivilege");
            shellToken = OpenShellToken(pid);
        }

        IntPtr primaryToken = IntPtr.Zero;
        ProcessInfo child;
        try {
            if (!DuplicateTokenEx(shellToken, 0x02000000, IntPtr.Zero, 2, 1, out primaryToken))
                throw new Win32Exception();
            var startup = new StartupInfo { Size = Marshal.SizeOf(typeof(StartupInfo)), Desktop = @"winsta0\default" };
            var command = new StringBuilder("\"" + executable + "\" " + arguments);
            if (!CreateProcessWithTokenW(primaryToken, 1, executable, command, 0x08000000,
                    IntPtr.Zero, directory, ref startup, out child)) throw new Win32Exception();
        } finally {
            if (primaryToken != IntPtr.Zero) CloseHandle(primaryToken);
            CloseHandle(shellToken);
        }
        CloseHandle(child.Thread);
        try {
            int code;
            if (WaitForSingleObject(child.Process, uint.MaxValue) != 0 ||
                !GetExitCodeProcess(child.Process, out code)) throw new Win32Exception();
            return code;
        } finally {
            CloseHandle(child.Process);
        }
    }
}
'@
    $powershell = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
    $arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Action {1} -ShellUser' -f $PSCommandPath, $UserAction
    return [SunPackSetupShell]::Run($powershell, $arguments, $app)
}

if (-not $ShellUser) {
    if ($Action -eq 'RegisterToast') {
        if (-not (Test-Path -LiteralPath $launcher -PathType Leaf)) { throw "SunPack launcher not found: $launcher" }
        $server = Join-Path $toastClass 'LocalServer32'
        $null = New-Item -Path $server -Force
        Set-Item -LiteralPath $server -Value ('"{0}" --toast-activated' -f $launcher)
        Set-ItemProperty -LiteralPath $server -Name 'ServerExecutable' -Value $launcher
    }
    if ($Action -in @('EnableContextMenu', 'DisableContextMenu')) {
        & (Join-Path $PSScriptRoot 'unregister_context_menu.ps1') -Machine
    }
    if ($Action -eq 'UninstallToast') {
        try { Remove-Registration $toastClass }
        finally { $code = Invoke-AsShellUser $Action }
        exit $code
    }
    exit (Invoke-AsShellUser $Action)
}

switch ($Action) {
    'RegisterToast' {
        $icon = Join-Path $app 'sunpack.ico'
        if (-not (Test-Path -LiteralPath $icon -PathType Leaf)) { throw "SunPack icon not found: $icon" }
        if (-not (Test-Path -LiteralPath $toastAppId)) {
            $null = New-Item -Path $toastAppId -Force
        }
        $null = New-ItemProperty -LiteralPath $toastAppId -Name 'DisplayName' -Value 'SunPack' -PropertyType ExpandString -Force
        $null = New-ItemProperty -LiteralPath $toastAppId -Name 'IconUri' -Value $icon -PropertyType ExpandString -Force
        $null = New-ItemProperty -LiteralPath $toastAppId -Name 'IconBackgroundColor' -Value 'FF0078D4' -PropertyType String -Force
        $null = New-ItemProperty -LiteralPath $toastAppId -Name 'CustomActivator' -Value $toastClsid -PropertyType String -Force
    }
    'EnableContextMenu' { & (Join-Path $PSScriptRoot 'register_context_menu.ps1') }
    'DisableContextMenu' { & (Join-Path $PSScriptRoot 'unregister_context_menu.ps1') }
    'EnableStartup' { Invoke-Daemon @('startup', 'enable') }
    'DisableStartup' { Invoke-Daemon @('startup', 'disable') }
    'StartDaemon' { Invoke-Daemon @('start') }
    'UninstallToast' { Remove-Registration $toastAppId }
    'RemoveGuiPreferences' { Remove-Registration 'HKCU:\Software\SunPack\GUI' }
    default { throw "Invalid shell-user action: $Action" }
}
exit 0
