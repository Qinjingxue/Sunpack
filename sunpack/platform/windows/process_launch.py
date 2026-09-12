from __future__ import annotations

import ctypes
import os
import subprocess
from ctypes import wintypes
from dataclasses import dataclass
from functools import lru_cache
from typing import Mapping, Sequence

from sunpack.platform.windows.elevation import is_process_elevated


PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TOKEN_ASSIGN_PRIMARY = 0x0001
TOKEN_DUPLICATE = 0x0002
TOKEN_QUERY = 0x0008
TOKEN_ADJUST_PRIVILEGES = 0x0020
MAXIMUM_ALLOWED = 0x02000000
SECURITY_IMPERSONATION = 2
TOKEN_PRIMARY = 1
LOGON_WITH_PROFILE = 0x00000001
CREATE_UNICODE_ENVIRONMENT = 0x00000400
CREATE_NO_WINDOW = 0x08000000
WAIT_OBJECT_0 = 0x00000000
WAIT_TIMEOUT = 0x00000102
STILL_ACTIVE = 259
SE_PRIVILEGE_ENABLED = 0x00000002


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(ctypes.c_ubyte)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]


class TOKEN_PRIVILEGES_ONE(ctypes.Structure):
    _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]


@dataclass
class NativeProcess:
    handle: int
    pid: int

    def poll(self) -> int | None:
        exit_code = wintypes.DWORD()
        if not _kernel32().GetExitCodeProcess(self.handle, ctypes.byref(exit_code)):
            raise ctypes.WinError(ctypes.get_last_error())
        return None if exit_code.value == STILL_ACTIVE else int(exit_code.value)

    def wait(self, timeout: float | None = None) -> int | None:
        milliseconds = 0xFFFFFFFF if timeout is None else max(0, min(0xFFFFFFFE, int(timeout * 1000)))
        result = _kernel32().WaitForSingleObject(self.handle, milliseconds)
        if result == WAIT_TIMEOUT:
            return None
        if result != WAIT_OBJECT_0:
            raise ctypes.WinError(ctypes.get_last_error())
        return self.poll()

    def terminate(self, exit_code: int = 1) -> None:
        if self.poll() is None and not _kernel32().TerminateProcess(self.handle, int(exit_code)):
            raise ctypes.WinError(ctypes.get_last_error())

    def close(self) -> None:
        handle, self.handle = self.handle, 0
        if handle:
            _kernel32().CloseHandle(handle)


def _environment_block(environment: Mapping[str, str]) -> ctypes.Array:
    """Build a UTF-16 Windows environment block for CreateProcessWithTokenW."""
    entries: list[str] = []
    for name, value in environment.items():
        name_text = str(name)
        value_text = str(value)
        if "\x00" in name_text or "\x00" in value_text:
            raise ValueError("environment names and values cannot contain NUL characters")
        entries.append(f"{name_text}={value_text}")

    entries.sort(key=lambda entry: entry.split("=", 1)[0].casefold())
    block = "\x00".join(entries) + "\x00\x00"
    return ctypes.create_unicode_buffer(block)


def launch_unelevated(
    argv: Sequence[str],
    *,
    cwd: str | None = None,
    env: Mapping[str, str] | None = None,
):
    """Start a process with the interactive shell's medium-integrity token."""

    command = [str(item) for item in argv if str(item)]
    if not command:
        raise ValueError("launch_unelevated requires an executable")
    environment = dict(os.environ if env is None else env)
    if not is_process_elevated():
        return subprocess.Popen(
            command,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=CREATE_NO_WINDOW,
            close_fds=True,
        )

    _enable_current_process_privilege("SeImpersonatePrivilege")

    shell_window = _user32().GetShellWindow()
    if not shell_window:
        raise OSError("the interactive Windows shell is unavailable")
    shell_pid = wintypes.DWORD()
    _user32().GetWindowThreadProcessId(shell_window, ctypes.byref(shell_pid))
    if not shell_pid.value:
        raise ctypes.WinError(ctypes.get_last_error())

    shell_process = _kernel32().OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, shell_pid.value)
    if not shell_process:
        raise ctypes.WinError(ctypes.get_last_error())
    shell_token = wintypes.HANDLE()
    primary_token = wintypes.HANDLE()
    try:
        access = TOKEN_DUPLICATE | TOKEN_QUERY
        if not _advapi32().OpenProcessToken(shell_process, access, ctypes.byref(shell_token)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not _advapi32().DuplicateTokenEx(
            shell_token,
            MAXIMUM_ALLOWED,
            None,
            SECURITY_IMPERSONATION,
            TOKEN_PRIMARY,
            ctypes.byref(primary_token),
        ):
            raise ctypes.WinError(ctypes.get_last_error())

        startup = STARTUPINFOW(
            cb=ctypes.sizeof(STARTUPINFOW),
            lpDesktop="winsta0\\default",
        )
        process = PROCESS_INFORMATION()
        command_line = ctypes.create_unicode_buffer(subprocess.list2cmdline(command))
        environment_block = _environment_block(environment)
        executable = os.path.abspath(command[0])
        working_directory = os.path.abspath(cwd) if cwd else os.path.dirname(executable)
        if not _advapi32().CreateProcessWithTokenW(
            primary_token,
            LOGON_WITH_PROFILE,
            executable,
            command_line,
            CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
            ctypes.cast(environment_block, ctypes.c_void_p),
            working_directory,
            ctypes.byref(startup),
            ctypes.byref(process),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        _kernel32().CloseHandle(process.hThread)
        return NativeProcess(handle=int(process.hProcess), pid=int(process.dwProcessId))
    finally:
        if primary_token:
            _kernel32().CloseHandle(primary_token)
        if shell_token:
            _kernel32().CloseHandle(shell_token)
        _kernel32().CloseHandle(shell_process)


def _enable_current_process_privilege(name: str) -> bool:
    token = wintypes.HANDLE()
    if not _advapi32().OpenProcessToken(
        _kernel32().GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        ctypes.byref(token),
    ):
        return False
    try:
        luid = LUID()
        if not _advapi32().LookupPrivilegeValueW(None, name, ctypes.byref(luid)):
            return False
        privileges = TOKEN_PRIVILEGES_ONE(
            PrivilegeCount=1,
            Privileges=(LUID_AND_ATTRIBUTES(luid, SE_PRIVILEGE_ENABLED),),
        )
        ctypes.set_last_error(0)
        if not _advapi32().AdjustTokenPrivileges(
            token,
            False,
            ctypes.byref(privileges),
            0,
            None,
            None,
        ):
            return False
        return ctypes.get_last_error() == 0
    finally:
        _kernel32().CloseHandle(token)


@lru_cache(maxsize=1)
def _kernel32():
    dll = ctypes.WinDLL("kernel32", use_last_error=True)
    dll.GetCurrentProcess.argtypes = []
    dll.GetCurrentProcess.restype = wintypes.HANDLE
    dll.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    dll.OpenProcess.restype = wintypes.HANDLE
    dll.CloseHandle.argtypes = [wintypes.HANDLE]
    dll.CloseHandle.restype = wintypes.BOOL
    dll.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    dll.GetExitCodeProcess.restype = wintypes.BOOL
    dll.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    dll.WaitForSingleObject.restype = wintypes.DWORD
    dll.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    dll.TerminateProcess.restype = wintypes.BOOL
    return dll


@lru_cache(maxsize=1)
def _user32():
    dll = ctypes.WinDLL("user32", use_last_error=True)
    dll.GetShellWindow.argtypes = []
    dll.GetShellWindow.restype = wintypes.HWND
    dll.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    dll.GetWindowThreadProcessId.restype = wintypes.DWORD
    return dll


@lru_cache(maxsize=1)
def _advapi32():
    dll = ctypes.WinDLL("advapi32", use_last_error=True)
    dll.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    dll.OpenProcessToken.restype = wintypes.BOOL
    dll.DuplicateTokenEx.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    dll.DuplicateTokenEx.restype = wintypes.BOOL
    dll.CreateProcessWithTokenW.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.LPCWSTR,
        ctypes.POINTER(STARTUPINFOW),
        ctypes.POINTER(PROCESS_INFORMATION),
    ]
    dll.CreateProcessWithTokenW.restype = wintypes.BOOL
    dll.LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(LUID)]
    dll.LookupPrivilegeValueW.restype = wintypes.BOOL
    dll.AdjustTokenPrivileges.argtypes = [
        wintypes.HANDLE,
        wintypes.BOOL,
        ctypes.POINTER(TOKEN_PRIVILEGES_ONE),
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    dll.AdjustTokenPrivileges.restype = wintypes.BOOL
    return dll
