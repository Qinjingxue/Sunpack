from __future__ import annotations

import ctypes
from ctypes import wintypes


class _SecurityAttributes(ctypes.Structure):
    _fields_ = (
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", wintypes.LPVOID),
        ("bInheritHandle", wintypes.BOOL),
    )


class _SidAndAttributes(ctypes.Structure):
    _fields_ = (("Sid", wintypes.LPVOID), ("Attributes", wintypes.DWORD))


class _TokenUser(ctypes.Structure):
    _fields_ = (("User", _SidAndAttributes),)


def _current_user_sid() -> str:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32.GetCurrentProcess.argtypes = ()
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = (wintypes.HLOCAL,)
    kernel32.LocalFree.restype = wintypes.HLOCAL
    advapi32.OpenProcessToken.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    )
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    )
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = (wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR))
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        required = wintypes.DWORD()
        advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(required))
        if not required.value:
            raise ctypes.WinError(ctypes.get_last_error())
        buffer = ctypes.create_string_buffer(required.value)
        if not advapi32.GetTokenInformation(
            token,
            1,
            buffer,
            required,
            ctypes.byref(required),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        sid_text = wintypes.LPWSTR()
        token_user = ctypes.cast(buffer, ctypes.POINTER(_TokenUser)).contents
        if not advapi32.ConvertSidToStringSidW(token_user.User.Sid, ctypes.byref(sid_text)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return str(sid_text.value)
        finally:
            kernel32.LocalFree(sid_text)
    finally:
        kernel32.CloseHandle(token)


def _pipe_security_attributes() -> tuple[_SecurityAttributes, wintypes.LPVOID]:
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.DWORD),
    )
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    descriptor = wintypes.LPVOID()
    sddl = f"D:P(A;;GA;;;SY)(A;;GA;;;{_current_user_sid()})"
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl,
        1,
        ctypes.byref(descriptor),
        None,
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    attributes = _SecurityAttributes(
        ctypes.sizeof(_SecurityAttributes),
        descriptor,
        False,
    )
    return attributes, descriptor


def _secure_pipe_server_type():
    import _winapi
    from asyncio import windows_events, windows_utils

    class CurrentUserPipeServer(windows_events.PipeServer):
        def _server_pipe_handle(self, first):
            if self.closed():
                return None
            flags = _winapi.PIPE_ACCESS_DUPLEX | _winapi.FILE_FLAG_OVERLAPPED
            if first:
                flags |= _winapi.FILE_FLAG_FIRST_PIPE_INSTANCE
            attributes, descriptor = _pipe_security_attributes()
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.LocalFree.argtypes = (wintypes.HLOCAL,)
            kernel32.LocalFree.restype = wintypes.HLOCAL
            kernel32.CreateNamedPipeW.argtypes = (
                wintypes.LPCWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.DWORD,
                ctypes.POINTER(_SecurityAttributes),
            )
            kernel32.CreateNamedPipeW.restype = wintypes.HANDLE
            try:
                handle = kernel32.CreateNamedPipeW(
                    self._address,
                    flags,
                    _winapi.PIPE_TYPE_MESSAGE | _winapi.PIPE_READMODE_MESSAGE | _winapi.PIPE_WAIT,
                    _winapi.PIPE_UNLIMITED_INSTANCES,
                    windows_utils.BUFSIZE,
                    windows_utils.BUFSIZE,
                    _winapi.NMPWAIT_WAIT_FOREVER,
                    ctypes.byref(attributes),
                )
            finally:
                kernel32.LocalFree(descriptor)
            if handle == wintypes.HANDLE(-1).value:
                raise ctypes.WinError(ctypes.get_last_error())
            pipe = windows_utils.PipeHandle(handle)
            self._free_instances.add(pipe)
            return pipe

    return CurrentUserPipeServer


async def start_serving_current_user_pipe(loop, protocol_factory, address):
    """Create an asyncio named-pipe server whose DACL grants only this SID and SYSTEM."""

    from asyncio import windows_events

    original = windows_events.PipeServer
    windows_events.PipeServer = _secure_pipe_server_type()
    try:
        return await loop.start_serving_pipe(protocol_factory, address)
    finally:
        windows_events.PipeServer = original
