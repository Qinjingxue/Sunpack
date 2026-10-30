"""Deterministic Windows timestamp collisions for event-invalidation tests."""
from contextlib import contextmanager
import ctypes
from ctypes import wintypes


class _BasicInfo(ctypes.Structure):
    _fields_ = [(name, ctypes.c_longlong) for name in (
        "creation", "access", "write", "change",
    )] + [("attributes", wintypes.DWORD)]


@contextmanager
def preserve_file_times(path):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    for name in ("GetFileInformationByHandleEx", "SetFileInformationByHandle"):
        getattr(kernel, name).argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.CreateFileW(str(path), 0x180, 7, None, 3, 0, None)
    if handle == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        saved = _BasicInfo()
        if not kernel.GetFileInformationByHandleEx(handle, 0, ctypes.byref(saved), ctypes.sizeof(saved)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            yield
        finally:
            if not kernel.SetFileInformationByHandle(handle, 0, ctypes.byref(saved), ctypes.sizeof(saved)):
                raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel.CloseHandle(handle)
