from contextlib import contextmanager
import ctypes
from ctypes import wintypes

from sunpack_native import fast_hash64
from sunpack.core.support.path_keys import absolute_path_key


def file_mutex_name(path, *, prefix="SunPack.EditableFile"):
    identity = absolute_path_key(path).encode("utf-8", errors="surrogatepass")
    return f"Local\\{prefix}-{fast_hash64(identity)}"


@contextmanager
def file_mutex(path, *, prefix="SunPack.EditableFile"):
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateMutexW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR]
    kernel32.CreateMutexW.restype = wintypes.HANDLE
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.ReleaseMutex.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel32.CreateMutexW(None, False, file_mutex_name(path, prefix=prefix))
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if kernel32.WaitForSingleObject(handle, 0xFFFFFFFF) not in (0, 0x80):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            yield
        finally:
            kernel32.ReleaseMutex(handle)
    finally:
        kernel32.CloseHandle(handle)
