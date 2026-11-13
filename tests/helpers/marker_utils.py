from __future__ import annotations

import ctypes
from ctypes import wintypes
import msvcrt
import os
from pathlib import Path


_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_kernel32.CreateFileW.argtypes = (
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
    wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
)
_kernel32.CreateFileW.restype = wintypes.HANDLE
_kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
_kernel32.CloseHandle.restype = wintypes.BOOL


def open_shared_file(path: Path, mode="r", **kwargs):
    # Live reads and simulated downloads allow moves without closing the file.
    writing = mode[0] in "wa"
    handle = _kernel32.CreateFileW(
        str(path), 0x40000000 if writing else 0x80000000, 0x1 | 0x2 | 0x4,
        None, {"w": 2, "a": 4}.get(mode[0], 3), 0x80, None,
    )
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        descriptor = msvcrt.open_osfhandle(handle, (os.O_WRONLY if writing else os.O_RDONLY) | os.O_BINARY)
    except BaseException:
        _kernel32.CloseHandle(handle)
        raise
    # Ownership passes to the descriptor, then to the returned stream.
    try:
        return os.fdopen(descriptor, mode, **kwargs)
    except BaseException:
        os.close(descriptor)
        raise


def marker_present(root: Path, marker_name: str) -> bool:
    return any(safe_rglob(root, marker_name))


def safe_rglob(root: Path, pattern: str):
    try:
        yield from root.rglob(pattern)
    except FileNotFoundError:
        return


def marker_was_extracted(root: Path, marker_name: str, marker_text: str) -> bool:
    """Return whether a file whose text equals the marker was produced under root."""
    return marker_scan_state(root, marker_name, marker_text) == "found"


def marker_scan_state(root: Path, marker_name: str, marker_text: str) -> str:
    candidate_exists = False
    read_length = len(marker_text) + 1

    for path in safe_rglob(root, marker_name):
        try:
            with open_shared_file(path, encoding="utf-8") as reader:
                if reader.read(read_length) == marker_text:
                    return "found"
        except UnicodeDecodeError:
            continue
        except OSError:
            candidate_exists = True
            continue
    for path in safe_rglob(root, "*"):
        try:
            if not path.is_file():
                continue
        except OSError:
            candidate_exists = True
            continue
        try:
            with open_shared_file(path, encoding="utf-8") as reader:
                if reader.read(read_length) == marker_text:
                    return "found"
        except UnicodeDecodeError:
            continue
        except OSError:
            candidate_exists = True
            continue
    return "locked" if candidate_exists else "missing"
