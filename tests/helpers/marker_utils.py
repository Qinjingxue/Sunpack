from __future__ import annotations

import ctypes
from ctypes import wintypes
import msvcrt
import os
from pathlib import Path
from typing import TextIO


_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_kernel32.CreateFileW.argtypes = (
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
    wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
)
_kernel32.CreateFileW.restype = wintypes.HANDLE
_kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
_kernel32.CloseHandle.restype = wintypes.BOOL


def _open_marker_text(path: Path) -> TextIO:
    # Polling observes live output: allow concurrent writes, moves and deletion.
    handle = _kernel32.CreateFileW(
        str(path), 0x80000000, 0x1 | 0x2 | 0x4, None, 3, 0x80, None,
    )
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except BaseException:
        _kernel32.CloseHandle(handle)
        raise
    # Ownership passes to the descriptor, then to the returned text stream.
    try:
        return os.fdopen(descriptor, "r", encoding="utf-8")
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

    for path in safe_rglob(root, marker_name):
        try:
            with _open_marker_text(path) as reader:
                if reader.read() == marker_text:
                    return "found"
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
            with _open_marker_text(path) as reader:
                if reader.read() == marker_text:
                    return "found"
        except UnicodeDecodeError:
            continue
        except OSError:
            candidate_exists = True
            continue
    return "locked" if candidate_exists else "missing"
