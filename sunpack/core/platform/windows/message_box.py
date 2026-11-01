from __future__ import annotations

import ctypes
from ctypes import wintypes


def show_error(title: str, message: str) -> None:
    """Show a classic Windows error dialog without loading a GUI framework."""
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    message_box = user32.MessageBoxW
    message_box.argtypes = (wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.UINT)
    message_box.restype = ctypes.c_int
    # MB_OK | MB_ICONERROR | MB_SETFOREGROUND
    if not message_box(None, message, title, 0x00010010):
        raise ctypes.WinError(ctypes.get_last_error())
