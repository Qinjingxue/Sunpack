from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes


def is_process_elevated() -> bool:
    if sys.platform != "win32":
        return False
    try:
        shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        check = shell32.IsUserAnAdmin
        check.argtypes = []
        check.restype = wintypes.BOOL
        return bool(check())
    except (AttributeError, OSError):
        return False
