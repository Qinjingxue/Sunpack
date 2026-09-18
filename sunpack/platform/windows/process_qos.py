from __future__ import annotations

import ctypes
import sys
import threading
from ctypes import wintypes


BELOW_NORMAL_PRIORITY_CLASS = 0x00004000
PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000
PROCESS_MODE_BACKGROUND_END = 0x00200000
NORMAL_PRIORITY_CLASS = 0x00000020
_MODE_LOCK = threading.Lock()
_BACKGROUND = False


def set_processing_mode(*, background: bool) -> str:
    """Switch the current process between foreground and background QoS."""

    global _BACKGROUND
    if sys.platform != "win32":
        return "unsupported"
    with _MODE_LOCK:
        if bool(background) == _BACKGROUND:
            return "background" if _BACKGROUND else "normal"
        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            current_process = kernel32.GetCurrentProcess
            current_process.argtypes = []
            current_process.restype = wintypes.HANDLE
            set_priority_class = kernel32.SetPriorityClass
            set_priority_class.argtypes = [wintypes.HANDLE, wintypes.DWORD]
            set_priority_class.restype = wintypes.BOOL
            process = current_process()
            requested = PROCESS_MODE_BACKGROUND_BEGIN if background else PROCESS_MODE_BACKGROUND_END
            if set_priority_class(process, requested):
                _BACKGROUND = bool(background)
                return "background" if background else "normal"
            fallback = BELOW_NORMAL_PRIORITY_CLASS if background else NORMAL_PRIORITY_CLASS
            if set_priority_class(process, fallback):
                _BACKGROUND = bool(background)
                return "below_normal" if background else "normal"
        except (AttributeError, OSError):
            pass
        return "unavailable"


def trim_working_set() -> bool:
    """Best-effort trim of the current process working set."""

    if sys.platform != "win32":
        return False
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        current_process = kernel32.GetCurrentProcess
        current_process.argtypes = []
        current_process.restype = wintypes.HANDLE
        empty_working_set = psapi.EmptyWorkingSet
        empty_working_set.argtypes = [wintypes.HANDLE]
        empty_working_set.restype = wintypes.BOOL
        return bool(empty_working_set(current_process()))
    except (AttributeError, OSError):
        return False
