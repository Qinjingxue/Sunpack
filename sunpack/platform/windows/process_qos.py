from __future__ import annotations

import ctypes
import sys
import threading
from ctypes import wintypes


BELOW_NORMAL_PRIORITY_CLASS = 0x00004000
NORMAL_PRIORITY_CLASS = 0x00000020
HIGH_PRIORITY_CLASS = 0x00000080
PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000
PROCESS_MODE_BACKGROUND_END = 0x00200000
_MODE_LOCK = threading.Lock()
_MODE = "normal"


def set_processing_mode(*, mode: str) -> str:
    """Apply one fixed Windows process scheduling mode."""

    global _MODE
    normalized = str(mode or "normal").strip().lower()
    if normalized not in {"background", "normal", "high"}:
        raise ValueError(f"unsupported process mode: {mode}")
    if sys.platform != "win32":
        return "unsupported"

    with _MODE_LOCK:
        if normalized == _MODE:
            return _MODE
        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            current_process = kernel32.GetCurrentProcess
            current_process.argtypes = []
            current_process.restype = wintypes.HANDLE
            set_priority_class = kernel32.SetPriorityClass
            set_priority_class.argtypes = [wintypes.HANDLE, wintypes.DWORD]
            set_priority_class.restype = wintypes.BOOL
            process = current_process()

            if normalized == "background":
                if _MODE == "high":
                    if not set_priority_class(process, NORMAL_PRIORITY_CLASS):
                        return "unavailable"
                    _MODE = "normal"
                if set_priority_class(process, PROCESS_MODE_BACKGROUND_BEGIN):
                    _MODE = "background"
                    return "background"
                if set_priority_class(process, BELOW_NORMAL_PRIORITY_CLASS):
                    _MODE = "background"
                    return "below_normal"
                return "unavailable"

            if _MODE == "background":
                set_priority_class(process, PROCESS_MODE_BACKGROUND_END)

            requested = HIGH_PRIORITY_CLASS if normalized == "high" else NORMAL_PRIORITY_CLASS
            if set_priority_class(process, requested):
                _MODE = normalized
                return normalized
        except (AttributeError, OSError):
            pass
        return "unavailable"
