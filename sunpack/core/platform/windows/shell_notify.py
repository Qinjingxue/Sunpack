from __future__ import annotations

import os
import sys
from typing import Iterable

# SHCNE_UPDATEDIR: directory contents changed; Explorer refreshes open views.
_SHCNE_UPDATEDIR = 0x00001000
# SHCNF_PATHW: dwItem1/dwItem2 are Unicode path strings.
_SHCNF_PATHW = 0x0005
# Do not wait for receivers; watch must not block on shell clients.
_SHCNF_FLUSHNOWAIT = 0x2000


def notify_shell_directories_updated(paths: Iterable[str]) -> list[str]:
    """Ask Explorer to refresh directories affected by the given paths.

    Paths may be files or directories and need not still exist (for example an
    archive already moved to the recycle bin). Returns the unique existing
    directories that were notified. Safe no-op when not on Windows, when no
    usable directories remain, or when shell notification fails.
    """
    directories = _unique_existing_directories(paths)
    if not directories or sys.platform != "win32":
        return directories
    try:
        _sh_change_notify_updatedir(directories)
    except Exception:
        return []
    return directories


def _unique_existing_directories(paths: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for raw in paths:
        for directory in _refresh_directories_for_path(str(raw or "").strip()):
            key = os.path.normcase(directory)
            if key in seen:
                continue
            seen.add(key)
            ordered.append(directory)
    return ordered


def _refresh_directories_for_path(path: str) -> list[str]:
    if not path:
        return []
    absolute = os.path.abspath(path)
    # Prefer the parent listing: that is where Explorer shows a new folder or
    # a recycled archive. Also refresh the path itself when it is a directory
    # so open views of the output folder pick up flatten/cleanup changes.
    if os.path.isdir(absolute):
        directories = [absolute]
        parent = os.path.dirname(absolute.rstrip("\\/"))
        if parent and os.path.normcase(parent) != os.path.normcase(absolute):
            directories.append(parent)
    else:
        parent = os.path.dirname(absolute)
        directories = [parent] if parent else []
    return [item for item in directories if item and os.path.isdir(item)]


def _sh_change_notify_updatedir(directories: list[str]) -> None:
    import ctypes
    from ctypes import wintypes

    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    notify = shell32.SHChangeNotify
    notify.argtypes = [wintypes.LONG, wintypes.UINT, wintypes.LPCVOID, wintypes.LPCVOID]
    notify.restype = None
    flags = _SHCNF_PATHW | _SHCNF_FLUSHNOWAIT
    for directory in directories:
        notify(_SHCNE_UPDATEDIR, flags, directory, None)
