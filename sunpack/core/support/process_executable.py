from __future__ import annotations

import sys
from pathlib import Path


def is_packaged_process() -> bool:
    return bool(getattr(sys, "frozen", False) or "__compiled__" in globals())


def current_process_executable() -> Path:
    """Return the executable image that owns the current process."""
    if is_packaged_process() and sys.argv:
        return Path(sys.argv[0]).resolve()
    return Path(sys.executable).resolve()
