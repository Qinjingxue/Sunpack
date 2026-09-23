from __future__ import annotations

from sunpack.core.support.resources import writable_data_dir
from sunpack.core.support.runtime_identity import runtime_id


def runtime_working_directory() -> str:
    """Return a process cwd that cannot pin an input, output, or install directory."""
    identity = runtime_id() or "direct"
    target = writable_data_dir() / "runtime-cwd" / identity
    target.mkdir(parents=True, exist_ok=True)
    return str(target)
