import os
from pathlib import Path
from typing import Any

from sunpack_native import windows_path_key


def normalized_path(path: Any) -> str:
    return os.path.normpath(str(path or ""))


def path_key(path: Any) -> str:
    return windows_path_key(normalized_path(path))


def case_key(value: Any) -> str:
    return windows_path_key(str(value or ""))


def absolute_path_key(path: Any) -> str:
    return windows_path_key(os.path.abspath(str(path or "")))


def resolved_path_key(path: Any) -> str:
    """Namespace identity, including an absent leaf below a junction/symlink."""
    try:
        resolved = str(Path(path).resolve())
    except (OSError, ValueError):
        resolved = os.path.abspath(path)
    if resolved.startswith("\\\\?\\UNC\\"):
        resolved = "\\\\" + resolved[8:]
    elif resolved.startswith("\\\\?\\"):
        resolved = resolved[4:]
    return path_key(resolved)


def path_key_is_under(candidate: str, root: str) -> bool:
    """Compare normalized absolute keys without Python's Unicode text folding."""
    return candidate == root or candidate.startswith(root.rstrip("\\/") + os.sep)


def safe_relative_path(path: Any, start: Any) -> str | None:
    if not path_key_is_under(absolute_path_key(path), absolute_path_key(start)):
        return None
    try:
        rel = os.path.relpath(normalized_path(path), normalized_path(start))
    except ValueError:
        return None
    if rel in {".", ".."} or rel.startswith(".." + os.sep):
        return None
    return rel
