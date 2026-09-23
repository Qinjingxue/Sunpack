import os
from typing import Any


def normalized_path(path: Any) -> str:
    return os.path.normpath(str(path or ""))


def path_key(path: Any) -> str:
    return os.path.normcase(normalized_path(path))


def case_key(value: Any) -> str:
    return os.path.normcase(str(value or ""))


def absolute_path_key(path: Any) -> str:
    return os.path.normcase(os.path.abspath(str(path or "")))


def safe_relative_path(path: Any, start: Any) -> str | None:
    try:
        rel = os.path.relpath(normalized_path(path), normalized_path(start))
    except ValueError:
        return None
    if rel == "." or rel.startswith(".."):
        return None
    return rel
