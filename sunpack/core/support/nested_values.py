from typing import Any


def get_path(payload: dict[str, Any], path: str, default: Any = None) -> Any:
    current: Any = payload
    for part in (part for part in str(path or "").split(".") if part):
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current
