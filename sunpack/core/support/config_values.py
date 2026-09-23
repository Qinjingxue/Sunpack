from typing import Any


def positive_int(config: dict[str, Any], key: str, default: int) -> int:
    try:
        value = int(config.get(key, default))
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def optional_positive_int(config: dict[str, Any], key: str) -> int | None:
    try:
        value = int(config.get(key))
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


def non_negative_int(config: dict[str, Any], key: str, default: int) -> int:
    try:
        value = int(config.get(key, default))
    except (TypeError, ValueError):
        return default
    return value if value >= 0 else default


def bool_value(config: dict[str, Any], key: str, default: bool) -> bool:
    value = config.get(key, default)
    return value if isinstance(value, bool) else default
