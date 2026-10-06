from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any


def jsonable_value(value: Any) -> Any:
    if is_dataclass(value):
        return jsonable_value(asdict(value))
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): jsonable_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [jsonable_value(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, bytes):
        return value.hex()
    if hasattr(value, "to_dict"):
        return jsonable_value(value.to_dict())
    raise TypeError(f"Unsupported JSON value type: {type(value).__name__}")
