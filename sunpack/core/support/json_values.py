from dataclasses import fields, is_dataclass
from pathlib import Path
from typing import Any
from sunpack_native import NativeJsonArray


def jsonable_value(value: Any) -> Any:
    if isinstance(value, NativeJsonArray):
        # Immutable native storage is shared by detached snapshots and streamed
        # by the JSON writer; never expand its complete row table in Python.
        return value
    if is_dataclass(value):
        # Build the detached JSON tree once; asdict() first deep-copies a tree
        # that this traversal would immediately rebuild.
        return {field.name: jsonable_value(getattr(value, field.name)) for field in fields(value)}
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
