import json
from io import StringIO
from pathlib import Path
from typing import Any
from sunpack_native import stream_json

from sunpack.core.support.resource_lifecycle import open_task_file


def json_safe(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [json_safe(item) for item in value]
    return value


def to_json_text(value: Any, *, pretty: bool = True) -> str:
    output = StringIO()
    stream_json(json_safe(value), output, pretty=pretty)
    return output.getvalue()


def load_json_file(path: Path) -> Any:
    with open_task_file(path, "r", encoding="utf-8") as handle:
        return json.load(handle)
