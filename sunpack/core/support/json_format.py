import json
from pathlib import Path
from typing import Any

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
    indent = 2 if pretty else None
    return json.dumps(json_safe(value), ensure_ascii=False, indent=indent)


def load_json_file(path: Path) -> Any:
    with open_task_file(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json_file(path: Path, value: Any, *, pretty: bool = True):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open_task_file(path, "w", encoding="utf-8") as handle:
        handle.write(to_json_text(value, pretty=pretty))
        handle.write("\n")


def parse_jsonish(raw_value: str) -> Any:
    try:
        return json.loads(raw_value)
    except json.JSONDecodeError:
        return raw_value
