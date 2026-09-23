from copy import deepcopy
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

from sunpack.core.support.json_format import load_json_file
from sunpack.core.support.resources import candidate_resource_paths, first_existing_path


ADVANCED_CONFIG_FILENAME = "sunpack_advanced_config.json"


@lru_cache(maxsize=1)
def _payload() -> dict[str, Any]:
    project_path = Path(__file__).resolve().parents[2] / ADVANCED_CONFIG_FILENAME
    path = first_existing_path([*candidate_resource_paths(ADVANCED_CONFIG_FILENAME), project_path])
    if path is None:
        raise RuntimeError(f"Missing canonical defaults file: {ADVANCED_CONFIG_FILENAME}")
    payload = load_json_file(path)
    if not isinstance(payload, dict):
        raise RuntimeError(f"Canonical defaults file must contain an object: {path}")
    return payload


def advanced_config_value(path: Iterable[str]) -> Any:
    parts = tuple(path)
    current: Any = _payload()
    for part in parts:
        if not isinstance(current, dict) or part not in current:
            raise KeyError(f"Missing canonical advanced config field: {'.'.join(parts)}")
        current = current[part]
    return deepcopy(current)


def advanced_named_config(path: Iterable[str], name: str) -> dict[str, Any]:
    values = advanced_config_value(path)
    if not isinstance(values, list):
        raise TypeError(f"Canonical advanced config field is not a list: {'.'.join(path)}")
    for item in values:
        if isinstance(item, dict) and item.get("name") == name:
            return deepcopy(item)
    raise KeyError(f"Missing canonical advanced config module: {'.'.join(path)}[{name}]")
