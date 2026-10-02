import copy
import json
import os
from pathlib import Path
import threading
from typing import Any

from sunpack.core.config.advanced_defaults import _payload as _advanced_defaults_payload
from sunpack.core.config.schema import ConfigSchemaError, config_fields, normalize_config
from sunpack.core.support.json_format import load_json_file
from sunpack.core.support.resources import candidate_resource_paths, first_existing_path, program_data_dir, resolve_resource_path
from sunpack.core.support.process_executable import is_packaged_process


class ConfigError(RuntimeError):
    pass


SIMPLE_CONFIG_FILENAME = "sunpack_config.json"
ADVANCED_CONFIG_FILENAME = "sunpack_advanced_config.json"
OVERRIDES_ENV_VAR = "SUNPACK_CONFIG_OVERRIDES"


_CONFIG_CACHE_LOCK = threading.RLock()
_CONFIG_CACHE_SIGNATURE: tuple[Any, ...] | None = None
_CONFIG_CACHE_VALUE: dict[str, Any] | None = None
_CONFIG_CACHE_RAW_VALUE: dict[str, Any] | None = None
_CONFIG_CACHE_PATH: Path | None = None


def _load_json(path: Path) -> dict[str, Any]:
    payload = load_json_file(path)
    if not isinstance(payload, dict):
        raise ConfigError(f"Config file must contain a JSON object: {path}")
    return payload


def _candidate_config_paths(filename: str, request_cwd: str | Path | None = None) -> list[Path]:
    return candidate_resource_paths(filename, request_cwd=request_cwd)


def _searched_config_paths(filename: str, request_cwd: str | Path | None = None) -> list[Path]:
    if not is_packaged_process() or filename != SIMPLE_CONFIG_FILENAME:
        return _candidate_config_paths(filename) if request_cwd is None else _candidate_config_paths(filename, request_cwd)
    return [program_data_dir() / filename]


def _first_existing_config(filename: str, request_cwd: str | Path | None = None) -> Path | None:
    return first_existing_path(_searched_config_paths(filename, request_cwd))


def _known_config_sections() -> frozenset[str]:
    sections = {field.path[0] for field in config_fields().values()}
    sections.update(_advanced_defaults_payload())
    return frozenset(sections)


def _load_override_payload() -> dict[str, Any]:
    """Read the SUNPACK_CONFIG_OVERRIDES layer (inline JSON object or file path)."""
    raw = os.environ.get(OVERRIDES_ENV_VAR, "").strip()
    if not raw:
        return {}
    path = Path(raw)
    if path.is_file():
        payload = load_json_file(path)
    else:
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            if raw[:1] in {"{", "["}:
                raise ConfigError(f"{OVERRIDES_ENV_VAR} contains invalid JSON: {exc}") from exc
            raise ConfigError(
                f"{OVERRIDES_ENV_VAR} must be an inline JSON object or an existing JSON file: {raw}"
            ) from exc
    if not isinstance(payload, dict):
        raise ConfigError(f"{OVERRIDES_ENV_VAR} must contain a JSON object")
    unknown = sorted(set(payload) - _known_config_sections())
    if unknown:
        raise ConfigError(
            f"{OVERRIDES_ENV_VAR} contains unknown config sections: {', '.join(unknown)}"
        )
    return payload


def _override_signature() -> tuple[str, int, int] | str | None:
    raw = os.environ.get(OVERRIDES_ENV_VAR, "").strip()
    if not raw:
        return None
    path = Path(raw)
    if not path.is_file():
        return raw
    try:
        stat = path.stat()
    except OSError:
        return (str(resolve_resource_path(path)), -1, -1)
    return (str(resolve_resource_path(path)), int(stat.st_mtime_ns), int(stat.st_size))


_NAMED_MODULE_LIST_PATHS = {
    ("filesystem", "scan_filters"),
}

_OVERRIDE_ORDERED_NAMED_MODULE_LIST_PATHS = {
    ("filesystem", "scan_filters"),
}


def _deep_merge_config(base: dict[str, Any], override: dict[str, Any], path: tuple[str, ...] = ()) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        item_path = path + (key,)
        base_value = merged.get(key)
        if isinstance(base_value, dict) and isinstance(value, dict):
            merged[key] = _deep_merge_config(base_value, value, item_path)
        elif item_path in _NAMED_MODULE_LIST_PATHS and isinstance(base_value, list) and isinstance(value, list):
            merged[key] = _merge_named_module_list(
                base_value,
                value,
                override_order=item_path in _OVERRIDE_ORDERED_NAMED_MODULE_LIST_PATHS,
            )
        else:
            merged[key] = value
    return merged


def _merge_named_module_list(base: list[Any], override: list[Any], *, override_order: bool = False) -> list[Any]:
    merged = list(base)
    indexes = {
        item.get("name"): index
        for index, item in enumerate(merged)
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    for item in override:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            merged.append(item)
            continue
        existing_index = indexes.get(item["name"])
        if existing_index is None or not isinstance(merged[existing_index], dict):
            indexes[item["name"]] = len(merged)
            merged.append(item)
            continue
        merged[existing_index] = _deep_merge_config(merged[existing_index], item)
    if override_order:
        override_names = [
            item.get("name")
            for item in override
            if isinstance(item, dict) and isinstance(item.get("name"), str)
        ]
        by_name = {
            item.get("name"): item
            for item in merged
            if isinstance(item, dict) and isinstance(item.get("name"), str)
        }
        ordered = [by_name[name] for name in override_names if name in by_name]
        ordered.extend(
            item
            for item in merged
            if not (
                isinstance(item, dict)
                and isinstance(item.get("name"), str)
                and item["name"] in override_names
            )
        )
        return ordered
    return merged


def apply_config_overrides(config: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
    """Merge a runtime override layer into config in place using the canonical layer semantics."""
    if not overrides:
        return config
    merged = _deep_merge_config(config, overrides)
    config.clear()
    config.update(merged)
    return config


def _load_layered_config_paths(
    simple_path: Path | None,
    advanced_path: Path | None,
    *,
    request_cwd: str | Path | None = None,
) -> tuple[Path, dict[str, Any]]:
    if simple_path is None and advanced_path is None:
        searched = [
            *[str(path) for path in _searched_config_paths(SIMPLE_CONFIG_FILENAME, request_cwd)],
            *[str(path) for path in _searched_config_paths(ADVANCED_CONFIG_FILENAME, request_cwd)],
        ]
        raise ConfigError(f"Missing required {SIMPLE_CONFIG_FILENAME} or {ADVANCED_CONFIG_FILENAME}. Searched: {', '.join(searched)}")

    advanced = _load_json(advanced_path) if advanced_path is not None else {}
    config = advanced
    if simple_path is not None:
        config = _deep_merge_config(advanced, _load_json(simple_path))
    overrides = _load_override_payload()
    return (simple_path or advanced_path), apply_config_overrides(config, overrides)


def load_raw_config_payload(request_cwd: str | Path | None = None) -> tuple[Path, dict[str, Any]]:
    """Load the merged external payload without schema initialization or validation."""
    global _CONFIG_CACHE_SIGNATURE, _CONFIG_CACHE_VALUE, _CONFIG_CACHE_RAW_VALUE, _CONFIG_CACHE_PATH
    simple_path = _first_existing_config(SIMPLE_CONFIG_FILENAME, request_cwd)
    advanced_path = _first_existing_config(ADVANCED_CONFIG_FILENAME, request_cwd)
    signature = (_config_file_signature(simple_path), _config_file_signature(advanced_path), _override_signature())
    with _CONFIG_CACHE_LOCK:
        if (
            signature == _CONFIG_CACHE_SIGNATURE
            and _CONFIG_CACHE_RAW_VALUE is not None
            and _CONFIG_CACHE_PATH is not None
        ):
            return _CONFIG_CACHE_PATH, copy.deepcopy(_CONFIG_CACHE_RAW_VALUE)
    config_path, config = _load_layered_config_paths(simple_path, advanced_path, request_cwd=request_cwd)
    with _CONFIG_CACHE_LOCK:
        _CONFIG_CACHE_SIGNATURE = signature
        _CONFIG_CACHE_VALUE = None
        _CONFIG_CACHE_RAW_VALUE = copy.deepcopy(config)
        _CONFIG_CACHE_PATH = config_path
    return config_path, config


def _config_file_signature(path: Path | None) -> tuple[str, int, int] | None:
    if path is None:
        return None
    try:
        stat = path.stat()
    except OSError:
        return (str(resolve_resource_path(path)), -1, -1)
    return (str(resolve_resource_path(path)), int(stat.st_mtime_ns), int(stat.st_size))


def config_cache_token(request_cwd: str | Path | None = None) -> tuple[Any, ...]:
    """Return the selected config files and mtimes used for cache invalidation."""
    simple_path = _first_existing_config(SIMPLE_CONFIG_FILENAME, request_cwd)
    advanced_path = _first_existing_config(ADVANCED_CONFIG_FILENAME, request_cwd)
    return (_config_file_signature(simple_path), _config_file_signature(advanced_path), _override_signature())


def _config_source_path(path: Path | None) -> str | None:
    return str(resolve_resource_path(path)) if path is not None else None


def _override_source_identity() -> str | None:
    raw = os.environ.get(OVERRIDES_ENV_VAR, "").strip()
    if not raw:
        return None
    path = Path(raw)
    return f"file:{resolve_resource_path(path)}" if path.is_file() else f"inline:{raw}"


def config_source_key(request_cwd: str | Path | None = None) -> tuple[str | None, str | None, str | None]:
    """Return the config source identity without any mtime-based invalidation."""
    simple_path = _first_existing_config(SIMPLE_CONFIG_FILENAME, request_cwd)
    advanced_path = _first_existing_config(ADVANCED_CONFIG_FILENAME, request_cwd)
    return (_config_source_path(simple_path), _config_source_path(advanced_path), _override_source_identity())


def clear_config_cache() -> None:
    global _CONFIG_CACHE_SIGNATURE, _CONFIG_CACHE_VALUE, _CONFIG_CACHE_RAW_VALUE, _CONFIG_CACHE_PATH
    with _CONFIG_CACHE_LOCK:
        _CONFIG_CACHE_SIGNATURE = None
        _CONFIG_CACHE_VALUE = None
        _CONFIG_CACHE_RAW_VALUE = None
        _CONFIG_CACHE_PATH = None


def load_config(request_cwd: str | Path | None = None) -> dict[str, Any]:
    """Read the external configuration required to run the pipeline."""
    global _CONFIG_CACHE_SIGNATURE, _CONFIG_CACHE_VALUE, _CONFIG_CACHE_RAW_VALUE, _CONFIG_CACHE_PATH
    simple_path = _first_existing_config(SIMPLE_CONFIG_FILENAME, request_cwd)
    advanced_path = _first_existing_config(ADVANCED_CONFIG_FILENAME, request_cwd)
    signature = (_config_file_signature(simple_path), _config_file_signature(advanced_path), _override_signature())
    with _CONFIG_CACHE_LOCK:
        if signature == _CONFIG_CACHE_SIGNATURE and _CONFIG_CACHE_VALUE is not None:
            return copy.deepcopy(_CONFIG_CACHE_VALUE)
        cached_raw = copy.deepcopy(_CONFIG_CACHE_RAW_VALUE) if signature == _CONFIG_CACHE_SIGNATURE else None
    if cached_raw is None:
        config_path, config = _load_layered_config_paths(simple_path, advanced_path, request_cwd=request_cwd)
    else:
        config_path, config = (_CONFIG_CACHE_PATH or simple_path or advanced_path), cached_raw
    raw_for_cache = copy.deepcopy(config)
    try:
        normalized = normalize_config(config)
    except ConfigSchemaError as exc:
        raise ConfigError(str(exc)) from exc
    with _CONFIG_CACHE_LOCK:
        _CONFIG_CACHE_SIGNATURE = signature
        _CONFIG_CACHE_VALUE = copy.deepcopy(normalized)
        _CONFIG_CACHE_RAW_VALUE = raw_for_cache
        _CONFIG_CACHE_PATH = config_path
    return normalized
