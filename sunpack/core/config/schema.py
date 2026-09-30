from copy import deepcopy
from dataclasses import dataclass
from importlib import import_module
from typing import Any, Callable, Iterable


Normalizer = Callable[[Any], Any]


@dataclass(frozen=True)
class ConfigField:
    path: tuple[str, ...]
    default: Any
    normalize: Normalizer
    owner: str

    @property
    def dotted_path(self) -> str:
        return ".".join(self.path)


CONFIG_FIELD_PROVIDER_MODULES = (
    "sunpack.core.config.fields.cli",
    "sunpack.core.config.fields.coordinator",
    "sunpack.core.config.fields.detection",
    "sunpack.core.config.fields.embedded",
    "sunpack.core.config.fields.extraction",
    "sunpack.core.config.fields.filesystem",
    "sunpack.core.config.fields.passwords",
    "sunpack.core.config.fields.postprocess",
    "sunpack.core.config.fields.runtime",
    "sunpack.core.config.fields.verification",
    "sunpack.core.config.fields.watch",
)

_FIELDS: dict[tuple[str, ...], ConfigField] | None = None


class ConfigSchemaError(ValueError):
    pass


def require_boolean(value: Any, path: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{path} must be boolean")
    return value


def config_fields() -> dict[tuple[str, ...], ConfigField]:
    global _FIELDS
    if _FIELDS is None:
        fields: dict[tuple[str, ...], ConfigField] = {}
        for module_name in CONFIG_FIELD_PROVIDER_MODULES:
            module = import_module(module_name)
            fields.update((field.path, field) for field in module.CONFIG_FIELDS)
        _FIELDS = fields
    return _FIELDS


def config_field(path: Iterable[str]) -> ConfigField:
    return config_fields()[tuple(path)]


def normalize_config_value(path: Iterable[str], value: Any) -> Any:
    field = config_field(path)
    return field.normalize(field.default if value is None else value)


def normalize_config(payload: dict[str, Any]) -> dict[str, Any]:
    """Validate external fields while constructing the internal config once."""
    normalized = deepcopy(payload)
    for field in config_fields().values():
        try:
            value = normalize_config_value(field.path, get_config_value(payload, field.path))
        except (TypeError, ValueError) as exc:
            raise ConfigSchemaError(str(exc)) from exc
        set_config_value(normalized, field.path, value)
    return normalized


def get_config_value(config: dict[str, Any], path: Iterable[str], default: Any = None) -> Any:
    current: Any = config
    for part in path:
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def set_config_value(config: dict[str, Any], path: Iterable[str], value: Any) -> None:
    parts = tuple(path)
    current = config
    for part in parts[:-1]:
        next_value = current.get(part)
        if not isinstance(next_value, dict):
            next_value = {}
            current[part] = next_value
        current = next_value
    current[parts[-1]] = value
