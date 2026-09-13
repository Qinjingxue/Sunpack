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
    "sunpack.config.fields.cli",
    "sunpack.config.fields.coordinator",
    "sunpack.config.fields.detection",
    "sunpack.config.fields.embedded",
    "sunpack.config.fields.extraction",
    "sunpack.config.fields.filesystem",
    "sunpack.config.fields.passwords",
    "sunpack.config.fields.postprocess",
    "sunpack.config.fields.verification",
    "sunpack.config.fields.watch",
)

_FIELDS: dict[tuple[str, ...], ConfigField] | None = None


class ConfigSchemaError(ValueError):
    pass


def config_fields() -> dict[tuple[str, ...], ConfigField]:
    global _FIELDS
    if _FIELDS is None:
        fields: dict[tuple[str, ...], ConfigField] = {}
        for module_name in CONFIG_FIELD_PROVIDER_MODULES:
            module = import_module(module_name)
            register_config_fields(fields, getattr(module, "CONFIG_FIELDS", ()))
        _FIELDS = fields
    return _FIELDS


def config_field(path: Iterable[str]) -> ConfigField:
    key = tuple(path)
    try:
        return config_fields()[key]
    except KeyError as exc:
        raise ConfigSchemaError(f"Unknown config field: {'.'.join(key)}") from exc


def normalize_config_value(path: Iterable[str], value: Any) -> Any:
    field = config_field(path)
    return field.normalize(field.default if value is None else value)


def normalize_config(payload: dict[str, Any], *, validate: bool = True) -> dict[str, Any]:
    normalized = deepcopy(payload)
    if validate:
        errors = validate_external_config(payload)
        if errors:
            raise ConfigSchemaError("; ".join(errors))
    for field in config_fields().values():
        set_config_value(normalized, field.path, normalize_config_value(field.path, get_config_value(payload, field.path)))
    return normalized


def validate_external_config(payload: dict[str, Any]) -> list[str]:
    errors = []
    performance = payload.get("performance") if isinstance(payload, dict) else None
    worker = performance.get("worker") if isinstance(performance, dict) else None
    if isinstance(worker, dict) and "profile" in worker:
        errors.append(
            "performance.worker.profile was removed; native worker sizing is derived from CPU and available memory"
        )
    for field in config_fields().values():
        try:
            normalize_config_value(field.path, get_config_value(payload, field.path))
        except (TypeError, ValueError) as exc:
            errors.append(str(exc))
    return errors


def get_config_value(config: dict[str, Any], path: Iterable[str], default: Any = None) -> Any:
    current: Any = config
    for part in path:
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def set_config_value(config: dict[str, Any], path: Iterable[str], value: Any) -> None:
    parts = tuple(path)
    if not parts:
        raise ConfigSchemaError("Config field path must not be empty")
    current = config
    for part in parts[:-1]:
        next_value = current.get(part)
        if not isinstance(next_value, dict):
            next_value = {}
            current[part] = next_value
        current = next_value
    current[parts[-1]] = value


def register_config_fields(target: dict[tuple[str, ...], ConfigField], fields: Iterable[ConfigField]) -> None:
    for field in fields:
        existing = target.get(field.path)
        if existing is not None:
            raise ConfigSchemaError(
                f"Duplicate config field {field.dotted_path}: {existing.owner} and {field.owner}"
            )
        target[field.path] = field
