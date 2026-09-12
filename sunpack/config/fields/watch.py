from typing import Any

from sunpack.config.advanced_defaults import advanced_config_value
from sunpack.config.schema import ConfigField


DEFAULT_WATCH_CONFIG = advanced_config_value(("watch",))


def normalize_watch_config(value: Any) -> dict[str, Any]:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise ValueError("watch must be an object")
    raw_config = dict(value)
    config = dict(DEFAULT_WATCH_CONFIG)
    config.update(raw_config)
    if "cold_start_seconds" not in raw_config and "quiet_seconds" in raw_config:
        config["cold_start_seconds"] = raw_config["quiet_seconds"]
    config.pop("quiet_seconds", None)
    config.pop("recursive", None)
    config["cold_start_seconds"] = max(0.0, _float_field(config, "cold_start_seconds"))
    config["quiet_min_seconds"] = max(0.0, _float_field(config, "quiet_min_seconds"))
    config["quiet_max_seconds"] = max(
        config["cold_start_seconds"],
        config["quiet_min_seconds"],
        _float_field(config, "quiet_max_seconds"),
    )
    config["boundary_confirmation_seconds"] = max(
        0.0,
        _float_field(config, "boundary_confirmation_seconds"),
    )
    config["max_folders"] = max(1, _int_field(config, "max_folders"))
    config["observer_stop_timeout_seconds"] = max(0.0, _float_field(config, "observer_stop_timeout_seconds"))
    config["runtime_cache_cleanup_enabled"] = bool(config["runtime_cache_cleanup_enabled"])
    config["runtime_cache_cleanup_idle_seconds"] = max(
        0.0,
        _float_field(config, "runtime_cache_cleanup_idle_seconds"),
    )
    config["password_retry_debounce_seconds"] = max(0.0, _float_field(config, "password_retry_debounce_seconds"))
    config["password_retry_include_subtree"] = bool(config["password_retry_include_subtree"])
    config["clipboard_monitor_enabled"] = bool(config["clipboard_monitor_enabled"])
    config["clipboard_builtin_max_entries"] = max(1, _int_field(config, "clipboard_builtin_max_entries"))
    roots = config["roots"]
    if roots is None:
        roots = []
    if not isinstance(roots, list):
        raise ValueError("watch.roots must be a list")
    config["roots"] = [str(item) for item in roots if str(item or "").strip()]
    config["enabled"] = bool(config["enabled"])
    config["out_dir"] = str(config["out_dir"])
    config["tray_enabled"] = bool(config["tray_enabled"])
    config["toast_enabled"] = bool(config["toast_enabled"])
    config["toast_update_interval_ms"] = max(10, _int_field(config, "toast_update_interval_ms"))
    config["toast_completion_debounce_ms"] = max(0, _int_field(config, "toast_completion_debounce_ms"))
    config["toast_success_ttl_seconds"] = max(0.0, _float_field(config, "toast_success_ttl_seconds"))
    config["toast_failure_ttl_seconds"] = max(0.0, _float_field(config, "toast_failure_ttl_seconds"))
    config["toast_report_retention_days"] = max(1, _int_field(config, "toast_report_retention_days"))
    config["toast_report_max_files"] = max(1, _int_field(config, "toast_report_max_files"))
    config["toast_report_max_bytes"] = max(1024, _int_field(config, "toast_report_max_bytes"))
    config["state_dir"] = str(config["state_dir"])
    return config


def _float_field(config: dict[str, Any], name: str) -> float:
    try:
        return float(config.get(name))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"watch.{name} must be a number") from exc


def _int_field(config: dict[str, Any], name: str) -> int:
    try:
        return int(config.get(name))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"watch.{name} must be an integer") from exc


CONFIG_FIELDS = (
    ConfigField(
        path=("watch",),
        default=DEFAULT_WATCH_CONFIG,
        normalize=normalize_watch_config,
        owner=__name__,
    ),
)
