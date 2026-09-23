from typing import Any


def enabled_module_configs(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    modules = config.get("modules")
    if not isinstance(modules, list):
        return {}
    return {
        name: {key: value for key, value in item.items() if key not in {"name", "enabled"}}
        for item in modules
        if isinstance(item, dict)
        and item.get("enabled", False)
        and (name := str(item.get("name") or "").strip())
    }
