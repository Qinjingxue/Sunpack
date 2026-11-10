from typing import Any



def validate_config_payload(config: dict) -> dict[str, Any]:
    """Validate native scan rules in normalized config."""
    errors = []
    from sunpack_native import NativePathRule
    for index, rule in enumerate(config["filesystem"]["scan_filters"]):
        if rule["name"] in {"blacklist", "whitelist"}:
            try:
                NativePathRule(*(rule.get(field, []) for field in ("paths", "files", "extensions", "full_names")))
            except (TypeError, ValueError) as error:
                errors.append(f"filesystem.scan_filters[{index}]: {error}")
    return {
        "ok": not errors,
        "errors": errors,
        "warnings": [],
    }
