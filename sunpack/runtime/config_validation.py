from typing import Any

from sunpack.pipeline.verification.registry import registered_verification_methods


def validate_config_payload(config: dict) -> dict[str, Any]:
    """Validate registered methods and native scan rules in normalized config."""
    available = registered_verification_methods()
    errors = []
    from sunpack_native import NativePathRule
    for index, rule in enumerate(config["filesystem"]["scan_filters"]):
        if rule["name"] in {"blacklist", "whitelist"}:
            try:
                NativePathRule(rule.get("paths", []), rule.get("files", []))
            except (TypeError, ValueError) as error:
                errors.append(f"filesystem.scan_filters[{index}]: {error}")
    for index, method in enumerate(config["verification"]["methods"]):
        if method["name"] not in available:
            errors.append(f"Unknown verification method at verification.methods[{index}]: {method['name']}")
    return {
        "ok": not errors,
        "errors": errors,
        "warnings": [],
        "available_verification_methods": sorted(available),
    }
