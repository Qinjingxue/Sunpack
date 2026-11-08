from sunpack_native import NativePathRule


def validate_path_rule_config(config: dict) -> None:
    unexpected = config.keys() - {"name", "enabled", "paths", "files", "extensions", "full_names"}
    if unexpected:
        raise ValueError(f"Unsupported {config.get('name')} fields: {', '.join(sorted(unexpected))}")
    for field in ("paths", "files", "extensions", "full_names"):
        values = config.get(field, [])
        if not isinstance(values, list):
            raise ValueError(f"{field} must be a list of rule objects")
        for index, item in enumerate(values):
            if (not isinstance(item, dict) or item.keys() != {"value", "regex"}
                    or not isinstance(item["value"], str) or not item["value"]
                    or not isinstance(item["regex"], bool)):
                raise ValueError(f"{field}[{index}] requires a nonempty value string and a regex boolean")


def compile_path_rule(config: dict) -> NativePathRule:
    validate_path_rule_config(config)
    return NativePathRule(
        config.get("paths", []), config.get("files", []),
        config.get("extensions", []), config.get("full_names", []),
    )
