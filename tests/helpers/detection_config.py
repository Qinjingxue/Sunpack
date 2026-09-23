def with_detection_pipeline(
    config: dict | None = None,
    *,
    precheck: list[dict] | None = None,
    processors: list[dict] | None = None,
) -> dict:
    result = dict(config or {})
    result.setdefault("verification", {})
    scan_filters = [
        dict(rule) for rule in precheck or []
        if isinstance(rule, dict) and rule.get("name") in {"blacklist", "size_range"}
    ]
    if scan_filters:
        filesystem = dict(result.get("filesystem") or {})
        filesystem["scan_filters"] = scan_filters
        result["filesystem"] = filesystem
    result["detection"] = {"enabled": True}
    return result
