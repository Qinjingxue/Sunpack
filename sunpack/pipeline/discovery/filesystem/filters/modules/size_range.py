from typing import Any


# Native comparison order: greater, greater-or-equal, less, less-or-equal, equal.
NumericBounds = tuple[int | None, int | None, int | None, int | None, int | None]


UINT64_MAX = (1 << 64) - 1


def validate_range_fields(config: dict[str, Any], bounds: tuple[str, str]) -> None:
    unknown = config.keys() - {"name", "enabled", *bounds}
    if unknown:
        raise ValueError(f"Unknown range filter fields: {', '.join(sorted(unknown))}")
    if "enabled" in config and type(config["enabled"]) is not bool:
        raise ValueError("enabled must be a boolean")


def size_bounds(config: dict[str, Any]) -> NumericBounds:
    validate_range_fields(config, ("min_bytes", "max_bytes"))
    lower, upper = (config.get(key) for key in ("min_bytes", "max_bytes"))
    for value in (lower, upper):
        if value is not None and (type(value) is not int or not 0 <= value <= UINT64_MAX):
            raise ValueError("Size bounds must be null or uint64 integer bytes")
    if lower is not None and upper is not None and lower > upper:
        raise ValueError("min_bytes must not exceed max_bytes")
    return None, lower, None, upper, None
