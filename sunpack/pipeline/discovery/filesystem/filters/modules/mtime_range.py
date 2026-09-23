from __future__ import annotations

from datetime import datetime
from typing import Any

from sunpack.pipeline.discovery.filesystem.filters.base import ScanCandidate, ScanDecision, keep, reject
from sunpack.pipeline.discovery.filesystem.filters.modules.size_range import NumericRange, parse_range_expression


class MtimeRangeScanFilter:
    name = "mtime_range"
    stage = "mtime"

    def __init__(self, value_range: NumericRange | None = None):
        self.value_range = value_range or NumericRange()

    @classmethod
    def from_config(cls, config: dict[str, Any]):
        expression = config.get("date")
        parsed = parse_range_expression(expression, _mtime_or_none, variable="d") if expression is not None else NumericRange()
        explicit = NumericRange(
            gt=_mtime_or_none(_first(config, "gt", "greater_than", "after")),
            gte=_mtime_or_none(_first(config, "gte", "greater_than_or_equal", "after_or_equal", "since")),
            lt=_mtime_or_none(_first(config, "lt", "less_than", "before")),
            lte=_mtime_or_none(_first(config, "lte", "less_than_or_equal", "before_or_equal", "until")),
            eq=_mtime_or_none(_first(config, "eq", "equal", "equals")),
        )
        return cls(parsed.merge(explicit))

    def evaluate(self, candidate: ScanCandidate) -> ScanDecision:
        if candidate.kind != "file":
            return keep()
        if not self.value_range.configured:
            return keep()
        if not self.value_range.allows(candidate.mtime_ns):
            return reject(f"File mtime outside configured range: {candidate.mtime_ns}")
        return keep()


def _first(config: dict[str, Any], *keys: str):
    for key in keys:
        if key in config:
            return config.get(key)
    return None


def _mtime_or_none(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        pass
    try:
        normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
        return int(datetime.fromisoformat(normalized).timestamp() * 1_000_000_000)
    except ValueError:
        pass
    for fmt in ("%Y%m%d %H:%M:%S", "%Y%m%d %H:%M", "%Y%m%d"):
        try:
            return int(datetime.strptime(text, fmt).timestamp() * 1_000_000_000)
        except ValueError:
            continue
    return None
