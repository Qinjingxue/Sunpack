from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Any

from sunpack.pipeline.discovery.filesystem.filters.base import ScanCandidate, ScanDecision, keep, reject
from sunpack.pipeline.discovery.filesystem.filters.modules.size_range import NumericRange, UINT64_MAX, validate_range_fields


class MtimeRangeScanFilter:
    name = "mtime_range"
    stage = "mtime"

    def __init__(self, value_range: NumericRange | None = None):
        self.value_range = value_range or NumericRange()

    @classmethod
    def from_config(cls, config: dict[str, Any]):
        return cls(time_bounds(config))

    def evaluate(self, candidate: ScanCandidate) -> ScanDecision:
        if candidate.kind != "file":
            return keep()
        if not self.value_range.configured:
            return keep()
        if not self.value_range.allows(candidate.mtime_ns):
            return reject(f"File mtime outside configured range: {candidate.mtime_ns}")
        return keep()



_UTC_MINUTE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}Z")
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def utc_minute_ns(value: Any) -> int | None:
    if value is None:
        return None
    if not isinstance(value, str) or _UTC_MINUTE.fullmatch(value) is None:
        raise ValueError("Time bounds must be null or UTC minutes: YYYY-MM-DDTHH:mmZ")
    try:
        parsed = datetime(int(value[:4]), int(value[5:7]), int(value[8:10]),
                          int(value[11:13]), int(value[14:16]), tzinfo=timezone.utc)
    except ValueError as error:
        raise ValueError("Invalid UTC minute") from error
    delta = parsed - _EPOCH
    return (delta.days * 86400 + delta.seconds) * 1_000_000_000


def time_bounds(config: dict[str, Any]) -> NumericRange:
    validate_range_fields(config, ("start_utc", "end_utc"))
    start, end = (utc_minute_ns(config.get(key)) for key in ("start_utc", "end_utc"))
    if start is not None and end is not None and start >= end:
        raise ValueError("start_utc must precede end_utc")
    # Keep the existing native uint64 metadata domain and comparison ABI.
    if (start is not None and start > UINT64_MAX) or (end is not None and end <= 0):
        return NumericRange(gt=0, lt=0)
    lower = max(0, start) if start is not None else None
    upper = end if end is not None and end <= UINT64_MAX else None
    if end is not None and upper is None and lower is None:
        lower = 0  # A configured time filter still rejects missing metadata.
    return NumericRange(gte=lower, lt=upper)
