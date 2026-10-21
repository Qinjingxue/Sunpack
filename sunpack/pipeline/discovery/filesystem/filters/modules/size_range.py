from typing import Any

from sunpack.pipeline.discovery.filesystem.filters.base import ScanCandidate, ScanDecision, keep, reject


class NumericRange:
    def __init__(
        self,
        *,
        gt: int | None = None,
        gte: int | None = None,
        lt: int | None = None,
        lte: int | None = None,
        eq: int | None = None,
    ):
        self.gt = gt
        self.gte = gte
        self.lt = lt
        self.lte = lte
        self.eq = eq

    @property
    def configured(self) -> bool:
        return any(value is not None for value in (self.gt, self.gte, self.lt, self.lte, self.eq))

    def allows(self, value: int | None) -> bool:
        if not self.configured:
            return True
        if value is None or value < 0:
            return False
        if self.eq is not None and value != self.eq:
            return False
        if self.gt is not None and value <= self.gt:
            return False
        if self.gte is not None and value < self.gte:
            return False
        if self.lt is not None and value >= self.lt:
            return False
        if self.lte is not None and value > self.lte:
            return False
        return True


class SizeRangeScanFilter:
    name = "size_range"
    stage = "size"

    def __init__(self, value_range: NumericRange | None = None):
        self.value_range = value_range or NumericRange()

    @classmethod
    def from_config(cls, config: dict[str, Any]):
        return cls(size_bounds(config))

    def evaluate(self, candidate: ScanCandidate) -> ScanDecision:
        if candidate.kind != "file":
            return keep()
        if not self.value_range.configured:
            return keep()
        if not self.value_range.allows(candidate.size):
            return reject(f"File size outside configured range: {candidate.size}")
        return keep()



UINT64_MAX = (1 << 64) - 1


def validate_range_fields(config: dict[str, Any], bounds: tuple[str, str]) -> None:
    unknown = config.keys() - {"name", "enabled", *bounds}
    if unknown:
        raise ValueError(f"Unknown range filter fields: {', '.join(sorted(unknown))}")
    if "enabled" in config and type(config["enabled"]) is not bool:
        raise ValueError("enabled must be a boolean")


def size_bounds(config: dict[str, Any]) -> NumericRange:
    validate_range_fields(config, ("min_bytes", "max_bytes"))
    lower, upper = (config.get(key) for key in ("min_bytes", "max_bytes"))
    for value in (lower, upper):
        if value is not None and (type(value) is not int or not 0 <= value <= UINT64_MAX):
            raise ValueError("Size bounds must be null or uint64 integer bytes")
    if lower is not None and upper is not None and lower > upper:
        raise ValueError("min_bytes must not exceed max_bytes")
    return NumericRange(gte=lower, lte=upper)
