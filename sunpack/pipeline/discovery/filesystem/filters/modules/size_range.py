import re
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

    @classmethod
    def from_config(cls, config: dict[str, Any]):
        expression = config.get("range")
        parsed = parse_range_expression(expression, parse_size_value, variable="r") if expression is not None else cls()
        explicit = cls(
            gt=_int_or_none(_first(config, "gt", "greater_than")),
            gte=_int_or_none(_first(config, "gte", "greater_than_or_equal", "min", "minimum")),
            lt=_int_or_none(_first(config, "lt", "less_than")),
            lte=_int_or_none(_first(config, "lte", "less_than_or_equal", "max", "maximum")),
            eq=_int_or_none(_first(config, "eq", "equal", "equals")),
        )
        return parsed.merge(explicit)

    def merge(self, other: "NumericRange") -> "NumericRange":
        return NumericRange(
            gt=_max_optional(self.gt, other.gt),
            gte=_max_optional(self.gte, other.gte),
            lt=_min_optional(self.lt, other.lt),
            lte=_min_optional(self.lte, other.lte),
            eq=other.eq if other.eq is not None else self.eq,
        )

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
        return cls(NumericRange.from_config(config))

    def evaluate(self, candidate: ScanCandidate) -> ScanDecision:
        if candidate.kind != "file":
            return keep()
        if not self.value_range.configured:
            return keep()
        if not self.value_range.allows(candidate.size):
            return reject(f"File size outside configured range: {candidate.size}")
        return keep()


def _first(config: dict[str, Any], *keys: str | None):
    for key in keys:
        if key and key in config:
            return config.get(key)
    return None


def _int_or_none(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_range_expression(expression: Any, value_parser, *, variable: str = "r") -> NumericRange:
    text = str(expression or "").strip()
    if not text:
        return NumericRange()
    parts = [part.strip() for part in re.split(r"(<=|>=|==|=|<|>)", text) if part.strip()]
    if len(parts) < 3 or len(parts) % 2 == 0:
        return NumericRange()
    result = NumericRange()
    operands = parts[0::2]
    operators = parts[1::2]
    for left, operator, right in zip(operands, operators, operands[1:]):
        comparison = _comparison_to_range(left, operator, right, value_parser, variable=variable)
        result = result.merge(comparison)
    return result


def parse_size_value(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value).strip()
    if not text:
        return None
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)\s*([a-zA-Z]+)?", text)
    if not match:
        return _int_or_none(text)
    number = float(match.group(1))
    unit = (match.group(2) or "B").lower()
    factors = {
        "b": 1,
        "byte": 1,
        "bytes": 1,
        "k": 1024,
        "kb": 1024,
        "kib": 1024,
        "m": 1024 ** 2,
        "mb": 1024 ** 2,
        "mib": 1024 ** 2,
        "g": 1024 ** 3,
        "gb": 1024 ** 3,
        "gib": 1024 ** 3,
        "t": 1024 ** 4,
        "tb": 1024 ** 4,
        "tib": 1024 ** 4,
    }
    factor = factors.get(unit)
    if factor is None:
        return None
    return int(number * factor)


def _comparison_to_range(left: str, operator: str, right: str, value_parser, *, variable: str) -> NumericRange:
    normalized_variable = variable.lower()
    left_is_var = left.lower() == normalized_variable
    right_is_var = right.lower() == normalized_variable
    if left_is_var == right_is_var:
        return NumericRange()
    value = value_parser(right if left_is_var else left)
    if value is None:
        return NumericRange()
    if not left_is_var:
        operator = _flip_operator(operator)
    if operator == ">":
        return NumericRange(gt=value)
    if operator == ">=":
        return NumericRange(gte=value)
    if operator == "<":
        return NumericRange(lt=value)
    if operator == "<=":
        return NumericRange(lte=value)
    if operator in {"=", "=="}:
        return NumericRange(eq=value)
    return NumericRange()


def _flip_operator(operator: str) -> str:
    return {
        ">": "<",
        ">=": "<=",
        "<": ">",
        "<=": ">=",
    }.get(operator, operator)


def _max_optional(left: int | None, right: int | None) -> int | None:
    values = [value for value in (left, right) if value is not None]
    return max(values) if values else None


def _min_optional(left: int | None, right: int | None) -> int | None:
    values = [value for value in (left, right) if value is not None]
    return min(values) if values else None
