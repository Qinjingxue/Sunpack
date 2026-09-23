from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


@dataclass(frozen=True, slots=True)
class FormatObservation:
    """Lossless, policy-free result of one format capability invocation."""

    format: str
    start_offset: int
    raw: Mapping[str, Any]
    capabilities: frozenset[str] = field(default_factory=frozenset)
    damage_flags: tuple[str, ...] = ()
    boundary_confidence: str = "unknown"
    integrity_confidence: str = "unknown"

    def to_raw_dict(self) -> dict[str, Any]:
        return dict(self.raw)

