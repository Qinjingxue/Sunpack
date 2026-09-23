from __future__ import annotations

from dataclasses import dataclass
from typing import Any


CONTENT_REQUIREMENT_COMPLETE = "complete"
CONTENT_REQUIREMENT_ALLOW_PARTIAL = "allow_partial"
CONTENT_REQUIREMENTS = frozenset({
    CONTENT_REQUIREMENT_COMPLETE,
    CONTENT_REQUIREMENT_ALLOW_PARTIAL,
})


@dataclass(frozen=True)
class ContentRecoveryPolicy:
    requirement: str = CONTENT_REQUIREMENT_COMPLETE

    @property
    def allows_partial(self) -> bool:
        return self.requirement == CONTENT_REQUIREMENT_ALLOW_PARTIAL

    @classmethod
    def from_config(cls, config: dict[str, Any] | None) -> "ContentRecoveryPolicy":
        extraction = (config or {}).get("extraction")
        if not isinstance(extraction, dict):
            extraction = {}
        requirement = str(
            extraction.get("content_requirement") or CONTENT_REQUIREMENT_COMPLETE
        ).strip().lower()
        if requirement not in CONTENT_REQUIREMENTS:
            raise ValueError(
                "extraction.content_requirement must be 'complete' or 'allow_partial'"
            )
        return cls(requirement=requirement)


def require_complete_content(config: dict[str, Any]) -> None:
    """Force a runtime config to retain outputs only after complete verification."""
    extraction = config.setdefault("extraction", {})
    if not isinstance(extraction, dict):
        extraction = {}
        config["extraction"] = extraction
    extraction["content_requirement"] = CONTENT_REQUIREMENT_COMPLETE
