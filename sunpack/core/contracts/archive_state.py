from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any

from sunpack.core.contracts.archive_input import ArchiveInputDescriptor


@dataclass(frozen=True)
class ArchiveState:
    archive_input: ArchiveInputDescriptor
    planning_analysis: dict[str, Any] = field(default_factory=dict)

    def to_archive_input_descriptor(self) -> ArchiveInputDescriptor:
        if not self.planning_analysis:
            return self.archive_input
        analysis = dict(self.archive_input.analysis)
        analysis.update(self.planning_analysis)
        if analysis == self.archive_input.analysis:
            return self.archive_input
        return replace(self.archive_input, analysis=analysis)

    @classmethod
    def from_archive_input(
        cls,
        descriptor: ArchiveInputDescriptor,
        *,
        planning_analysis: dict[str, Any] | None = None,
    ) -> "ArchiveState":
        return cls(
            archive_input=descriptor,
            planning_analysis=dict(planning_analysis or {}),
        )
