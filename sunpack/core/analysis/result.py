from dataclasses import dataclass, field
from typing import Any, Literal


AnalysisStatus = Literal["not_found", "weak", "damaged", "extractable", "error"]


@dataclass(frozen=True)
class ArchiveSegment:
    start_offset: int
    end_offset: int | None
    confidence: float
    role: str = "primary"
    damage_flags: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ArchiveFormatEvidence:
    format: str
    confidence: float
    status: AnalysisStatus
    segments: list[ArchiveSegment] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ArchiveAnalysisReport:
    path: str
    size: int
    evidences: list[ArchiveFormatEvidence]
    selected: list[ArchiveFormatEvidence]
    prepass: dict[str, Any] = field(default_factory=dict)
    read_bytes: int = 0
    cache_hits: int = 0

    @property
    def has_extractable(self) -> bool:
        return bool(self.selected)
