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
    # Native selection and segment plan: the evidence naming the input format,
    # carved extractable segments in extraction order, the encrypted segment
    # to probe when nothing is extractable, and proof that a split input is
    # missing a later volume.
    best_selected: ArchiveFormatEvidence | None = None
    extractable_segments: tuple[tuple[ArchiveFormatEvidence, ArchiveSegment], ...] = ()
    password_segment: tuple[ArchiveFormatEvidence, ArchiveSegment] | None = None
    missing_volume_evidence: str = ""

    @property
    def has_extractable(self) -> bool:
        return bool(self.selected)
