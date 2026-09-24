from __future__ import annotations

from sunpack.core.support.collections import clamp01 as _clamp01

from dataclasses import asdict, dataclass
from typing import Any

from sunpack.pipeline.verification.methods._output_stats import output_stats_for_evidence
from sunpack.core.contracts.verification import ArchiveCoverage, FileVerificationObservation


@dataclass(frozen=True)
class OutputQuality:
    score: float = 0.0
    file_count: int = 0
    total_bytes: int = 0
    complete_ratio: float = 0.0
    failed_ratio: float = 0.0
    empty: bool = True
    confidence: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def compute_output_quality(
    evidence: Any,
    file_observations: list[FileVerificationObservation],
    *,
    archive_coverage: ArchiveCoverage | None = None,
) -> OutputQuality:
    stats = output_stats_for_evidence(evidence)
    file_count = int(stats.file_count or 0)
    total_bytes = int(stats.total_size or 0)
    empty = file_count <= 0
    if empty:
        return OutputQuality(empty=True)

    observation_quality = _observation_quality(file_observations)
    coverage_quality = _coverage_quality(archive_coverage)
    if observation_quality is not None:
        complete_ratio, failed_ratio, confidence = observation_quality
    elif coverage_quality is not None:
        complete_ratio, failed_ratio, confidence = coverage_quality
    else:
        complete_ratio = 0.55 if total_bytes > 0 else 0.35
        failed_ratio = 0.0
        confidence = 0.35

    if coverage_quality is not None:
        coverage_complete, coverage_failed, coverage_confidence = coverage_quality
        if observation_quality is None or coverage_confidence >= confidence:
            complete_ratio = max(complete_ratio, coverage_complete)
            failed_ratio = max(failed_ratio, coverage_failed)
            confidence = max(confidence, coverage_confidence)

    presence_score = 0.82 if total_bytes > 0 else 0.45
    if file_count > 1:
        presence_score = min(0.9, presence_score + 0.04)
    presence_score *= 1.0 - min(0.3, failed_ratio * 0.15)
    byte_presence_bonus = 0.05 if total_bytes > 0 else 0.0
    score = max(
        presence_score,
        _clamp01(complete_ratio + byte_presence_bonus - failed_ratio * 0.25),
    )
    return OutputQuality(
        score=score,
        file_count=file_count,
        total_bytes=total_bytes,
        complete_ratio=_clamp01(complete_ratio),
        failed_ratio=_clamp01(failed_ratio),
        empty=False,
        confidence=_clamp01(confidence),
    )


def _observation_quality(
    file_observations: list[FileVerificationObservation],
) -> tuple[float, float, float] | None:
    if not file_observations:
        return None
    total = max(1, len(file_observations))
    complete_value = 0.0
    failed_count = 0
    for item in file_observations:
        if item.progress is not None:
            complete_value += _clamp01(float(item.progress))
        elif item.state == "complete":
            complete_value += 1.0
        elif item.state == "partial":
            complete_value += 0.5
        elif item.state == "unverified":
            complete_value += 0.65
        if item.state in {"failed", "missing"}:
            failed_count += 1
    return (_clamp01(complete_value / total), _clamp01(failed_count / total), 0.8)


def _coverage_quality(
    archive_coverage: ArchiveCoverage | None,
) -> tuple[float, float, float] | None:
    if archive_coverage is None or archive_coverage.confidence <= 0:
        return None
    total = max(1, int(archive_coverage.expected_files or archive_coverage.matched_files or 1))
    failed = int(archive_coverage.failed_files or 0) + int(archive_coverage.missing_files or 0)
    return (
        _clamp01(float(archive_coverage.completeness)),
        _clamp01(failed / total),
        _clamp01(float(archive_coverage.confidence)),
    )

