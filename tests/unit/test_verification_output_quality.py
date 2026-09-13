from types import SimpleNamespace

import pytest

from sunpack.verification.output_quality import compute_output_quality
from sunpack.verification.pipeline import _decision_hint
from sunpack.contracts.verification import (
    ASSESSMENT_COMPLETE,
    DECISION_ACCEPT,
    DECISION_ACCEPT_PARTIAL,
    CONTENT_INTEGRITY_UNKNOWN,
    ArchiveCoverageSummary,
    FileVerificationObservation,
)


def test_output_quality_complete_manifest_like_observations(tmp_path):
    (tmp_path / "a.txt").write_text("alpha", encoding="utf-8")
    (tmp_path / "b.txt").write_text("beta", encoding="utf-8")
    observations = [
        FileVerificationObservation(path="a.txt", state="complete", bytes_written=5, expected_size=5),
        FileVerificationObservation(path="b.txt", state="complete", bytes_written=4, expected_size=4),
    ]

    quality = compute_output_quality(SimpleNamespace(output_dir=str(tmp_path)), observations)

    assert quality.file_count == 2
    assert quality.total_bytes == 9
    assert quality.empty is False
    assert quality.complete_ratio == pytest.approx(1.0)
    assert quality.failed_ratio == pytest.approx(0.0)
    assert quality.score == pytest.approx(1.0)
    assert quality.confidence >= 0.8


def test_output_quality_empty_output_dir_is_zero(tmp_path):
    quality = compute_output_quality(SimpleNamespace(output_dir=str(tmp_path)), [])

    assert quality.file_count == 0
    assert quality.total_bytes == 0
    assert quality.empty is True
    assert quality.score == 0.0
    assert quality.confidence == 0.0


def test_output_quality_uses_archive_coverage_when_observations_missing(tmp_path):
    (tmp_path / "recovered.bin").write_bytes(b"x" * 10)
    coverage = ArchiveCoverageSummary(
        completeness=0.75,
        expected_files=4,
        matched_files=3,
        complete_files=3,
        failed_files=1,
        confidence=0.95,
    )

    quality = compute_output_quality(
        SimpleNamespace(output_dir=str(tmp_path)),
        [],
        archive_coverage=coverage,
    )

    assert quality.score > 0.5
    assert quality.complete_ratio == pytest.approx(0.75)
    assert quality.failed_ratio == pytest.approx(0.25)
    assert quality.confidence == pytest.approx(0.95)


def test_output_quality_keeps_value_for_large_failed_output(tmp_path):
    (tmp_path / "song.mp3").write_bytes(b"x" * 4096)
    observations = [
        FileVerificationObservation(path="song.mp3", state="failed", bytes_written=4096, expected_size=4096)
    ]

    quality = compute_output_quality(SimpleNamespace(output_dir=str(tmp_path)), observations)

    assert quality.score > 0.6
    assert quality.failed_ratio == pytest.approx(1.0)
    assert quality.file_count == 1


def test_complete_unverified_content_with_high_output_quality_accepts():
    decision = _decision_hint(
        assessment_status=ASSESSMENT_COMPLETE,
        content_integrity=CONTENT_INTEGRITY_UNKNOWN,
        completeness=1.0,
        recoverable_upper_bound=1.0,
        decision_hints=[],
        complete_accept_threshold=0.999,
        partial_accept_threshold=0.2,
        output_quality_score=1.0,
        output_confidence=0.8,
    )

    assert decision == DECISION_ACCEPT


def test_complete_unverified_content_with_low_output_quality_still_accepts():
    decision = _decision_hint(
        assessment_status=ASSESSMENT_COMPLETE,
        content_integrity=CONTENT_INTEGRITY_UNKNOWN,
        completeness=1.0,
        recoverable_upper_bound=1.0,
        decision_hints=[],
        complete_accept_threshold=0.999,
        partial_accept_threshold=0.2,
        output_quality_score=0.0,
        output_confidence=0.0,
    )

    assert decision == DECISION_ACCEPT


def test_partial_unverified_content_with_output_quality_accepts_partial():
    decision = _decision_hint(
        assessment_status="partial",
        content_integrity=CONTENT_INTEGRITY_UNKNOWN,
        completeness=0.0,
        recoverable_upper_bound=1.0,
        decision_hints=[],
        complete_accept_threshold=0.999,
        partial_accept_threshold=0.2,
        output_quality_score=0.7,
        output_confidence=0.8,
    )

    assert decision == DECISION_ACCEPT_PARTIAL


def test_complete_unverified_content_with_partial_output_quality_accepts():
    decision = _decision_hint(
        assessment_status=ASSESSMENT_COMPLETE,
        content_integrity=CONTENT_INTEGRITY_UNKNOWN,
        completeness=1.0,
        recoverable_upper_bound=0.99,
        decision_hints=[],
        complete_accept_threshold=0.999,
        partial_accept_threshold=0.2,
        output_quality_score=0.82,
        output_confidence=0.35,
    )

    assert decision == DECISION_ACCEPT
