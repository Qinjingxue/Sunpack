from types import SimpleNamespace

import pytest

import sunpack.core.support.archive_sessions as archive_sessions
import sunpack.core.support.output_paths as output_paths
from sunpack.pipeline.discovery.detection.input_planning import ArchiveInputPlanningStage
from sunpack.pipeline.discovery.filesystem.filters.modules.size_range import (
    parse_range_expression,
    parse_size_value,
)
from sunpack.pipeline.verification.pipeline import VerificationPipeline
from sunpack.runtime.cli.cli import preprocess_sys_argv


def test_verification_thresholds_preserve_explicit_zero():
    pipeline = VerificationPipeline({
        "complete_accept_threshold": 0,
        "partial_accept_threshold": 0,
        "methods": [],
    })

    assert pipeline.complete_accept_threshold == 0
    assert pipeline.partial_accept_threshold == 0


def test_input_planning_cache_size_zero_disables_cache():
    stage = ArchiveInputPlanningStage({
        "input_planning": {"enabled": False, "cache_size": 0},
    })

    stage._remember_report(("fixture",), SimpleNamespace())

    assert stage._report_cache == {}


def test_preprocess_sys_argv_preserves_literal_trailing_quote_and_backslash():
    argv = [
        "extract",
        "--password",
        'secret"',
        r"C:\\archive\\",
    ]

    assert preprocess_sys_argv(argv) == argv


@pytest.mark.parametrize("expression", ["r >= 1,5 MB", "r != 0", "r >= nope"])
def test_nonempty_invalid_range_expression_is_rejected(expression):
    with pytest.raises(ValueError, match="Invalid range expression"):
        parse_range_expression(expression, parse_size_value)


def test_valid_range_expression_still_accepts_zero_boundary():
    parsed = parse_range_expression("r >= 0 B", parse_size_value)

    assert parsed.gte == 0


def test_output_path_containment_uses_canonical_case(monkeypatch):
    monkeypatch.setattr(
        output_paths,
        "absolute_path_key",
        lambda value: str(value).replace("\\", "/").lower(),
    )

    assert output_paths._is_relative_to(
        "/ROOT/Output/Nested/archive.zip",
        "/root/output",
    ) is True


def test_archive_session_containment_uses_canonical_case(monkeypatch):
    monkeypatch.setattr(
        archive_sessions,
        "absolute_path_key",
        lambda value: str(value).replace("\\", "/").lower(),
    )

    assert archive_sessions._is_under(
        "/ROOT/Output/Nested/archive.zip",
        "/root/output",
    ) is True
    roots = archive_sessions._merge_release_roots([
        "/ROOT/Output",
        "/root/output",
    ])
    assert len(roots) == 1
