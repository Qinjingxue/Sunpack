from types import SimpleNamespace

import pytest

import sunpack.core.support.archive_sessions as archive_sessions
import sunpack.core.support.output_paths as output_paths
from sunpack.pipeline.discovery.detection.input_planning import ArchiveInputPlanningStage

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


def test_output_path_containment_uses_canonical_case(monkeypatch):
    monkeypatch.setattr(
        output_paths,
        "absolute_path_key",
        # Mirror the real key's Windows normcase form (backslashes, lower
        # case); os.path.commonpath always returns backslash separators.
        lambda value: str(value).replace("/", "\\").lower(),
    )

    assert output_paths._is_relative_to(
        "/ROOT/Output/Nested/archive.zip",
        "/root/output",
    ) is True


def test_archive_release_roots_preserve_case_and_component_boundaries():
    roots = archive_sessions._merge_release_roots([
        "/ROOT/Output",
        "/root/output",
    ])
    assert len(roots) == 1
    roots = archive_sessions._merge_release_roots([
        r"C:\Input\Output\nested\part.001",
        r"C:\Input\Output-other\keep.001",
        r"C:\INPUT\OUTPUT",
        r"C:\Input\Output-else",
        "C:\\Input\\Output\\",
        r"\\server\share\nested\part.001",
        "\\\\SERVER\\SHARE\\",
        r"D:\nested\part.001",
        "D:\\",
    ])
    assert {path.lower().rstrip("\\") for path in roots} == {
        r"c:\input\output", r"c:\input\output-other\keep.001",
        r"c:\input\output-else", r"\\server\share", "d:",
    }
