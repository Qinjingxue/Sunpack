from pathlib import Path

import pytest

from tests.helpers.pipeline_engine import execute_pipeline
from sunpack.core.config.schema import normalize_config
from sunpack.core.contracts.failures import FailureKind
from tests.helpers.marker_utils import marker_was_extracted
from tests.helpers.real_archives import ArchiveFixtureFactory
from tests.helpers.detection_config import with_detection_pipeline
from tests.helpers.tool_config import get_optional_rar, require_7z


PASSWORD = "123"
FACTORY = ArchiveFixtureFactory()


def edge_config(passwords: list[str] | None = None, *, allow_partial: bool = False) -> dict:
    return normalize_config(with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
        "recursive_extract": "1",
        "extraction": {
            "content_requirement": "allow_partial" if allow_partial else "complete",
        },
        "post_extract": {
            "archive_cleanup_mode": "k",
            "flatten_single_directory": False,
        },
        "verification": {"enabled": True},
        "user_passwords": passwords or [],
        "builtin_passwords": [],
    }, processors=[
        {"name": "embedded_archive", "enabled": True},
        {"name": "pe_overlay_structure", "enabled": True},
        {"name": "executable_carrier", "enabled": True},
        {"name": "zip_eocd_structure", "enabled": True},
        {"name": "tar_header_structure", "enabled": True},
        {"name": "compression_stream_structure", "enabled": True},
        {"name": "seven_zip_structure", "enabled": True},
        {"name": "rar_structure", "enabled": True},
    ], precheck=[
        {"name": "size_range", "enabled": True, "gte": 0},
        {"name": "zip_structure_accept", "enabled": True},
        {"name": "tar_structure_accept", "enabled": True},
        {"name": "seven_zip_structure_accept", "enabled": True},
        {"name": "rar_structure_accept", "enabled": True},
        {"name": "compression_stream_accept", "enabled": True},
        {"name": "embedded_payload_identity", "enabled": True},
    ]))


def run_pipeline(target: Path, passwords: list[str] | None = None, *, allow_partial: bool = False):
    return execute_pipeline(
        edge_config(passwords=passwords, allow_partial=allow_partial),
        str(target),
    )


def sfx_format_params():
    formats = ["7z"]
    if get_optional_rar():
        formats.append("rar")
    return [
        pytest.param(
            archive_format,
            id=archive_format,
        )
        for archive_format in formats
    ]


@pytest.mark.parametrize("archive_format", sfx_format_params())
def test_real_archive_edge_corrupted_sfx_archives_fail(tmp_path, archive_format):
    require_7z()
    case = FACTORY.create(tmp_path, f"corrupted_sfx_{archive_format}", archive_format, sfx=True, corruption="truncate")

    summary = run_pipeline(case.archive_dir)

    assert summary.success_count == 0
    assert summary.failed_tasks
    assert any(failure.contains(FailureKind.DAMAGED) for failure in summary.failures)
    assert not marker_was_extracted(case.archive_dir, case.marker_name, case.marker_text)
