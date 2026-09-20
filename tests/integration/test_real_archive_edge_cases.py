import json
import shutil
from pathlib import Path

import pytest

from tests.helpers.pipeline_engine import execute_pipeline
from sunpack.config.schema import normalize_config
from tests.helpers.marker_utils import marker_was_extracted
from tests.helpers.real_archives import ArchiveCase, ArchiveFixtureFactory
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


def _workspace_with_entry(case: ArchiveCase, root: Path) -> Path:
    """Copy the case entry into a directory that holds nothing else.

    A second pipeline run over the same directory would also scan the output the
    first run produced there, and would report that output as an archive that is
    already extracted instead of re-attempting the archive under test.
    """
    root.mkdir(parents=True, exist_ok=True)
    for source in sorted(case.archive_dir.iterdir(), key=lambda item: item.name.lower()):
        if source.is_file():
            shutil.copy2(source, root / source.name)
    return root


def run_pipeline_in_fresh_workspace(
    case: ArchiveCase,
    run_root: Path,
    output_root: Path,
    passwords: list[str] | None = None,
    *,
    allow_partial: bool = False,
):
    config = edge_config(passwords=passwords, allow_partial=allow_partial)
    # Extract below a dedicated output root so the run under test neither scans
    # nor overwrites the fixture directory.
    config["output"] = {"root": str(output_root), "common_root": str(run_root)}
    return execute_pipeline(config, str(_workspace_with_entry(case, run_root)))


def _failure_contains(summary, expected_options: set[str]) -> bool:
    return any(
        any(expected in item for expected in expected_options)
        for item in summary.failed_tasks
    )


def assert_success(case: ArchiveCase, passwords: list[str] | None = None):
    summary = run_pipeline(case.archive_dir, passwords=passwords)

    assert summary.success_count == 1
    assert summary.failed_tasks == []
    assert marker_was_extracted(case.archive_dir, case.marker_name, case.marker_text)


def assert_failure_contains(
    case: ArchiveCase,
    expected_options: set[str],
    passwords: list[str] | None = None,
    *,
    allow_best_effort_outputs: bool = False,
):
    summary = run_pipeline(case.archive_dir, passwords=passwords)

    assert summary.success_count == 0
    assert summary.failed_tasks
    assert _failure_contains(summary, expected_options)
    if allow_best_effort_outputs:
        manifests = list(case.archive_dir.rglob("extraction_manifest.json"))
        assert manifests
        assert any(json.loads(path.read_text(encoding="utf-8")).get("partial_outputs") for path in manifests)
    else:
        assert not marker_was_extracted(case.archive_dir, case.marker_name, case.marker_text)


def assert_wrong_password_then_success(
    case: ArchiveCase,
    run_root: Path,
    output_root: Path,
) -> None:
    """Attempt without the password, then with it, in isolated workspaces."""
    without_password = run_pipeline_in_fresh_workspace(
        case, run_root / "without-password", output_root / "without-password"
    )

    assert without_password.success_count == 0
    assert without_password.failed_tasks
    assert any(failure.is_password_failure for failure in without_password.failures)
    assert not marker_was_extracted(output_root / "without-password", case.marker_name, case.marker_text)

    with_password = run_pipeline_in_fresh_workspace(
        case,
        run_root / "with-password",
        output_root / "with-password",
        passwords=[PASSWORD],
    )

    assert with_password.success_count == 1
    assert with_password.failed_tasks == []
    assert marker_was_extracted(output_root / "with-password", case.marker_name, case.marker_text)


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


def carrier_params():
    carriers = ["jpg", "png", "pdf", "gif", "webp"]
    return [
        pytest.param(
            carrier,
            id=carrier,
        )
        for carrier in carriers
    ]


def carrier_archive_case_params():
    cases = [("pdf", "zip"), ("webp", "7z")]
    if get_optional_rar():
        cases.extend([("jpg", "rar"), ("png", "rar"), ("gif", "rar")])
    return [
        pytest.param(
            carrier,
            archive_format,
            id=f"{carrier}-{archive_format}",
        )
        for carrier, archive_format in cases
    ]


@pytest.mark.parametrize("archive_format", sfx_format_params())
def test_real_archive_edge_corrupted_sfx_archives_fail(tmp_path, archive_format):
    require_7z()
    case = FACTORY.create(tmp_path, f"corrupted_sfx_{archive_format}", archive_format, sfx=True, corruption="truncate")

    assert_failure_contains(case, {"压缩包损坏", "致命错误"})


@pytest.mark.parametrize("carrier", carrier_params())
def test_real_archive_edge_prefixed_carrier_archives_extract(tmp_path, carrier):
    require_7z()
    case = FACTORY.create(tmp_path, f"prefixed_{carrier}_7z", "7z", carrier=carrier)

    assert_success(case)


@pytest.mark.parametrize(("carrier", "archive_format"), carrier_archive_case_params())
def test_real_archive_edge_prefixed_password_carrier_archives_require_matching_password(tmp_path, carrier, archive_format):
    require_7z()
    case = FACTORY.create(tmp_path, f"pwd_prefixed_{carrier}_{archive_format}", archive_format, password=PASSWORD, carrier=carrier)

    assert_wrong_password_then_success(
        case,
        tmp_path / "runs",
        tmp_path / "runs-out",
    )


