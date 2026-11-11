import pytest

from tests.helpers.real_archives import ArchiveFixtureFactory
from tests.real.archive_boundary import extract_report, failure_kinds, require_generator
from tests.real.plan4_missing_volumes.plan4_support import (
    MAY_LACK_RECOGNIZABLE_HEAD,
    SCENARIOS,
    apply_missing_volume_scenario,
)


@pytest.mark.parametrize("archive_format", ["zip", "rar", "7z"])
@pytest.mark.parametrize("scenario", SCENARIOS)
@pytest.mark.parametrize("sfx", [False, True], ids=["archive", "sfx"])
def test_encrypted_split_missing_volumes(package, tmp_path, archive_format, scenario, sfx):
    require_generator(archive_format, sfx=sfx)
    password = "incomplete-archive-password"
    case = ArchiveFixtureFactory().create(
        tmp_path, f"{archive_format}-{scenario}", archive_format,
        password=password, split=True, sfx=sfx, payload_size=620 * 1024,
    )
    apply_missing_volume_scenario(case, scenario)
    original_parts = {path.name for path in case.archive_dir.iterdir() if path.is_file()}
    output = tmp_path / "out"
    report = extract_report(
        package, case.archive_dir, output, passwords=[password], cleanup="d",
        code=(0, 1) if scenario in MAY_LACK_RECOGNIZABLE_HEAD else 1,
    )
    summary = report["summary"]
    assert summary["success_count"] == summary["partial_success_count"] == 0, report
    assert not any(path.is_file() for path in output.rglob("*"))
    assert {path.name for path in case.archive_dir.iterdir() if path.is_file()} == original_parts
    if scenario not in MAY_LACK_RECOGNIZABLE_HEAD or summary["failed_count"]:
        assert "missing_volume" in failure_kinds(report), report
