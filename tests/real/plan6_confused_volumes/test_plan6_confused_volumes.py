from pathlib import Path

import pytest

from tests.helpers.real_archives import ArchiveFixtureFactory
from tests.helpers.tool_config import get_optional_rar
from tests.real.archive_boundary import assert_extracted, extract_report
from tests.real.plan6_confused_volumes.plan6_support import SCENARIOS, apply_volume_confusion


FACTORY = ArchiveFixtureFactory()
RAR_AVAILABLE = get_optional_rar() is not None


def _assert_scan_group(package, case, parts, passwords):
    arguments = [argument for password in passwords for argument in ("-p", password)]
    report = package.json("scan", "--no-builtin-pw", "--no-pause", *arguments, case.entry_path)
    assert report["summary"]["archive_count"] == 1
    assert report["summary"]["failed_count"] == 0
    item, = report["items"]
    assert item["format"] == case.archive_format
    assert item["password_used"] == case.password
    if "volume_attempts" in item:
        found = {Path(part["path"]) for part in item["volume_attempts"]["sources"]}
    else:
        found = set(map(Path, item["all_parts"]))
    assert found == set(parts)


@pytest.mark.parametrize("archive_format", ["7z", "zip", "rar"])
@pytest.mark.parametrize("sfx", [False, True], ids=["split", "sfx-split"])
@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda item: item.case_id)
def test_plan6_encrypted_confused_volumes_extract(package, tmp_path, archive_format, sfx, scenario):
    if archive_format == "rar" and not RAR_AVAILABLE:
        pytest.skip("RAR generator is not configured")
    package.configure(filesystem={"scan_filters_enabled": False})
    password = f"correct-{archive_format}-{scenario.case_id}"
    case = FACTORY.create(
        tmp_path, f"conf_{archive_format}_{scenario.case_id}", archive_format,
        password=password, sfx=sfx, split=True, payload_size=420 * 1024,
    )
    parts = apply_volume_confusion(case, scenario)
    # For 7z and ZIP, the PE launcher is owned by the group but has no data.
    data_parts = parts[1:] if sfx and archive_format != "rar" else parts
    passwords = [f"wrong-{index:03d}" for index in range(99)]
    passwords.insert(63, password)
    _assert_scan_group(package, case, data_parts, passwords)

    output = tmp_path / "out"
    report = extract_report(package, case.entry_path, output, passwords=passwords, deep=False)
    assert report["summary"]["success_count"] == 1
    assert_extracted(case, output)
    assert all(part.is_file() for part in parts)


def test_plan6_confused_encrypted_groups_mixed_in_one_directory(package, tmp_path):
    if not RAR_AVAILABLE:
        pytest.skip("RAR generator is not configured")
    package.configure(filesystem={"scan_filters_enabled": False})
    common = tmp_path / "plan6_mixed"
    common.mkdir()
    groups = []
    for archive_format, stem in (("7z", "release"), ("rar", "album")):
        case = FACTORY.create(
            tmp_path, f"mixed_src_{archive_format}", archive_format,
            password=f"mixed-{archive_format}", split=True, payload_size=420 * 1024,
        )
        case.case_id = stem
        renamed = apply_volume_confusion(case, SCENARIOS[0], add_distractors=False)
        members = [path.replace(common / path.name) for path in renamed]
        case.archive_dir = common
        case.entry_path = members[0]
        groups.append((case, members))
        (common / f"{stem}.notes.txt").write_bytes(b"unrelated notes")
    (common / "unrelated_mixed.bin").write_bytes(b"\x00unrelated\xff" * 64)
    passwords = [case.password for case, _ in groups]
    for case, parts in groups:
        _assert_scan_group(package, case, parts, passwords)

    output = tmp_path / "out"
    report = extract_report(package, common, output, passwords=passwords, deep=False)
    assert report["summary"]["success_count"] == 2
    for case, _ in groups:
        assert_extracted(case, output)
