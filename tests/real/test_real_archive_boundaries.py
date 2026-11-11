import shutil
import unicodedata
import zipfile
from pathlib import Path

import pytest

from tests.helpers.real_archives import ArchiveFixtureFactory, corrupt_file
from tests.real.archive_boundary import extract_report


FACTORY = ArchiveFixtureFactory()


@pytest.mark.parametrize(
    ("case_id", "members", "expect_success"),
    [
        ("multilingual", {"日本語/说明/marker.txt": "multilingual"}, True),
        (
            "unicode-normalization",
            {f"{unicodedata.normalize('NFD', 'café')}/😀/marker.txt": "unicode-normalization"},
            True,
        ),
        ("long-path", {("deep-directory/" * 22) + "marker.txt": "long-path"}, True),
        ("case-collision", {"Case/marker.txt": "upper", "case/MARKER.txt": "lower"}, True),
        ("path-traversal", {"../escape.txt": "must-not-escape", "safe/marker.txt": "safe"}, False),
    ],
)
def test_real_windows_name_and_path_boundaries(package, tmp_path, case_id, members, expect_success):
    package.configure(post_extract={"flatten_single_directory": False})
    source = tmp_path / f"{case_id}.zip"
    with zipfile.ZipFile(source, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
        for name, payload in members.items():
            archive.writestr(name, payload.encode("utf-8"))
    output = tmp_path / "out"
    report = extract_report(
        package, source, output, recur="1", deep=False, direct=True, code=int(not expect_success),
    )
    assert not list(tmp_path.rglob("escape.txt"))
    assert report["summary"]["success_count"] == int(expect_success)
    if expect_success:
        target = output / case_id
        if case_id == "case-collision":
            assert (target / "Case" / "marker.txt").read_text(encoding="utf-8") in {"upper", "lower"}
        else:
            for name, expected in members.items():
                assert (target / Path(name)).read_text(encoding="utf-8") == expected
    else:
        assert report["summary"]["failed_count"] == 1


@pytest.mark.parametrize(
    ("case_id", "damage", "expected_success"),
    [
        ("zip-download-truncated", "truncate", False),
        ("zip-payload-bitrot", "byte_flip", False),
        ("zip-appended-download-junk", "trailing_junk", True),
        ("7z-missing-middle-volume", "missing_middle", False),
    ],
)
def test_real_damage_patterns(package, tmp_path, case_id, damage, expected_success):
    if damage == "missing_middle":
        case = FACTORY.create(tmp_path, case_id, "7z", split=True, payload_size=420 * 1024)
        parts = sorted(path for path in case.archive_dir.iterdir() if path.is_file())
        assert len(parts) >= 3
        parts[1].unlink()
    else:
        case = FACTORY.create(tmp_path, case_id, "zip", payload_size=260 * 1024)
        corrupt_file(case.entry_path, mode=damage)
    report = extract_report(
        package, case.entry_path, tmp_path / "out", recur="1", deep=False, direct=True,
        code=int(not expected_success),
    )
    assert report["summary"]["success_count"] == int(expected_success)
    if damage == "missing_middle":
        assert {failure["kind"] for failure in report["tasks"][0]["failures"]} == {"missing_volume"}


@pytest.mark.parametrize("tool_name", ["7z.exe", "sunpack_sevenzip_worker.exe"])
def test_real_executables_are_not_archive_candidates(package, tmp_path, tool_name):
    executable = tmp_path / tool_name
    shutil.copyfile(package.tools / tool_name, executable)
    report = package.json("scan", executable)
    assert report["summary"]["archive_count"] == 0
    assert not report["items"]
