import io
import json
import zipfile
from pathlib import Path

import pytest

from tests.helpers.real_archives import ArchiveFixtureFactory, create_zip_multidisk_archive
from tests.helpers.tool_config import get_optional_rar
from tests.real.archive_boundary import assert_extracted, extract_report, failure_kinds
from tests.real.plan4_missing_volumes.plan4_support import (
    MAY_LACK_RECOGNIZABLE_HEAD,
    SCENARIOS,
    apply_missing_volume_scenario,
)
from tests.real.plan7_watch_downloads.plan7_support import Watch, write_passwords


WRONG = ["wrong-one", "wrong-two"]
BLOCKERS = {
    "failed_password": "wrong_password",
    "suspended_missing_volume": "missing_volume",
}


def _watch_once(package, watch):
    result = package.run("watch", "start", "--once", "--no-tray", "--json")
    assert result.returncode in (0, 1), (result.stdout, result.stderr)
    assert json.loads(result.stdout)["summary"]["exit_code"] == result.returncode
    display = watch.display()
    rows = [*display["history"], *display["live"]]
    return result.returncode, [
        row for row in rows
        if row["event"] in {*BLOCKERS, "failed_terminal"}
        and Path(row.get("path", "")).parent == watch.root
    ]


@pytest.mark.parametrize("origin", ["foreground", pytest.param("watch", marks=pytest.mark.requires_watch_broker)])
@pytest.mark.parametrize("encryption", ["ZipCrypto", "AES256"])
def test_real_pkzip_disks_classify_wrong_password_and_missing_volumes(
    package, tmp_path, origin, encryption,
):
    password = "correct-spanned-password"
    case = create_zip_multidisk_archive(
        tmp_path / "source", "spanned", password=password, encryption=encryption,
        payload_size=170000, split_volume_size=65536,
    )
    if encryption == "AES256":
        paths = [
            path.rename(path.with_name(path.name + ".图片"))
            for path in case.metadata["volume_paths"]
        ]
        case.metadata["volume_paths"] = paths
        case.entry_path = paths[0]
    originals = {path: path.read_bytes() for path in case.metadata["volume_paths"]}
    package.configure(filesystem={"scan_filters_enabled": False}, recursive_extract=1)

    def run(phase, passwords, expected):
        root = tmp_path / phase
        root.mkdir()
        for path in originals:
            if path.exists():
                (root / path.name).write_bytes(originals[path])
        output = root.with_name(phase + "-out")
        if origin == "foreground":
            if phase == "missing_middle-correct":
                scan = package.json("scan", "-d", "--no-bpw", "-p", password, root, code=1)
                item, = scan["items"]
                assert item["error_kind"] == "missing_volume"
                assert {Path(part).name for part in item["all_parts"]} == {
                    path.name for path in root.iterdir()
                }
            report = extract_report(package, root, output, passwords=passwords, code=(0, 1))
            summary = report["summary"]
            assert summary["success_count"] == int(not expected), report
            assert summary["partial_success_count"] == 0
            failures = failure_kinds(report)
            if failures:
                assert summary["failed_count"] == 1, report
        else:
            watch = Watch(package, root, output)
            write_passwords(package, root, passwords)
            package.json("watch", "add", "-d", root, "-o", output)
            try:
                _, events = _watch_once(package, watch)
                failures = {BLOCKERS.get(row["event"], "failed_terminal") for row in events}
            finally:
                package.json("watch", "remove", root)
        if expected:
            if "unrecognized" in expected and not failures:
                assert not list(output.rglob(case.marker_name))
                return
            assert len(failures) == 1 and failures <= expected, (phase, failures)
            assert not list(output.rglob(case.marker_name))
        else:
            assert not failures
            assert_extracted(case, output)

    run("complete-correct", ["wrong", password], set())
    run("complete-wrong", WRONG, {"wrong_password"})
    for scenario in SCENARIOS:
        apply_missing_volume_scenario(case, scenario)
        try:
            expected = {"missing_volume"}
            if scenario in MAY_LACK_RECOGNIZABLE_HEAD:
                expected.add("unrecognized")
            run(f"{scenario}-correct", ["wrong", password], expected)
            run(f"{scenario}-wrong", WRONG, {*expected, "wrong_password"})
        finally:
            for path, data in originals.items():
                if not path.exists():
                    path.write_bytes(data)


def _mixed_nested_carrier(tmp_path):
    fixtures = tmp_path / "fixtures"
    healthy = ArchiveFixtureFactory().create(
        fixtures, "healthy", "zip", password="known", split=True,
        payload_size=170000, split_volume_size=65536,
    )
    wrong = create_zip_multidisk_archive(
        fixtures, "wrong", password="unknown", encryption="AES256",
        payload_size=170000, split_volume_size=65536,
    )
    missing = create_zip_multidisk_archive(
        fixtures, "missing", password="known", payload_size=170000, split_volume_size=65536,
    )
    cases = (healthy, wrong, missing)
    apply_missing_volume_scenario(missing, "missing_middle")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        for case in cases:
            for path in case.archive_dir.iterdir():
                archive.writestr(path.name + ".图片", path.read_bytes())
    watch_root = tmp_path / "inputs"
    watch_root.mkdir()
    outer = watch_root / "nested-carrier.opaque"
    outer.write_bytes(b"opaque-prefix" + buffer.getvalue() + b"opaque-tail")
    return outer, cases


def _assert_mixed_outputs(cases, output):
    healthy, *blocked = cases
    assert_extracted(healthy, output)
    assert all(not list(output.rglob(case.marker_name)) for case in blocked)


def test_cli_nested_disguised_split_groups_keep_failure_classifications(package, tmp_path):
    outer, cases = _mixed_nested_carrier(tmp_path)
    output = tmp_path / "out"
    package.configure(filesystem={"scan_filters_enabled": False})
    report = extract_report(package, outer, output, passwords=["wrong-candidate", "known"], code=1)
    summary = report["summary"]
    assert summary["success_count"] == summary["failed_count"] == 2
    assert summary["partial_success_count"] == 0
    assert failure_kinds(report) == {"wrong_password", "missing_volume"}
    _assert_mixed_outputs(cases, output)


@pytest.mark.requires_watch_broker
def test_watch_nested_split_groups_persist_distinct_blockers(package, tmp_path):
    outer, cases = _mixed_nested_carrier(tmp_path)
    output = tmp_path / "out"
    watch = Watch(package, outer.parent, output)
    package.configure(filesystem={"scan_filters_enabled": False}, recursive_extract="*")
    write_passwords(package, watch.root, ["wrong-candidate", "known"])
    package.json("watch", "add", "-d", watch.root, "-o", output)
    code, events = _watch_once(package, watch)
    # Like main, --once reports service execution, while archive blockers are
    # recorded in Watch state rather than propagated as its process exit code.
    assert code == 0
    assert {
        Path(row["path"]).name: row["event"] for row in events
    } == {
        "wrong.z01.图片": "failed_password",
        "missing.z01.图片": "suspended_missing_volume",
    }
    assert all(Path(row["path"]).is_file() for row in events)
    _assert_mixed_outputs(cases, output)


@pytest.mark.requires_watch_broker
@pytest.mark.parametrize(("archive_kind", "missing_position"), [
    ("pkzip-ZipCrypto", "middle"), ("pkzip-AES256", "middle"),
    ("zip", "middle"), ("7z", "middle"), ("rar", "middle"), ("rar", "tail"),
])
def test_watch_dual_faults_resume_after_each_blocker_is_resolved(
    package, tmp_path, archive_kind, missing_position,
):
    if archive_kind == "rar" and get_optional_rar() is None:
        pytest.skip("RAR generator is not configured")
    password = "correct-retry-password"
    if archive_kind.startswith("pkzip-"):
        case = create_zip_multidisk_archive(
            tmp_path / "inputs", "retry", password=password,
            encryption=archive_kind.removeprefix("pkzip-"),
            payload_size=170000, split_volume_size=65536,
        )
        parts = case.metadata["volume_paths"]
    else:
        case = ArchiveFixtureFactory().create(
            tmp_path / "inputs", "retry", archive_kind, password=password,
            split=True, payload_size=170000, split_volume_size=65536,
        )
        parts = sorted(case.archive_dir.iterdir())
    disguised = [path.rename(path.with_name(path.name + ".图片")) for path in parts]
    missing = disguised[-1] if missing_position == "tail" else disguised[len(disguised) // 2]
    missing_data = missing.read_bytes()
    missing.unlink()
    watch = Watch(package, case.archive_dir, tmp_path / "out")
    package.configure(filesystem={"scan_filters_enabled": False}, recursive_extract=1)
    write_passwords(package, watch.root, WRONG)
    package.json("watch", "add", "-d", watch.root, "-o", watch.output)

    remaining = set(BLOCKERS)
    for _ in range(2):
        code, events = _watch_once(package, watch)
        assert code == 0 and events
        blocker = events[-1]["event"]
        assert blocker in remaining, events
        remaining.remove(blocker)
        assert not list(watch.output.rglob(case.marker_name))
        if blocker == "suspended_missing_volume":
            missing.write_bytes(missing_data)
        else:
            write_passwords(package, watch.root, [password])

    code, _ = _watch_once(package, watch)
    assert code == 0
    assert_extracted(case, watch.output)
    assert all(path.is_file() for path in disguised)
