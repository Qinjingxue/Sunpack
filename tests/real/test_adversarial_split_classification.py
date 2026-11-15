"""Keep password and volume failures local to each same-named split set."""

from pathlib import Path
from shutil import copyfile

import pytest

from tests.helpers.native_fixture import file_inventory
from tests.helpers.real_archives import run_cmd
from tests.real.archive_boundary import extract_report, require_generator
from tests.real.plan7_watch_downloads.plan7_support import FACTORY, watch_setup


WATCH = pytest.param("watch", marks=pytest.mark.requires_watch_broker)
PASSWORDS = ("incorrect-candidate", "available-volume-password")
COMPLETE_PASSWORD = "unavailable-volume-password"
WATCH_FAILURES = {
    "failed_password": "wrong_password",
    "suspended_missing_volume": "missing_volume",
    "failed_terminal": "failed_terminal",
}


def _stage_same_named_sets(package, fixtures, inputs, archive_format):
    sfx = archive_format == "rar"
    require_generator(archive_format, sfx=sfx)
    part_names = []
    middle_sizes = []
    for group, password in (("complete", COMPLETE_PASSWORD), ("incomplete", PASSWORDS[-1])):
        case = FACTORY.create(
            fixtures, group, archive_format, password=password, split=True, sfx=sfx,
            payload_size=170 * 1024, split_volume_size=64 * 1024,
        )
        run_cmd([str(package.tools / "7z.exe"), "t", f"-p{password}", str(case.entry_path)], case.archive_dir)
        parts = sorted(case.archive_dir.iterdir())
        assert len(parts) >= 3 and parts[0] == case.entry_path
        middle_sizes.append(parts[1].stat().st_size)
        group_dir = inputs / group
        group_dir.mkdir(parents=True)
        names = [f"资料{part.name.removeprefix(group)}.图片" for part in parts]
        part_names.append(names)
        for index, (part, name) in enumerate(zip(parts, names)):
            if group == "complete" or index != 1:
                copyfile(part, group_dir / name)
    assert part_names[0] == part_names[1]
    assert middle_sizes[0] == middle_sizes[1]
    return part_names[0][1]


def _cli_failures(package, inputs, output):
    report = extract_report(package, inputs, output, passwords=PASSWORDS, cleanup="d", recursive=True, code=(0, 1))
    assert report["summary"]["success_count"] == report["summary"]["partial_success_count"] == 0, report
    failures = []
    for task in report["tasks"]:
        for failure in task["failures"]:
            details = failure["details"]
            path = details.get("path")
            if path is None:
                recovery, = details["input_recovery"]["inputs"]
                path = recovery["archive_input"]["entry_path"]
            failures.append((Path(path), failure["kind"]))
    return failures


def _watch_failures(package, watch):
    with package.watch_session():
        package.await_watch_admission()
    display = watch.display()
    failures = []
    for row in (*display["live"], *display["history"]):
        event = row["event"]
        if event == "archive_failure_evidence":
            failures.append((Path(row["path"]), row["failure"]["kind"]))
        elif event in WATCH_FAILURES:
            kind = row.get("failure", {}).get("kind") or WATCH_FAILURES[event]
            failures.append((Path(row["path"]), kind))
    return failures


@pytest.mark.parametrize("origin", ["cli", WATCH])
@pytest.mark.parametrize("archive_format", ["7z", pytest.param("rar", id="rar5-sfx")])
def test_same_named_encrypted_split_sets_keep_distinct_blockers(package, tmp_path, origin, archive_format):
    # Both directories expose identical disguised names. The complete set needs
    # a new password, while the other already has its password and lacks a disk.
    package.configure(filesystem={"scan_filters_enabled": False})
    inputs = tmp_path / "watch"
    output = tmp_path / "out"
    _stage_same_named_sets(package, tmp_path / "fixtures", inputs, archive_format)
    original_inputs = file_inventory(inputs)

    if origin == "cli":
        failures = _cli_failures(package, inputs, output)
    else:
        watch = watch_setup(package, tmp_path, passwords=PASSWORDS, cleanup="d", recursive=True, start=False)
        failures = _watch_failures(package, watch)

    assert all(path.parent in {inputs / "complete", inputs / "incomplete"} for path, _ in failures), failures
    assert {kind for path, kind in failures if path.parent.name == "complete"} == {"wrong_password"}, failures
    assert {kind for path, kind in failures if path.parent.name == "incomplete"} <= {"missing_volume"}, failures
    assert not any(path.is_file() for path in output.rglob("*"))
    assert file_inventory(inputs) == original_inputs


@pytest.mark.parametrize("origin", ["cli", WATCH])
def test_foreign_rar_continuation_does_not_create_password_failure(package, tmp_path, origin):
    # A byte-distinct RAR5 disk has exactly the missing disk's name, length,
    # and volume number. Its header uses the foreign set's password, but that
    # set's SFX head is outside the input root and is never submitted.
    package.configure(filesystem={"scan_filters_enabled": False})
    staged = tmp_path / "staged-sets"
    disk_name = _stage_same_named_sets(package, tmp_path / "fixtures", staged, "rar")
    inputs = (staged / "incomplete").rename(tmp_path / "watch")
    copyfile(staged / "complete" / disk_name, inputs / disk_name)
    original_inputs = file_inventory(inputs)
    output = tmp_path / "out"

    if origin == "cli":
        failures = _cli_failures(package, inputs, output)
    else:
        watch = watch_setup(package, tmp_path, passwords=PASSWORDS, cleanup="d", start=False)
        failures = _watch_failures(package, watch)

    assert not any(path.is_file() for path in output.rglob("*"))
    assert file_inventory(inputs) == original_inputs
    assert {kind for _, kind in failures} <= {"missing_volume"}, failures
