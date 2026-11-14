"""A recognizable split head must remain usable through grouping and retry."""

import json
from pathlib import Path
from shutil import copyfile
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from tests.helpers.native_fixture import assemble_carrier
from tests.helpers.real_archives import create_encrypted_rar_archive, create_zip_multidisk_archive, run_cmd
from tests.real.archive_boundary import assert_extracted, failure_kinds, require_generator
from tests.real.plan7_watch_downloads.plan7_support import FACTORY, download, stage_initial, watch_setup


PASSWORD = "split-head-key"
PASSWORDS = ["wrong-key", PASSWORD]
FORMATS = ["7z", "zip-numbered", "zip-pkzip", "rar4-part", "rar4-old", "rar5"]
WATCH = pytest.param("watch", marks=pytest.mark.requires_watch_broker)
PREFIX = 4096


@pytest.fixture(params=FORMATS)
def split_set(request, tmp_path, package):
    kind = request.param
    root = tmp_path / "generated"
    options = dict(payload_size=62 * 1024, split_volume_size=24 * 1024)
    if kind.startswith("rar"):
        require_generator("rar")
        case = create_encrypted_rar_archive(
            root, "series", password=PASSWORD, split=True, rar4=kind.startswith("rar4"),
            old_numbering=kind == "rar4-old", **options,
        )
        entry = case.entry_path
        parts = [entry, *sorted(path for path in case.archive_dir.iterdir() if path != entry)]
    elif kind == "zip-pkzip":
        case = create_zip_multidisk_archive(root, "series", password=PASSWORD, encryption="AES256", **options)
        parts = case.metadata["volume_paths"]
        entry = parts[-1]  # The external reader starts at the central directory.
    else:
        case = FACTORY.create(root, "series", kind.split("-")[0], password=PASSWORD, split=True, **options)
        parts = sorted(case.archive_dir.iterdir())
        entry = parts[0]
    assert len(parts) == 3 and parts[0] == case.entry_path
    run_cmd([str(package.tools / "7z.exe"), "t", f"-p{PASSWORD}", str(entry)], case.archive_dir)
    return case, parts


def _head_file(source, directory, archive_format, disguise):
    if disguise == "carrier-numbered":
        name = f"{source.name}.图片"
    elif disguise == "carrier-wrong-extension":
        name = "series.rar" if archive_format == "zip" else "series.zip"
    else:
        name = "series.图片"
    head = directory / name
    if disguise == "renamed":
        copyfile(source, head)
    else:
        assemble_carrier(head, [source], prefix_lengths=[PREFIX], seed=4096)
    return head


def _scan_head(package, case, head):
    result = package.run("scan", "-d", "--json", "--no-bpw", "--no-pause", "-p", PASSWORD, head)
    assert result.returncode in (0, 1), (result.stdout, result.stderr)
    items = json.loads(result.stdout)["items"]
    return {
        "head_reported": any(Path(item["main_path"]) == head and item["format"] == case.archive_format
                             for item in items),
        "scan": [(Path(item["main_path"]).name, item["format"], item.get("offset"), item.get("error_kind"))
                 for item in items],
    }


def _cli_extract(package, source, output):
    result = package.run(
        "extract", "-d", "-r", "*", "-F", "-c", "d", "-o", output, "--json", "--no-pause", "--no-bpw",
        "-p", PASSWORDS[0], "-p", PASSWORDS[1], source,
    )
    assert result.returncode in (0, 1), (result.stdout, result.stderr)
    return json.loads(result.stdout)


def _watch_result(package, watch):
    package.json("watch", "start", "--once", "--no-tray")
    display = watch.display()
    return [
        (Path(row.get("path", "")).name, row["event"], row.get("error_kind") or row.get("failure", {}).get("kind"))
        for row in display["history"] + display["live"]
        if row["event"] in {"archive_failure_evidence", "failed_password", "suspended_missing_volume", "done"}
    ]


@pytest.mark.parametrize("entry_mode", ["cli", WATCH])
@pytest.mark.parametrize("disguise", ["renamed", "carrier-numbered", "carrier-opaque", "carrier-wrong-extension"])
def test_disguised_split_head_resolves_unchanged_continuation_names(package, tmp_path, split_set, entry_mode, disguise):
    case, (original_head, *continuations) = split_set
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    head = _head_file(original_head, inputs, case.archive_format, disguise)
    for part in continuations:
        copyfile(part, inputs / part.name)

    output = tmp_path / "out"
    if entry_mode == "cli":
        report = _cli_extract(package, head, output)
        summary = report["summary"]
        assert (summary["success_count"], summary["failed_count"]) == (1, 0), (
            _scan_head(package, case, head), failure_kinds(report),
        )
    else:
        watch = watch_setup(package, tmp_path, passwords=PASSWORDS, cleanup="d", start=False)
        for part in sorted(inputs.iterdir()):
            stage_initial(watch, part)
        inputs = watch.root
        events = _watch_result(package, watch)
        assert list(output.rglob(case.marker_name)), (_scan_head(package, case, head), events)
        watch.assert_no_terminal_failures()
    assert_extracted(case, output, exact=True)
    assert not any(inputs.iterdir())


@pytest.mark.parametrize("entry_mode", ["cli", WATCH])
def test_opaque_carrier_head_recovers_when_tail_arrives(package, tmp_path, split_set, entry_mode):
    case, (original_head, middle, tail) = split_set
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    head = _head_file(original_head, inputs, case.archive_format, "carrier-opaque")
    copyfile(middle, inputs / middle.name)
    output = tmp_path / "out"
    if entry_mode == "cli":
        report = _cli_extract(package, head, output)
        assert report["summary"]["success_count"] == 0, report
        assert failure_kinds(report) == {"missing_volume"}, report
        assert not list(output.rglob(case.marker_name))
        assert head.is_file() and (inputs / middle.name).is_file()
        copyfile(tail, inputs / tail.name)
        report = _cli_extract(package, head, output)
        summary = report["summary"]
        assert (summary["success_count"], summary["failed_count"]) == (1, 0), (
            _scan_head(package, case, head), failure_kinds(report),
        )
    else:
        watch = watch_setup(package, tmp_path, passwords=PASSWORDS, cleanup="d", start=False)
        stage_initial(watch, head)
        stage_initial(watch, middle)
        inputs = watch.root
        head = inputs / head.name
        before = _watch_result(package, watch)
        assert any(kind == "missing_volume" for _, _, kind in before), before
        assert not list(output.rglob(case.marker_name))
        assert head.is_file() and (inputs / middle.name).is_file()
        download(watch, tail, mode="direct")
        events = _watch_result(package, watch)
        assert list(output.rglob(case.marker_name)), (_scan_head(package, case, head), events)
        watch.assert_no_terminal_failures()
    assert_extracted(case, output, exact=True)
    assert not any(inputs.iterdir())


@pytest.mark.parametrize("entry_mode", ["cli", WATCH])
def test_continuation_waits_for_disguised_entry(package, tmp_path, split_set, entry_mode):
    # A continuation is a catalog candidate, not a failed archive. The later
    # entry must still recall it, including after a Watch restart.
    case, (original_head, middle, tail) = split_set
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    copyfile(middle, inputs / middle.name)
    output = tmp_path / "out"
    if entry_mode == "cli":
        report = _cli_extract(package, inputs, output)
        assert (report["summary"]["success_count"], report["summary"]["failed_count"]) == (0, 0), report
        assert (inputs / middle.name).is_file()
        _head_file(original_head, inputs, case.archive_format, "carrier-opaque")
        copyfile(tail, inputs / tail.name)
        report = _cli_extract(package, inputs, output)
        assert (report["summary"]["success_count"], report["summary"]["failed_count"]) == (1, 0), report
    else:
        watch = watch_setup(package, tmp_path, passwords=PASSWORDS, cleanup="d", start=False)
        stage_initial(watch, inputs / middle.name)
        inputs = watch.root
        assert not _watch_result(package, watch)
        assert (inputs / middle.name).is_file()
        head = _head_file(original_head, tmp_path, case.archive_format, "carrier-opaque")
        stage_initial(watch, head)
        stage_initial(watch, tail)
        _watch_result(package, watch)
        watch.assert_no_terminal_failures()
    assert_extracted(case, output, exact=True)
    assert not any(inputs.iterdir())
