"""Assertions against the real launcher and independent fixture inventories."""

import json
from pathlib import Path

import pytest

from tests.helpers.native_fixture import file_inventory
from tests.helpers.real_archives import STREAM_FORMATS
from tests.helpers.tool_config import get_optional_rar, get_optional_rar_sfx, get_test_tools


def require_generator(archive_format, *, sfx=False, seven_zip_lz4=False):
    tools = get_test_tools()
    if archive_format == "rar" and not get_optional_rar():
        pytest.skip("RAR generator is not configured")
    if archive_format == "rar" and sfx and not get_optional_rar_sfx():
        pytest.skip("RAR SFX generator is not configured")
    if archive_format in {"7z", "zip"} and sfx:
        stub = tools["seven_zip_sfx"]
        if not stub or not stub.is_file():
            pytest.skip("7-Zip SFX stub is not configured")
    if archive_format in {"zstd", "tar.zst"}:
        tool = tools["zstd_exe"]
        if not tool or not tool.is_file():
            pytest.skip("Zstandard generator is not configured")
    if seven_zip_lz4:
        tool = tools["seven_zip_zstd"]
        if not tool or not tool.is_file():
            pytest.skip("7-Zip-Zstandard LZ4 generator is not configured")


def extract_report(package, inputs, output, *, passwords=(), cleanup="k", recursive=False,
                   recur="*", code=0, deep=True, direct=False):
    paths = [inputs] if isinstance(inputs, (Path, str)) else inputs
    flags = ["-R"] if recursive else []
    if deep:
        flags.append("-d")
    if direct:
        flags.append("--direct-file")
    password_args = [f"--password={password}" for password in passwords]
    result = package.run(
        "extract", "--json", "--no-pause", "--no-bpw", "--no-flatten",
        "-r", recur, "-c", cleanup, "-o", output, *flags, *password_args, *paths,
    )
    expected_codes = (code,) if isinstance(code, int) else code
    assert result.returncode in expected_codes, (result.stdout, result.stderr)
    return json.loads(result.stdout)


def failure_kinds(report):
    return {
        failure["kind"]
        for task in report["tasks"]
        for failure in task["failures"]
    }


def assert_extracted(case, output, *, exact=False):
    expected_files = case.metadata.get("expected_files")
    if not expected_files:
        marker = case.marker_text.encode("utf-8")
        assert any(marker in path.read_bytes() for path in output.rglob(case.marker_name)), case.case_id
        return
    actual = file_inventory(output)
    if exact:
        assert len(actual) == len(expected_files), (case.case_id, expected_files, actual)
    for name, expected in expected_files.items():
        name = name.replace("\\", "/")
        assert any(
            contents == expected and (
                case.archive_format in STREAM_FORMATS or path == name or path.endswith(f"/{name}")
            )
            for path, contents in actual.items()
        ), (case.case_id, name, expected, actual)


def scan_case(package, case, *, passwords=()):
    password_args = [f"--password={password}" for password in passwords]
    report = package.json("scan", "-d", "--no-bpw", *password_args, case.archive_dir)
    assert report["summary"]["archive_count"] == 1, report
    assert report["summary"]["failed_count"] == 0, report
    item, = report["items"]
    assert detected_archive_format(item["format"]) == detected_archive_format(case.archive_format), report
    return item


def detected_archive_format(format_name):
    format_name = format_name.removeprefix("tar.")
    return {"gz": "gzip", "bz2": "bzip2", "zst": "zstd"}.get(format_name, format_name)


def assert_scan_parts(case, item):
    if "volume_attempts" in item:
        parts = [source["path"] for source in item["volume_attempts"]["sources"]]
    else:
        parts = item["all_parts"]
    assert {Path(part).name for part in parts} == {
        path.name for path in case.archive_dir.iterdir() if path.is_file()
    }, item


def assert_archive_round_trip(package, case, output, *, passwords=()):
    item = scan_case(package, case, passwords=passwords)
    report = extract_report(package, case.archive_dir, output, passwords=passwords)
    assert report["summary"]["success_count"] >= 1, report
    assert report["summary"]["failed_count"] == 0, report
    assert_extracted(case, output, exact=True)
    return item
