from collections import Counter
from pathlib import Path

import pytest

from tests.helpers.native_fixture import assemble_carrier
from tests.helpers.real_archives import ArchiveFixtureFactory, create_encrypted_rar_archive
from tests.helpers.tool_config import get_optional_rar
from tests.real.archive_boundary import extract_report
from tests.real.plan5_embedded_archives.plan5_support import (
    LARGE_SEGMENT_COUNT,
    PASSWORD,
    build_embedded_mixed_case,
    build_large_embedded_case,
)


def _scan(package, carrier, password=None):
    arguments = ["scan", "--deep-detect", "--no-builtin-pw", "--no-pause"]
    if password is not None:
        arguments.extend(("-p", password))
    report = package.json(*arguments, carrier)
    assert report["summary"]["failed_count"] == 0
    assert {Path(item["main_path"]) for item in report["items"]} == {carrier}
    return report["items"]


def _extent(item):
    return item["format"], item["offset"], item["end_offset"]


def _assert_markers(output, segments, *, encrypted=True):
    all_markers = {segment.marker_text for segment in segments}
    largest_marker = max(len(text.encode("utf-8")) + text.count("\n") for text in all_markers)
    found = Counter()
    for path in output.rglob("*"):
        if path.is_file() and path.stat().st_size <= largest_marker:
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            if text in all_markers:
                found[text] += 1
    expected = Counter(
        segment.marker_text for segment in segments if encrypted or not segment.encrypted
    )
    assert found == expected


@pytest.mark.parametrize("seed", [0x5A17C0DE, 1, 0xDEADBEEF])
def test_plan5_scans_all_logical_segments_of_one_mixed_carrier(package, tmp_path, seed):
    case = build_embedded_mixed_case(tmp_path, seed=seed)
    items = _scan(package, case.file_path, case.password)
    expected = {
        (segment.archive_format, segment.offset, segment.offset + segment.length)
        for segment in case.segments
    }
    assert {_extent(item) for item in items} == expected
    assert len(items) == len(expected)


@pytest.mark.parametrize("formats", [("zip", "zip"), ("7z", "7z"), ("zip", "7z")])
@pytest.mark.parametrize("boundary", [64 * 1024, 1024 * 1024])
def test_plan5_fixed_decoys_and_boundary_split_signatures(package, tmp_path, formats, boundary):
    factory = ArchiveFixtureFactory()
    cases = [
        factory.create(tmp_path / "sources", f"boundary-{index}", fmt, payload_size=256)
        for index, fmt in enumerate(formats)
    ]
    first_length = cases[0].entry_path.stat().st_size
    next_boundary = ((boundary - 3 + first_length + 192) // boundary + 1) * boundary
    prefixes = [boundary - 3, next_boundary - 3 - (boundary - 3 + first_length)]
    carrier = tmp_path / "fixed-decoys.mp4"
    layout = assemble_carrier(
        carrier, [case.entry_path for case in cases],
        prefix_lengths=prefixes, seed=0xDEC05, decoys=True,
    )
    items = _scan(package, carrier)
    expected = {
        (fmt, extent["offset"], extent["offset"] + extent["length"])
        for fmt, extent in zip(formats, layout["segments"], strict=True)
    }
    assert {_extent(item) for item in items} == expected
    assert len(items) == len(expected)


@pytest.mark.parametrize("correct_password", [True, False], ids=["correct-password", "wrong-passwords"])
def test_plan5_mixed_carrier_preserves_recoverable_segments(package, tmp_path, correct_password):
    case = build_embedded_mixed_case(tmp_path)
    passwords = [case.password] if correct_password else [f"wrong-{index:03d}-plan5" for index in range(20)]
    output = tmp_path / "out"
    report = extract_report(
        package, case.file_path, output, passwords=passwords, code=int(not correct_password),
    )
    summary = report["summary"]
    if correct_password:
        assert summary["success_count"] >= 1 and summary["failed_count"] == 0
    else:
        assert summary["success_count"] == summary["partial_success_count"] == 0
        assert summary["failed_count"] == 1
        assert any(item["kind"] == "wrong_password" for item in report["tasks"][0]["failures"])
    _assert_markers(output, case.segments, encrypted=correct_password)
    assert case.file_path.is_file()


def test_plan5_large_file_extracts_128_real_embedded_archives(package, tmp_path):
    case = build_large_embedded_case(tmp_path, count=LARGE_SEGMENT_COUNT)
    assert len(case.segments) == 128
    output = tmp_path / "out"
    report = extract_report(package, case.file_path, output, passwords=[case.password])
    assert report["summary"]["success_count"] >= 1
    assert report["summary"]["failed_count"] == 0
    _assert_markers(output, case.segments)


def test_plan5_rar4_encrypted_header_preserves_exact_carrier_range(package, tmp_path):
    if get_optional_rar() is None:
        pytest.skip("Rar.exe is required for the rar4-header fixture")
    case = create_encrypted_rar_archive(
        tmp_path / "sources", "p5_rar4-header", password=PASSWORD,
        rar4=True, header_encrypt=True, payload_size=8 * 1024,
    )
    carrier = tmp_path / "carrier.bin"
    prefix = b"PLAN5-CARRIER-PREFIX-"
    payload = case.entry_path.read_bytes()
    carrier.write_bytes(prefix + payload + b"-PLAN5-CARRIER-SUFFIX")
    assert list(map(_extent, _scan(package, carrier, PASSWORD))) == [
        ("rar", len(prefix), len(prefix) + len(payload)),
    ]
