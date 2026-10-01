from __future__ import annotations

import pytest

from tests.helpers.native_fixture import assemble_carrier, file_inventory
from tests.helpers.real_archives import ArchiveFixtureFactory
from sunpack.core.analysis.embedded import scan_embedded_archives
from tests.real.plan5_embedded_archives import plan5_support
from tests.real.plan5_embedded_archives.plan5_support import (
    assert_plan5_native_scan_coverage,
    assert_plan5_single_task_scan,
    build_embedded_mixed_case,
    _segment_table,
)


@pytest.mark.parametrize("seed", [0x5A17C0DE, 1, 0xDEADBEEF])
def test_plan5_native_scan_covers_every_embedded_segment(tmp_path, plan5_error, seed, monkeypatch):
    """检测层：native 全流扫描必须命中每个构造段，且垃圾块两两不同。"""
    # A regression guard against using the implementation as a fixture oracle.
    def forbidden_scan(*args, **kwargs):
        pytest.fail("fixture generation must not query the archive scanner")

    with monkeypatch.context() as patch:
        patch.setattr(plan5_support, "scan_embedded_archives", forbidden_scan)
        case = build_embedded_mixed_case(tmp_path, seed=seed, error_info=plan5_error)
    plan5_error["case_id"] = case.case_id
    plan5_error["file_size"] = case.file_path.stat().st_size
    plan5_error["segment_count"] = len(case.segments)
    plan5_error["segments"] = _segment_table(case)
    plan5_error["skipped_formats"] = list(case.skipped_formats)

    assert_plan5_native_scan_coverage(case, error_info=plan5_error)

    digests = [digest for _length, digest in case.junk_blocks]
    plan5_error["junk_block_count"] = len(digests)
    plan5_error["distinct_junk_blocks"] = len(set(digests))
    assert len(set(digests)) == len(digests), (
        "junk blocks must be random and mutually distinct, but duplicates were generated"
    )


@pytest.mark.parametrize("formats", [("zip", "zip"), ("7z", "7z"), ("zip", "7z")])
@pytest.mark.parametrize("boundary", [64 * 1024, 1024 * 1024])
def test_plan5_fixed_decoys_and_boundary_split_signatures(tmp_path, plan5_error, formats, boundary):
    factory = ArchiveFixtureFactory()
    cases = [
        factory.create(tmp_path / "sources", f"boundary-{index}", fmt, payload_size=256)
        for index, fmt in enumerate(formats)
    ]
    first_length = cases[0].entry_path.stat().st_size
    # Both real signatures straddle a known block boundary. The second archive
    # has the same format in two cases; no alternating-format assumption holds.
    next_boundary = ((boundary - 3 + first_length + 192) // boundary + 1) * boundary
    prefixes = [boundary - 3, next_boundary - 3 - (boundary - 3 + first_length)]
    carrier = tmp_path / "fixed-decoys.mp4"
    layout = assemble_carrier(
        carrier, [case.entry_path for case in cases],
        prefix_lengths=prefixes, seed=0xDEC05, decoys=True,
    )
    twin = tmp_path / "identical-layout.mp4"
    repeated = assemble_carrier(
        twin, [case.entry_path for case in cases],
        prefix_lengths=prefixes, seed=0xDEC05, decoys=True,
    )
    assert layout == repeated
    inventory = file_inventory(tmp_path)
    assert inventory[carrier.name] == inventory[twin.name]
    result = scan_embedded_archives(str(carrier), expected_size=carrier.stat().st_size)
    found = {(item.format, item.offset) for item in result.candidates}
    expected = {(fmt, extent["offset"]) for fmt, extent in zip(formats, layout["segments"], strict=True)}
    plan5_error.update({"layout": layout, "expected": sorted(expected), "actual": sorted(found)})
    assert found == expected


def test_plan5_mixed_file_scans_as_single_archive_task(tmp_path, plan5_error):
    """扫描层：整个混合文件必须恰好成为一个待处理压缩包任务。"""
    case = build_embedded_mixed_case(tmp_path, error_info=plan5_error)
    plan5_error["case_id"] = case.case_id
    plan5_error["file_name"] = case.file_path.name
    plan5_error["segment_count"] = len(case.segments)
    plan5_error["segments"] = _segment_table(case)
    plan5_error["skipped_formats"] = list(case.skipped_formats)

    assert_plan5_single_task_scan(case, error_info=plan5_error)
