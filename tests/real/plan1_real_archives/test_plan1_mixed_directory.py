from __future__ import annotations

from pathlib import Path

import pytest

from sunpack.coordinator.task_provider import ArchiveTaskProvider
from tests.helpers.detection_probe import detect_archive_hits, detection_pipeline_config
from tests.helpers.marker_utils import marker_was_extracted
from tests.helpers.real_archives import ArchiveFixtureFactory
from tests.helpers.tool_config import get_optional_rar, get_test_tools
from tests.real.plan1_real_archives.plan1_support import (
    assert_expected_files_extracted,
    detected_ext,
    detected_ext_from_format,
    run_plan1_pipeline,
)


FACTORY = ArchiveFixtureFactory()
RAR_AVAILABLE = get_optional_rar() is not None
ZSTD_TOOL = get_test_tools().get("zstd_exe")


def _zstd_available() -> bool:
    return bool(ZSTD_TOOL and ZSTD_TOOL.is_file())


def test_plan1_mixed_same_name_plain_formats_in_one_directory(tmp_path, plan1_error):
    """同名不同格式（release.zip/.rar/.7z/.tar.gz）混合在一个目录，逐个识别并解压。"""
    common = tmp_path / "mixed_plain"
    common.mkdir()
    cases = {}
    expected_ext = {"zip": ".zip", "rar": ".rar", "7z": ".7z", "tar.gz": ".gz"}
    for archive_format in ("zip", "rar", "7z", "tar.gz"):
        if archive_format == "rar" and not RAR_AVAILABLE:
            pytest.skip("RAR generator is not configured")
        if archive_format == "tar.gz" and not _zstd_available():
            # tar.gz 走 tarfile，不依赖 zstd 工具，仅 rar/zstd 特殊格式需要工具。
            pass
        case = FACTORY.create(
            tmp_path,
            f"mixed_src_{archive_format.replace('.', '_')}",
            archive_format,
            payload_size=256,
            payload_profile="structured",
        )
        suffix = {"zip": ".zip", "rar": ".rar", "7z": ".7z", "tar.gz": ".tar.gz"}[archive_format]
        target = common / f"release{suffix}"
        case.entry_path.replace(target)
        cases[archive_format] = (target, case)

    # 每个文件单独检测，格式必须与真实格式一致。
    for archive_format, (target, case) in cases.items():
        hits = detect_archive_hits(target)
        plan1_error[f"detect_{archive_format}"] = {
            "expected": expected_ext[archive_format],
            "actual": detected_ext(hits[0]) if hits else None,
            "hit_count": len(hits),
        }
        assert len(hits) == 1, f"{target.name}: expected one hit, got {len(hits)}"
        assert detected_ext(hits[0]) == expected_ext[archive_format]

    # 目录扫描应得到 4 个逻辑归档。
    tasks = ArchiveTaskProvider(detection_pipeline_config()).scan_targets([str(common)])
    tasks_by_name = {Path(task.main_path).name: task for task in tasks}
    plan1_error["directory_scan_heads"] = sorted(tasks_by_name)
    assert len(tasks_by_name) == 4, f"expected 4 logical archives, got {sorted(tasks_by_name)}"
    for name, expected in (
        ("release.zip", ".zip"),
        ("release.rar", ".rar"),
        ("release.7z", ".7z"),
        ("release.tar.gz", ".gz"),
    ):
        assert name in tasks_by_name
        assert detected_ext_from_format(tasks_by_name[name].archive_input().format_hint) == expected

    # 目录整体解压，每个 marker 都要出现。
    summary = run_plan1_pipeline(common)
    plan1_error["pipeline_success_count"] = summary.success_count
    plan1_error["pipeline_partial_success_count"] = summary.partial_success_count
    plan1_error["pipeline_failed_tasks"] = [str(item) for item in summary.failed_tasks]
    assert summary.failed_tasks == [], f"pipeline reported failures: {summary.failed_tasks}"
    assert summary.partial_success_count == 0
    for _archive_format, (_target, case) in cases.items():
        assert_expected_files_extracted(case, common)
        assert marker_was_extracted(common, case.marker_name, case.marker_text), (
            f"marker {case.marker_name!r} not extracted"
        )


def test_plan1_mixed_compressed_formats_in_one_directory(tmp_path, plan1_error):
    """Directory scheduling must also keep compressed codecs separated by format."""
    common = tmp_path / "mixed_compressed"
    common.mkdir()
    cases = {}
    settings = {
        "7z": {"compression_method": "LZMA2", "compression_level": 5, "solid": True},
        "zip": {"compression_method": "Deflate", "compression_level": 5},
        "rar": {"compression_level": 5, "solid": True},
    }
    suffixes = {"7z": ".7z", "zip": ".zip", "rar": ".rar"}
    for archive_format, options in settings.items():
        if archive_format == "rar" and not RAR_AVAILABLE:
            pytest.skip("RAR generator is not configured")
        case = FACTORY.create(
            tmp_path,
            f"mixed_compressed_src_{archive_format}",
            archive_format,
            payload_size=512,
            payload_profile="structured",
            **options,
        )
        target = common / f"release{suffixes[archive_format]}"
        case.entry_path.replace(target)
        cases[archive_format] = case

    tasks = ArchiveTaskProvider(detection_pipeline_config()).scan_targets([str(common)])
    tasks_by_name = {Path(task.main_path).name: task for task in tasks}
    plan1_error["directory_scan_heads"] = sorted(tasks_by_name)
    assert len(tasks_by_name) == 3, f"expected 3 logical archives, got {sorted(tasks_by_name)}"
    for archive_format, expected in (("7z", ".7z"), ("zip", ".zip"), ("rar", ".rar")):
        name = f"release{suffixes[archive_format]}"
        assert detected_ext_from_format(tasks_by_name[name].archive_input().format_hint) == expected

    summary = run_plan1_pipeline(common)
    plan1_error["pipeline_success_count"] = summary.success_count
    plan1_error["pipeline_partial_success_count"] = summary.partial_success_count
    plan1_error["pipeline_failed_tasks"] = [str(item) for item in summary.failed_tasks]
    assert summary.failed_tasks == [], f"pipeline reported failures: {summary.failed_tasks}"
    assert summary.partial_success_count == 0
    for archive_format, case in cases.items():
        assert_expected_files_extracted(case, common)
        assert marker_was_extracted(common, case.marker_name, case.marker_text), (
            f"{archive_format}: marker {case.marker_name!r} not extracted"
        )


def test_plan1_mixed_same_stem_split_formats_in_one_directory(tmp_path, plan1_error):
    """同 stem 的 7z/zip/rar 分卷混合在一个目录，结构分辨后每个都要解出。"""
    common = tmp_path / "mixed_split"
    common.mkdir()
    schemes = {
        "7z": lambda _base, index, _count: f"bundle.7z.{index:03d}",
        "zip": lambda _base, index, _count: f"bundle.zip.{index:03d}",
        "rar": lambda _base, index, _count: f"bundle.part{index}.rar",
    }
    cases = {}
    for archive_format, scheme in schemes.items():
        if archive_format == "rar" and not RAR_AVAILABLE:
            pytest.skip("RAR generator is not configured")
        case = FACTORY.create(
            tmp_path,
            f"split_src_{archive_format}",
            archive_format,
            split=True,
            payload_size=96 * 1024,
            payload_profile="structured",
        )
        parts = sorted(path for path in case.archive_dir.iterdir() if path.is_file())
        for index, source in enumerate(parts, start=1):
            source.replace(common / scheme("bundle", index, len(parts)))
        cases[archive_format] = case

    tasks = ArchiveTaskProvider(detection_pipeline_config()).scan_targets([str(common)])
    tasks_by_name = {Path(task.main_path).name: task for task in tasks}
    plan1_error["directory_scan_heads"] = sorted(tasks_by_name)
    assert len(tasks_by_name) == 3, f"expected 3 logical archives, got {sorted(tasks_by_name)}"
    for name, expected in (
        ("bundle.7z.001", ".7z"),
        ("bundle.zip.001", ".zip"),
        ("bundle.part1.rar", ".rar"),
    ):
        assert name in tasks_by_name, f"missing head {name}"
        assert detected_ext_from_format(tasks_by_name[name].archive_input().format_hint) == expected

    summary = run_plan1_pipeline(common)
    plan1_error["pipeline_success_count"] = summary.success_count
    plan1_error["pipeline_partial_success_count"] = summary.partial_success_count
    plan1_error["pipeline_failed_tasks"] = [str(item) for item in summary.failed_tasks]
    assert summary.failed_tasks == [], f"pipeline reported failures: {summary.failed_tasks}"
    assert summary.partial_success_count == 0
    for archive_format, case in cases.items():
        assert_expected_files_extracted(case, common)
        assert marker_was_extracted(common, case.marker_name, case.marker_text), (
            f"{archive_format}: marker {case.marker_name!r} not extracted"
        )
