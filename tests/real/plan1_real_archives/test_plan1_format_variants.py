from __future__ import annotations

import pytest

from tests.helpers.detection_probe import detect_archive_hits
from tests.helpers.real_archives import (
    create_7z_nonsolid_archive,
    create_multi_member_stream_archive,
    create_rar4_archive,
    create_stream_variant_archive,
    create_streaming_zip_archive,
    create_xz_sha256_archive,
    create_zip64_archive,
    create_zip_multidisk_archive,
)
from tests.helpers.tool_config import get_optional_rar, get_test_tools
from tests.real.plan1_real_archives.plan1_support import (
    EXPECTED_DETECTED_EXT,
    assert_plan1_success,
    detected_ext,
    marker_text_contained,
    run_plan1_pipeline,
)


RAR_AVAILABLE = get_optional_rar() is not None
ZSTD_TOOL = get_test_tools().get("zstd_exe")


def _zstd_available() -> bool:
    return bool(ZSTD_TOOL and ZSTD_TOOL.is_file())


def test_plan1_streaming_zip_uses_data_descriptors_and_extracts(tmp_path, plan1_error):
    case = create_streaming_zip_archive(tmp_path, "zip_streaming", payload_size=16 * 1024)
    plan1_error["case_id"] = case.case_id
    plan1_error["archive_format"] = "zip"
    flags = int.from_bytes(case.entry_path.read_bytes()[6:8], "little")
    plan1_error["local_header_flags"] = hex(flags)
    assert flags & 0x08, "fixture must use data descriptors (general purpose bit 3)"

    assert_plan1_success(case, ".zip", error_info=plan1_error)


def test_plan1_zip64_archive_structural_and_detection(tmp_path, plan1_error):
    """小 ZIP64 样本：ZIP64 EOCD + locator 结构 + 检测。"""
    case = create_zip64_archive(tmp_path, "zip64_small", payload_size=4096)
    plan1_error["case_id"] = case.case_id
    raw = case.entry_path.read_bytes()
    plan1_error["zip64_eocd_present"] = b"PK\x06\x06" in raw
    plan1_error["zip64_locator_present"] = b"PK\x06\x07" in raw
    assert b"PK\x06\x06" in raw, "fixture must contain a ZIP64 end-of-central-directory record"
    assert b"PK\x06\x07" in raw, "fixture must contain a ZIP64 end-of-central-directory locator"

    hits = detect_archive_hits(case.entry_path)
    plan1_error["detection_hit_count"] = len(hits)
    plan1_error["detected_ext"] = detected_ext(hits[0]) if hits else None
    assert len(hits) == 1
    assert detected_ext(hits[0]) == ".zip"


def test_plan1_zip64_archive_extracts_and_detects(tmp_path, plan1_error):
    """小 ZIP64 样本全量解压：7z 可正常解压，sunpack 检测 .zip 并解出 marker。"""
    case = create_zip64_archive(tmp_path, "zip64_extract", payload_size=4096)
    plan1_error["case_id"] = case.case_id
    assert_plan1_success(case, ".zip", error_info=plan1_error)


def test_plan1_real_pkzip_multidisk_archive_extracts_and_detects(tmp_path, plan1_error):
    """A real .z01 + .zip PKZIP disk pair, not a generic 7-Zip split stream."""
    case = create_zip_multidisk_archive(tmp_path, "zip_multidisk", payload_size=512)
    plan1_error["case_id"] = case.case_id
    plan1_error["archive_format"] = "zip"
    plan1_error["multidisk"] = True
    assert case.entry_path.name.endswith(".z01")
    assert (case.archive_dir / "zip_multidisk.zip").is_file()
    assert_plan1_success(
        case,
        ".zip",
        expected_member_count=2,
        error_info=plan1_error,
    )


def test_plan1_7z_nonsolid_archive_extracts_and_detects(tmp_path, plan1_error):
    case = create_7z_nonsolid_archive(tmp_path, "7z_nonsolid", payload_size=16 * 1024)
    plan1_error["case_id"] = case.case_id
    plan1_error["archive_format"] = "7z"
    assert_plan1_success(case, ".7z", error_info=plan1_error)


def test_plan1_rar4_legacy_archive_extracts_and_detects(tmp_path, plan1_error):
    if not RAR_AVAILABLE:
        pytest.skip("RAR generator is not configured")
    case = create_rar4_archive(tmp_path, "rar4_plain", payload_size=16 * 1024)
    plan1_error["case_id"] = case.case_id
    plan1_error["archive_format"] = "rar"
    plan1_error["rar4"] = True
    assert_plan1_success(case, ".rar", error_info=plan1_error)


def test_plan1_rar4_split_archive_extracts_and_detects(tmp_path, plan1_error):
    if not RAR_AVAILABLE:
        pytest.skip("RAR generator is not configured")
    case = create_rar4_archive(
        tmp_path,
        "rar4_split",
        split=True,
        payload_size=420 * 1024,
    )
    plan1_error["case_id"] = case.case_id
    plan1_error["archive_format"] = "rar"
    plan1_error["rar4"] = True
    plan1_error["split"] = True
    part_count = len([path for path in case.archive_dir.iterdir() if path.is_file()])
    plan1_error["part_count"] = part_count
    assert_plan1_success(
        case,
        ".rar",
        expected_member_count=part_count,
        error_info=plan1_error,
    )


@pytest.mark.parametrize(
    ("stream_format", "expected_ext"),
    [
        ("gzip", ".gz"),
        ("bzip2", ".bz2"),
        ("xz", ".xz"),
        ("zstd", ".zst"),
    ],
    ids=["gzip", "bzip2", "xz", "zstd"],
)
def test_plan1_multi_member_streams_extract_all_members(
    tmp_path, stream_format, expected_ext, plan1_error
):
    """多成员/多流：解压后所有成员的内容都必须出现（成员会被拼接输出）。"""
    if stream_format == "zstd" and not _zstd_available():
        pytest.skip("zstd.exe is not configured")
    case = create_multi_member_stream_archive(
        tmp_path,
        f"multi_{stream_format}",
        stream_format,
        payload_size=16 * 1024,
    )
    plan1_error["case_id"] = case.case_id
    plan1_error["archive_format"] = stream_format
    plan1_error["multi_member"] = True
    second_content = case.metadata.get("second_member_content", "")

    hits = detect_archive_hits(case.entry_path)
    plan1_error["detection_hit_count"] = len(hits)
    plan1_error["detected_ext"] = detected_ext(hits[0]) if hits else None
    assert len(hits) == 1
    assert detected_ext(hits[0]) == expected_ext

    summary = run_plan1_pipeline(case.archive_dir)
    plan1_error["pipeline_success_count"] = summary.success_count
    plan1_error["pipeline_failed_tasks"] = [str(item) for item in summary.failed_tasks]
    plan1_error["first_member_contained"] = marker_text_contained(
        case.archive_dir, case.marker_text
    )
    plan1_error["second_member_contained"] = marker_text_contained(
        case.archive_dir, second_content
    )
    assert summary.failed_tasks == [], f"pipeline reported failures: {summary.failed_tasks}"
    assert marker_text_contained(case.archive_dir, case.marker_text), (
        "first member content was not extracted"
    )
    assert marker_text_contained(case.archive_dir, second_content), (
        "second member content was not extracted"
    )


def test_plan1_xz_sha256_check_archive_extracts_and_detects(tmp_path, plan1_error):
    case = create_xz_sha256_archive(tmp_path, "xz_sha256", payload_size=16 * 1024)
    plan1_error["case_id"] = case.case_id
    plan1_error["archive_format"] = "xz"
    assert_plan1_success(case, ".xz", error_info=plan1_error)


@pytest.mark.parametrize(
    ("stream_format", "level", "gzip_filename", "xz_check", "zstd_checksum"),
    [
        pytest.param("gzip", 1, "", None, True, id="gzip-level1-no-name"),
        pytest.param("gzip", 9, "member.txt", None, True, id="gzip-level9-name"),
        pytest.param("bzip2", 1, None, None, True, id="bzip2-level1"),
        pytest.param("bzip2", 9, None, None, True, id="bzip2-level9"),
        pytest.param("xz", 1, None, "crc32", True, id="xz-crc32"),
        pytest.param("xz", 6, None, "crc64", True, id="xz-crc64"),
        pytest.param("xz", 9, None, "sha256", True, id="xz-sha256"),
        pytest.param("zstd", 1, None, None, False, id="zstd-level1-no-check"),
        pytest.param("zstd", 19, None, None, True, id="zstd-level19-check"),
    ],
)
def test_plan1_stream_codec_headers_levels_and_checks_extract(
    tmp_path,
    stream_format,
    level,
    gzip_filename,
    xz_check,
    zstd_checksum,
    plan1_error,
):
    if stream_format == "zstd" and not _zstd_available():
        pytest.skip("zstd.exe is not configured")
    case = create_stream_variant_archive(
        tmp_path,
        f"stream_variant_{stream_format}_{level}",
        stream_format,
        payload_size=256,
        compression_level=level,
        gzip_filename=gzip_filename,
        xz_check=xz_check,
        zstd_checksum=zstd_checksum,
    )
    plan1_error.update(
        {
            "case_id": case.case_id,
            "archive_format": stream_format,
            "compression_level": level,
            "gzip_filename": gzip_filename,
            "xz_check": xz_check,
            "zstd_checksum": zstd_checksum,
        }
    )
    assert_plan1_success(
        case,
        EXPECTED_DETECTED_EXT[stream_format],
        error_info=plan1_error,
    )
