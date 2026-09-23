from __future__ import annotations

import pytest

from tests.helpers.detection_probe import detect_archive_hits
from tests.helpers.real_archives import ArchiveFixtureFactory
from tests.helpers.tool_config import get_optional_rar
from tests.real.plan1_real_archives.plan1_support import assert_plan1_success, detected_ext
from tests.real.split_cases import SPLIT_NAMING_CASES, rename_split_parts


FACTORY = ArchiveFixtureFactory()
RAR_AVAILABLE = get_optional_rar() is not None


@pytest.mark.parametrize("naming", SPLIT_NAMING_CASES, ids=lambda item: item.case_id)
def test_plan1_split_archives_extract_and_detect_format(tmp_path, naming, plan1_error):
    if naming.archive_format == "rar" and not RAR_AVAILABLE:
        pytest.skip("RAR generator is not configured")
    plan1_error["case_id"] = naming.case_id
    plan1_error["archive_format"] = naming.archive_format
    plan1_error["naming_scheme"] = naming.case_id
    case = FACTORY.create(
        tmp_path,
        naming.case_id,
        naming.archive_format,
        split=True,
        payload_size=420 * 1024,
    )
    rename_split_parts(case, naming)
    part_count = len([path for path in case.archive_dir.iterdir() if path.is_file()])
    plan1_error["part_count"] = part_count

    assert_plan1_success(
        case,
        f".{naming.archive_format}",
        expected_member_count=part_count,
        error_info=plan1_error,
    )


@pytest.mark.parametrize("archive_format", ["7z", "zip", "rar"])
def test_plan1_split_archives_detected_as_one_logical_stream_with_chaotic_names(
    tmp_path, archive_format, plan1_error
):
    """分卷被当成一个逻辑流识别，且不依赖扩展名（旧测试迁移升级）。"""
    if archive_format == "rar" and not RAR_AVAILABLE:
        pytest.skip("RAR generator is not configured")
    case_id = f"split_{archive_format}_chaos"
    plan1_error["case_id"] = case_id
    plan1_error["archive_format"] = archive_format
    case = FACTORY.create(
        tmp_path,
        case_id,
        archive_format,
        split=True,
        disguise_ext=".unrelated",
    )

    hits = detect_archive_hits(case.entry_path)
    actual_ext = detected_ext(hits[0]) if hits else None
    member_count = len(hits[0].member_paths) if hits else 0
    plan1_error["detection_hit_count"] = len(hits)
    plan1_error["actual_detected_ext"] = actual_ext
    plan1_error["member_path_count"] = member_count

    assert len(hits) == 1
    assert actual_ext == f".{archive_format}"
    assert member_count > 1

