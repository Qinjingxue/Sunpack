from __future__ import annotations

import pytest

from tests.helpers.detection_probe import detect_archive_hits
from tests.helpers.marker_utils import marker_was_extracted
from tests.helpers.real_archives import ArchiveFixtureFactory
from tests.helpers.tool_config import get_optional_rar
from tests.real.plan1_real_archives.plan1_support import detected_ext, run_plan1_pipeline
from tests.real.plan6_confused_volumes.plan6_support import (
    SCENARIOS,
    apply_volume_confusion,
)


FACTORY = ArchiveFixtureFactory()
RAR_AVAILABLE = get_optional_rar() is not None


def test_plan6_confused_encrypted_groups_mixed_in_one_directory(tmp_path, plan6_error):
    """多个加密分卷组（不同 stem）各带部分混乱卷名，混合在同一个目录里分别解出。"""
    if not RAR_AVAILABLE:
        pytest.skip("RAR generator is not configured")
    common = tmp_path / "plan6_mixed"
    common.mkdir()
    scenario = SCENARIOS[0]
    groups = {}
    passwords = []
    for archive_format, stem in (("7z", "release"), ("rar", "album")):
        password = f"mixed-{archive_format}"
        case_id = f"mixed_src_{archive_format}"
        case = FACTORY.create(
            tmp_path,
            case_id,
            archive_format,
            password=password,
            split=True,
            payload_size=420 * 1024,
        )
        # 先在各自的生成目录里统一 stem 并做部分混淆，避免干扰文件互相污染。
        case.case_id = stem
        renamed = apply_volume_confusion(case, scenario, add_distractors=False)
        for path in renamed:
            path.replace(common / path.name)
        case.archive_dir = common
        case.entry_path = common / renamed[0].name
        groups[archive_format] = case
        passwords.append(password)

    (common / "release.notes.txt").write_text("unrelated notes\n", encoding="utf-8")
    (common / "album.notes.txt").write_text("unrelated notes\n", encoding="utf-8")
    (common / "unrelated_mixed.bin").write_bytes(b"\x00unrelated\xff" * 64)

    expected_count = {
        archive_format: len(
            [
                path
                for path in common.iterdir()
                if path.is_file()
                and path.name.startswith(stem)
                and "notes" not in path.name
            ]
        )
        for archive_format, stem in (("7z", "release"), ("rar", "album"))
    }
    plan6_error["case_id"] = "plan6_mixed"
    plan6_error["groups"] = {
        archive_format: {
            "stem": case.case_id,
            "volume_count": expected_count[archive_format],
            "head": case.entry_path.name,
        }
        for archive_format, case in groups.items()
    }

    # 每个组的头卷单独检测：格式正确、成员数与卷数一致。
    for archive_format, case in groups.items():
        hits = detect_archive_hits(case.entry_path)
        plan6_error[f"detect_{archive_format}"] = {
            "expected_ext": f".{archive_format}",
            "actual_ext": detected_ext(hits[0]) if hits else None,
            "hit_count": len(hits),
            "member_count": len(hits[0].all_parts) if hits else 0,
        }
        assert len(hits) == 1, f"{archive_format}: expected one hit, got {len(hits)}"
        assert detected_ext(hits[0]) == f".{archive_format}"
        assert len(hits[0].all_parts) == expected_count[archive_format]

    summary = run_plan1_pipeline(common, passwords=passwords)
    plan6_error["pipeline_success_count"] = summary.success_count
    plan6_error["pipeline_failed_tasks"] = [str(item) for item in summary.failed_tasks]
    assert summary.success_count == 2, (
        f"expected 2 successes for two mixed groups, got {summary.success_count}"
    )
    assert summary.failed_tasks == [], (
        f"pipeline reported failures: {[str(item) for item in summary.failed_tasks]}"
    )
    for archive_format, case in groups.items():
        assert marker_was_extracted(common, case.marker_name, case.marker_text), (
            f"marker {case.marker_name!r} not extracted for {archive_format}"
        )
