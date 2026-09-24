from __future__ import annotations

from tests.real.plan5_embedded_archives.plan5_support import (
    assert_plan5_wrong_password_blocks_carrier,
    build_embedded_mixed_case,
    _segment_table,
)


def test_plan5_wrong_passwords_block_whole_carrier(tmp_path, plan5_error):
    """密码全错时：无法确定精确边界，整个 carrier 停止且不得部分解压。"""
    case = build_embedded_mixed_case(tmp_path, error_info=plan5_error)
    plan5_error["case_id"] = case.case_id
    plan5_error["file_size"] = case.file_path.stat().st_size
    plan5_error["segment_count"] = len(case.segments)
    plan5_error["segments"] = _segment_table(case)
    plan5_error["skipped_formats"] = list(case.skipped_formats)

    assert_plan5_wrong_password_blocks_carrier(case, error_info=plan5_error)
