from __future__ import annotations

import pytest

from tests.real.diagnostics import environment_snapshot, record_exception, snapshot_path
from tests.real.plan5_embedded_archives.plan5_support import (
    assert_plan5_success,
    assert_plan5_password_failure_preserves_healthy_segments,
    build_embedded_mixed_case,
    _segment_table,
)


@pytest.mark.parametrize("correct_password", [True, False], ids=["correct-password", "wrong-passwords"])
def test_plan5_mixed_carrier_preserves_recoverable_segments(
    tmp_path, plan5_error, correct_password,
):
    """第 5 条主用例：一个文件内嵌入全部支持格式的加密/非加密压缩段，
    中间是随机垃圾；正确密码恢复全部段，全错密码仍须恢复健康明文段。"""
    diagnostics = plan5_error.setdefault("diagnostics", {})
    diagnostics["environment"] = environment_snapshot()
    diagnostics["fixture_phase"] = "build_embedded_mixed_case"
    try:
        case = build_embedded_mixed_case(tmp_path, error_info=plan5_error)
    except BaseException as exc:
        record_exception(plan5_error, "fixture_build", exc)
        diagnostics["filesystem_after_fixture_failure"] = snapshot_path(tmp_path)
        raise

    diagnostics["fixture_phase"] = "pipeline"
    plan5_error["case_id"] = case.case_id
    plan5_error["file_name"] = case.file_path.name
    plan5_error["file_size"] = case.file_path.stat().st_size
    plan5_error["segment_count"] = len(case.segments)
    plan5_error["segments"] = _segment_table(case)
    plan5_error["junk_block_count"] = len(case.junk_blocks)
    plan5_error["skipped_formats"] = list(case.skipped_formats)

    if correct_password:
        assert_plan5_success(
            case,
            passwords=[case.password],
            error_info=plan5_error,
            detailed_diagnostics=True,
        )
    else:
        assert_plan5_password_failure_preserves_healthy_segments(case, error_info=plan5_error)
