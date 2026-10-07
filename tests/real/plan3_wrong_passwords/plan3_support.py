from __future__ import annotations

import uuid

from tests.helpers.marker_utils import marker_was_extracted
from tests.real.diagnostics import (
    case_snapshot,
    environment_snapshot,
    password_summary,
    pipeline_snapshot,
    record_exception,
    scan_tasks_snapshot,
    snapshot_path,
)
from tests.real.plan1_real_archives.plan1_support import run_plan1_pipeline


WRONG_PASSWORD_LIST_SIZE = 100


def wrong_password_list(count: int = WRONG_PASSWORD_LIST_SIZE) -> list[str]:
    """计划第 3 条：100 个全部错误的密码，且彼此唯一。"""
    return [f"wrong-{index:03d}-{uuid.uuid4().hex[:8]}" for index in range(count)]


def assert_password_error(
    case,
    error_info: dict | None = None,
    *,
    detailed_diagnostics: bool = False,
    passwords: list[str] | None = None,
) -> None:
    """全错密码下必须：0 成功、有失败任务、失败分类为密码错误、marker 未解出。"""
    passwords = wrong_password_list() if passwords is None else passwords
    diagnostics = (
        error_info.setdefault("diagnostics", {})
        if error_info is not None and detailed_diagnostics
        else None
    )
    if diagnostics is not None:
        diagnostics["environment"] = environment_snapshot()
        diagnostics["case"] = case_snapshot(case)
        diagnostics["passwords"] = password_summary(passwords)
        diagnostics["input_before_pipeline"] = snapshot_path(case.archive_dir)
        try:
            diagnostics["scan_before_pipeline"] = scan_tasks_snapshot(
                case.archive_dir,
                passwords=passwords,
            )
        except BaseException as exc:
            record_exception(error_info, "scan_before_pipeline", exc)
            raise

    summary = None
    try:
        summary = run_plan1_pipeline(case.archive_dir, passwords=passwords)
    except BaseException as exc:
        if diagnostics is not None:
            record_exception(error_info, "pipeline", exc)
            pipeline_snapshot(
                error_info,
                phase="pipeline_exception",
                roots=(case.archive_dir,),
            )
        raise

    if diagnostics is not None:
        pipeline_snapshot(
            error_info,
            phase="pipeline_returned",
            summary=summary,
            roots=(case.archive_dir,),
        )

    try:
        extracted = marker_was_extracted(case.archive_dir, case.marker_name, case.marker_text)
    except BaseException as exc:
        if diagnostics is not None:
            record_exception(error_info, "marker_check", exc)
            pipeline_snapshot(
                error_info,
                phase="marker_check_exception",
                summary=summary,
                roots=(case.archive_dir,),
            )
        raise

    if error_info is not None:
        error_info.update(
            {
                "password_list_size": len(passwords),
                "pipeline_success_count": summary.success_count,
                "pipeline_failed_tasks": [str(item) for item in summary.failed_tasks],
                "failure_kinds": [str(failure.kind) for failure in summary.failures],
                "password_failure_reported": any(
                    failure.is_password_failure for failure in summary.failures
                ),
                "marker_extracted": extracted,
            }
        )
        if diagnostics is not None:
            diagnostics["marker_check"] = {
                "marker_name": case.marker_name,
                "marker_text_length": len(case.marker_text),
                "marker_extracted": extracted,
            }
            pipeline_snapshot(
                error_info,
                phase="before_assertions",
                summary=summary,
                roots=(case.archive_dir,),
            )
    assert summary.success_count == 0, f"expected 0 success, got {summary.success_count}"
    assert summary.failed_tasks, "expected failed tasks for all-wrong passwords"
    assert any(failure.is_password_failure for failure in summary.failures), (
        f"no password failure reported; kinds={[str(f.kind) for f in summary.failures]}"
    )
    assert not extracted, "marker must not be extracted with all-wrong passwords"
