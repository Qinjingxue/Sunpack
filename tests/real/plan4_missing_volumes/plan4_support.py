from __future__ import annotations

from sunpack.core.contracts.failures import FailureKind
from tests.helpers.marker_utils import marker_was_extracted
from tests.real.plan1_real_archives.plan1_support import run_plan1_pipeline


SCENARIOS = [
    "missing_head",
    "missing_tail",
    "missing_middle",
    "only_middle",
    "only_head",
    "only_tail",
]


def apply_missing_volume_scenario(case, scenario: str) -> None:
    """按场景删除分卷：缺头/尾/中，或只留中间/头/尾单卷。"""
    if scenario not in SCENARIOS:
        raise ValueError(f"Unsupported scenario: {scenario}")
    parts = sorted(path for path in case.archive_dir.iterdir() if path.is_file())
    entry = case.entry_path.resolve()
    # SFX zip/7z：.exe 只是启动器（不含数据），真正的头卷是 .001 数据卷；
    # rar SFX 的 part1.exe 本身就是数据头卷。
    if str(entry).lower().endswith(".exe") and any(
        path.name.lower().endswith(".001") for path in parts
    ):
        volumes = [path for path in parts if path != entry]
        launcher = entry
    else:
        volumes = list(parts)
        launcher = None
    assert len(volumes) >= 5, f"fixture needs at least 5 volumes, got {len(volumes)}"
    head = volumes[0]
    tail = volumes[-1]
    middle = volumes[len(volumes) // 2]
    assert head != tail and middle != head and middle != tail
    keep_extra = {launcher} if launcher is not None else set()
    deletions = {
        "missing_head": [head],
        "missing_tail": [tail],
        "missing_middle": [middle],
        "only_middle": [path for path in parts if path not in keep_extra | {middle}],
        "only_head": [path for path in parts if path not in keep_extra | {head}],
        "only_tail": [path for path in parts if path not in keep_extra | {tail}],
    }
    for path in deletions[scenario]:
        path.unlink()


def assert_missing_volume_or_ignored(case, passwords, *, error_info: dict | None = None) -> None:
    """计划第 4 条：要么正确报缺失分卷，要么扫描阶段不当成压缩包而忽略。"""
    summary = run_plan1_pipeline(case.archive_dir, passwords=passwords)
    missing_volume_reported = any(
        failure.contains(FailureKind.MISSING_VOLUME) for failure in summary.failures
    )
    ignored_at_scan = summary.success_count == 0 and not summary.failed_tasks
    extracted = marker_was_extracted(case.archive_dir, case.marker_name, case.marker_text)
    if error_info is not None:
        error_info.update(
            {
                "success_count": summary.success_count,
                "partial_success_count": summary.partial_success_count,
                "failed_tasks": [str(item) for item in summary.failed_tasks],
                "failure_kinds": [str(failure.kind) for failure in summary.failures],
                "missing_volume_reported": missing_volume_reported,
                "ignored_at_scan": ignored_at_scan,
                "marker_extracted": extracted,
            }
        )
    assert missing_volume_reported or ignored_at_scan, (
        "expected missing-volume error or scan-stage ignore; "
        f"kinds={[str(f.kind) for f in summary.failures]}"
    )
