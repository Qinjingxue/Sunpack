from __future__ import annotations

import time

from tests.real.plan7_watch_downloads.plan7_support import (
    PASSWORD,
    MemorySampler,
    assert_plan7_success,
    arrive_slowly,
    build_plain_sfx_cases,
    drive_watch_until,
    marker_text_extracted,
    start_watch,
    wrong_password_list,
)


def test_plan7_plain_and_sfx_downloads_complete_and_record_memory(
    tmp_path, plan7_error, record_property
):
    """普通压缩包（zip/rar/7z 加密，tar/流格式）与 SFX 压缩包逐一分块下载，
    密码列表含错误与正确密码；每个文件到达后 watch 必须立即处理，
    并记录内存随到达归档数量的变化。"""
    cases, skipped = build_plain_sfx_cases(tmp_path / "fixtures")
    plan7_error["case_id"] = "plan7_plain_sfx"
    plan7_error["skipped"] = skipped
    plan7_error["archives"] = sorted(cases)
    assert not skipped, f"Plan 7 requires the full generator matrix: {skipped}"
    assert cases, "no plain/SFX cases could be generated"
    assert {"plain_lz4", "plain_tar.lz4"} <= cases.keys()

    passwords = [*wrong_password_list(), PASSWORD]
    harness = start_watch(tmp_path, "plain_sfx", passwords=passwords)
    sampler = MemorySampler()
    tick_latencies: list[float] = []
    started_at = time.perf_counter()
    sampler.sample(installed_volumes=0, completed_archives=0, elapsed=0.0, label="baseline")

    try:
        arrived_count = 0
        for plan7_case in cases.values():
            arrive_slowly(harness, plan7_case.case.entry_path, tick_latencies=tick_latencies)
            arrived_count += 1
            plan7_case.stable_at = harness.stable_at_by_name[plan7_case.case.entry_path.name]
            sampler.sample(
                installed_volumes=arrived_count,
                completed_archives=0,
                elapsed=time.perf_counter() - started_at,
                label=f"arrived_{plan7_case.key}",
            )

        for plan7_case in cases.values():
            drive_watch_until(
                harness.watcher,
                lambda case=plan7_case: marker_text_extracted(
                    harness.output_root,
                    case.case.marker_name,
                    case.case.marker_text,
                ),
            )
            plan7_case.completion_latency = time.perf_counter() - plan7_case.stable_at
            sampler.sample(
                installed_volumes=len(cases),
                completed_archives=sum(
                    1 for item in cases.values() if item.completion_latency is not None
                ),
                elapsed=time.perf_counter() - started_at,
                label=f"after_{plan7_case.key}",
            )

        assert_plan7_success(
            harness,
            cases,
            sampler=sampler,
            tick_latencies=tick_latencies,
            expect_exact_submissions=False,
            error_info=plan7_error,
            record_property=record_property,
        )
    finally:
        harness.close()
