from __future__ import annotations

import random
import time

from tests.real.plan7_watch_downloads.plan7_support import (
    PASSWORD,
    MemorySampler,
    assert_plan7_success,
    arrive_slowly,
    build_split_cases,
    drive_watch_until,
    input_volume_names,
    marker_text_extracted,
    split_arrival_order,
    start_watch,
    wrong_password_list,
)


def test_plan7_split_downloads_out_of_order_complete_and_record_memory(
    tmp_path, plan7_error, record_property
):
    """各种形式分卷与 SFX 分卷分块下载、卷号乱序到达，密码含错误与正确密码；
    卷齐后 watch 必须自动重试并完成，同时记录内存随到达数量的变化。"""
    cases, skipped = build_split_cases(tmp_path / "fixtures")
    plan7_error["case_id"] = "plan7_split"
    plan7_error["skipped"] = skipped
    plan7_error["archives"] = sorted(cases)
    assert not skipped, f"Plan 7 requires the full generator matrix: {skipped}"
    assert cases, "no split cases could be generated"

    passwords = [*wrong_password_list(), PASSWORD]
    harness = start_watch(tmp_path, "split", passwords=passwords)
    sampler = MemorySampler()
    tick_latencies: list[float] = []
    sampler.sample(files_seen=0, completed_files=0, label="baseline")
    rng = random.Random(0x5EED)

    try:
        files_seen = 0
        arrived_count = 0
        arrival_records = {}
        for plan7_case in cases.values():
            order = split_arrival_order(plan7_case, rng)
            arrival_records[plan7_case.key] = [path.name for path in order]
            for volume in order:
                arrive_slowly(harness, volume, tick_latencies=tick_latencies)
                files_seen += 1
            input_names = set(input_volume_names(plan7_case))
            last_input = next(path for path in reversed(order) if path.name in input_names)
            plan7_case.stable_at = harness.stable_at_by_name[last_input.name]
            arrived_count += 1
            sampler.sample(
                files_seen=files_seen,
                completed_files=0,
                label=f"arrived_{plan7_case.key}",
            )

        plan7_error["arrival_orders"] = arrival_records
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
                files_seen=files_seen,
                completed_files=sum(
                    1 for item in cases.values() if item.completion_latency is not None
                ),
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
