from __future__ import annotations

import time

from tests.real.plan7_watch_downloads.plan7_support import (
    PASSWORD,
    MemorySampler,
    arrive_slowly,
    assert_plan7_success,
    build_disguised_cases,
    drive_watch_until,
    marker_text_extracted,
    start_watch,
    wrong_password_list,
)


def test_plan7_disguised_extensions_and_carrier_prefixes_react(tmp_path):
    cases, skipped = build_disguised_cases(tmp_path / "fixtures")
    assert not skipped, f"required Plan 7 generator capability missing: {skipped}"
    assert cases
    harness = start_watch(
        tmp_path,
        "disguised",
        passwords=[*wrong_password_list(), PASSWORD],
    )
    sampler = MemorySampler()
    tick_latencies: list[float] = []
    sampler.sample(files_seen=0, completed_files=0, label="baseline")
    try:
        for item in cases.values():
            arrive_slowly(harness, item.case.entry_path, tick_latencies=tick_latencies)
            item.stable_at = harness.stable_at_by_name[item.case.entry_path.name]
            sampler.sample(
                files_seen=1,
                completed_files=0,
                label=f"arrived_{item.key}",
            )
        for item in cases.values():
            drive_watch_until(
                harness.watcher,
                lambda item=item: marker_text_extracted(
                    harness.output_root,
                    item.case.marker_name,
                    item.case.marker_text,
                ),
            )
            item.completion_latency = time.perf_counter() - item.stable_at
            sampler.sample(
                files_seen=len(cases),
                completed_files=sum(
                    1 for current in cases.values() if current.completion_latency is not None
                ),
                label=f"after_{item.key}",
            )
        assert_plan7_success(
            harness,
            cases,
            sampler=sampler,
            tick_latencies=tick_latencies,
            expect_exact_submissions=False,
        )
    finally:
        harness.close()
