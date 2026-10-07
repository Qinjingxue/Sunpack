from __future__ import annotations

import time

from tests.helpers.real_archives import ArchiveFixtureFactory
from tests.real.plan7_watch_downloads.plan7_support import (
    PASSWORD,
    MemorySampler,
    Plan7Case,
    arrive_interleaved,
    arrive_slowly,
    assert_plan7_success,
    drive_watch_until,
    marker_text_extracted,
    start_watch,
    wrong_password_list,
)


FACTORY = ArchiveFixtureFactory()


def _case(case, kind: str = "plain") -> Plan7Case:
    return Plan7Case(
        key=f"{kind}_{case.archive_format}",
        archive_format=case.archive_format,
        kind=kind,
        case=case,
    )


def test_plan7_interleaved_downloads_react_for_every_final_path(tmp_path):
    cases = {
        "interleaved_zip": _case(
            FACTORY.create(
                tmp_path / "fixtures",
                "p7_interleaved_zip",
                "zip",
                password=PASSWORD,
                payload_size=96 * 1024,
            )
        ),
        "interleaved_7z": _case(
            FACTORY.create(
                tmp_path / "fixtures",
                "p7_interleaved_7z",
                "7z",
                password=PASSWORD,
                payload_size=96 * 1024,
            )
        ),
    }
    harness = start_watch(
        tmp_path,
        "interleaved",
        passwords=[*wrong_password_list(), PASSWORD],
    )
    tick_latencies: list[float] = []
    sampler = MemorySampler()
    sampler.sample(files_seen=0, completed_files=0, label="baseline")
    try:
        stable = arrive_interleaved(
            harness,
            [item.case.entry_path for item in cases.values()],
            tick_latencies=tick_latencies,
        )
        for item in cases.values():
            sampler.sample(
                files_seen=len(cases),
                completed_files=0,
                label=f"arrived_{item.key}",
            )
        for item in cases.values():
            item.stable_at = stable[item.case.entry_path.name]
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


def test_plan7_direct_final_path_download_does_not_stall_after_completion(tmp_path):
    case = _case(
        FACTORY.create(
            tmp_path / "fixtures",
            "p7_direct_zip",
            "zip",
            password=PASSWORD,
            payload_size=128 * 1024,
        )
    )
    harness = start_watch(
        tmp_path,
        "direct",
        passwords=[*wrong_password_list(), PASSWORD],
    )
    tick_latencies: list[float] = []
    sampler = MemorySampler()
    sampler.sample(files_seen=0, completed_files=0, label="baseline")
    try:
        arrive_slowly(
            harness,
            case.case.entry_path,
            tick_latencies=tick_latencies,
            write_mode="direct_final_path",
        )
        sampler.sample(files_seen=1, completed_files=0, label="arrived_direct_zip")
        case.stable_at = harness.stable_at_by_name[case.case.entry_path.name]
        drive_watch_until(
            harness.watcher,
            lambda: marker_text_extracted(
                harness.output_root,
                case.case.marker_name,
                case.case.marker_text,
            ),
        )
        case.completion_latency = time.perf_counter() - case.stable_at
        sampler.sample(
            files_seen=1,
            completed_files=1,
            label="after_direct_zip",
        )
        assert_plan7_success(
            harness,
            {case.key: case},
            sampler=sampler,
            tick_latencies=tick_latencies,
            expect_exact_submissions=False,
        )
    finally:
        harness.close()


def test_plan7_interrupted_download_resumes_after_watch_restart(tmp_path):
    case = _case(
        FACTORY.create(
            tmp_path / "fixtures",
            "p7_restart_zip",
            "zip",
            password=PASSWORD,
            payload_size=128 * 1024,
        )
    )
    state_path = tmp_path / "restart" / "state.json"
    first = start_watch(
        tmp_path,
        "restart",
        passwords=[*wrong_password_list(), PASSWORD],
        state_path=state_path,
    )
    try:
        interrupted = arrive_slowly(
            first,
            case.case.entry_path,
            interrupt_after_chunks=1,
        )
        assert interrupted.processed == 0
    finally:
        first.close()

    second = start_watch(
        tmp_path,
        "restart",
        passwords=[*wrong_password_list(), PASSWORD],
        state_path=state_path,
    )
    try:
        arrive_slowly(second, case.case.entry_path, resume=True)
        stable_at = second.stable_at_by_name[case.case.entry_path.name]
        drive_watch_until(
            second.watcher,
            lambda: marker_text_extracted(
                second.output_root,
                case.case.marker_name,
                case.case.marker_text,
            ),
        )
        assert time.perf_counter() - stable_at < 60.0
        assert not second.watcher.state.entries
    finally:
        second.close()
