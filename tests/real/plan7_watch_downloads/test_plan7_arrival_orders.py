from __future__ import annotations

import random
import time
from pathlib import Path

import pytest

from tests.helpers.real_archives import ArchiveFixtureFactory
from tests.real.plan7_watch_downloads.plan7_support import (
    PASSWORD,
    arrive_slowly,
    drive_watch_until,
    input_volume_names,
    marker_text_extracted,
    split_arrival_order,
    start_watch,
    wrong_password_list,
)


FACTORY = ArchiveFixtureFactory()


def _build_case(tmp_path, archive_format: str):
    return FACTORY.create(
        tmp_path / "fixtures",
        f"p7_order_{archive_format}",
        archive_format,
        password=PASSWORD,
        split=True,
        sfx=True,
        payload_size=192 * 1024,
    )


def _finish_case(harness, case, stable_at: float):
    drive_watch_until(
        harness.watcher,
        lambda: marker_text_extracted(
            harness.output_root,
            case.marker_name,
            case.marker_text,
        ),
    )
    assert time.perf_counter() - stable_at < 60.0
    assert not harness.watcher.state.entries


@pytest.mark.parametrize("archive_format", ["7z", "zip"])
def test_plan7_launcher_first_then_data_volumes_reacts_after_group_completion(
    tmp_path, archive_format
):
    case = _build_case(tmp_path, archive_format)
    harness = start_watch(
        tmp_path,
        "launcher_first",
        passwords=[*wrong_password_list(), PASSWORD],
    )
    try:
        plan_case = type("PlanCase", (), {"case": case, "archive_format": archive_format, "sfx": True})()
        order = split_arrival_order(plan_case, random.Random(7), policy="launcher_first")
        launcher = next(path for path in order if path.suffix.casefold() == ".exe")
        data_order = [path for path in order if path != launcher]

        arrive_slowly(harness, launcher)
        assert not marker_text_extracted(harness.output_root, case.marker_name, case.marker_text)
        for volume in data_order:
            arrive_slowly(harness, volume)
        input_names = set(input_volume_names(plan_case))
        last_input = next(path for path in reversed(data_order) if path.name in input_names)
        stable_at = harness.stable_at_by_name[last_input.name]
        _finish_case(harness, case, stable_at)

        submitted_names = {
            path.name
            for event in harness.submission_events
            for path in map(Path, event.paths)
        }
        assert launcher.name in submitted_names
        assert any(
            path.name.endswith(f".{archive_format}.001")
            for event in harness.submission_events
            for path in map(Path, event.paths)
        )
    finally:
        harness.close()


@pytest.mark.parametrize("archive_format", ["7z", "zip"])
def test_plan7_data_volumes_before_launcher_do_not_resubmit(
    tmp_path, archive_format
):
    case = _build_case(tmp_path, archive_format)
    harness = start_watch(
        tmp_path,
        "data_first",
        passwords=[*wrong_password_list(), PASSWORD],
    )
    try:
        plan_case = type("PlanCase", (), {"case": case, "archive_format": archive_format, "sfx": True})()
        order = split_arrival_order(plan_case, random.Random(11), policy="data_first_launcher_last")
        input_names = set(input_volume_names(plan_case))
        data_order = [path for path in order if path.name in input_names]
        launcher = next(path for path in order if path.name not in input_names)
        for volume in data_order:
            arrive_slowly(harness, volume)
        stable_at = harness.stable_at_by_name[data_order[-1].name]
        _finish_case(harness, case, stable_at)
        submissions_before_launcher = len(harness.submission_events)

        arrive_slowly(harness, launcher)
        for _ in range(3):
            harness.watcher.run_once()
        later_submissions = harness.submission_events[submissions_before_launcher:]
        assert not later_submissions
    finally:
        harness.close()


def test_plan7_rar_part1_exe_enters_pipeline_as_real_head_before_family_complete(tmp_path):
    case = _build_case(tmp_path, "rar")
    harness = start_watch(
        tmp_path,
        "rar_part1",
        passwords=[*wrong_password_list(), PASSWORD],
    )
    try:
        plan_case = type("PlanCase", (), {"case": case, "archive_format": "rar", "sfx": True})()
        order = split_arrival_order(plan_case, random.Random(19), policy="head_first")
        head, *remaining = order
        assert head.name == case.entry_path.name

        arrive_slowly(harness, head)
        assert any(
            any(path.name == case.entry_path.name for path in map(Path, event.paths))
            for event in harness.submission_events
        )

        for volume in remaining:
            arrive_slowly(harness, volume)
        stable_at = harness.stable_at_by_name[head.name]
        _finish_case(harness, case, stable_at)
    finally:
        harness.close()
