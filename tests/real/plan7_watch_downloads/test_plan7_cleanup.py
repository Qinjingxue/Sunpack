from __future__ import annotations

import random
import time

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


def test_plan7_sfx_split_success_cleans_unique_validated_launcher(tmp_path):
    case = FACTORY.create(
        tmp_path / "fixtures",
        "p7_cleanup_sfx_7z",
        "7z",
        password=PASSWORD,
        split=True,
        sfx=True,
        payload_size=192 * 1024,
    )
    harness = start_watch(
        tmp_path,
        "cleanup",
        passwords=[*wrong_password_list(), PASSWORD],
        cleanup_mode="delete",
    )
    try:
        plan_case = type("PlanCase", (), {"case": case, "archive_format": "7z", "sfx": True})()
        order = split_arrival_order(plan_case, random.Random(23), policy="launcher_first")
        for path in order:
            arrive_slowly(harness, path)
        input_names = set(input_volume_names(plan_case))
        last_input = next(path for path in reversed(order) if path.name in input_names)
        stable_at = harness.stable_at_by_name[last_input.name]
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
        input_names = set(input_volume_names(plan_case))
        launcher = next(path for path in order if path.name not in input_names)
        assert all(
            not (harness.watch_root / path.name).exists()
            for path in order
            if path.name in input_names or path.name == launcher.name
        )
    finally:
        harness.close()
