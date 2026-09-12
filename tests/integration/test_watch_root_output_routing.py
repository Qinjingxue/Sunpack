from __future__ import annotations

import asyncio
import shutil
import time
from pathlib import Path

import pytest

from sunpack.config.loader import load_config
from sunpack.coordinator.engine import PipelineEngine
from sunpack.coordinator.watch_group_coordinator import WatchGroupCoordinator
from sunpack.filesystem.watcher.scheduler import WatchRunResult, WatchScheduler
from tests.helpers.real_archives import ArchiveCase, ArchiveFixtureFactory


MAX_SETTLE_SECONDS = 45.0
PAYLOAD_SIZE = 64 * 1024
pytestmark = pytest.mark.requires_watch_broker


@pytest.fixture(scope="module", autouse=True)
def _watch_broker_lease():
    from sunpack_native import watch_broker_acquire, watch_broker_release

    watch_broker_acquire()
    try:
        yield
    finally:
        watch_broker_release()


def _watch_config() -> dict:
    config = load_config()
    config["cli"] = {**(config.get("cli") or {}), "quiet": True}
    config["post_extract"] = {
        **(config.get("post_extract") or {}),
        "archive_cleanup_mode": "keep",
        "flatten_single_directory": False,
    }
    config["watch"] = {
        **(config.get("watch") or {}),
        "clipboard_monitor_enabled": False,
        "password_retry_debounce_seconds": 0,
    }
    return config


async def _drive_watch_until(
    watcher: WatchScheduler,
    condition,
    *,
    timeout_seconds: float = MAX_SETTLE_SECONDS,
) -> WatchRunResult:
    deadline = time.perf_counter() + timeout_seconds
    combined = WatchRunResult()
    while time.perf_counter() < deadline:
        result = await watcher.run_once()
        combined.processed += result.processed
        combined.succeeded += result.succeeded
        combined.failed += result.failed
        combined.pending = result.pending
        combined.errors.extend(result.errors)
        with watcher._lock:
            inflight = bool(watcher._inflight_requests)
        if condition() and watcher.pending_count == 0 and not inflight:
            return combined
        await asyncio.sleep(0.01)
    pytest.fail(
        "watch condition did not settle before timeout: "
        f"pending={watcher.pending_count}, entries={watcher.state.entries}, "
        f"groups={watcher.state.groups}"
    )


def _extracted(output_root: Path, case: ArchiveCase) -> bool:
    return bool(list(output_root.rglob(case.marker_name)))


def test_watch_routes_each_root_to_its_output_root_and_keeps_probes_with_the_input(tmp_path):
    case = ArchiveFixtureFactory().create(tmp_path / "fixtures", "watch_output_routing", "zip", payload_size=PAYLOAD_SIZE)
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_out = tmp_path / "out-first"
    second_out = tmp_path / "elsewhere" / "out-second"
    for directory in (first_root, second_root, first_out):
        directory.mkdir(parents=True)

    config = _watch_config()
    output_roots = {
        str(first_root): str(first_out),
        str(second_root): str(second_out),
    }

    async def scenario():
        async with PipelineEngine(config) as delegate:
            watcher = WatchScheduler(
                config,
                [str(first_root), str(second_root)],
                out_dir=".",
                output_roots=output_roots,
                state_path=str(tmp_path / "state.json"),
                quiet_seconds=0,
                initial_scan=False,
                pipeline_engine=delegate,
                group_coordinator=WatchGroupCoordinator(config),
            )
            destination = second_root / case.entry_path.name
            shutil.copy2(case.entry_path, destination)
            watcher.enqueue(str(destination))
            await _drive_watch_until(watcher, lambda: _extracted(second_out, case))

    asyncio.run(scenario())

    extracted = list(second_out.rglob(case.marker_name))
    assert len(extracted) == 1
    assert extracted[0].read_text(encoding="utf-8") == case.marker_text
    # The configured output root replaces the legacy one for its own input root only.
    assert not list(first_out.rglob(case.marker_name))
    assert not list(first_root.rglob(case.marker_name))
    # Compression still happens in the probe workspace below the input root, so
    # the promotion stays a rename; only the promoted output crosses to the
    # configured output root.
    assert (second_root / ".sunpack_watch_probes").is_dir()
