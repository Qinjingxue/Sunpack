from __future__ import annotations

import asyncio
import shutil
import time
from pathlib import Path

import pytest

from sunpack.config.loader import load_config
from sunpack.coordinator.engine import PipelineEngine
from sunpack.coordinator.watch_group_coordinator import WatchGroupCoordinator
from sunpack.filesystem.watcher.group_models import BLOCKER_PASSWORD
from sunpack.filesystem.watcher.scheduler import WatchRunResult, WatchScheduler
from tests.helpers.real_archives import ArchiveCase, ArchiveFixtureFactory


MAX_SETTLE_SECONDS = 45.0
PAYLOAD_SIZE = 256 * 1024
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
    config["detection"] = {
        "fact_collectors": [],
        "processors": [],
        "rule_pipeline": {"precheck": []},
    }
    return config


def _create_case(root: Path, case_id: str, *, split: bool, password: str) -> ArchiveCase:
    try:
        return ArchiveFixtureFactory().create(
            root,
            case_id,
            "rar",
            password=password,
            split=split,
            payload_size=PAYLOAD_SIZE,
            split_volume_size=100 * 1024,
        )
    except (FileNotFoundError, RuntimeError) as exc:
        pytest.skip(str(exc))


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


def _password_blocked(watcher: WatchScheduler) -> bool:
    return any(entry.status == "failed_password" for entry in watcher.state.entries.values()) or any(
        BLOCKER_PASSWORD in group.blockers for group in watcher.state.groups.values()
    )


def _extracted(output_root: Path, case: ArchiveCase) -> bool:
    return bool(list(output_root.rglob(case.marker_name)))


def test_watch_single_hp_rar_extracts_with_correct_password(tmp_path):
    """Single header-encrypted RAR with the right password must extract."""
    case = _create_case(tmp_path / "fixtures", "watch_hp_single_ok", split=False, password="single-hp-ok")
    watch_root = tmp_path / "watch"
    output_root = tmp_path / "out"
    watch_root.mkdir()
    output_root.mkdir()
    (watch_root / ".sunpack-passwords.txt").write_text("single-hp-ok\n", encoding="utf-8")

    config = _watch_config()
    async def scenario():
        async with PipelineEngine(config) as delegate:
            watcher = WatchScheduler(
                config, [str(watch_root)], out_dir=str(output_root),
                state_path=str(tmp_path / "state.json"), quiet_seconds=0,
                initial_scan=False, pipeline_engine=delegate,
                group_coordinator=WatchGroupCoordinator(config),
            )
            destination = watch_root / case.entry_path.name
            shutil.copy2(case.entry_path, destination); watcher.enqueue(str(destination))
            await _drive_watch_until(watcher, lambda: _extracted(output_root, case))
            extracted = list(output_root.rglob(case.marker_name))
            assert len(extracted) == 1
            assert extracted[0].read_text(encoding="utf-8") == case.marker_text
    asyncio.run(scenario())


def test_watch_single_hp_rar_reports_wrong_password_without_hanging(tmp_path):
    """Single header-encrypted RAR without the right password must fail fast."""
    case = _create_case(tmp_path / "fixtures", "watch_hp_single_wrong", split=False, password="single-hp-right")
    watch_root = tmp_path / "watch"
    output_root = tmp_path / "out"
    watch_root.mkdir()
    output_root.mkdir()
    (watch_root / ".sunpack-passwords.txt").write_text("wrong-password\n", encoding="utf-8")

    config = _watch_config()
    async def scenario():
        async with PipelineEngine(config) as delegate:
            watcher = WatchScheduler(
                config, [str(watch_root)], out_dir=str(output_root),
                state_path=str(tmp_path / "state.json"), quiet_seconds=0,
                initial_scan=False, pipeline_engine=delegate,
                group_coordinator=WatchGroupCoordinator(config),
            )
            destination = watch_root / case.entry_path.name
            shutil.copy2(case.entry_path, destination); watcher.enqueue(str(destination))
            await _drive_watch_until(watcher, lambda: _password_blocked(watcher))
            assert not _extracted(output_root, case)
            blocked_entries = [entry for entry in watcher.state.entries.values() if entry.status == "failed_password"]
            assert blocked_entries, watcher.state.entries
            assert BLOCKER_PASSWORD in ((blocked_entries[0].failure_payload or {}).get("blockers") or [])
            assert (await watcher.run_once()).processed == 0
    asyncio.run(scenario())


def test_watch_split_hp_rar_extracts_with_correct_password(tmp_path):
    """Split header-encrypted RAR with the right password must extract once."""
    case = _create_case(tmp_path / "fixtures", "watch_hp_split_ok", split=True, password="split-hp-ok")
    watch_root = tmp_path / "watch"
    output_root = tmp_path / "out"
    watch_root.mkdir()
    output_root.mkdir()
    (watch_root / ".sunpack-passwords.txt").write_text("split-hp-ok\n", encoding="utf-8")

    config = _watch_config()
    async def scenario():
        async with PipelineEngine(config) as delegate:
            watcher = WatchScheduler(
                config, [str(watch_root)], out_dir=str(output_root),
                state_path=str(tmp_path / "state.json"), quiet_seconds=0,
                initial_scan=False, pipeline_engine=delegate,
                group_coordinator=WatchGroupCoordinator(config),
            )
            for source in sorted(case.archive_dir.iterdir(), key=lambda path: path.name.lower()):
                destination = watch_root / source.name
                shutil.copy2(source, destination); watcher.enqueue(str(destination))
            await _drive_watch_until(watcher, lambda: _extracted(output_root, case))
            extracted = list(output_root.rglob(case.marker_name))
            assert len(extracted) == 1
            assert extracted[0].read_text(encoding="utf-8") == case.marker_text
            assert not _password_blocked(watcher)
    asyncio.run(scenario())


def test_watch_split_hp_rar_recovers_after_wrong_then_correct_password(tmp_path):
    """Split header-encrypted RAR: wrong password blocks, correction succeeds."""
    correct = "split-hp-right"
    case = _create_case(tmp_path / "fixtures", "watch_hp_split_wrong", split=True, password=correct)
    watch_root = tmp_path / "watch"
    output_root = tmp_path / "out"
    watch_root.mkdir()
    output_root.mkdir()
    password_file = watch_root / ".sunpack-passwords.txt"
    password_file.write_text("wrong-password\n", encoding="utf-8")

    config = _watch_config()
    async def scenario():
        async with PipelineEngine(config) as delegate:
            watcher = WatchScheduler(
                config, [str(watch_root)], out_dir=str(output_root),
                state_path=str(tmp_path / "state.json"), quiet_seconds=0,
                initial_scan=False, pipeline_engine=delegate,
                group_coordinator=WatchGroupCoordinator(config),
            )
            for source in sorted(case.archive_dir.iterdir(), key=lambda path: path.name.lower()):
                destination = watch_root / source.name
                shutil.copy2(source, destination); watcher.enqueue(str(destination))
            await _drive_watch_until(watcher, lambda: _password_blocked(watcher))
            assert not _extracted(output_root, case)
            password_file.write_text(correct + "\n", encoding="utf-8")
            watcher.notify_password_table_changed(str(password_file))
            await _drive_watch_until(watcher, lambda: _extracted(output_root, case))
            extracted = list(output_root.rglob(case.marker_name))
            assert len(extracted) == 1
            assert extracted[0].read_text(encoding="utf-8") == case.marker_text
    asyncio.run(scenario())
