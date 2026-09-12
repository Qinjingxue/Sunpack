from __future__ import annotations

import asyncio
import struct
from types import SimpleNamespace

import pytest

from sunpack.contracts.failures import FailureInfo, FailureKind
from sunpack.coordinator.watch_group_coordinator import WatchGroupCoordinator
from tests.helpers.fake_pipeline_engine import FakePipelineEngine
import sunpack.filesystem.watcher.scheduler as scheduler_module
from sunpack.filesystem.watcher.scheduler import WatchScheduler


_TEST_LOOP = asyncio.new_event_loop()


def _run_once(watcher):
    return _TEST_LOOP.run_until_complete(watcher.run_once())


def _summary(*failures: FailureInfo):
    return SimpleNamespace(
        success_count=0 if failures else 1,
        failed_tasks=[failure.message for failure in failures],
        failures=list(failures),
    )


def _partial_summary(*failures: FailureInfo):
    return SimpleNamespace(
        success_count=0,
        partial_success_count=1,
        failed_tasks=[],
        failures=list(failures),
        target_results=[],
    )


def _watcher(tmp_path, runner_factory, *, quiet_seconds=0) -> WatchScheduler:
    root = tmp_path / "in"
    root.mkdir(exist_ok=True)
    return WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False, "password_retry_debounce_seconds": 0}},
        [str(root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=quiet_seconds,
        initial_scan=False,
        pipeline_engine=FakePipelineEngine(runner_factory),
        group_coordinator=WatchGroupCoordinator({}),
    )


class _FakeClock:
    def __init__(self, value: float):
        self.value = value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def _split_zip_first_bytes() -> bytes:
    return b"PK\x07\x08" + b"PK\x03\x04" + (b"\x00" * 64)


def _split_zip_terminal_bytes(disk_number: int) -> bytes:
    return b"tail" + struct.pack(
        "<4s4H2LH",
        b"PK\x05\x06",
        disk_number,
        disk_number,
        0,
        0,
        0,
        0,
        0,
    )


def test_watch_holds_orphan_non_head_until_first_volume_arrives(tmp_path):
    attempts: list[str] = []

    class Runner:
        def __init__(self, config):
            pass

        def run_targets(self, paths):
            attempts.extend(paths)
            return _summary()

    watcher = _watcher(tmp_path, Runner)
    root = tmp_path / "in"
    second = root / "sample.7z.002"
    second.write_bytes(b"part-2")
    watcher.enqueue(str(second))

    first = _run_once(watcher)
    head = root / "sample.7z.001"
    head.write_bytes(b"part-1")
    watcher.enqueue(str(head))
    second_result = _run_once(watcher)

    assert first.processed == 0
    assert second_result.succeeded == 1
    assert attempts == [str(head.resolve())]


def test_watch_aligned_group_deadlines_dispatch_together_without_restarting_quiet(
    tmp_path,
    monkeypatch,
):
    """Members that become quiet in different ticks must not defer each other forever.

    Each member arrives with a slightly different quiet deadline.  The first
    members become ready while the rest are still pending; the scheduler must
    keep them pending with aligned deadlines (and keep co-ready members alive)
    so the whole group dispatches at the latest member deadline instead of
    restarting the quiet window every second.
    """
    attempts: list[str] = []

    class Runner:
        def __init__(self, config):
            pass

        def run_targets(self, paths):
            attempts.extend(paths)
            return _summary()

    clock = _FakeClock(1000.0)
    monkeypatch.setattr(scheduler_module.time, "time", lambda: clock.value)
    watcher = _watcher(tmp_path, Runner, quiet_seconds=1.0)
    root = tmp_path / "in"
    parts = [root / f"aligned.7z.00{index}" for index in (1, 2, 3, 4)]
    for part in parts:
        part.write_bytes(b"part")
        clock.advance(0.02)
        watcher.enqueue(str(part))

    # Enqueues left the clock at 1000.08; member deadlines are 1001.02,
    # 1001.04, 1001.06 and 1001.08.  Landing at 1001.05 makes only the first
    # two members due while the other two are still pending.  Deferred members
    # must stay pending (not be dropped) and their deadlines must align with
    # the latest pending member instead of restarting.
    clock.advance(0.97)
    first = _run_once(watcher)
    assert first.processed == 0
    assert watcher.pending_count == 4

    clock.advance(0.06)
    second = _run_once(watcher)
    assert second.succeeded == 1
    assert attempts == [str((root / "aligned.7z.001").resolve())]


def test_watch_conservatively_holds_old_rar_orphan_until_head_arrives(tmp_path):
    attempts: list[str] = []

    class Runner:
        def __init__(self, config):
            pass

        def run_targets(self, paths):
            attempts.extend(paths)
            return _summary()

    watcher = _watcher(tmp_path, Runner)
    root = tmp_path / "in"
    for name in ("old-style.r00",):
        path = root / name
        path.write_bytes(name.encode())
        watcher.enqueue(str(path))
    assert _run_once(watcher).processed == 0

    head = root / "old-style.rar"
    head.write_bytes(b"head")
    watcher.enqueue(str(head))

    assert _run_once(watcher).succeeded == 1
    assert attempts == [str(head.resolve())]


def test_watch_does_not_hold_plain_numeric_files_as_missing_volumes(tmp_path):
    attempts: list[str] = []

    class Runner:
        def __init__(self, config):
            pass

        def run_targets(self, paths):
            attempts.extend(paths)
            return _summary()

    watcher = _watcher(tmp_path, Runner)
    root = tmp_path / "in"
    for name in ("plain.002", "plain.003"):
        path = root / name
        path.write_bytes(name.encode())
        watcher.enqueue(str(path))

    result = _run_once(watcher)

    assert result.processed == 2
    assert len(attempts) == 2


def test_watch_holds_strong_middle_gap_until_missing_volume_arrives(tmp_path):
    attempts: list[str] = []

    class Runner:
        def __init__(self, config):
            pass

        def run_targets(self, paths):
            attempts.extend(paths)
            return _summary()

    watcher = _watcher(tmp_path, Runner)
    root = tmp_path / "in"
    head = root / "gap.7z.001"
    third = root / "gap.7z.003"
    head.write_bytes(b"7z\xbc\xaf\x27\x1c-head")
    third.write_bytes(b"tail")
    watcher.enqueue(str(head))

    first_result = _run_once(watcher)

    assert first_result.processed == 0
    assert attempts == []
    state = watcher.state.group_state(next(iter(watcher.state.groups)))
    assert state is not None
    assert "missing_volume" not in state.blockers
    assert state.failure_payload["details"]["completeness_status"] == "middle_gap"
    assert state.failure_payload["details"]["completeness_confidence"] == "strong"

    second = root / "gap.7z.002"
    second.write_bytes(b"middle")
    watcher.enqueue(str(second))

    second_result = _run_once(watcher)
    assert second_result.succeeded == 1
    assert attempts == [str(head.resolve())]


def test_watch_dispatches_weak_camouflaged_gap_for_backend_classification(tmp_path):
    attempts: list[str] = []

    class Runner:
        def __init__(self, config):
            pass

        def run_targets(self, paths):
            attempts.extend(paths)
            return _summary()

    watcher = _watcher(tmp_path, Runner)
    root = tmp_path / "in"
    head = root / "gap.part1.123"
    third = root / "gap.part3.789"
    head.write_bytes(b"ordinary data")
    third.write_bytes(b"ordinary data")
    watcher.enqueue(str(head))

    result = _run_once(watcher)

    assert result.succeeded == 1
    assert attempts == [str(head.resolve())]


def test_watch_does_not_infer_missing_tail_from_equal_volume_sizes(tmp_path):
    attempts: list[str] = []

    class Runner:
        def __init__(self, config):
            pass

        def run_targets(self, paths):
            attempts.extend(paths)
            return _summary()

    watcher = _watcher(tmp_path, Runner)
    root = tmp_path / "in"
    head = root / "exact-boundary.7z.001"
    second = root / "exact-boundary.7z.002"
    head.write_bytes(b"x" * 4096)
    second.write_bytes(b"y" * 4096)
    watcher.enqueue(str(head))

    result = _run_once(watcher)

    assert result.succeeded == 1
    assert attempts == [str(head.resolve())]


def test_watch_holds_modern_split_zip_until_terminal_volume_arrives(tmp_path):
    attempts: list[str] = []

    class Runner:
        def __init__(self, config):
            pass

        def run_targets(self, paths):
            attempts.extend(paths)
            return _summary()

    watcher = _watcher(tmp_path, Runner)
    root = tmp_path / "in"
    first = root / "shared.z01"
    second = root / "shared.z02"
    first.write_bytes(_split_zip_first_bytes())
    second.write_bytes(b"opaque middle volume")
    watcher.enqueue(str(first))

    first_result = _run_once(watcher)

    assert first_result.processed == 0
    assert attempts == []
    state = watcher.state.group_state(next(iter(watcher.state.groups)))
    assert state is not None
    assert state.failure_payload["details"]["completeness_status"] == "tail_missing"
    assert state.failure_payload["details"]["completeness_confidence"] == "strong"

    terminal = root / "shared.zip"
    terminal.write_bytes(_split_zip_terminal_bytes(2))
    watcher.enqueue(str(terminal))

    second_result = _run_once(watcher)
    assert second_result.succeeded == 1
    assert attempts == [str(first.resolve())]


def test_watch_runtime_missing_volume_retries_only_after_group_changes(tmp_path):
    attempts: list[str] = []

    class Runner:
        def __init__(self, config):
            pass

        def run_targets(self, paths):
            attempts.extend(paths)
            if len(attempts) == 1:
                return _summary(FailureInfo(FailureKind.MISSING_VOLUME, "extraction", "missing volume"))
            return _summary()

    watcher = _watcher(tmp_path, Runner)
    root = tmp_path / "in"
    head = root / "sample.7z.001"
    second = root / "sample.7z.002"
    head.write_bytes(b"part-1")
    second.write_bytes(b"part-2")
    watcher.enqueue(str(head))
    watcher.enqueue(str(second))
    assert _run_once(watcher).failed == 1

    watcher.enqueue(str(head), force=True)
    assert _run_once(watcher).processed == 0
    third = root / "sample.7z.003"
    third.write_bytes(b"part-3")
    watcher.enqueue(str(third))

    assert _run_once(watcher).succeeded == 1
    assert attempts == [str(head.resolve()), str(head.resolve())]


def test_watch_treats_possible_missing_partial_recovery_as_suspended(tmp_path):
    attempts: list[str] = []
    possible_missing = FailureInfo(
        FailureKind.MISSING_VOLUME,
        "extraction_report",
        "one or more split volumes may be missing",
        details={"missing_volume_confirmed": False, "partial_recovery": True},
    )

    class Runner:
        def __init__(self, config):
            pass

        def run_targets(self, paths):
            attempts.extend(paths)
            return _partial_summary(possible_missing) if len(attempts) == 1 else _summary()

    watcher = _watcher(tmp_path, Runner)
    root = tmp_path / "in"
    head = root / "sample.zip.001"
    second = root / "sample.zip.002"
    head.write_bytes(b"part-1")
    second.write_bytes(b"part-2")
    watcher.enqueue(str(head))
    watcher.enqueue(str(second))

    assert _run_once(watcher).failed == 1
    group_state = watcher.state.group_state(next(iter(watcher.state.groups)))
    assert group_state is not None
    assert group_state.status == "suspended"
    assert group_state.has_blocker("missing_volume")

    watcher.enqueue(str(head), force=True)
    assert _run_once(watcher).processed == 0
    third = root / "sample.zip.003"
    third.write_bytes(b"part-3")
    watcher.enqueue(str(third))

    assert _run_once(watcher).succeeded == 1
    assert attempts == [str(head.resolve()), str(head.resolve())]


def test_watch_combined_missing_volume_and_password_requires_both_changes(tmp_path):
    attempts: list[str] = []
    combined = FailureInfo(
        FailureKind.MISSING_VOLUME,
        "extraction",
        "missing volume and password",
        causes=(FailureInfo(FailureKind.WRONG_PASSWORD, "password_resolution", "wrong password"),),
    )

    class Runner:
        def __init__(self, config):
            pass

        def run_targets(self, paths):
            attempts.extend(paths)
            return _summary(combined) if len(attempts) == 1 else _summary()

    watcher = _watcher(tmp_path, Runner)
    root = tmp_path / "in"
    head = root / "sample.7z.001"
    second = root / "sample.7z.002"
    head.write_bytes(b"part-1")
    second.write_bytes(b"part-2")
    watcher.enqueue(str(head))
    watcher.enqueue(str(second))
    assert _run_once(watcher).failed == 1

    watcher.notify_password_source_changed("test")
    assert _run_once(watcher).processed == 0
    third = root / "sample.7z.003"
    third.write_bytes(b"part-3")
    watcher.enqueue(str(third))

    assert _run_once(watcher).succeeded == 1
    assert len(attempts) == 2


def test_watch_replaces_missing_blocker_with_password_blocker_after_retry(tmp_path):
    attempts: list[str] = []

    class Runner:
        def __init__(self, config):
            pass

        def run_targets(self, paths):
            attempts.extend(paths)
            if len(attempts) == 1:
                return _summary(FailureInfo(FailureKind.MISSING_VOLUME, "extraction", "missing volume"))
            if len(attempts) == 2:
                return _summary(FailureInfo(FailureKind.WRONG_PASSWORD, "password_resolution", "wrong password"))
            return _summary()

    watcher = _watcher(tmp_path, Runner)
    root = tmp_path / "in"
    head = root / "sample.7z.001"
    second = root / "sample.7z.002"
    head.write_bytes(b"part-1")
    second.write_bytes(b"part-2")
    watcher.enqueue(str(head))
    watcher.enqueue(str(second))
    assert _run_once(watcher).failed == 1

    third = root / "sample.7z.003"
    third.write_bytes(b"part-3")
    watcher.enqueue(str(third))
    assert _run_once(watcher).failed == 1
    watcher.notify_password_source_changed("test")

    assert _run_once(watcher).succeeded == 1
    assert len(attempts) == 3


def test_watch_combined_failure_waits_for_split_group_change(tmp_path):
    attempts: list[str] = []
    combined = FailureInfo(
        FailureKind.MISSING_VOLUME,
        "extraction",
        "missing split ZIP volume",
        causes=(FailureInfo(FailureKind.WRONG_PASSWORD, "password_resolution", "wrong password"),),
    )

    class Runner:
        def __init__(self, config):
            pass

        def run_targets(self, paths):
            attempts.extend(paths)
            return _summary(combined) if len(attempts) == 1 else _summary()

    watcher = _watcher(tmp_path, Runner)
    root = tmp_path / "in"
    head = root / "sample.7z.001"
    second = root / "sample.7z.002"
    head.write_bytes(b"7z\xbc\xaf\x27\x1c-head")
    second.write_bytes(b"part-2")
    watcher.enqueue(str(head))
    watcher.enqueue(str(second))
    assert _run_once(watcher).failed == 1

    watcher.notify_password_source_changed("test")
    assert _run_once(watcher).processed == 0
    third = root / "sample.7z.003"
    third.write_bytes(b"part-3")
    watcher.enqueue(str(third))

    assert _run_once(watcher).succeeded == 1
    assert attempts == [str(head.resolve()), str(head.resolve())]


def test_watch_split_suspension_survives_restart(tmp_path):
    attempts: list[str] = []

    class Runner:
        def __init__(self, config):
            pass

        def run_targets(self, paths):
            attempts.extend(paths)
            if len(attempts) == 1:
                return _summary(FailureInfo(FailureKind.MISSING_VOLUME, "extraction", "missing volume"))
            return _summary()

    first_watcher = _watcher(tmp_path, Runner)
    root = tmp_path / "in"
    head = root / "restart.7z.001"
    second = root / "restart.7z.002"
    head.write_bytes(b"part-1")
    second.write_bytes(b"part-2")
    first_watcher.enqueue(str(head))
    first_watcher.enqueue(str(second))
    assert _run_once(first_watcher).failed == 1

    restarted = _watcher(tmp_path, Runner)
    restarted.enqueue(str(head), force=True)
    assert _run_once(restarted).processed == 0
    third = root / "restart.7z.003"
    third.write_bytes(b"part-3")
    restarted.enqueue(str(third))

    assert _run_once(restarted).succeeded == 1
    assert len(attempts) == 2
