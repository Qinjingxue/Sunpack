from __future__ import annotations

import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from sunpack.runtime.watch.toast import WatchToastCoordinator
from sunpack.core.platform.windows.toast_protocol import (
    ToastActionKind,
    ToastProgressMode,
    ToastSnapshotKind,
)


class _Host:
    def __init__(self):
        self.snapshots = []
        self.clear_count = 0
        self._condition = threading.Condition()

    def publish(self, snapshot):
        with self._condition:
            self.snapshots.append(snapshot)
            self._condition.notify_all()

    def clear(self):
        with self._condition:
            self.clear_count += 1
            self._condition.notify_all()

    def wait_for_terminal_snapshots(self, timeout=1.0):
        with self._condition:
            ready = self._condition.wait_for(
                lambda: any(
                    snapshot.kind != ToastSnapshotKind.PROGRESS
                    for snapshot in self.snapshots
                ),
                timeout=timeout,
            )
            assert ready, "timed out waiting for a terminal toast snapshot"
            return [
                snapshot
                for snapshot in self.snapshots
                if snapshot.kind != ToastSnapshotKind.PROGRESS
            ]


def _config(*, language="en", debounce_ms=20):
    return {
        "cli": {"language": language},
        "watch": {
            "toast_completion_debounce_ms": debounce_ms,
            "toast_report_retention_days": 30,
            "toast_report_max_files": 32,
            "toast_report_max_bytes": 1024 * 1024,
        },
    }


def _task(path):
    return SimpleNamespace(main_path=str(path))


def _ready(coordinator, request_id, task):
    coordinator.progress(
        request_id,
        task,
        {
            "type": "progress",
            "event": "extract_started",
            "completed_bytes": 1,
            "total_bytes": 100,
        },
    )


def _terminal_snapshots(host):
    return [snapshot for snapshot in host.snapshots if snapshot.kind != ToastSnapshotKind.PROGRESS]


@pytest.mark.parametrize("errors", [[], ["output is in use"]])
@pytest.mark.parametrize("pause", [None, "space_blocked", "memory_blocked"])
@pytest.mark.parametrize("language", ["en", "zh"])
def test_stop_targets_only_current_batch_and_reports_cleanup_truthfully(tmp_path, errors, pause, language):
    # Normal success/failure aggregation cannot cover stale activation, repeated
    # stop, or falsely claiming rollback succeeded. One batch covers all three.
    host = _Host()
    coordinator = WatchToastCoordinator(host, _config(language=language), str(tmp_path / "state"))
    try:
        coordinator.submitted("active", str(tmp_path / "active.zip"))
        coordinator.submitted("scanning", str(tmp_path / "scanning.zip"))
        task = _task(tmp_path / "active.zip")
        _ready(coordinator, "active", task)
        if pause:
            coordinator.progress("active", task, {"event": pause})
        snapshot = host.snapshots[-1]
        assert snapshot.actions[0].kind == ToastActionKind.CANCEL_BATCH
        assert coordinator.cancel_batch("obsolete") == ()
        assert coordinator.cancel_batch(snapshot.batch_id) == ("active", "scanning")
        assert coordinator.cancel_batch(snapshot.batch_id) == ("active", "scanning")
        stopping = host.snapshots[-1]
        assert stopping.title == ("SunPack 正在停止" if language == "zh" else "SunPack is stopping")
        assert stopping.actions == ()
        assert stopping.progress_status == stopping.body == coordinator.i18n.t("interrupt.stopping")
        assert stopping.progress_mode == ToastProgressMode.INDETERMINATE
        assert stopping.progress_value_text == ""
        coordinator.progress("active", task, {"event": "memory_blocked"})
        assert host.snapshots[-1].title == stopping.title
        assert host.snapshots[-1].actions == ()
        coordinator.interrupted("active", errors)
        coordinator._finalize(coordinator._finalize_generation)
        assert not _terminal_snapshots(host)
        coordinator.interrupted("scanning", [])
        final = host.wait_for_terminal_snapshots()[-1]
        assert final.body == coordinator.i18n.t("interrupt.cleanup_failed" if errors else "interrupt.cleaned")
        assert coordinator.cancel_batch(snapshot.batch_id) == ()
    finally:
        coordinator.stop()


@pytest.mark.parametrize("late_ready", [False, True])
@pytest.mark.parametrize("errors", [[], ["output is in use"]])
def test_arrivals_during_stop_keep_controls_and_allow_finalization(tmp_path, late_ready, errors):
    # Ordinary stop tests admit every request before the click. Only this
    # arrival order catches inherited stop UI and a final invisible retirement.
    # Reuse one small coordinator lifecycle, with no polling or fixed sleeps.
    host = _Host()
    coordinator = WatchToastCoordinator(host, _config(), str(tmp_path / "state"))
    try:
        first, late = _task(tmp_path / "first.zip"), _task(tmp_path / "late.zip")
        coordinator.submitted("first", first.main_path)
        _ready(coordinator, "first", first)
        assert coordinator.cancel_batch(host.snapshots[-1].batch_id) == ("first",)
        coordinator.submitted("late", late.main_path)
        if late_ready:
            _ready(coordinator, "late", late)
            assert host.snapshots[-1].actions[0].kind == ToastActionKind.CANCEL_BATCH
            assert host.snapshots[-1].title != coordinator.i18n.t("interrupt.stopping_title")
        coordinator.interrupted("first", errors)
        if late_ready:
            assert host.snapshots[-1].actions[0].kind == ToastActionKind.CANCEL_BATCH
            coordinator.succeeded("late", [])
        else:
            coordinator.suppressed("late")
        final = host.wait_for_terminal_snapshots()[-1]
        assert coordinator.i18n.t("interrupt.cleanup_failed" if errors else "interrupt.cleaned") in final.body
        if late_ready:
            assert final.title == coordinator.i18n.t("toast.final.mixed.title" if errors else "toast.final.success.title")
        assert not coordinator._requests
    finally:
        coordinator.stop()


def test_aggregate_progress_regresses_when_a_new_archive_joins(tmp_path):
    host = _Host()
    coordinator = WatchToastCoordinator(host, _config(), str(tmp_path / "state"))
    first = _task(tmp_path / "first.zip")
    second = _task(tmp_path / "second.zip")
    coordinator.submitted("first", str(first.main_path))
    coordinator.submitted("second", str(second.main_path))

    _ready(coordinator, "first", first)
    coordinator.progress("first", first, {"type": "progress", "completed_bytes": 40, "total_bytes": 100})
    before_join = host.snapshots[-1]
    assert before_join.progress_mode == ToastProgressMode.DETERMINATE
    assert before_join.progress_value == pytest.approx(0.4)

    _ready(coordinator, "second", second)
    coordinator.progress("second", second, {"type": "progress", "completed_bytes": 0, "total_bytes": 300})
    after_join = host.snapshots[-1]
    assert after_join.progress_value == pytest.approx(0.1)
    assert "2" in after_join.progress_title

    coordinator.progress("second", second, {"type": "progress", "completed_bytes": 150, "total_bytes": 300})
    assert host.snapshots[-1].progress_value == pytest.approx(190 / 400)
    coordinator.stop()


def test_busy_batch_releases_completed_requests_and_bounds_failure_details(tmp_path):
    # A continuously active request prevents finalization. Normal drained-batch
    # tests miss retention and repeated progress scans of completed payloads.
    host = _Host()
    config = _config(debounce_ms=60_000)
    config["watch"]["toast_report_max_bytes"] = 1024
    coordinator = WatchToastCoordinator(host, config, str(tmp_path / "state"))
    active = _task(tmp_path / "active.zip")
    coordinator.submitted("active", active.main_path)
    _ready(coordinator, "active", active)
    output = tmp_path / "output"
    output.mkdir()
    for index in range(40):
        key = str(index)
        task = _task(tmp_path / f"{key}.zip")
        coordinator.submitted(key, task.main_path)
        _ready(coordinator, key, task)
        if index % 2:
            coordinator.failed(key, ["failed"], [{"message": "x" * 4096}])
        else:
            coordinator.succeeded(key, [str(output)])
    assert set(coordinator._requests) == {"active"}
    assert coordinator._batch.succeeded == coordinator._batch.failed == 20
    assert coordinator._batch.failure_chars <= coordinator.report_store.max_bytes // 4
    assert len(coordinator._batch.failure_details) < coordinator._batch.failed
    assert host.snapshots[-1].progress_value == pytest.approx(4001 / 4100)
    coordinator.succeeded("active", [])
    # The debounced final notification has not replaced progress yet. A drained
    # batch must already have removed its Stop action during that window.
    assert host.snapshots[-1].actions == ()
    coordinator._finalize(coordinator._finalize_generation)
    terminal = _terminal_snapshots(host)[-1]
    assert terminal.kind == ToastSnapshotKind.MIXED
    assert terminal.actions[0].target == str(output)
    report = Path(terminal.actions[-1].target).read_text(encoding="utf-8")
    assert "20" in report and "omitted" in report
    assert coordinator._batch.completed == 0
    coordinator.stop()


@pytest.mark.parametrize("language,title,hint", [
    ("zh", "SunPack 解压已暂停", "磁盘空间不足，释放空间后自动继续"),
    ("en", "SunPack extraction paused", "Disk full. Free space to resume automatically."),
])
def test_disk_full_toast_shows_recovery_hint_and_resumes(tmp_path, language, title, hint):
    host = _Host()
    coordinator = WatchToastCoordinator(host, _config(language=language), str(tmp_path / "state"))
    task = _task(tmp_path / "first.zip")
    coordinator.submitted("first", task.main_path)
    # A full output volume can block before the first extract_started event.
    coordinator.progress("first", task, {
        "event": "space_blocked", "volume_key": "C:",
        "episode_id": 1, "job_id": "job-1",
    })
    paused = host.snapshots[-1]
    assert paused.kind == ToastSnapshotKind.PROGRESS
    assert paused.title == title
    assert paused.progress_status == hint
    assert paused.progress_mode == ToastProgressMode.INDETERMINATE

    coordinator.progress("first", task, {
        "event": "space_resumed", "volume_key": "C:",
        "episode_id": 1, "job_id": "job-1",
    })
    resumed = host.snapshots[-1]
    assert resumed.kind == ToastSnapshotKind.PROGRESS
    assert resumed.title != title
    assert resumed.progress_status != hint
    coordinator.stop()


def test_space_waits_are_released_for_every_request_exit(tmp_path):
    # Suppression/abort and invisible failures bypass normal completion; two
    # concurrent jobs in one episode must retain only the surviving owner's job.
    for finish in ("suppressed", "aborted", "failed", "succeeded", "stop"):
        coordinator = WatchToastCoordinator(_Host(), _config(), str(tmp_path / "state"))
        for key in ("first", "second"):
            task = _task(tmp_path / f"{key}.zip")
            coordinator.submitted(key, task.main_path)
            coordinator.progress(key, task, {
                "event": "space_blocked", "volume_key": "C:", "episode_id": 1, "job_id": key,
            })
        if finish == "stop":
            coordinator.stop()
        elif finish == "failed":
            coordinator.failed("first", ["failed"], [])
        elif finish == "succeeded":
            coordinator.succeeded("first", [])
        else:
            getattr(coordinator, finish)("first")
        if finish != "stop":
            assert coordinator._space_blocked_jobs == {("C:", 1): {"second"}}
            coordinator.aborted("second")
        assert coordinator._space_blocked_jobs_empty()
        coordinator.stop()


def test_concurrent_requests_emit_one_unified_success_after_debounce(tmp_path):
    host = _Host()
    coordinator = WatchToastCoordinator(host, _config(debounce_ms=30), str(tmp_path / "state"))
    output_root = tmp_path / "out"
    first_output = output_root / "first"
    second_output = output_root / "second"
    first_output.mkdir(parents=True)
    second_output.mkdir()
    first = _task(tmp_path / "first.zip")
    second = _task(tmp_path / "second.zip")
    coordinator.submitted("first", str(first.main_path))
    coordinator.submitted("second", str(second.main_path))
    _ready(coordinator, "first", first)
    _ready(coordinator, "second", second)
    coordinator.progress("first", first, {"type": "progress", "completed_bytes": 100, "total_bytes": 100})
    coordinator.progress("second", second, {"type": "progress", "completed_bytes": 50, "total_bytes": 100})

    coordinator.succeeded("first", [str(first_output)])
    time.sleep(0.04)
    assert _terminal_snapshots(host) == []
    coordinator.succeeded("second", [str(second_output)])
    time.sleep(0.06)

    terminal = _terminal_snapshots(host)
    assert len(terminal) == 1
    assert terminal[0].kind == ToastSnapshotKind.SUCCESS
    assert terminal[0].actions[0].kind == ToastActionKind.OPEN_DIRECTORY
    assert terminal[0].actions[0].target == str(output_root)
    coordinator.stop()


def test_batch_id_is_stable_through_final_and_unique_per_batch(tmp_path):
    host = _Host()
    coordinator = WatchToastCoordinator(host, _config(debounce_ms=0), str(tmp_path / "state"))

    first = _task(tmp_path / "first.zip")
    coordinator.submitted("first", str(first.main_path))
    _ready(coordinator, "first", first)
    first_batch = host.snapshots[-1].batch_id
    assert first_batch
    coordinator.succeeded("first", [])
    first_terminal = host.wait_for_terminal_snapshots()
    assert first_terminal[-1].batch_id == first_batch

    second = _task(tmp_path / "second.zip")
    coordinator.submitted("second", str(second.main_path))
    _ready(coordinator, "second", second)
    second_batch = host.snapshots[-1].batch_id
    assert second_batch
    assert second_batch != first_batch
    coordinator.stop()


def test_new_ready_request_cancels_pending_finalization(tmp_path):
    host = _Host()
    coordinator = WatchToastCoordinator(host, _config(debounce_ms=60), str(tmp_path / "state"))
    first = _task(tmp_path / "first.zip")
    second = _task(tmp_path / "second.zip")
    coordinator.submitted("first", str(first.main_path))
    _ready(coordinator, "first", first)
    coordinator.succeeded("first", [])

    time.sleep(0.02)
    coordinator.submitted("second", str(second.main_path))
    _ready(coordinator, "second", second)
    time.sleep(0.07)
    assert _terminal_snapshots(host) == []

    coordinator.succeeded("second", [])
    time.sleep(0.08)
    terminal = _terminal_snapshots(host)
    assert len(terminal) == 1
    assert "2" in terminal[0].body
    coordinator.stop()


def test_mixed_batch_exposes_output_and_aggregate_failure_report(tmp_path):
    host = _Host()
    coordinator = WatchToastCoordinator(host, _config(), str(tmp_path / "state"))
    output = tmp_path / "out" / "good"
    output.mkdir(parents=True)
    good = _task(tmp_path / "good.zip")
    broken = _task(tmp_path / "broken.zip")
    coordinator.submitted("good", str(good.main_path))
    coordinator.submitted("broken", str(broken.main_path))
    _ready(coordinator, "good", good)
    _ready(coordinator, "broken", broken)

    coordinator.succeeded("good", [str(output)])
    coordinator.failed("broken", ["CRC mismatch"], [{"kind": "corrupt_archive"}])
    terminal = host.wait_for_terminal_snapshots(timeout=1.0)
    assert len(terminal) == 1
    assert terminal[0].kind == ToastSnapshotKind.MIXED
    assert [action.kind for action in terminal[0].actions] == [
        ToastActionKind.OPEN_DIRECTORY,
        ToastActionKind.OPEN_LOG,
    ]
    assert terminal[0].actions[0].target == str(output)
    assert Path(terminal[0].actions[1].target).is_file()
    coordinator.stop()


def test_password_or_missing_volume_suppression_never_creates_a_final_toast(tmp_path):
    host = _Host()
    coordinator = WatchToastCoordinator(host, _config(), str(tmp_path / "state"))
    coordinator.submitted("password", str(tmp_path / "locked.rar"))
    coordinator.suppressed("password")
    time.sleep(0.04)
    assert host.snapshots == []
    assert host.clear_count == 0

    task = _task(tmp_path / "late-missing.7z")
    coordinator.submitted("missing", str(task.main_path))
    _ready(coordinator, "missing", task)
    coordinator.suppressed("missing")
    time.sleep(0.04)
    assert _terminal_snapshots(host) == []
    assert host.clear_count == 1

    # Suppressing one member must also update the remaining single-archive name.
    remaining = _task(tmp_path / "remaining.zip")
    coordinator.submitted("missing", task.main_path)
    coordinator.submitted("remaining", remaining.main_path)
    _ready(coordinator, "missing", task)
    _ready(coordinator, "remaining", remaining)
    coordinator.suppressed("missing")
    assert "remaining.zip" in host.snapshots[-1].progress_title
    coordinator.succeeded("remaining", [])
    assert "remaining.zip" in host.snapshots[-1].progress_title
    coordinator.stop()


def test_failure_toast_does_not_interpret_nested_scope(tmp_path):
    host = _Host()
    coordinator = WatchToastCoordinator(host, _config(language="zh", debounce_ms=0), str(tmp_path / "state"))
    task = _task(tmp_path / "nested-inner.7z.001")
    coordinator.submitted("request", str(tmp_path / "outer.zip"))
    _ready(coordinator, "request", task)
    coordinator.failed(
        "request",
        [f"nested-inner.7z.001 [missing split volume]"],
        [{
            "kind": "missing_volume",
            "message": "missing split volume",
            "details": {"scope": "nested_archive", "reason": "missing_volume"},
        }],
    )
    terminal = host.wait_for_terminal_snapshots()
    assert len(terminal) == 1
    assert terminal[0].kind == ToastSnapshotKind.FAILURE
    assert "内层归档缺少分卷" not in terminal[0].body
    report = Path(terminal[0].actions[-1].target).read_text(encoding="utf-8")
    assert "nested-inner.7z.001" in report
    assert "原因：内层归档缺少分卷" not in report
    coordinator.stop()


def test_extract_ready_stays_invisible_until_native_extract_started(tmp_path):
    host = _Host()
    coordinator = WatchToastCoordinator(host, _config(debounce_ms=0), str(tmp_path / "state"))
    task = _task(tmp_path / "archive.zip")
    coordinator.submitted("request", str(task.main_path))

    coordinator.progress(
        "request",
        task,
        {
            "type": "semantic",
            "event": "extract_ready",
            "completed_bytes": 0,
            "total_bytes": 0,
        },
    )
    assert host.snapshots == []

    _ready(coordinator, "request", task)
    assert host.snapshots
    assert host.snapshots[-1].kind == ToastSnapshotKind.PROGRESS
    coordinator.stop()


def test_invisible_failure_does_not_create_a_final_toast(tmp_path):
    host = _Host()
    coordinator = WatchToastCoordinator(host, _config(debounce_ms=0), str(tmp_path / "state"))
    coordinator.submitted("request", str(tmp_path / "outer.zip"))
    coordinator.failed("request", ["failure"], [{"kind": "unknown"}])
    time.sleep(0.04)
    assert _terminal_snapshots(host) == []
    coordinator.stop()


def test_failure_toast_links_to_unique_localized_aggregate_report(tmp_path):
    host = _Host()
    coordinator = WatchToastCoordinator(host, _config(language="zh"), str(tmp_path / "state"))
    task = _task(tmp_path / "broken.zip")
    coordinator.submitted("broken", str(task.main_path))
    _ready(coordinator, "broken", task)
    coordinator.failed(
        "broken",
        ["CRC mismatch"],
        [{"kind": "corrupt_archive", "message": "CRC mismatch"}],
    )
    terminal = host.wait_for_terminal_snapshots(timeout=1.0)
    assert len(terminal) == 1
    assert terminal[0].kind == ToastSnapshotKind.FAILURE
    assert terminal[0].title == "解压失败"
    assert terminal[0].actions[-1].kind == ToastActionKind.OPEN_LOG
    report_path = terminal[0].actions[-1].target
    report = Path(report_path)
    text = report.read_text(encoding="utf-8")
    assert "SunPack watch 失败报告" in text
    assert "broken.zip" in text
    assert "CRC mismatch" in text
    assert report.parent.name == "failures"
    coordinator.stop()


@pytest.mark.parametrize("language", ["zh", "en"])
@pytest.mark.parametrize("separate_requests", [False, True])
@pytest.mark.parametrize("blocked_first", ["memory", "space"])
@pytest.mark.parametrize("resumed_first", ["memory", "space"])
def test_overlapping_resource_waits_clear_independently(tmp_path, language, separate_requests, blocked_first, resumed_first):
    # A batch can wait on different resources in different requests. Verify the
    # aggregate stays paused until the last reason clears, including task exit.
    host = _Host()
    coordinator = WatchToastCoordinator(host, _config(language=language), str(tmp_path / "state"))
    tasks = {"memory": _task(tmp_path / "first.7z"), "space": _task(tmp_path / "second.zip")}
    requests = {"memory": "first", "space": "second" if separate_requests else "first"}
    if not separate_requests:
        tasks["space"] = tasks["memory"]
    for resource in ("memory", "space"):
        key = requests[resource]
        if key not in coordinator._requests:
            coordinator.submitted(key, tasks[resource].main_path)
            _ready(coordinator, key, tasks[resource])

    def send(resource, action, **extra):
        coordinator.progress(requests[resource], tasks[resource], {
            "event": resource + "_" + action, "volume_key": "C:",
            "episode_id": 1, "job_id": resource, **extra})

    try:
        send(blocked_first, "blocked")
        send("space" if blocked_first == "memory" else "memory", "blocked")
        combined = coordinator.i18n.t("report.status.resources_paused")
        assert host.snapshots[-1].progress_value_text == combined
        send("space", "status", volume_query_ok=False, volume_query_error=21)
        unavailable = coordinator.i18n.t("report.status.disk_unavailable", error="21")
        assert host.snapshots[-1].progress_status == unavailable
        send("space", "status", volume_query_ok=True)
        assert unavailable not in host.snapshots[-1].progress_status
        send(resumed_first, "resumed")
        remaining = "space" if resumed_first == "memory" else "memory"
        label = coordinator.i18n.t("report.status." + ("disk" if remaining == "space" else "memory") + "_paused")
        assert host.snapshots[-1].progress_value_text == label
        assert host.snapshots[-1].progress_mode == ToastProgressMode.INDETERMINATE
        if separate_requests:
            coordinator.succeeded(requests[remaining], [])
        else:
            send(remaining, "resumed")
        resumed = host.snapshots[-1]
        assert resumed.title == coordinator.i18n.t("toast.progress.title")
        assert resumed.progress_mode == ToastProgressMode.DETERMINATE
        assert unavailable not in resumed.progress_status
        assert resumed.progress_value_text not in (label, combined)
    finally:
        coordinator.stop()
