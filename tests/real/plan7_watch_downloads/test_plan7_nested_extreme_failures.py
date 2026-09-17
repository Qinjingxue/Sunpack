from __future__ import annotations

import time
import zipfile
from pathlib import Path

from sunpack.contracts.failures import FailureKind
from sunpack.filesystem.watcher.toast import WatchToastCoordinator
from sunpack.platform.windows.toast_protocol import ToastSnapshotKind
from tests.helpers.real_archives import (
    ArchiveFixtureFactory,
    create_encrypted_zip_archive,
)
from tests.real.plan1_real_archives.plan1_support import run_plan1_pipeline
from tests.real.plan7_watch_downloads.plan7_support import (
    arrive_slowly,
    drive_watch_until,
    plan7_watch_config,
    start_watch,
)


FACTORY = ArchiveFixtureFactory()
INNER_PASSWORD = "nested-inner-password-only-fixture"


class _ToastHost:
    def __init__(self):
        self.snapshots = []
        self.clear_count = 0

    def publish(self, snapshot):
        self.snapshots.append(snapshot)

    def clear(self):
        self.clear_count += 1


def _terminal_toast(host):
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        terminal = [
            snapshot
            for snapshot in host.snapshots
            if snapshot.kind != ToastSnapshotKind.PROGRESS
        ]
        if terminal:
            return terminal[-1]
        time.sleep(0.01)
    return None


def _write_outer_zip(path: Path, entries: list[tuple[str, bytes]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, payload in entries:
            archive.writestr(name, payload)
    return path


def _nested_encrypted_outer(tmp_path: Path) -> Path:
    inner = create_encrypted_zip_archive(
        tmp_path / "fixtures",
        "nested-inner-encrypted",
        password=INNER_PASSWORD,
        encryption="ZipCrypto",
        payload_size=32 * 1024,
    )
    return _write_outer_zip(
        tmp_path / "archives" / "nested-outer-encrypted.zip",
        [
            ("outer-note.txt", b"outer is not encrypted"),
            ("nested-inner-encrypted.zip", inner.entry_path.read_bytes()),
        ],
    )


def _nested_missing_volume_outer(tmp_path: Path) -> Path:
    inner = FACTORY.create(
        tmp_path / "fixtures",
        "nested-inner-split",
        "7z",
        split=True,
        payload_size=620 * 1024,
        split_volume_size=80 * 1024,
    )
    parts = sorted(path for path in inner.archive_dir.iterdir() if path.is_file())
    assert len(parts) >= 3
    missing = next(
        path for path in parts if path.name.casefold().endswith(".002")
    )
    return _write_outer_zip(
        tmp_path / "archives" / "nested-outer-missing-volume.zip",
        [
            (path.name, path.read_bytes())
            for path in parts
            if path != missing
        ],
    )


def _failure_kinds(summary) -> list[FailureKind]:
    return [failure.kind for failure in list(summary.failures or [])]


def _settle_watch(harness):
    return drive_watch_until(
        harness.watcher,
        lambda: bool(harness.run_durations),
    )


def test_plan7_nested_inner_unknown_password_normal_mode(tmp_path, plan7_error):
    """外层无密码、内层密码未知时，普通模式只把内层报为密码错误。"""
    outer = _nested_encrypted_outer(tmp_path)
    summary = run_plan1_pipeline(outer, passwords=["definitely-wrong"])

    plan7_error.update({
        "case": "nested_outer_plain_inner_encrypted_normal",
        "outer": str(outer),
        "failure_kinds": [kind.value for kind in _failure_kinds(summary)],
        "failed_tasks": [str(item) for item in summary.failed_tasks],
    })
    assert summary.success_count == 1
    assert summary.partial_success_count == 0
    assert any(kind == FailureKind.WRONG_PASSWORD for kind in _failure_kinds(summary))
    assert any("nested-inner-encrypted.zip" in str(item) for item in summary.failed_tasks)


def test_plan7_nested_inner_missing_volume_normal_mode(tmp_path, plan7_error):
    """外层无密码、内层缺分卷时，内层可报缺卷或在扫描阶段忽略。"""
    outer = _nested_missing_volume_outer(tmp_path)
    summary = run_plan1_pipeline(outer, passwords=[])

    missing_volume_reported = any(
        kind == FailureKind.MISSING_VOLUME for kind in _failure_kinds(summary)
    )
    ignored_at_scan = not summary.failures and not summary.failed_tasks
    plan7_error.update({
        "case": "nested_outer_plain_inner_missing_volume_normal",
        "outer": str(outer),
        "failure_kinds": [kind.value for kind in _failure_kinds(summary)],
        "failed_tasks": [str(item) for item in summary.failed_tasks],
        "missing_volume_reported": missing_volume_reported,
        "ignored_at_scan": ignored_at_scan,
    })
    assert summary.success_count == 1
    assert summary.partial_success_count == 0
    assert missing_volume_reported or ignored_at_scan
    if missing_volume_reported:
        assert any("nested-inner-split.7z.001" in str(item) for item in summary.failed_tasks)


def test_plan7_nested_inner_unknown_password_watch_is_password_blocked(
    tmp_path,
    plan7_error,
):
    """watch 模式下，密码失败挂在实际内层任务并静默等待密码变化。"""
    outer = _nested_encrypted_outer(tmp_path)
    label = "nested-inner-password-watch"
    toast_config = plan7_watch_config(passwords=[])
    toast_config["watch"]["toast_completion_debounce_ms"] = 0
    toast_host = _ToastHost()
    toast = WatchToastCoordinator(toast_host, toast_config, str(tmp_path / label))
    harness = start_watch(
        tmp_path,
        label,
        passwords=[],
        notification_sink=toast,
    )
    try:
        arrive_slowly(harness, outer)
        result = _settle_watch(harness)
        terminal = _terminal_toast(toast_host)
        entry = next(iter(harness.watcher.state.entries.values()))
        plan7_error.update({
            "case": "nested_outer_plain_inner_encrypted_watch",
            "result": result.__dict__,
            "entry_path": entry.path,
            "entry_status": entry.status,
            "failure_kind": entry.failure_kind,
            "blockers": list((entry.failure_payload or {}).get("blockers") or []),
            "toast_kind": terminal.kind.value if terminal is not None else "",
        })
        assert result.failed == 1
        assert entry.status == "failed_password"
        assert Path(entry.path).name == "nested-inner-encrypted.zip"
        assert Path(entry.path) != outer
        assert entry.failure_kind == FailureKind.WRONG_PASSWORD.value
        assert (entry.failure_payload or {}).get("blockers") == ["password"]
        assert terminal is None
    finally:
        toast.stop()
        harness.close()


def test_plan7_nested_inner_missing_volume_watch_is_not_outer_volume_blocked(
    tmp_path,
    plan7_error,
):
    """watch 模式下，生成归档缺分卷是终态失败，不建立等待 blocker。"""
    outer = _nested_missing_volume_outer(tmp_path)
    label = "nested-inner-missing-volume-watch"
    toast_config = plan7_watch_config(passwords=[])
    toast_config["watch"]["toast_completion_debounce_ms"] = 0
    toast_host = _ToastHost()
    toast = WatchToastCoordinator(toast_host, toast_config, str(tmp_path / label))
    harness = start_watch(
        tmp_path,
        label,
        passwords=[],
        notification_sink=toast,
    )
    try:
        arrive_slowly(harness, outer)
        result = _settle_watch(harness)
        terminal = _terminal_toast(toast_host)
        events = (tmp_path / label / "events.jsonl").read_text(encoding="utf-8")
        missing_volume_reported = result.failed == 1 and any(
            "nested-inner-split.7z.001" in error for error in result.errors
        )
        ignored_at_scan = (
            result.failed == 0
            and result.succeeded == 1
            and not result.errors
        )
        plan7_error.update({
            "case": "nested_outer_plain_inner_missing_volume_watch",
            "result": result.__dict__,
            "state_entries": list(harness.watcher.state.entries),
            "state_groups": list(harness.watcher.state.groups),
            "failed_terminal_logged": '"event":"failed_terminal"' in events,
            "suspended_missing_volume_logged": '"event":"suspended_missing_volume"' in events,
            "missing_volume_reported": missing_volume_reported,
            "ignored_at_scan": ignored_at_scan,
            "toast_kind": terminal.kind.value if terminal is not None else "",
        })
        assert missing_volume_reported or ignored_at_scan
        assert not harness.watcher.state.entries
        assert not harness.watcher.state.groups
        assert '"event":"suspended_missing_volume"' not in events
        assert terminal is not None
        if missing_volume_reported:
            assert '"event":"failed_terminal"' in events
            assert terminal.kind == ToastSnapshotKind.FAILURE
            report = Path(terminal.actions[-1].target).read_text(encoding="utf-8")
            assert "nested-inner-split.7z.001" in report
        else:
            assert terminal.kind == ToastSnapshotKind.SUCCESS
    finally:
        toast.stop()
        harness.close()

