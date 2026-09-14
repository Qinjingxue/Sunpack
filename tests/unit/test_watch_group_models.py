from sunpack.filesystem.watcher.group_models import (
    BLOCKER_PASSWORD,
    WatchGroupSnapshot,
    WatchGroupState,
)
from sunpack.filesystem.watcher.group_dispatch import plan_watch_dispatches
import sunpack.coordinator.watch_group_coordinator as coordinator_module
from sunpack.filesystem.watcher.scanner import WatchCandidate
from sunpack.filesystem.watcher.state import WatchStateStore
from sunpack.coordinator.watch_group_coordinator import WatchGroupCoordinator
from sunpack.support.path_keys import path_key


def _snapshot(fingerprint: str, ownership_fingerprint: str | None = None) -> WatchGroupSnapshot:
    ownership_fingerprint = ownership_fingerprint or fingerprint
    return WatchGroupSnapshot(
        group_id="group",
        directory="/downloads",
        logical_name="archive",
        split_family="7z_numbered",
        head_path="/downloads/archive.7z.001",
        input_paths=("/downloads/archive.7z.001",),
        companion_paths=(),
        owned_paths=("/downloads/archive.7z.001",),
        input_fingerprint=fingerprint,
        ownership_fingerprint=ownership_fingerprint,
    )


def test_password_blocker_retries_when_split_group_input_changes():
    state = WatchGroupState(
        group_id="group",
        directory="/downloads",
        logical_name="archive",
        split_family="7z_numbered",
        head_path="/downloads/archive.7z.001",
        blockers=[BLOCKER_PASSWORD],
        last_attempted_input_fingerprint="old",
        password_generation=4,
    )

    assert state.retry_ready(_snapshot("new"), password_generation=4) is True
    assert state.retry_ready(_snapshot("old"), password_generation=4) is False
    assert state.retry_ready(_snapshot("old"), password_generation=5) is True


def test_companion_arrival_changes_ownership_without_restarting_same_input():
    state = WatchGroupState(
        group_id="group",
        directory="/downloads",
        logical_name="archive",
        split_family="7z_numbered",
        head_path="/downloads/archive.7z.001",
        status="done",
        last_attempted_input_fingerprint="same-input",
    )

    snapshot = _snapshot("same-input", ownership_fingerprint="launcher-arrived")

    assert state.retry_ready(snapshot, password_generation=0) is False


def test_split_group_fingerprint_includes_file_identity_and_usn(tmp_path, monkeypatch):
    archive = tmp_path / "archive.7z.001"
    archive.write_bytes(b"split volume")
    group = type("Group", (), {
        "split_volumes": [type("Volume", (), {
            "number": 1,
            "path": str(archive),
            "style": "7z_numbered",
            "source": "filename",
        })()],
        "input_paths": [str(archive)],
        "companion_paths": [],
        "owned_paths": [str(archive)],
        "relation": type("Relation", (), {"split_family": "7z_numbered"})(),
        "logical_name": "archive",
    })()
    observation = WatchCandidate(str(archive), archive.stat().st_size, archive.stat().st_mtime, "file-a", 10)
    monkeypatch.setattr(coordinator_module, "watch_candidate_for_path", lambda _path: observation)
    first = WatchGroupCoordinator({})._snapshot(group, str(tmp_path))

    observation = WatchCandidate(str(archive), archive.stat().st_size, archive.stat().st_mtime, "file-b", 11)
    second = WatchGroupCoordinator({})._snapshot(group, str(tmp_path))

    assert first.input_fingerprint != second.input_fingerprint


def test_watch_snapshot_uses_relation_owned_paths_for_launcher_events(tmp_path):
    launcher = tmp_path / "archive.exe"
    first = tmp_path / "archive.7z.001"
    second = tmp_path / "archive.7z.002"
    launcher.write_bytes(b"MZ")
    first.write_bytes(b"volume 1")
    second.write_bytes(b"volume 2")

    resolved = WatchGroupCoordinator({}).resolve_paths([str(launcher)])
    snapshot = resolved[path_key(str(launcher))]

    # A launcher and filename-like siblings without structural validation do
    # not form a relation proposal.
    assert snapshot is None


def test_watch_dispatch_treats_launcher_as_active_group_path(tmp_path):
    launcher = tmp_path / "archive.exe"
    first = tmp_path / "archive.7z.001"
    launcher.write_bytes(b"MZ")
    first.write_bytes(b"volume 1")
    snapshot = WatchGroupSnapshot(
        group_id="group",
        directory=str(tmp_path),
        logical_name="archive",
        split_family="7z_numbered",
        head_path=str(first),
        input_paths=(str(first),),
        companion_paths=(str(launcher),),
        owned_paths=(str(first), str(launcher)),
        input_fingerprint="input",
        ownership_fingerprint="owned",
    )

    class Resolver:
        def resolve_paths(self, paths):
            return {path_key(path): snapshot for path in paths}

    candidate = WatchCandidate(str(launcher), launcher.stat().st_size, launcher.stat().st_mtime)
    dispatches, waiting, deferred = plan_watch_dispatches(
        [candidate],
        active_paths={path_key(str(launcher))},
        coordinator=Resolver(),
        state=WatchStateStore(str(tmp_path / "state.json")),
        prepare_candidate=lambda _path: candidate,
    )

    assert dispatches == []
    assert waiting == []
    assert [item.candidate.path for item in deferred] == [str(launcher)]
