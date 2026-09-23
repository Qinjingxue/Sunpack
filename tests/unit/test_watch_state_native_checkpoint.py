import json

from sunpack.runtime.watch.state import WatchStateStore


def test_native_checkpoint_persists_only_declared_dataclass_fields(tmp_path):
    state_path = tmp_path / "state.json"
    state = WatchStateStore(str(state_path))
    archive = tmp_path / "archive.7z"
    state.mark(
        str(archive),
        7,
        12.0,
        status="failed_password",
        failure_payload={"blockers": ["password"]},
    )
    entry = state.latest_entry_for_path(str(archive))
    assert entry is not None
    entry.runtime_only_probe = {"must_not_persist": True}

    state.save()

    payload = json.loads(state_path.read_text(encoding="utf-8"))
    [persisted] = payload["entries"].values()
    assert "runtime_only_probe" not in persisted
    assert persisted["path"] == str(archive)
    assert WatchStateStore(str(state_path)).latest_entry_for_path(str(archive)) is not None
