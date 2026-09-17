import json

from sunpack.filesystem.watcher.group_models import WatchGroupState
from sunpack.filesystem.watcher.state import WatchStateStore


def test_native_checkpoint_persists_only_declared_dataclass_fields(tmp_path):
    state_path = tmp_path / "state.json"
    state = WatchStateStore(str(state_path))
    group = WatchGroupState(
        group_id="group-runtime-field",
        directory=str(tmp_path),
        logical_name="archive",
        split_family="7z",
        head_path=str(tmp_path / "archive.7z.001"),
        input_paths=[str(tmp_path / "archive.7z.001")],
        owned_paths=[str(tmp_path / "archive.7z.001")],
        status="waiting",
    )
    group.runtime_only_probe = {"must_not_persist": True}
    state.groups[group.group_id] = group

    state.save()

    payload = json.loads(state_path.read_text(encoding="utf-8"))
    persisted = payload["groups"][group.group_id]
    assert "runtime_only_probe" not in persisted
    assert persisted["group_id"] == group.group_id
    assert WatchStateStore(str(state_path)).group_state(group.group_id) is not None
