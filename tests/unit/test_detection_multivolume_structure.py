from sunpack.core.contracts.failures import FailureKind
from sunpack.core.support.path_keys import path_key
from sunpack.pipeline.coordinator.task_provider import ArchiveTaskProvider
from tests.helpers.config_factory import make_config
from tests.helpers.fs_builder import make_minimal_7z


def test_native_discovery_keeps_complete_blocked_and_residual_families_separate(tmp_path):
    # Replaces synthetic Resolver-only tests: one native scan checks ownership
    # across competing successful, incomplete and unrecognized physical inputs.
    # Isolated family tests cannot detect their paths leaking between routes.
    payload = make_minimal_7z()
    first = tmp_path / "complete.7z.001.photo"
    second = tmp_path / "complete.7z.002.text"
    missing = tmp_path / "missing.7z.001.photo"
    unknown = tmp_path / "unknown.opaque"
    first.write_bytes(payload[:32])
    second.write_bytes(payload[32:])
    missing.write_bytes(payload[:32])
    unknown.write_bytes(b"ordinary file")

    result = ArchiveTaskProvider(make_config()).discover_targets([str(tmp_path)])

    assert len(result.tasks) == 2
    complete = next(task for task in result.tasks if task.discovery_failure is None)
    blocked = next(task for task in result.tasks if task.discovery_failure is not None)
    assert complete.all_parts == [str(first), str(second)]
    assert blocked.main_path == str(missing)
    assert blocked.discovery_failure.kind is FailureKind.MISSING_VOLUME
    assert result.claimed_paths == {path_key(str(first)), path_key(str(second))}
    assert result.blocked_paths == {path_key(str(missing))}
    assert path_key(str(unknown)) in result.residual_paths
    result.validate()
