from sunpack.core.contracts.discovery import StageResult
from sunpack.core.contracts.failures import FailureInfo, FailureKind
from sunpack.core.contracts.run_state import RunState
from sunpack.pipeline.coordinator.task_provider import ArchiveTaskProvider
from sunpack.pipeline.coordinator.task_scan import ArchiveTaskScanner


def test_recursive_provider_discovers_each_logical_root_independently(monkeypatch):
    provider = ArchiveTaskProvider({})
    build_calls = []
    discover_calls = []

    def fake_build(scan_roots, *, session, config):
        build_calls.append(tuple(scan_roots))
        return []

    def fake_discover(candidates, *, is_recursive_scan=False):
        discover_calls.append((tuple(candidates), is_recursive_scan))
        return StageResult()

    monkeypatch.setattr(
        "sunpack.pipeline.coordinator.task_provider.build_candidates_for_targets",
        fake_build,
    )
    monkeypatch.setattr(provider.discovery, "discover", fake_discover)

    result = provider.discover_targets(
        ["segment-a", "segment-b"],
        is_recursive_scan=True,
    )

    assert result.resolved_tasks == []
    assert build_calls == [("segment-a",), ("segment-b",)]
    assert discover_calls == [((), True), ((), True)]


def test_discover_targets_preserves_provider_failures_in_run_state(monkeypatch):
    context = RunState()
    scanner = ArchiveTaskScanner({}, context)
    failure = FailureInfo(
        kind=FailureKind.WRONG_PASSWORD,
        stage="embedded_boundary",
        message="wrong password",
    )

    def fake_discover_targets(*_args, **_kwargs):
        scanner.provider.failed_candidates = ["carrier.bin"]
        scanner.provider.failed_candidate_failures = [failure]
        return StageResult()

    monkeypatch.setattr(scanner.provider, "discover_targets", fake_discover_targets)

    assert scanner.discover_targets(["carrier.bin"]) == []
    assert context.scan_failed_tasks == ["carrier.bin"]
    assert context.scan_failures == [failure]
