from sunpack.core.contracts.discovery import StageResult
from sunpack.core.contracts.run_state import RunState
from sunpack.core.support.filesystem_scan_errors import filesystem_scan_failure
from sunpack.pipeline.coordinator.task_provider import ArchiveTaskProvider
from sunpack.pipeline.coordinator.task_scan import ArchiveTaskScanner


def test_recursive_provider_discovers_each_logical_root_independently(monkeypatch):
    provider = ArchiveTaskProvider({})
    build_calls = []
    discover_calls = []
    table = object()

    def fake_build(scan_roots, *, session, config):
        build_calls.append(tuple(scan_roots))
        return table

    def fake_discover(native_table, session, *, is_recursive_scan=False, include_details=True):
        discover_calls.append((native_table is table, session is not None, is_recursive_scan, include_details))
        return StageResult()

    monkeypatch.setattr(
        "sunpack.pipeline.coordinator.task_provider.build_native_table_for_targets",
        fake_build,
    )
    monkeypatch.setattr(provider.discovery, "discover_native", fake_discover)

    result = provider.discover_targets(
        ["segment-a", "segment-b"],
        is_recursive_scan=True,
    )

    assert result.tasks == []
    assert build_calls == [("segment-a",), ("segment-b",)]
    assert discover_calls == [(True, True, True, True), (True, True, True, True)]


def test_discover_targets_preserves_provider_failures_in_run_state(monkeypatch):
    context = RunState()
    scanner = ArchiveTaskScanner({}, context)
    failure = filesystem_scan_failure(("metadata", "carrier.bin", "Unable to read input"), "en")

    def fake_discover_targets(*_args, **_kwargs):
        scanner.provider.failed_candidate_failures = [failure]
        return StageResult()

    monkeypatch.setattr(scanner.provider, "discover_targets", fake_discover_targets)

    assert scanner.discover_targets(["carrier.bin"]) == []
    assert context.scan_failures == [failure]
