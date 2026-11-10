from weakref import ref

from sunpack.core.contracts.discovery import DiscoveryTrace, StageResult
from sunpack.core.contracts.failures import FailureInfo, FailureKind
from sunpack.core.contracts.run_state import RunState
from sunpack.pipeline.coordinator.task_scan import ArchiveTaskScanner


def test_discovery_records_each_batch_and_releases_its_session(monkeypatch):
    context = RunState()
    scanner = ArchiveTaskScanner({}, context)
    error = DiscoveryTrace("carrier.bin", "embedded",
                           reason="embedded_scan_io_error", error="Unable to read input")
    failure = FailureInfo(FailureKind.FILESYSTEM_ERROR, "embedded_boundary", error.error,
                          details={"path": error.entry_path, "reason": error.reason})
    sessions = []
    reported = []

    def fake_discover_targets(roots, *, scan_session, **_kwargs):
        sessions.append(ref(scan_session))
        return StageResult(traces=[error] if roots == ["carrier.bin"] else [])

    def record_failures(failures, language):
        failures = list(failures)
        reported.append(failures)
        RunState.record_failures(context, failures, language)

    monkeypatch.setattr(context, "record_failures", record_failures)
    monkeypatch.setattr(scanner.provider, "discover_targets", fake_discover_targets)

    assert scanner.discover_targets(["carrier.bin"]) == []
    assert sessions[-1]() is None
    assert scanner.discover_targets(["different.bin"]) == []
    assert sessions[-1]() is None
    assert reported == [[failure], []]
    assert context.scan_failures == [failure]
