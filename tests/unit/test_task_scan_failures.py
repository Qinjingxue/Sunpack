from sunpack.core.contracts.discovery import StageResult
from sunpack.core.contracts.run_state import RunState
from sunpack.core.support.filesystem_scan_errors import filesystem_scan_failure
from sunpack.pipeline.coordinator.task_scan import ArchiveTaskScanner


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
