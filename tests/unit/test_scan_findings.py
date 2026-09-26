from sunpack.core.contracts.archive_input import (
    ArchiveInputDescriptor,
    ArchiveInputPart,
    InputExtent,
)
from sunpack.core.contracts.discovery import DiscoveryFinding, StageResult
from sunpack.core.contracts.tasks import ArchiveTask
from sunpack.pipeline.coordinator.scanner import ScanOrchestrator


def _segment(path: str, archive_format: str, start: int, end: int, name: str):
    descriptor = ArchiveInputDescriptor(
        entry_path=path,
        open_mode="file_range",
        format_hint=archive_format,
        logical_name=name,
        parts=[
            ArchiveInputPart(
                extent=InputExtent(path=path, start=start, end=end),
                role="main",
            )
        ],
        analysis={"segment_confidence": 1.0, "segment_source": "embedded"},
    )
    evidence = {
        "format": archive_format,
        "offset": start,
        "end_offset": end,
        "confidence": 1.0,
    }
    return descriptor, evidence


def test_scan_report_preserves_blocked_findings_without_creating_tasks(monkeypatch):
    finding = DiscoveryFinding(
        entry_path="carrier.bin",
        source="embedded",
        format="rar",
        status="blocked",
        reason="embedded_password_required",
        logical_name="carrier.bin_01_rar",
        part_paths=("carrier.bin",),
        offset=128,
        end_offset=None,
        boundary_kind="unresolved",
        extractable=False,
    )
    orchestrator = ScanOrchestrator({})
    monkeypatch.setattr(
        orchestrator.task_scanner,
        "scan_stage_result",
        lambda _paths: StageResult(findings=[finding]),
    )

    report = orchestrator.scan_report(["carrier.bin"])

    assert report.tasks == []
    assert report.findings == [finding]


def test_scan_report_projects_multiple_embedded_findings_from_one_task(monkeypatch):
    path = "carrier.bin"
    first = _segment(path, "zip", 16, 64, "carrier_01_zip")
    second = _segment(path, "7z", 96, 160, "carrier_02_7z")
    task = ArchiveTask.from_archive_input(
        first[0],
        discovery_source="embedded",
        discovery_segments=(first, second),
    )
    orchestrator = ScanOrchestrator({})
    monkeypatch.setattr(
        orchestrator.task_scanner,
        "scan_stage_result",
        lambda _paths: StageResult(resolved_tasks=[task]),
    )

    report = orchestrator.scan_report([path])

    assert len(report.tasks) == 1
    assert [finding.format for finding in report.findings] == ["zip", "7z"]
    assert [finding.offset for finding in report.findings] == [16, 96]
    assert [finding.end_offset for finding in report.findings] == [64, 160]
    assert all(finding.status == "resolved" for finding in report.findings)
    assert all(finding.extractable for finding in report.findings)
