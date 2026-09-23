import pytest

from sunpack.core.analysis import (
    AnalysisBudget,
    AnalysisCapability,
    AnalysisCost,
    AnalysisRequest,
    ArchiveAnalyzer,
    FileAnalysisSource,
    MultiVolumeAnalysisSource,
)
from sunpack.core.analysis.result import ArchiveAnalysisReport


class _RecordingScheduler:
    def __init__(self):
        self.calls = []

    def analyze_path(self, path, **kwargs):
        self.calls.append(("file", path, kwargs))
        return _report(kwargs.get("report_path") or path)

    def analyze_paths(self, paths, **kwargs):
        self.calls.append(("volumes", tuple(paths), kwargs))
        return _report(kwargs.get("report_path") or "volume")


def _report(path):
    return ArchiveAnalysisReport(path=path, size=0, evidences=[], selected=[])


def test_archive_analyzer_dispatches_file_source_and_request():
    scheduler = _RecordingScheduler()
    analyzer = ArchiveAnalyzer(engine=scheduler)
    request = AnalysisRequest(
        capabilities=frozenset({AnalysisCapability.SIGNATURE_PREPASS}),
        budget=AnalysisBudget(max_cost=AnalysisCost.CHEAP),
        initial_prepass={"hits": []},
    )

    report = analyzer.analyze(FileAnalysisSource("sample.bin", report_path="logical.zip"), request)

    assert report.path == "logical.zip"
    assert scheduler.calls == [("file", "sample.bin", {
        "report_path": "logical.zip",
        "initial_prepass": {"hits": []},
        "capabilities": frozenset({AnalysisCapability.SIGNATURE_PREPASS}),
        "embedded_scan_allowed": True,
    })]


def test_archive_analyzer_dispatches_multi_volume_source():
    scheduler = _RecordingScheduler()
    analyzer = ArchiveAnalyzer(engine=scheduler)

    analyzer.analyze(MultiVolumeAnalysisSource(("a.001", "a.002"), report_path="a.zip"))

    assert scheduler.calls[0][0:2] == ("volumes", ("a.001", "a.002"))


def test_analysis_request_rejects_capability_over_budget():
    with pytest.raises(ValueError, match="exceed cheap budget"):
        AnalysisRequest(
            capabilities=frozenset({AnalysisCapability.EMBEDDED_SCAN}),
            budget=AnalysisBudget(max_cost=AnalysisCost.CHEAP),
        )
