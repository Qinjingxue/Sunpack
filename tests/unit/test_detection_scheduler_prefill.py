from sunpack.core.analysis import ArchiveAnalyzer
from sunpack.core.contracts.archive_input import ArchiveInputDescriptor
from sunpack.core.contracts.discovery import DiscoveryCandidate
from sunpack.pipeline.discovery.detection.scheduler import DetectionScheduler


def _candidate(path: str, format_hint: str = "") -> DiscoveryCandidate:
    return DiscoveryCandidate(
        archive_input=ArchiveInputDescriptor.from_parts(
            archive_path=path, logical_name=path.rsplit("/", 1)[-1], format_hint=format_hint,
        ),
        carrier_path=path,
        cleanup_paths=(path,),
        route="detection",
    )


def test_unrouted_and_unsupported_candidates_do_not_run_confirmation(monkeypatch):
    scheduler = DetectionScheduler({})
    monkeypatch.setattr(
        ArchiveAnalyzer,
        "confirm_format_identity",
        staticmethod(lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("not routed"))),
    )

    for candidate in (
        _candidate("C:/game/misleading.tar"),
        _candidate("C:/game/archive.zip", "zip"),
    ):
        accepted, _ = scheduler.confirm(candidate)
        assert accepted is False
