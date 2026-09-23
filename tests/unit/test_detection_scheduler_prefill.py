from sunpack.contracts.discovery import DiscoveryCandidate
from sunpack.detection.scheduler import DetectionScheduler


def _candidate(path: str, format_hint: str = "") -> DiscoveryCandidate:
    return DiscoveryCandidate(
        entry_path=path,
        member_paths=(path,),
        logical_name=path.rsplit("/", 1)[-1],
        carrier_path=path,
        cleanup_paths=(path,),
        route="detection",
        format_hint=format_hint,
    )


def test_unrouted_file_is_not_guessed_from_extension(monkeypatch):
    scheduler = DetectionScheduler({})
    monkeypatch.setattr(
        scheduler.analyzer,
        "probe_tar",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("not routed")),
    )

    accepted, _ = scheduler.confirm(_candidate("C:/game/misleading.tar"))

    assert accepted is False


def test_unsupported_format_does_not_run_any_confirmation(monkeypatch):
    scheduler = DetectionScheduler({})
    monkeypatch.setattr(
        scheduler.analyzer,
        "probe_tar",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("not routed")),
    )

    accepted, _ = scheduler.confirm(_candidate("C:/game/archive.zip", "zip"))

    assert accepted is False
