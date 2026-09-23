from sunpack.contracts.detection import FactBag
from sunpack.detection.scheduler import DetectionScheduler


def test_unrouted_file_is_not_guessed_from_extension(monkeypatch):
    scheduler = DetectionScheduler({})
    bag = FactBag()
    bag.set("file.path", "C:/game/misleading.tar")
    monkeypatch.setattr(
        scheduler.analyzer, "probe_tar",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("not routed")),
    )
    assert scheduler.evaluate_bag(bag).should_extract is False


def test_unsupported_format_does_not_run_any_confirmation(monkeypatch):
    scheduler = DetectionScheduler({})
    bag = FactBag()
    bag.set("file.path", "C:/game/archive.zip")
    bag.set("filesystem.format_hint", "zip")
    monkeypatch.setattr(
        scheduler.analyzer, "probe_tar",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("not routed")),
    )
    assert scheduler.evaluate_bag(bag).should_extract is False
