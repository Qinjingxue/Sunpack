from sunpack.contracts.detection import FactBag
from sunpack.detection.scheduler import DetectionScheduler
from tests.helpers.config_factory import get_config


def _bag(path: str, *, members: list[str] | None = None) -> FactBag:
    bag = FactBag()
    bag.set("file.path", path)
    bag.set("candidate.member_paths", members or [path])
    return bag


def test_format_reject_mask_skips_only_single_file_prechecks(monkeypatch):
    config = get_config(
        "archive_scan_full",
        overrides={
            "detection": {
                "rule_pipeline": {
                    "precheck": [
                        {"name": "zip_structure_accept", "enabled": True},
                    ],
                },
            },
        },
    )
    scheduler = DetectionScheduler(config)
    single = _bag("C:/game/ordinary.bin")
    single.set("candidate.format_reject_mask", 1)

    def fail_if_facts_are_requested(*args, **kwargs):
        raise AssertionError("definite single-file reject must not run ZIP processor")

    monkeypatch.setattr(scheduler, "_ensure_pool_facts", fail_if_facts_are_requested)
    decision = scheduler.evaluate_bag(single)

    assert decision.should_extract is False
    assert not single.has("zip.eocd_structure")


def test_format_reject_mask_is_fail_open_for_split_inputs(monkeypatch):
    config = get_config(
        "archive_scan_full",
        overrides={
            "detection": {
                "rule_pipeline": {
                    "precheck": [
                        {"name": "zip_structure_accept", "enabled": True},
                    ],
                },
            },
        },
    )
    scheduler = DetectionScheduler(config)
    split = _bag(
        "C:/game/part.001",
        members=["C:/game/part.001", "C:/game/part.002"],
    )
    split.set("candidate.format_reject_mask", 1)
    requested: list[set[str]] = []

    def record_fact_request(fact_bags, required_facts, fact_configs=None):
        requested.append(set(required_facts))
        for bag in fact_bags:
            for fact_name in required_facts:
                bag.mark_missing(fact_name)

    monkeypatch.setattr(scheduler, "_ensure_pool_facts", record_fact_request)
    decision = scheduler.evaluate_bag(split)

    assert decision.should_extract is False
    assert requested == [{"zip.eocd_structure"}]


def test_extractable_pool_drops_negative_decisions():
    config = get_config("minimal")
    scheduler = DetectionScheduler(config)
    negative = _bag("C:/game/ordinary.bin")

    results = scheduler.evaluate_extractable_bags([negative])

    assert results == []
    assert negative.get("file.path") == "C:/game/ordinary.bin"
