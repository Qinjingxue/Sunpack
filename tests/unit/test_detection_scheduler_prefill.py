from sunpack.contracts.detection import FactBag
from sunpack.detection.scheduler import DetectionScheduler
from tests.helpers.config_factory import get_config


def _bag(path: str) -> FactBag:
    bag = FactBag()
    bag.set("file.path", path)
    return bag


def test_unified_format_prefill_only_handles_single_physical_inputs():
    scheduler = DetectionScheduler(get_config("minimal"))
    scheduler.enabled_processors = None

    single = _bag("C:/game/ordinary.bin")
    single.set("candidate.member_paths", ["C:/game/ordinary.bin"])
    single.set("candidate.format_reject_mask", 31)
    split = _bag("C:/game/part.001")
    split.set("candidate.member_paths", ["C:/game/part.001", "C:/game/part.002"])
    companion = _bag("C:/game/launcher.exe")
    companion.set("candidate.member_paths", ["C:/game/launcher.exe"])
    companion.set("relation.is_split_exe_companion", True)

    scheduler._prefill_format_negatives([single, split, companion])

    for fact_name in (
        "zip.eocd_structure",
        "rar.structure",
        "7z.structure",
        "tar.header_structure",
        "compression.stream_structure",
    ):
        assert single.get(fact_name)["plausible"] is False
        assert not split.has(fact_name)
        assert not companion.has(fact_name)


def test_unified_format_prefill_is_fail_open_without_snapshot_evidence():
    scheduler = DetectionScheduler(get_config("minimal"))
    scheduler.enabled_processors = None
    single = _bag("C:/game/ordinary.bin")
    single.set("candidate.member_paths", ["C:/game/ordinary.bin"])

    scheduler._prefill_format_negatives([single])
    assert single.to_dict() == {
        "file.path": "C:/game/ordinary.bin",
        "candidate.member_paths": ["C:/game/ordinary.bin"],
    }


def test_unified_format_prefill_does_not_overwrite_existing_or_missing_facts():
    scheduler = DetectionScheduler(get_config("minimal"))
    scheduler.enabled_processors = None
    single = _bag("C:/game/ordinary.bin")
    single.set("candidate.member_paths", ["C:/game/ordinary.bin"])
    single.set("candidate.format_reject_mask", 31)
    existing = {"plausible": True}
    single.set("zip.eocd_structure", existing)
    single.mark_missing("rar.structure")

    scheduler._prefill_format_negatives([single])

    assert single.get("zip.eocd_structure") is existing
    assert single.is_missing("rar.structure")
    assert single.get("7z.structure")["plausible"] is False
