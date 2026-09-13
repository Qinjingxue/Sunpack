from sunpack.contracts.detection import FactBag
from sunpack.detection.scheduler import DetectionScheduler
from sunpack.support.path_keys import path_key
from tests.helpers.config_factory import get_config


def _bag(path: str) -> FactBag:
    bag = FactBag()
    bag.set("file.path", path)
    return bag


class _EvidenceSession:
    def __init__(self, masks):
        self.masks = {path_key(path): mask for path, mask in masks.items()}

    def format_reject_masks_for_paths(self, paths):
        return {
            path_key(path): self.masks[path_key(path)]
            for path in paths
            if path_key(path) in self.masks
        }


def test_unified_format_prefill_only_handles_single_physical_inputs():
    scheduler = DetectionScheduler(get_config("minimal"))
    scheduler.enabled_processors = None
    scheduler._active_scan_session = object()

    single = _bag("C:/game/ordinary.bin")
    single.set("candidate.member_paths", ["C:/game/ordinary.bin"])
    split = _bag("C:/game/part.001")
    split.set("candidate.member_paths", ["C:/game/part.001", "C:/game/part.002"])
    companion = _bag("C:/game/launcher.exe")
    companion.set("candidate.member_paths", ["C:/game/launcher.exe"])
    companion.set("relation.is_split_exe_companion", True)

    scheduler._active_scan_session = _EvidenceSession({"C:/game/ordinary.bin": 31})
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


def test_unified_format_prefill_is_fail_open_and_requires_scan_session():
    scheduler = DetectionScheduler(get_config("minimal"))
    scheduler.enabled_processors = None
    single = _bag("C:/game/ordinary.bin")
    single.set("candidate.member_paths", ["C:/game/ordinary.bin"])

    scheduler._active_scan_session = None
    scheduler._prefill_format_negatives([single])
    scheduler._active_scan_session = _EvidenceSession({})
    scheduler._prefill_format_negatives([single])
    assert single.to_dict() == {
        "file.path": "C:/game/ordinary.bin",
        "candidate.member_paths": ["C:/game/ordinary.bin"],
    }


def test_unified_format_prefill_does_not_overwrite_existing_or_missing_facts():
    scheduler = DetectionScheduler(get_config("minimal"))
    scheduler.enabled_processors = None
    scheduler._active_scan_session = object()
    single = _bag("C:/game/ordinary.bin")
    single.set("candidate.member_paths", ["C:/game/ordinary.bin"])
    existing = {"plausible": True}
    single.set("zip.eocd_structure", existing)
    single.mark_missing("rar.structure")

    scheduler._active_scan_session = _EvidenceSession({"C:/game/ordinary.bin": 31})
    scheduler._prefill_format_negatives([single])

    assert single.get("zip.eocd_structure") is existing
    assert single.is_missing("rar.structure")
    assert single.get("7z.structure")["plausible"] is False
