from unittest.mock import patch

from sunpack.contracts.detection import FactBag
from sunpack.detection.pipeline.facts.batch_provider import BatchFactProvider
from sunpack.detection.pipeline.processors.modules.format_structure import tar_header
from sunpack.detection.scheduler import DetectionScheduler
from sunpack.support.path_keys import path_key
from tests.helpers.config_factory import get_config


class _FakeScanSession:
    def __init__(self):
        self.calls = []

    def file_head_facts_for_paths(self, paths, *, magic_size, copy_results):
        self.calls.append((list(paths), magic_size, copy_results))
        return {
            path_key(path): {
                "size": 123,
                "mtime_ns": 456,
                "magic": b"PK\x03\x04extra",
            }
            for path in paths
        }


def _bag(path: str) -> FactBag:
    bag = FactBag()
    bag.set("file.path", path)
    return bag


def test_prefetch_file_head_facts_only_queries_bags_with_missing_facts():
    session = _FakeScanSession()
    provider = BatchFactProvider(scan_session=session)

    complete = _bag("C:/game/complete.bin")
    complete.set("file.size", 999)
    complete.set("file.magic_bytes", b"complete")
    complete.set("file.mtime_ns", 888)
    pending = _bag("C:/game/pending.bin")

    provider._prefetch_file_head_facts(
        [complete, pending],
        {"file.size", "file.magic_bytes"},
    )

    assert session.calls == [(["C:/game/pending.bin"], 16, False)]
    assert complete.to_dict() == {
        "file.path": "C:/game/complete.bin",
        "file.size": 999,
        "file.magic_bytes": b"complete",
        "file.mtime_ns": 888,
    }
    assert pending.get("file.size") == 123
    assert pending.get("file.magic_bytes") == b"PK\x03\x04extra"
    assert pending.get("file.mtime_ns") == 456

    provider._prefetch_file_head_facts(
        [complete, pending],
        {"file.size", "file.magic_bytes"},
    )

    assert len(session.calls) == 1


def test_precheck_head_warmup_skips_independent_detection_without_scan_session():
    scheduler = DetectionScheduler(get_config("minimal"))
    bag = _bag("C:/game/independent.bin")

    with patch("sunpack.detection.scheduler.BatchFactProvider") as provider:
        scheduler._active_scan_session = None
        scheduler._prefill_precheck_head_facts([bag])

    provider.assert_not_called()


def test_tar_batch_prefill_only_sets_definite_negative_bags():
    short = _bag("C:/game/short.bin")
    short.set("file.size", 128)
    pending = _bag("C:/game/pending.bin")
    pending.set("file.size", 512)
    unknown = _bag("C:/game/unknown.bin")
    unknown.set("file.size", 1024)
    complete = _bag("C:/game/complete.bin")
    complete.set("file.size", 2048)
    complete.set("tar.header_structure", {"plausible": True})

    with patch.object(
        tar_header.sunpack_native,
        "batch_tar_first_header_reject_indices",
        return_value=[0],
    ) as batch:
        tar_header.prefill_tar_header_definite_negatives([short, pending, unknown, complete])

    batch.assert_called_once_with(["C:/game/pending.bin", "C:/game/unknown.bin"])
    assert short.get("tar.header_structure")["plausible"] is False
    assert pending.get("tar.header_structure")["plausible"] is False
    assert not unknown.has("tar.header_structure")
    assert complete.get("tar.header_structure") == {"plausible": True}
