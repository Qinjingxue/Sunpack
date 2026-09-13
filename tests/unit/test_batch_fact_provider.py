from unittest.mock import patch

from sunpack.contracts.detection import FactBag
from sunpack.detection.pipeline.facts.batch_provider import BatchFactProvider
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
