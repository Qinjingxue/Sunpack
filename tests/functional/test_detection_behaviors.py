import io
import zipfile

from sunpack.contracts.detection import FactBag
from sunpack.coordinator.task_provider import ArchiveTaskProvider
from sunpack.detection.scheduler import DetectionScheduler
from sunpack.embedded.discovery import select_single_candidate_ratio


def _zip_bytes() -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("inside.txt", "hello")
    return output.getvalue()


def _bag(path, size):
    bag = FactBag()
    bag.set("file.path", str(path))
    bag.set("file.size", size)
    return bag


def test_disguised_zip_is_resolved_by_relations(tmp_path):
    path = tmp_path / "movie.dat"
    path.write_bytes(_zip_bytes())
    result = ArchiveTaskProvider({"detection": {"enabled": True}}).discover_targets([str(path)])
    assert len(result.resolved_inputs) == 1
    assert result.resolved_inputs[0].source == "relations"


def test_embedded_carrier_with_prefix_and_suffix_is_discovered(tmp_path):
    path = tmp_path / "carrier.bin"
    path.write_bytes(b"prefix" + _zip_bytes() + b"suffix")
    result = ArchiveTaskProvider({"embedded_scan": {"enabled": True}}).discover_targets([str(path)])
    assert len(result.resolved_inputs) == 1
    assert result.resolved_inputs[0].source == "embedded"
    assert result.resolved_inputs[0].archive_input.open_mode == "file_range"


def test_embedded_switch_prevents_carrier_scan(tmp_path):
    path = tmp_path / "carrier.bin"
    path.write_bytes(b"prefix" + _zip_bytes() + b"suffix")
    result = ArchiveTaskProvider({"embedded_scan": {"enabled": False}}).discover_targets([str(path)])
    assert result.resolved_inputs == []


def test_detection_does_not_accept_relation_metadata(tmp_path):
    path = tmp_path / "fake.zip"
    path.write_bytes(b"plain text")
    bag = FactBag()
    bag.set("file.path", str(path))
    bag.set("relation.volume_anchor", {"format": "zip", "relation_confirmed": True})
    assert DetectionScheduler({}).evaluate_bag(bag).should_extract is False


def test_recursive_embedded_ratio_uses_individual_candidate_share(tmp_path):
    paths = [tmp_path / name for name in ("large", "medium", "small")]
    bags = [_bag(path, size) for path, size in zip(paths, (70, 25, 5))]
    assert select_single_candidate_ratio(bags, 0.3) == [bags[0]]
    assert select_single_candidate_ratio(bags, 0.05) == bags
    assert select_single_candidate_ratio(bags, 0) == []
