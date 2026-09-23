import io
import tarfile

from sunpack.contracts.detection import FactBag
from sunpack.detection.scheduler import DetectionScheduler
from sunpack.detection.validation import validate_detection_contracts


def _tar_bytes() -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        info = tarfile.TarInfo("payload.txt")
        info.size = 5
        archive.addfile(info, io.BytesIO(b"hello"))
    return output.getvalue()


def test_routed_tar_is_confirmed_with_disguised_extension(tmp_path):
    target = tmp_path / "random.bin"
    target.write_bytes(_tar_bytes())
    bag = FactBag()
    bag.set("file.path", str(target))
    bag.set("filesystem.format_hint", "tar")
    decision = DetectionScheduler({}).evaluate_bag(bag)
    assert decision.should_extract is True
    assert bag.get("file.detected_ext") == ".tar"


def test_tar_extension_does_not_establish_format(tmp_path):
    target = tmp_path / "archive.tar"
    target.write_bytes(b"plain text")
    bag = FactBag()
    bag.set("file.path", str(target))
    bag.set("filesystem.format_hint", "tar")
    assert DetectionScheduler({}).evaluate_bag(bag).should_extract is False


def test_removed_pipeline_schema_is_rejected():
    result = validate_detection_contracts({
        "detection": {"rule_pipeline": {"precheck": []}},
    })
    assert result["errors"]
    assert any("rule_pipeline" in error for error in result["errors"])
