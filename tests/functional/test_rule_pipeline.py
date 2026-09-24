import io
import tarfile

from sunpack.core.contracts.archive_input import ArchiveInputDescriptor
from sunpack.core.contracts.discovery import DiscoveryCandidate
from sunpack.pipeline.discovery.detection.scheduler import DetectionScheduler
from sunpack.pipeline.discovery.detection.validation import validate_detection_contracts


def _tar_bytes() -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        info = tarfile.TarInfo("payload.txt")
        info.size = 5
        archive.addfile(info, io.BytesIO(b"hello"))
    return output.getvalue()


def _candidate(path, format_hint: str) -> DiscoveryCandidate:
    value = str(path)
    return DiscoveryCandidate(
        archive_input=ArchiveInputDescriptor.from_parts(
            archive_path=value, logical_name=path.name, format_hint=format_hint,
        ),
        carrier_path=value,
        cleanup_paths=(value,),
        route="detection",
        size=path.stat().st_size,
    )


def test_routed_tar_is_confirmed_with_disguised_extension(tmp_path):
    target = tmp_path / "random.bin"
    target.write_bytes(_tar_bytes())

    accepted, reason = DetectionScheduler({}).confirm(_candidate(target, "tar"))

    assert accepted is True
    assert reason == "Confirmed tar structure"


def test_tar_extension_does_not_establish_format(tmp_path):
    target = tmp_path / "archive.tar"
    target.write_bytes(b"plain text")

    accepted, _ = DetectionScheduler({}).confirm(_candidate(target, "tar"))

    assert accepted is False


def test_removed_pipeline_schema_is_rejected():
    result = validate_detection_contracts({
        "detection": {"rule_pipeline": {"precheck": []}},
    })
    assert result["errors"]
    assert any("rule_pipeline" in error for error in result["errors"])
