import io
import tarfile

from sunpack_native import AnalysisBinaryView

from sunpack.core.analysis import ArchiveAnalyzer


def _tar_bytes(payload: bytes = b"payload") -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        info = tarfile.TarInfo("payload.txt")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    return output.getvalue()


def _tar_details(source) -> dict:
    config = {"analysis": {"modules": [
        {"name": "tar", "enabled": True},
    ]}}
    report = ArchiveAnalyzer(config).analyze(source)
    return next(item for item in report.evidences if item.format == "tar").details


def confirm_tar(path: str) -> bool:
    return ArchiveAnalyzer.confirm_format_identity(path, "tar")


def test_tar_analysis_preserves_detection_fields(tmp_path):
    path = tmp_path / "archive.bin"
    path.write_bytes(_tar_bytes())

    raw = _tar_details(str(path))

    assert raw["plausible"] is True
    assert raw["format"] == "ustar"
    assert raw["ustar_magic"] is True
    assert raw["fuzzy_name_nonempty"] is True
    assert raw["fuzzy_numeric_fields_valid"] is True
    assert raw["fuzzy_typeflag_valid"] is True
    assert raw["fuzzy_payload_in_range"] is True
    assert raw["stored_checksum"] == raw["computed_checksum"]
    assert raw["integrity_confidence"] == "high"
    assert raw["entry_walk_ok"] is True
    assert raw["end_zero_blocks"] is True


def test_tar_confirmation_uses_native_identity(tmp_path):
    path = tmp_path / "disguised.bin"
    path.write_bytes(_tar_bytes())
    assert confirm_tar(str(path)) is True


def test_tar_analysis_keeps_fuzzy_evidence_when_checksum_is_bad(tmp_path):
    data = bytearray(_tar_bytes())
    data[0] ^= 1
    path = tmp_path / "damaged.tar"
    path.write_bytes(data)

    raw = _tar_details(str(path))

    assert raw["plausible"] is False
    assert raw["ustar_magic"] is True
    assert raw["fuzzy_name_nonempty"] is True
    assert raw["fuzzy_numeric_fields_valid"] is True
    assert raw["fuzzy_typeflag_valid"] is True
    assert raw["fuzzy_payload_in_range"] is True
    assert raw["stored_checksum"] != raw["computed_checksum"]
    assert raw["error"] == "checksum_mismatch"


def test_tar_analysis_rejects_truncated_first_payload(tmp_path):
    data = _tar_bytes(payload=b"A" * 600)
    path = tmp_path / "truncated.tar"
    path.write_bytes(data[:700])

    raw = _tar_details(str(path))

    assert raw["fuzzy_payload_in_range"] is False
    assert raw["plausible"] is False
    assert raw["entry_walk_ok"] is False
    assert raw["error"] == "member_payload_out_of_range"
    assert "probably_truncated" in raw["damage_flags"]


def test_tar_detection_uses_first_header_only_and_keeps_deep_analysis_separate(tmp_path):
    data = bytearray(_tar_bytes(payload=b"A" * 32))
    # The first member occupies header + one padded payload block. Corrupt
    # later TAR metadata without touching the first header identity proof.
    second_header = 1024
    data[second_header] ^= 0x5A
    path = tmp_path / "later-damaged.tar"
    path.write_bytes(data)

    assert confirm_tar(str(path)) is True

    deep = _tar_details(str(path))
    assert deep["entry_walk_ok"] is True
    assert deep["walk_complete"] is False
    assert deep["error"]
    assert deep["damage_flags"]
