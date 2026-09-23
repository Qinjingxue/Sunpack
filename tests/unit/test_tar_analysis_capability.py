import io
import tarfile

from sunpack.analysis import ArchiveAnalyzer, MultiVolumeAnalysisSource, TarProbeOptions
from sunpack.detection.formats.tar import confirm as confirm_tar


def _tar_bytes(payload: bytes = b"payload") -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        info = tarfile.TarInfo("payload.txt")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    return output.getvalue()


def test_public_tar_capability_preserves_detection_fields(tmp_path):
    path = tmp_path / "archive.bin"
    path.write_bytes(_tar_bytes())

    raw = ArchiveAnalyzer().probe_tar(
        str(path),
        TarProbeOptions(max_entries_to_walk=8),
    ).to_raw_dict()

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


def test_tar_confirmation_uses_public_analysis_observation(tmp_path):
    path = tmp_path / "disguised.bin"
    path.write_bytes(_tar_bytes())
    assert confirm_tar(str(path), ArchiveAnalyzer()) is True


def test_public_tar_capability_keeps_fuzzy_evidence_when_checksum_is_bad(tmp_path):
    data = bytearray(_tar_bytes())
    data[0] ^= 1
    path = tmp_path / "damaged.tar"
    path.write_bytes(data)

    raw = ArchiveAnalyzer().probe_tar(str(path)).to_raw_dict()

    assert raw["plausible"] is False
    assert raw["ustar_magic"] is True
    assert raw["fuzzy_name_nonempty"] is True
    assert raw["fuzzy_numeric_fields_valid"] is True
    assert raw["fuzzy_typeflag_valid"] is True
    assert raw["fuzzy_payload_in_range"] is True
    assert raw["stored_checksum"] != raw["computed_checksum"]
    assert raw["error"] == "checksum_mismatch"


def test_public_tar_capability_rejects_truncated_first_payload(tmp_path):
    data = _tar_bytes(payload=b"A" * 600)
    path = tmp_path / "truncated.tar"
    path.write_bytes(data[:700])

    raw = ArchiveAnalyzer().probe_tar(str(path)).to_raw_dict()

    assert raw["fuzzy_payload_in_range"] is False
    assert raw["plausible"] is False
    assert raw["entry_walk_ok"] is False
    assert raw["error"] == "member_payload_out_of_range"
    assert "probably_truncated" in raw["damage_flags"]


def test_tar_file_and_multi_volume_readers_return_same_observation(tmp_path):
    data = _tar_bytes(payload=b"split payload")
    whole = tmp_path / "whole.tar"
    first = tmp_path / "split.tar.001"
    second = tmp_path / "split.tar.002"
    whole.write_bytes(data)
    first.write_bytes(data[:400])
    second.write_bytes(data[400:])
    analyzer = ArchiveAnalyzer()

    file_raw = analyzer.probe_tar(str(whole)).to_raw_dict()
    split_raw = analyzer.probe_tar(MultiVolumeAnalysisSource((
        {"path": str(first), "number": 1},
        {"path": str(second), "number": 2},
    ))).to_raw_dict()

    fields = {
        "plausible", "format", "stored_checksum", "computed_checksum", "member_size",
        "ustar_magic", "fuzzy_name_nonempty", "fuzzy_numeric_fields_valid",
        "fuzzy_typeflag_valid", "fuzzy_payload_in_range", "entries_checked",
        "entry_walk_ok", "end_zero_blocks", "segment_end", "error",
    }
    assert {field: split_raw[field] for field in fields} == {
        field: file_raw[field] for field in fields
    }


def test_tar_native_and_multi_volume_fallback_match_damage(tmp_path):
    checksum_bad = bytearray(_tar_bytes())
    checksum_bad[0] ^= 1
    cases = [bytes(checksum_bad), _tar_bytes(payload=b"A" * 600)[:700]]
    analyzer = ArchiveAnalyzer()

    for index, data in enumerate(cases):
        whole = tmp_path / f"damaged-{index}.tar"
        first = tmp_path / f"damaged-{index}.tar.001"
        second = tmp_path / f"damaged-{index}.tar.002"
        whole.write_bytes(data)
        first.write_bytes(data[:400])
        second.write_bytes(data[400:])

        file_raw = analyzer.probe_tar(str(whole)).to_raw_dict()
        split_raw = analyzer.probe_tar(MultiVolumeAnalysisSource((
            {"path": str(first), "number": 1},
            {"path": str(second), "number": 2},
        ))).to_raw_dict()

        fields = {
            "plausible", "stored_checksum", "computed_checksum", "member_size",
            "ustar_magic", "fuzzy_numeric_fields_valid", "fuzzy_payload_in_range",
            "entries_checked", "entry_walk_ok", "error", "damage_flags",
        }
        assert {field: split_raw[field] for field in fields} == {
            field: file_raw[field] for field in fields
        }
