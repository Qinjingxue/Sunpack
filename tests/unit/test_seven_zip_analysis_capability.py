import struct
from binascii import crc32

from sunpack.core.analysis import ArchiveAnalyzer, SevenZipProbeOptions


def _seven_zip_bytes(version_major=0):
    next_header = b"\x01"
    start_header = struct.pack("<QQI", 0, len(next_header), crc32(next_header) & 0xFFFFFFFF)
    return (
        b"7z\xbc\xaf\x27\x1c"
        + bytes([version_major, 4])
        + struct.pack("<I", crc32(start_header) & 0xFFFFFFFF)
        + start_header
        + next_header
    )


def test_public_seven_zip_capability_preserves_detection_fields(tmp_path):
    path = tmp_path / "archive.bin"
    path.write_bytes(_seven_zip_bytes())

    raw = ArchiveAnalyzer().probe_seven_zip(str(path), SevenZipProbeOptions()).to_raw_dict()

    assert raw["magic_matched"] is True
    assert raw["version_major"] == 0
    assert raw["version_minor"] == 4
    assert raw["start_header_crc_ok"] is True
    assert raw["next_header_crc_ok"] is True
    assert raw["next_header_nid_valid"] is True
    assert raw["next_header_semantic_ok"] is True
    assert raw["strong_accept"] is True
    assert raw["detected_ext"] == ".7z"


def test_public_seven_zip_capability_rejects_unsupported_version(tmp_path):
    path = tmp_path / "future.7z"
    path.write_bytes(_seven_zip_bytes(version_major=1))

    raw = ArchiveAnalyzer().probe_seven_zip(str(path)).to_raw_dict()

    assert raw["magic_matched"] is True
    assert raw["plausible"] is False
    assert raw["strong_accept"] is False
    assert raw["error"] == "unsupported_version"
