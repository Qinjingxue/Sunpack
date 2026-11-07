import struct
from binascii import crc32

from sunpack.core.analysis import AnalysisRequest, ArchiveAnalyzer
from sunpack.core.analysis.embedded import scan_embedded_archives


def _seven_zip_bytes(*, version_major=0, next_header=b"\x01", declared_size=None):
    declared = len(next_header) if declared_size is None else declared_size
    start_header = struct.pack("<QQI", 0, declared, crc32(next_header) & 0xFFFFFFFF)
    return (
        b"7z\xbc\xaf\x27\x1c"
        + bytes([version_major, 4])
        + struct.pack("<I", crc32(start_header) & 0xFFFFFFFF)
        + start_header
        + next_header
    )


def _seven_zip_evidence(path, request=None):
    report = ArchiveAnalyzer().analyze(str(path), request)
    return report, next(item for item in report.evidences if item.format == "7z")


def test_seven_zip_analysis_preserves_detection_fields(tmp_path):
    path = tmp_path / "archive.bin"
    path.write_bytes(_seven_zip_bytes())

    report, evidence = _seven_zip_evidence(path)
    raw = evidence.details

    assert evidence.status == "extractable"
    assert report.best_selected is evidence
    assert raw["magic_matched"] is True
    assert raw["version_major"] == 0
    assert raw["version_minor"] == 4
    assert raw["start_header_crc_ok"] is True
    assert raw["next_header_crc_ok"] is True
    assert raw["next_header_nid_valid"] is True
    assert raw["next_header_semantic_ok"] is True
    assert raw["strong_accept"] is True
    assert raw["detected_ext"] == ".7z"


def test_seven_zip_analysis_rejects_unsupported_version(tmp_path):
    path = tmp_path / "future.7z"
    path.write_bytes(_seven_zip_bytes(version_major=1))

    report, evidence = _seven_zip_evidence(path)
    raw = evidence.details

    assert evidence.status == "weak"
    assert report.selected == []
    assert raw["magic_matched"] is True
    assert raw["plausible"] is False
    assert raw["strong_accept"] is False
    assert raw["error"] == "unsupported_version"


def test_damaged_seven_zip_never_reuses_guessed_embedded_end(tmp_path):
    path = tmp_path / "carrier.bin"
    start = 128
    path.write_bytes(b"c" * start + _seven_zip_bytes(declared_size=8192))

    # Analysis consumes discovered roots; it must not search the carrier again.
    prepass = scan_embedded_archives(str(path)).to_prepass()
    report, evidence = _seven_zip_evidence(path, AnalysisRequest(initial_prepass=prepass))

    assert evidence.status != "extractable"
    assert evidence.segments[0].start_offset == start
    assert evidence.segments[0].end_offset is None
    assert "boundary_unreliable" in evidence.segments[0].damage_flags
    assert evidence.details["boundary_confidence"] == "none"
    assert report.extractable_segments == ()


def test_exact_embedded_seven_zip_boundary_skips_next_header_revalidation(tmp_path):
    path = tmp_path / "carrier.bin"
    payload = _seven_zip_bytes()
    end = 128 + len(payload)
    path.write_bytes(b"\x00" * 128 + payload + b"carrier tail")
    prepass = scan_embedded_archives(str(path)).to_prepass()

    report, evidence = _seven_zip_evidence(path, AnalysisRequest(initial_prepass=prepass))

    assert evidence.status == "extractable"
    assert [(item.start_offset, item.end_offset) for item in evidence.segments] == [(128, end)]
    assert evidence.details["source"] == "embedded_scan"
    assert evidence.details["boundary_kind"] == "exact"
    assert evidence.details["integrity_confidence"] == "deferred"
    assert [(item[0].format, item[1].start_offset) for item in report.extractable_segments] == [("7z", 128)]
