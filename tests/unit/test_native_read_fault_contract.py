import struct
import zlib

from sunpack.core.analysis.structure_pipeline.modules._read_fault import read_fault_damage_flags
from sunpack_native import AnalysisBinaryView


def test_native_zip_probe_reports_empty_archive_start_at_zero(tmp_path):
    archive = tmp_path / "empty.zip"
    archive.write_bytes(struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, 0, 0, 0, 0, 0))

    result = dict(AnalysisBinaryView(str(archive)).probe_zip(0, 16))

    assert result["plausible"] is True
    assert result["archive_starts_at_zero"] is True
    assert result["archive_start_kind"] == "empty_eocd"


def test_zip_tail_read_fault_names_eocd_and_suggests_missing_volume(tmp_path):
    archive = tmp_path / "truncated.zip"
    archive.write_bytes(b"PK\x05\x06")

    result = dict(AnalysisBinaryView(str(archive)).probe_zip(0, 16))

    assert result["error"] == "eocd_too_small"
    assert result["read_error"]["field"] == "zip.eocd"
    assert result["read_error"]["requested"] == 22
    assert result["read_error"]["actual"] == 4
    assert result["read_error"]["possible_missing_volume"] is True
    assert "field_read_error:zip.eocd" in read_fault_damage_flags(result)
    assert "missing_volume" in read_fault_damage_flags(result)


def test_seven_zip_declared_next_header_fault_names_tail_field(tmp_path):
    start_header = (
        (0).to_bytes(8, "little")
        + (4096).to_bytes(8, "little")
        + (0).to_bytes(4, "little")
    )
    archive = tmp_path / "truncated.7z.001"
    archive.write_bytes(
        b"7z\xbc\xaf\x27\x1c"
        + b"\x00\x04"
        + (zlib.crc32(start_header) & 0xFFFFFFFF).to_bytes(4, "little")
        + start_header
    )

    result = dict(AnalysisBinaryView(str(archive)).probe_seven_zip(0, 1024 * 1024))

    assert result["error"] == "next_header_out_of_range"
    assert result["read_error"]["field"] == "7z.next_header"
    assert result["read_error"]["offset"] == 32
    assert result["read_error"]["possible_missing_volume"] is True


def test_rar_head_fault_is_field_specific_without_missing_volume_guess(tmp_path):
    archive = tmp_path / "truncated.rar"
    archive.write_bytes(b"Rar!")

    result = dict(AnalysisBinaryView(str(archive)).probe_rar(0, 16))

    assert result["read_error"]["field"] == "rar.signature"
    assert result["read_error"]["location"] == "head"
    assert result["read_error"]["possible_missing_volume"] is False


def test_rar_declared_payload_beyond_eof_is_a_tail_or_volume_fault(tmp_path):
    body = b"\x73\x00\x80\x0b\x00" + (4096).to_bytes(4, "little")
    header_crc = (zlib.crc32(body) & 0xFFFF).to_bytes(2, "little")
    archive = tmp_path / "truncated-payload.rar"
    archive.write_bytes(b"Rar!\x1a\x07\x00" + header_crc + body)

    result = dict(AnalysisBinaryView(str(archive)).probe_rar(0, 16))

    assert result["error"] == "rar4_block_payload_out_of_range"
    assert result["read_error"]["field"] == "rar4.block.payload"
    assert result["read_error"]["possible_missing_volume"] is True


def test_tar_missing_end_blocks_at_physical_eof_is_noncanonical_boundary(tmp_path):
    header = bytearray(512)
    header[0:8] = b"file.txt"
    header[100:108] = b"0000644\0"
    header[108:116] = b"0000000\0"
    header[116:124] = b"0000000\0"
    header[124:136] = b"00000000000\0"
    header[136:148] = b"00000000000\0"
    header[148:156] = b"        "
    header[156] = ord("0")
    header[257:263] = b"ustar\0"
    checksum = sum(header)
    header[148:156] = f"{checksum:06o}\0 ".encode("ascii")
    archive = tmp_path / "missing-end-blocks.tar"
    archive.write_bytes(header)

    result = dict(AnalysisBinaryView(str(archive)).probe_tar(0, 16))

    assert result["error"] == "tar_end_zero_blocks_missing_at_eof"
    assert result["walk_complete"] is True
    assert result["segment_end"] == 512
    assert result["boundary_confidence"] == "medium"
    assert result.get("read_error") is None
    assert result.get("possible_missing_volume") is not True
    assert "missing_end_block" in result["damage_flags"]
