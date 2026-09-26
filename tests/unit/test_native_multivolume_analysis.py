import io
import struct
import tarfile
from binascii import crc32

from sunpack.core.analysis.view import MultiVolumeBinaryView


_SEVEN_ZIP_SIGNATURE = b"7z\xbc\xaf\x27\x1c"


def _seven_zip_bytes(next_header: bytes) -> bytes:
    next_crc = crc32(next_header) & 0xFFFFFFFF
    start_header = struct.pack("<QQI", 0, len(next_header), next_crc)
    start_crc = crc32(start_header) & 0xFFFFFFFF
    return (
        _SEVEN_ZIP_SIGNATURE
        + b"\x00\x04"
        + struct.pack("<I", start_crc)
        + start_header
        + next_header
    )


def _write_parts(tmp_path, first: bytes, second: bytes | None = None):
    first_path = tmp_path / "archive.001"
    first_path.write_bytes(first)
    paths = [str(first_path)]
    if second is not None:
        second_path = tmp_path / "archive.002"
        second_path.write_bytes(second)
        paths.append(str(second_path))
    return paths


def _tar_bytes() -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        info = tarfile.TarInfo("payload.bin")
        info.size = 3
        archive.addfile(info, io.BytesIO(b"abc"))
    return output.getvalue()


def test_multivolume_7z_uses_native_parser_across_header_boundary_and_carrier_offset(tmp_path):
    next_header = b"\x01\x00"
    archive = _seven_zip_bytes(next_header)
    carrier = b"carrier-prefix" * 7
    logical = carrier + archive
    split = len(carrier) + 19
    paths = _write_parts(tmp_path, logical[:split], logical[split:])

    with MultiVolumeBinaryView(paths) as view:
        raw = view.probe_seven_zip(
            start_offset=len(carrier),
            max_next_header_check_bytes=1024 * 1024,
        )

    assert raw["error"] == ""
    assert raw["plausible"] is True
    assert raw["strong_accept"] is True
    assert raw["archive_offset"] == len(carrier)
    assert raw["segment_end"] == len(logical)
    assert raw["password_state"] == "not_required"


def test_multivolume_7z_missing_tail_reports_missing_volume(tmp_path):
    next_header = b"\x01\x00"
    archive = _seven_zip_bytes(next_header)
    paths = _write_parts(tmp_path, archive[:32])

    with MultiVolumeBinaryView(paths) as view:
        raw = view.probe_seven_zip(start_offset=0)

    assert raw["error"] == "next_header_out_of_range"
    assert raw["possible_missing_volume"] is True
    assert "missing_volume" in raw["damage_flags"]
    assert raw["read_error"]["field"] == "7z.next_header"


def test_multivolume_7z_encryption_is_structural_not_aes_byte_search(tmp_path):
    # AES method-id bytes appear only inside a FilesInfo property payload.
    # A byte-search heuristic would falsely classify this as encrypted.
    files_info_with_aes_bytes = bytes([
        0x01,       # Header
        0x05, 0x01, # FilesInfo, one file
        0x11, 0x04, # arbitrary property, four payload bytes
        0x06, 0xF1, 0x07, 0x01,
        0x00,       # FilesInfo End
        0x00,       # Header End
    ])
    archive = _seven_zip_bytes(files_info_with_aes_bytes)
    paths = _write_parts(tmp_path, archive[:35], archive[35:])

    with MultiVolumeBinaryView(paths) as view:
        raw = view.probe_seven_zip(start_offset=0)

    assert raw["error"] == ""
    assert raw["password_required"] is False
    assert raw["encrypted_header"] is False
    assert raw["encrypted_payload"] is False
    assert raw["encryption_scan_complete"] is True
    assert raw["password_state"] == "not_required"


def test_multivolume_7z_structural_aes_coder_is_encrypted(tmp_path):
    aes_header = bytes([
        0x01,       # Header
        0x04,       # MainStreamsInfo
        0x07,       # UnpackInfo
        0x0B, 0x01, 0x00,  # Folder, one inline folder
        0x01,       # one coder
        0x04,       # method-id length = 4
        0x06, 0xF1, 0x07, 0x01,  # 7z AES method id
        0x0C, 0x01, # CodersUnpackSize = 1
        0x00,       # UnpackInfo End
        0x00,       # MainStreamsInfo End
        0x00,       # Header End
    ])
    archive = _seven_zip_bytes(aes_header)
    paths = _write_parts(tmp_path, archive[:34], archive[34:])

    with MultiVolumeBinaryView(paths) as view:
        raw = view.probe_seven_zip(start_offset=0)

    assert raw["error"] == ""
    assert raw["password_required"] is True
    assert raw["encrypted_payload"] is True
    assert raw["encrypted_header"] is False
    assert raw["encryption_scan_complete"] is True
    assert raw["password_state"] == "required"


def test_multivolume_tar_walks_across_physical_volume_boundary(tmp_path):
    archive = _tar_bytes()
    # Split inside the first 512-byte TAR header.
    paths = _write_parts(tmp_path, archive[:173], archive[173:])

    with MultiVolumeBinaryView(paths) as view:
        raw = view.probe_tar(start_offset=0, max_entries_to_walk=16)

    assert raw["plausible"] is True
    assert raw["entry_walk_ok"] is True
    assert raw["entries_checked"] == 1
    assert raw["walk_complete"] is True
    assert raw["end_zero_blocks"] is True
