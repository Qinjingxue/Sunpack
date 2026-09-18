from pathlib import Path
import struct
import zlib


def _minimal_7z_header(payload_size: int) -> bytes:
    next_header = b"\x17\x06"
    start_header = struct.pack("<QQI", payload_size, len(next_header), zlib.crc32(next_header) & 0xFFFFFFFF)
    start_crc = zlib.crc32(start_header) & 0xFFFFFFFF
    return b"7z\xbc\xaf\x27\x1c" + b"\x00\x04" + struct.pack("<I", start_crc) + start_header


def build_cli_pipeline_fixture(root: Path) -> Path:
    fixture = root / "pipeline_run"
    fixture.mkdir(parents=True, exist_ok=True)
    # Small fixtures are fine: pytest disables the size_range filter via
    # SUNPACK_CONFIG_OVERRIDES, so there is no 1 MB floor to dodge.
    payload_size = 64 * 1024
    (fixture / "sample123456.7z.001").write_bytes(_minimal_7z_header(payload_size) + b"x" * payload_size + b"\x17\x06")
    (fixture / "sample123456.7z").write_bytes(b"companion-7z" + b"y" * payload_size)
    (fixture / "sample123456").write_bytes(b"companion-plain" + b"z" * payload_size)
    return fixture
