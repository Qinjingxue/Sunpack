import bz2
import gzip
import lzma
import random

import zstandard

from sunpack_native import inspect_compression_stream_identity

from sunpack.core.analysis import ArchiveAnalyzer


_FORMATS = {
    "gzip": gzip.compress,
    "bzip2": bz2.compress,
    "xz": lambda data: lzma.compress(data, format=lzma.FORMAT_XZ),
    "zstd": lambda data: zstandard.ZstdCompressor().compress(data),
}


def confirm(path: str, fmt: str) -> bool:
    return ArchiveAnalyzer.confirm_format_identity(path, fmt)


def test_detection_stream_identity_is_bounded_independent_of_archive_size(tmp_path):
    payload = random.Random(20260924).randbytes(2 * 1024 * 1024)
    for fmt, encode in _FORMATS.items():
        path = tmp_path / f"large-{fmt}.bin"
        path.write_bytes(encode(payload))

        raw = dict(inspect_compression_stream_identity(str(path)))

        assert confirm(str(path), fmt) is True, fmt
        assert raw["identity_strong"] is True
        assert raw["validation_scope"] == "format_identity"
        assert raw["structure_validation_complete"] is False
        assert raw["integrity_validation_complete"] is False
        assert raw["boundary_exact"] is False
        assert raw["identity_bytes_read"] <= 64 * 1024 + 8


def test_detection_stream_identity_does_not_revalidate_payload_or_trailer(tmp_path):
    payload = random.Random(7).randbytes(256 * 1024)
    for fmt, encode in _FORMATS.items():
        encoded = bytearray(encode(payload))
        encoded[-1] ^= 0x5A
        path = tmp_path / f"tail-damaged-{fmt}.bin"
        path.write_bytes(encoded)

        assert confirm(str(path), fmt) is True, fmt


def test_detection_rejects_magic_only_compression_false_positives(tmp_path):
    cases = {
        "gzip": b"\x1f\x8b\x08\xe0" + b"\x00" * 32,
        "bzip2": b"BZh9" + b"not-a-bzip-marker" + b"\x00" * 16,
        "xz": b"\xfd7zXZ\x00" + b"\x00\x01" + b"\x00" * 20,
        "zstd": b"\x28\xb5\x2f\xfd\x08" + b"\x00" * 16,
    }
    for fmt, data in cases.items():
        path = tmp_path / f"false-positive-{fmt}.bin"
        path.write_bytes(data)
        assert confirm(str(path), fmt) is False, fmt

    wrong_format = tmp_path / "gzip-routed-as-xz.bin"
    wrong_format.write_bytes(gzip.compress(b"payload"))
    assert confirm(str(wrong_format), "xz") is False
