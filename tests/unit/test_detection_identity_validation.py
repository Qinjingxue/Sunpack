import bz2
import gzip
import lzma
import random

import zstandard

from sunpack.core.analysis import ArchiveAnalyzer
from sunpack.core.analysis.probes.compression_stream import CompressionStreamProbeOptions
from sunpack.pipeline.discovery.detection.formats import bzip2 as bzip2_format
from sunpack.pipeline.discovery.detection.formats import gzip as gzip_format
from sunpack.pipeline.discovery.detection.formats import xz as xz_format
from sunpack.pipeline.discovery.detection.formats import zstd as zstd_format


_FORMATS = {
    "gzip": (gzip_format.confirm, gzip.compress),
    "bzip2": (bzip2_format.confirm, bz2.compress),
    "xz": (xz_format.confirm, lambda data: lzma.compress(data, format=lzma.FORMAT_XZ)),
    "zstd": (zstd_format.confirm, lambda data: zstandard.ZstdCompressor().compress(data)),
}


def test_detection_stream_identity_is_bounded_independent_of_archive_size(tmp_path):
    payload = random.Random(20260924).randbytes(2 * 1024 * 1024)
    analyzer = ArchiveAnalyzer()

    for fmt, (confirm, encode) in _FORMATS.items():
        path = tmp_path / f"large-{fmt}.bin"
        path.write_bytes(encode(payload))

        raw = analyzer.probe_compression_stream(
            str(path),
            CompressionStreamProbeOptions(format=fmt, identity_only=True),
        ).to_raw_dict()

        assert confirm(str(path), analyzer) is True, fmt
        assert raw["identity_strong"] is True
        assert raw["validation_scope"] == "format_identity"
        assert raw["structure_validation_complete"] is False
        assert raw["integrity_validation_complete"] is False
        assert raw["boundary_exact"] is False
        assert raw["identity_bytes_read"] <= 64 * 1024 + 8


def test_detection_stream_identity_does_not_revalidate_payload_or_trailer(tmp_path):
    payload = random.Random(7).randbytes(256 * 1024)
    analyzer = ArchiveAnalyzer()

    for fmt, (confirm, encode) in _FORMATS.items():
        encoded = bytearray(encode(payload))
        encoded[-1] ^= 0x5A
        path = tmp_path / f"tail-damaged-{fmt}.bin"
        path.write_bytes(encoded)

        assert confirm(str(path), analyzer) is True, fmt


def test_detection_rejects_magic_only_compression_false_positives(tmp_path):
    cases = {
        "gzip": (
            gzip_format.confirm,
            b"\x1f\x8b\x08\xe0" + b"\x00" * 32,
        ),
        "bzip2": (
            bzip2_format.confirm,
            b"BZh9" + b"not-a-bzip-marker" + b"\x00" * 16,
        ),
        "xz": (
            xz_format.confirm,
            b"\xfd7zXZ\x00" + b"\x00\x01" + b"\x00" * 20,
        ),
        "zstd": (
            zstd_format.confirm,
            b"\x28\xb5\x2f\xfd\x08" + b"\x00" * 16,
        ),
    }
    analyzer = ArchiveAnalyzer()

    for fmt, (confirm, data) in cases.items():
        path = tmp_path / f"false-positive-{fmt}.bin"
        path.write_bytes(data)
        assert confirm(str(path), analyzer) is False, fmt
