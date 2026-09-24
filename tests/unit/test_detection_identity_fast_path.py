from __future__ import annotations

import bz2
import gzip
import lzma
from io import BytesIO
import tarfile

import pytest
import zstandard

from sunpack.core.analysis import (
    ArchiveAnalyzer,
    CompressionStreamProbeOptions,
    TarProbeOptions,
)


def _stream_bytes(archive_format: str, payload: bytes) -> bytes:
    if archive_format == "gzip":
        return gzip.compress(payload)
    if archive_format == "bzip2":
        return bz2.compress(payload)
    if archive_format == "xz":
        return lzma.compress(payload)
    if archive_format == "zstd":
        return zstandard.ZstdCompressor().compress(payload)
    raise AssertionError(archive_format)


@pytest.mark.parametrize("archive_format", ["gzip", "bzip2", "xz", "zstd"])
def test_stream_detection_uses_bounded_strong_identity(tmp_path, archive_format):
    path = tmp_path / f"payload-{archive_format}.bin"
    path.write_bytes(_stream_bytes(archive_format, b"A" * (256 * 1024)))

    raw = ArchiveAnalyzer().probe_compression_stream(
        str(path),
        CompressionStreamProbeOptions(format=archive_format, identity_only=True),
    ).to_raw_dict()

    assert raw["format"] == archive_format
    assert raw["plausible"] is True
    assert raw["identity_strong"] is True
    assert raw["validation_scope"] == "format_identity"
    assert raw["validation_cost"] == "bounded"
    assert raw["structure_validation_complete"] is False
    assert raw["boundary_exact"] is False
    assert raw["identity_bytes_read"] <= 64


@pytest.mark.parametrize(
    ("archive_format", "data"),
    [
        ("gzip", b"\x1f\x8b\x00" + b"\x00" * 64),
        ("bzip2", b"BZh9" + b"not-a-bzip-marker" + b"\x00" * 64),
        ("xz", b"\xfd7zXZ\x00" + b"\x00" * 26),
        ("zstd", b"\x28\xb5\x2f\xfd\x18" + b"\x00" * 64),
    ],
)
def test_stream_identity_rejects_magic_only_lookalikes(tmp_path, archive_format, data):
    path = tmp_path / f"lookalike-{archive_format}.bin"
    path.write_bytes(data)

    raw = ArchiveAnalyzer().probe_compression_stream(
        str(path),
        CompressionStreamProbeOptions(format=archive_format, identity_only=True),
    ).to_raw_dict()

    assert raw["plausible"] is False
    assert raw.get("identity_strong") is not True


def _tar_bytes() -> bytes:
    output = BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        info = tarfile.TarInfo("payload.txt")
        payload = b"payload"
        info.size = len(payload)
        archive.addfile(info, BytesIO(payload))
    return output.getvalue()


def test_tar_zero_walk_budget_is_identity_only(tmp_path):
    path = tmp_path / "payload.tar"
    path.write_bytes(_tar_bytes())

    observation = ArchiveAnalyzer().probe_tar(
        str(path),
        TarProbeOptions(max_entries_to_walk=0),
    )
    raw = observation.to_raw_dict()

    assert raw["plausible"] is True
    assert raw["identity_strong"] is True
    assert raw["validation_scope"] == "format_identity"
    assert raw["entries_checked"] == 0
    assert raw["entry_walk_ok"] is False
    assert "tar_header" in observation.capabilities
    assert "tar_entry_walk" not in observation.capabilities
