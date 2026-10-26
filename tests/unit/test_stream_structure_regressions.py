import bz2
import asyncio
import io
import lzma
import os
import tarfile
import time

import pytest
import zstandard
from sunpack_native import inspect_compression_stream_structure, inspect_tar_header_structure


def test_gzip_optional_header_contract_is_shared_by_analysis_identity_and_carving(tmp_path):
    # The streaming parser's optional-header tests cannot detect a separate
    # analysis/identity parser misplacing FHCRC. One small matrix covers all
    # optional-field combinations, split headers, invalid CRC and truncation.
    import struct
    import zlib
    from sunpack_native import (
        AnalysisBinaryView, AnalysisMultiVolumeView, NativeAnalysisConfig,
        inspect_compression_stream_identity, scan_embedded_archives,
    )

    raw = _tar("payload.txt")
    cfg = NativeAnalysisConfig({"modules": [{"name": "tar_gz", "enabled": True}]})
    for optional in range(8):
        for crc in (False, True):
            flags = (optional << 2) | (2 if crc else 0)
            head = bytearray(b"\x1f\x8b\x08" + bytes([flags]) + bytes(6))
            if flags & 4:
                head.extend(struct.pack("<H", 513) + b"x" * 513)
            if flags & 8:
                head.extend(b"payload-" + b"n" * 300 + b".tar\0")
            if flags & 16:
                head.extend(b"comment" * 50 + b"\0")
            if crc:
                head.extend(struct.pack("<H", zlib.crc32(head) & 0xFFFF))
            encoder = zlib.compressobj(wbits=-15)
            body = bytes(head) + encoder.compress(raw) + encoder.flush()
            body += struct.pack("<II", zlib.crc32(raw), len(raw))
            path = tmp_path / f"{optional}-{crc}.bin"
            path.write_bytes(body)
            assert inspect_compression_stream_identity(str(path))["plausible"]
            assert inspect_compression_stream_structure(str(path))["plausible"]
            split = len(head) - 1
            parts = [tmp_path / f"first-{optional}-{crc}.jpg", tmp_path / f"second-{optional}-{crc}.jpg"]
            parts[0].write_bytes(body[:split])
            parts[1].write_bytes(body[split:])
            for view in (AnalysisBinaryView(str(path)), AnalysisMultiVolumeView(list(map(str, parts)))):
                try:
                    assert view.probe_compression_stream("gzip")["plausible"]
                    report = view.analyze(cfg)
                    assert report["evidences"][0][1:3] == (0.93, "extractable")
                finally:
                    view.close()
            if crc:
                damaged = bytearray(body)
                damaged[len(head) - 1] ^= 1
                bad = tmp_path / f"bad-{optional}.bin"
                bad.write_bytes(damaged)
                view = AnalysisBinaryView(str(bad))
                try:
                    assert not view.probe_compression_stream("gzip")["plausible"]
                finally:
                    view.close()
                assert not inspect_compression_stream_identity(str(bad))["plausible"]
                assert not inspect_compression_stream_structure(str(bad))["plausible"]
                truncated = tmp_path / f"short-{optional}.bin"
                truncated.write_bytes(body[:len(head) - 1])
                view = AnalysisBinaryView(str(truncated))
                try:
                    assert not view.probe_compression_stream("gzip")["plausible"]
                finally:
                    view.close()
    carrier = tmp_path / "carrier.bin"
    carrier.write_bytes(b"carrier prefix" + body + b"carrier suffix")
    carved = scan_embedded_archives(str(carrier))
    assert any(row["format"] == "gzip" and row["offset"] == len(b"carrier prefix")
               and row["end_offset"] == len(b"carrier prefix") + len(body)
               for row in carved["candidates"])


def test_dense_false_headers_preserve_empty_and_nonempty_bzip2_peers(tmp_path):
    # This is discovery correctness, not a speed assertion: filtering noisy
    # prefixes must retain both legal first-marker kinds and later real peers.
    # Ordinary bzip2 fixtures contain no noise or empty streams to catch that.
    from sunpack_native import scan_embedded_archives

    data = bytearray(b"BZh1" * 20000)
    expected = []
    for payload in (b"", b"real payload"):
        expected.append(len(data))
        data.extend(bz2.compress(payload))
        data.extend(b"invalid gap")
    path = tmp_path / "disguised.bin"
    path.write_bytes(data)
    result = scan_embedded_archives(str(path))
    assert result["complete"]
    assert [candidate["offset"] for candidate in result["candidates"]
            if candidate["format"] == "bzip2"] == expected


def _tar(name: str) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        info = tarfile.TarInfo(name)
        info.size = 10
        archive.addfile(info, io.BytesIO(b"x" * 10))
    # Header, one payload block and the two end-of-archive blocks.
    return buffer.getvalue()[: 512 * 4]


@pytest.mark.parametrize("prefix", [0, 100])
def test_concatenated_tar_is_aligned_to_the_archive_start_inside_a_carrier(tmp_path, prefix):
    body = b"J" * prefix + _tar("a.txt") + _tar("b.txt")
    path = tmp_path / "carrier.bin"
    path.write_bytes(body)

    result = inspect_tar_header_structure(str(path), prefix, len(body))

    assert result["archive.concatenated"] is True
    assert result["archive.concatenated_offset"] == prefix + 2048
    assert result["archive.trailing_data"] == 0
    assert "trailing_junk" not in result["damage_flags"]


def test_multistream_bzip2_is_not_trailing_junk_or_falsely_verified(tmp_path):
    path = tmp_path / "multi.bz2"
    path.write_bytes(bz2.compress(b"a" * 5000) + bz2.compress(b"b" * 5000))

    result = inspect_compression_stream_structure(str(path))

    assert result["plausible"] is True
    assert result["structure.stream_count"] == 2
    assert result["archive.trailing_data"] == 0
    assert "trailing_junk" not in result["damage_flags"]
    # The eager decoder only checks the first stream.
    assert result["integrity_status"] != "verified"


def test_bzip2_real_trailing_junk_is_still_flagged(tmp_path):
    path = tmp_path / "junk.bz2"
    path.write_bytes(bz2.compress(b"q" * 999) + b"garbage!" * 10)

    result = inspect_compression_stream_structure(str(path))

    assert result["archive.trailing_data"] == 80
    assert "trailing_junk" in result["damage_flags"]
    assert result["integrity_status"] == "verified"


def test_xz_multistream_checks_and_padding_share_one_structure(tmp_path):
    # Single-stream cases cannot detect comparing the last footer with the
    # first header, or validating only the first expanded stream.
    path = tmp_path / "disguised.bin"
    body = (lzma.compress(b"a" * 257, check=lzma.CHECK_CRC32) + b"\0" * 4
            + lzma.compress(b"b" * 1536, check=lzma.CHECK_CRC64))
    path.write_bytes(body + b"trailing carrier bytes")
    result = inspect_compression_stream_structure(str(path))
    assert result["plausible"] is True
    assert result["structure.stream_count"] == 2
    assert result["block.uncompressed_data"] == 1793
    assert result["segment_end"] == len(body)
    assert result["integrity_status"] == "deferred"
    assert result["integrity_validation_complete"] is False
    assert result["damage_flags"] == ["trailing_junk"]


@pytest.mark.parametrize("corrupt_second", [False, True])
def test_zstd_second_frame_is_neither_junk_nor_covered_by_first_frame_checksum(tmp_path, corrupt_second):
    # No single-frame test can expose extending first-frame evidence across
    # a later frame. Both cases are small and keep content integrity deferred.
    compressor = zstandard.ZstdCompressor(write_checksum=True)
    first = compressor.compress(b"first")
    second = bytearray(compressor.compress(b"second"))
    if corrupt_second:
        second[-1] ^= 1
    path = tmp_path / "multi.bin"
    path.write_bytes(first + second)
    result = inspect_compression_stream_structure(str(path))
    assert result["plausible"] is True
    assert result["structure.stream_count"] == 2
    assert result["archive.trailing_data"] == 0
    assert "trailing_junk" not in result["damage_flags"]
    assert result["integrity_status"] != "verified"
    assert result["integrity_validation_complete"] is False


def test_zstd_structure_accepts_the_format_maximum_window_without_decoding(tmp_path):
    # Ordinary compressor output never exercises the full Window_Descriptor
    # range. A legal empty frame needs no actual huge allocation or host load.
    path = tmp_path / "maximum-window.bin"
    path.write_bytes(b"\x28\xb5\x2f\xfd\x00\xff\x01\x00\x00")
    result = inspect_compression_stream_structure(str(path))
    assert result["plausible"] is True
    assert result["structure_validation_complete"] is True
    assert result["frame.header.window_descriptor"] == "raw=255;window=4123168604160"
    assert result["frame.decoded_content"] == "not_decoded"
    assert result["integrity_validation_complete"] is False


@pytest.mark.parametrize(("compress", "size_field"), [
    (bz2.compress, "block.decoded_content"),
    (lzma.compress, "block.uncompressed_data"),
    (zstandard.ZstdCompressor(write_checksum=True).compress, "frame.decoded_content"),
])
def test_bounded_decode_probe_keeps_structure_without_claiming_integrity(tmp_path, compress, size_field):
    # Ordinary small fixtures never exercise the shared probe output limit.
    # One compressible input per codec covers the cap with little disk I/O.
    limit = 8 * 1024 * 1024
    path = tmp_path / "large-expanded.bin"
    path.write_bytes(compress(b"x" * (limit + 100)))
    result = inspect_compression_stream_structure(str(path))
    assert result["plausible"] is True
    assert result["structure_validation_complete"] is True
    if size_field == "block.decoded_content":
        assert result[size_field] == limit + 1
    elif size_field == "block.uncompressed_data":
        assert result[size_field] == limit + 100  # XZ Index, no payload decode
    else:
        assert result[size_field] == "not_decoded"
    assert result["integrity_status"] != "verified"


@pytest.mark.performance
def test_bzip2_structure_analysis_allows_event_loop_progress(tmp_path):
    path = tmp_path / "random.blob"
    path.write_bytes(bz2.compress(os.urandom(3 * 1024 * 1024)))

    def inspect():
        start = time.perf_counter()
        result = inspect_compression_stream_structure(str(path))
        return result, start, time.perf_counter()

    async def scenario():
        ticks = []

        async def heartbeat():
            while True:
                ticks.append(time.perf_counter())
                await asyncio.sleep(0.001)

        pulse = asyncio.create_task(heartbeat())
        try:
            result, start, end = await asyncio.to_thread(inspect)
        finally:
            pulse.cancel()
            await asyncio.gather(pulse, return_exceptions=True)
        assert result["plausible"] is True
        assert result["integrity_status"] == "verified"
        assert sum(start < tick < end for tick in ticks) >= 2
        points = [start, *(tick for tick in ticks if start < tick < end), end]
        max_gap = max(right - left for left, right in zip(points, points[1:]))
        print(f"analysis={end - start:.4f}s, event_loop_max_gap={max_gap:.4f}s")

    asyncio.run(scenario())
