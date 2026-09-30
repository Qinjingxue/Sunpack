import bz2
import asyncio
import io
import os
import tarfile
import time

import pytest
from sunpack_native import inspect_compression_stream_structure, inspect_tar_header_structure


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

    result = inspect_tar_header_structure(str(path), 8, prefix, len(body))

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
