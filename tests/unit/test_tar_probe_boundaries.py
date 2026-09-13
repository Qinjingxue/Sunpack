import io
import tarfile

import sunpack_native

from sunpack.analysis.structure_pipeline.modules.tar import TarAnalysisModule
from sunpack.analysis.view import _probe_tar_view


class BytesView:
    def __init__(self, data: bytes):
        self.data = data
        self.size = len(data)

    def read_at(self, offset: int, size: int) -> bytes:
        return self.data[offset:offset + size]

    def probe_tar(self, *, start_offset: int = 0, max_entries_to_walk: int = 64):
        return _probe_tar_view(self, start_offset, max_entries_to_walk)


def _many_member_tar(count: int, *, fmt=tarfile.USTAR_FORMAT) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=fmt) as archive:
        for index in range(count):
            payload = bytes([index % 251])
            info = tarfile.TarInfo(f"file-{index:05d}.bin")
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    return output.getvalue()


def _header_offsets(data: bytes) -> list[int]:
    offsets = []
    offset = 0
    while offset + 512 <= len(data):
        header = data[offset:offset + 512]
        if not any(header):
            break
        size = int(header[124:136].rstrip(b"\0 ") or b"0", 8)
        offsets.append(offset)
        offset += 512 + size + (-size % 512)
    return offsets


def test_tar_walk_budget_is_not_an_archive_boundary():
    raw = _probe_tar_view(BytesView(_many_member_tar(1100)), 0, 64)

    assert raw["plausible"] is True
    assert raw["entries_checked"] == 64
    assert raw["walk_budget_exhausted"] is True
    assert raw["walk_complete"] is False
    assert raw["segment_end"] is None
    assert raw["boundary_confidence"] == "none"
    assert raw["damage_flags"] == []


def test_primary_tar_owns_internal_ustar_hits():
    data = _many_member_tar(100)
    prepass = {
        "source": "embedded_scan",
        "hits": [{"name": "tar_ustar", "offset": offset + 257} for offset in _header_offsets(data)],
    }

    evidence = TarAnalysisModule().analyze(BytesView(data), prepass, {"max_entries_to_walk": 64})

    assert len(evidence.segments) == 1
    assert evidence.segments[0].start_offset == 0
    assert evidence.segments[0].end_offset is None
    assert evidence.details["walk_budget_exhausted"] is True


def test_v7_tar_is_recognized_without_ustar_magic():
    data = bytearray(_many_member_tar(2))
    data[257:512] = b"\0" * (512 - 257)
    data[148:156] = b" " * 8
    checksum = sum(data[:512])
    data[148:156] = f"{checksum:06o}\0 ".encode("ascii")
    raw = _probe_tar_view(BytesView(bytes(data)), 0, 8)

    assert raw["plausible"] is True
    assert raw["entry_walk_ok"] is True
    assert raw["ustar_magic"] is False


def test_gnu_base256_size_is_accepted():
    data = bytearray(_many_member_tar(1))
    data[124:136] = b"\x80" + b"\0" * 10 + b"\x01"
    data[148:156] = b" " * 8
    checksum = sum(data[:512])
    data[148:156] = f"{checksum:06o}\0 ".encode("ascii")

    raw = _probe_tar_view(BytesView(bytes(data)), 0, 8)

    assert raw["plausible"] is True
    assert raw["member_size"] == 1


def test_native_tar_semantics_honor_embedded_archive_offset(tmp_path):
    tar_data = _many_member_tar(2)
    carrier = tmp_path / "carrier.bin"
    carrier.write_bytes(b"carrier!" * 128 + tar_data)
    start = len(b"carrier!" * 128)

    raw = dict(sunpack_native.inspect_tar_header_structure(
        str(carrier), 8, start, start + len(tar_data)
    ))

    assert raw["plausible"] is True
    assert raw["archive_start"] == start
    assert raw["member.header.name"] == "file-00000.bin"
    assert f"offset={start + 512}" in raw["member.payload.span"]


def test_native_semantics_do_not_call_budget_remainder_trailing_junk(tmp_path):
    path = tmp_path / "many.tar"
    path.write_bytes(_many_member_tar(65))

    raw = dict(sunpack_native.inspect_tar_header_structure(str(path), 8))

    assert raw["plausible"] is True
    assert raw["walk_budget_exhausted"] is True
    assert "missing_end_block" not in raw["damage_flags"]
    assert "trailing_junk" not in raw["damage_flags"]
    assert raw["archive.trailing_data"] == 0


def test_native_semantics_validate_exact_pax_record_lengths(tmp_path):
    output = io.BytesIO()
    long_path = "nested/" + "x" * 180 + "/payload.bin"
    with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive:
        info = tarfile.TarInfo(long_path)
        info.size = 1
        archive.addfile(info, io.BytesIO(b"x"))
    data = bytearray(output.getvalue())
    assert data[156] == ord("x")
    data[512] = ord("9") if data[512] != ord("9") else ord("8")
    path = tmp_path / "bad-pax.tar"
    path.write_bytes(data)

    raw = dict(sunpack_native.inspect_tar_header_structure(str(path), 8))

    assert "pax_header_bad" in raw["damage_flags"]
    assert "invalid:" in raw["pax.header.records"]
