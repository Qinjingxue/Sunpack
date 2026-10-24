from __future__ import annotations

import asyncio
import io
import struct
import zipfile
import zlib
import tarfile
from pathlib import Path

import pytest

from sunpack.pipeline.coordinator.engine import PipelineEngine
from tests.helpers.config_factory import make_config


def _config(output: Path, **extra):
    return make_config({
        "output": {"root": str(output)},
        "recursive_extract": 1,
        "post_extract": {"archive_cleanup_mode": "k", "flatten_single_directory": False},
        **extra,
    })


async def _run(config, path: Path, origin: str):
    async with PipelineEngine(config) as engine:
        return await engine.run([str(path)], origin=origin, stdout=io.StringIO(), stderr=io.StringIO())


@pytest.mark.parametrize("origin", ["foreground", "watch"])
def test_tar_metadata_sizes_and_directory_types_survive_carriers(tmp_path, origin):
    # Ordinary TAR fixtures agree on raw/extended sizes and use type '5'. This
    # single end-to-end family catches boundary and manifest disagreements that
    # those tests cannot, including later peers, nesting and both origins.
    from sunpack_native import AnalysisBinaryView, archive_state_tar_manifest_native

    payload = b"payload"
    cases = []
    for raw_size in (0, 4096):
        member = tarfile.TarInfo("payload.txt")
        member.size = raw_size
        member.pax_headers = {"size": str(len(payload))}
        cases.append((f"pax-{raw_size}", member.tobuf(format=tarfile.PAX_FORMAT)
                      + payload + bytes(505) + bytes(1024), ["payload.txt"]))
    for kind in (b"\0", b"0", b"2", b"D"):
        directory = bytearray(tarfile.TarInfo("folder/").tobuf())
        directory[156] = kind[0]
        directory[148:156] = b" " * 8
        directory[148:156] = f"{sum(directory):06o}\0 ".encode()
        member = tarfile.TarInfo("folder/payload.txt")
        member.size = len(payload)
        cases.append((f"dir-{kind.hex()}", bytes(directory) + member.tobuf()
                      + payload + bytes(505) + bytes(1024), ["folder/payload.txt"]))

    for case, body, names in cases:
        plain = tmp_path / f"{case}.tar"
        plain.write_bytes(body)
        manifest = archive_state_tar_manifest_native({"entry_path": str(plain)})
        assert manifest.archive_walk_complete, case
        assert manifest.file_count == 1, case
        assert [entry["path"] for entry in manifest.entry_page(0, 10)] == names, case
        view = AnalysisBinaryView(str(plain))
        try:
            assert view.probe_tar(0, 32)["walk_complete"], case
        finally:
            view.close()

        # A later peer must not be hidden by a miscomputed TAR extent.
        peer = io.BytesIO()
        with zipfile.ZipFile(peer, "w") as archive:
            archive.writestr("peer.txt", b"peer")
        carrier = tmp_path / f"{case}.opaque"
        carrier.write_bytes(b"prefix" + body + b"gap" + peer.getvalue() + b"tail")
        output = tmp_path / f"out-{case}"
        response = asyncio.run(_run(_config(output), carrier, origin))
        assert response.summary.success_count == 1, (case, response.summary.failed_tasks)
        assert [p.read_bytes() for p in output.rglob("payload.txt")] == [payload], case
        assert [p.read_bytes() for p in output.rglob("peer.txt")] == [b"peer"], case


@pytest.mark.parametrize("origin", ["foreground", "watch"])
def test_unproven_carrier_header_cannot_hide_a_real_archive(tmp_path, origin):
    # Unique coverage: ordinary carrier tests have no competing, CRC-valid
    # start header or a RAR4 packed-size high word. Without these cases the
    # remaining carrier tests miss invalid outer ranges hiding valid payloads;
    # tiny real extractions cover both request origins at low cost.
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("payload.txt", b"real independent archive")
    payload = buffer.getvalue()
    cases = []
    for case, next_header, next_crc in (
        ("bad_crc", b"\x01\x00", 12345),
        ("bad_nid", b"\x7f", zlib.crc32(b"\x7f")),
        ("absent_header", b"", 0),
    ):
        fields = struct.pack("<QQI", len(payload), len(next_header), next_crc)
        fake = b"7z\xbc\xaf\x27\x1c\x00\x04" + struct.pack("<I", zlib.crc32(fields)) + fields
        cases.append((case, fake + payload + next_header))

    member = tarfile.TarInfo("payload.txt")
    member.size = len(b"real independent archive")
    tar_body = member.tobuf() + b"real independent archive"
    tar_body += bytes(-member.size % 512) + bytes(1024)
    cases.append(("pax_foreign_size_context",
                  tarfile.TarInfo.create_pax_global_header({"size": "1048576"}) + tar_body))

    def rar4_block(kind, flags, body=b""):
        raw = struct.pack("<BHH", kind, flags, 7 + len(body)) + body
        return struct.pack("<H", zlib.crc32(raw) & 0xffff) + raw

    main = b"Rar!\x1a\x07\x00" + rar4_block(0x73, 0, bytes(6))
    fixed = struct.pack("<IIBIIBBHI", len(payload), len(payload), 2, 0, 0, 20, 0x30, 1, 0)
    for case, high in (("rar4_large", struct.pack("<II", 1, 0)), ("rar4_large_missing_high", b"")):
        fake = main + rar4_block(0x74, 0x8100, fixed + high + b"a")
        cases.append((case, fake + payload + rar4_block(0x7b, 0)))

    for case, content in cases:
        carrier = tmp_path / f"{case}.opaque"
        carrier.write_bytes(b"prefix" + content + b"tail")
        output = tmp_path / f"out-{case}"
        response = asyncio.run(_run(_config(output), carrier, origin))
        assert response.summary.success_count == 1, response.summary.failed_tasks
        assert [path.read_bytes() for path in output.rglob("payload.txt")] == [b"real independent archive"]


