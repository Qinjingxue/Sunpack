import tarfile
import zipfile
import bz2
import gzip
import lzma
import random
import zstandard
from binascii import crc32
from io import BytesIO

import pytest

from sunpack_native import AnalysisBinaryView, inspect_rar_structure, probe_rar_bytes
from sunpack.core.analysis.embedded import scan_embedded_archives
from sunpack.core.analysis.engine import AnalysisEngine
from sunpack.core.analysis.view import SharedBinaryView


def _zip_bytes(tmp_path):
    archive = tmp_path / "inner.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("marker.txt", "hello")
    return archive.read_bytes()


def _rar4_block(header_type: int, flags: int = 0, payload: bytes = b"") -> bytes:
    add_size = len(payload).to_bytes(4, "little") if payload else b""
    header_size = 7 + len(add_size)
    body = bytes([header_type]) + flags.to_bytes(2, "little") + header_size.to_bytes(2, "little") + add_size
    header_crc = (crc32(body) & 0xFFFF).to_bytes(2, "little")
    return header_crc + body + payload


def _rar4_bytes() -> bytes:
    return b"Rar!\x1a\x07\x00" + _rar4_block(0x73) + _rar4_block(0x7B)


def _rar5_vint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _rar5_block(header_type: int, flags: int = 0, data: bytes = b"") -> bytes:
    fields = _rar5_vint(header_type) + _rar5_vint(flags)
    if data:
        flags |= 0x0002
        fields = _rar5_vint(header_type) + _rar5_vint(flags) + _rar5_vint(len(data))
    header_size = _rar5_vint(len(fields))
    header_data = header_size + fields
    return crc32(header_data).to_bytes(4, "little") + header_data + data


def _rar5_bytes() -> bytes:
    return b"Rar!\x1a\x07\x01\x00" + _rar5_block(1) + _rar5_block(5)


def _rar5_oversized_size_vint_block() -> bytes:
    # A non-canonical 10-byte vint close to u64::MAX used to wrap the
    # semantic walker's total-header arithmetic after the bounded first-pass
    # inspector had already rejected the block.
    oversized_header_size = _rar5_vint((1 << 64) - 11)
    return b"\x00\x00\x00\x00" + oversized_header_size + _rar5_vint(2) + _rar5_vint(0)


def _rar5_impossible_extra_area_block() -> bytes:
    fields = _rar5_vint(1) + _rar5_vint(0x01) + _rar5_vint(127)
    header_data = _rar5_vint(len(fields)) + fields
    return crc32(header_data).to_bytes(4, "little") + header_data


def _seven_zip_bytes() -> bytes:
    gap = b"abcde"
    next_header = b"\x01"
    start_header = len(gap).to_bytes(8, "little") + len(next_header).to_bytes(8, "little") + crc32(next_header).to_bytes(4, "little")
    return b"7z\xbc\xaf\x27\x1c" + b"\x00\x04" + crc32(start_header).to_bytes(4, "little") + start_header + gap + next_header


def _write_bytes(path, data: bytes):
    path.write_bytes(data)
    return path


def _tar_bytes() -> bytes:
    buffer = BytesIO()
    payload = b"tar payload"
    info = tarfile.TarInfo("payload.txt")
    info.size = len(payload)
    with tarfile.open(fileobj=buffer, mode="w") as tf:
        tf.addfile(info, BytesIO(payload))
    return buffer.getvalue()


def test_rar5_oversized_second_header_vint_does_not_panic(tmp_path):
    archive = tmp_path / "crafted-rar5.bin"
    archive.write_bytes(
        b"Rar!\x1a\x07\x01\x00"
        + _rar5_block(1)
        + _rar5_oversized_size_vint_block()
    )

    result = dict(inspect_rar_structure(str(archive)))

    assert result["magic_matched"] is True
    assert result["error"] == "rar5_second_header_size_vint_too_long"


def test_rar5_extra_area_larger_than_header_does_not_panic(tmp_path):
    archive = tmp_path / "crafted-rar5-extra.bin"
    archive.write_bytes(
        b"Rar!\x1a\x07\x01\x00"
        + _rar5_impossible_extra_area_block()
    )

    result = dict(inspect_rar_structure(str(archive)))

    assert result["magic_matched"] is True
    assert result["format"] == "rar"


def test_rar4_large_packed_sizes_agree_across_native_analysis_paths(tmp_path):
    # Carrier extraction alone bypasses the standalone inspectors. This small
    # matrix uniquely catches high-word/truncated-header errors in those paths;
    # removing it leaves the single-file analysis APIs untested for large RAR4.
    import struct

    def block(kind, flags, body=b""):
        raw = struct.pack("<BHH", kind, flags, 7 + len(body)) + body
        return struct.pack("<H", crc32(raw) & 0xffff) + raw

    for name, flags, low, high, complete in (
        ("small", 0x8000, 0, b"", True),
        ("large_zero", 0x8100, 0, bytes(8), True),
        ("large_truncated", 0x8100, 0, struct.pack("<II", 1, 0), False),
        ("large_overflow", 0x8100, 0xffffffff, struct.pack("<II", 0xffffffff, 0), False),
        ("large_header_truncated", 0x8100, 0, b"", False),
    ):
        fixed = struct.pack("<IIBIIBBHI", low, 0, 2, 0, 0, 20, 0x30, 1, 0)
        data = (b"Rar!\x1a\x07\x00" + block(0x73, 0, bytes(6))
                + block(0x74, flags, fixed + high + b"a") + block(0x7b, 0))
        path = _write_bytes(tmp_path / f"{name}.opaque", data)
        observation = probe_rar_bytes(data, 0)
        assert observation["end_block_found"] == complete, name
        report = AnalysisEngine().analyze_path(str(path))
        assert any(item.format == "rar" for item in report.selected) == complete, name
        structure = inspect_rar_structure(str(path))
        assert bool(structure["second_block_ok"]) == complete, name


def test_clean_whole_input_formats_use_structure_evidence(tmp_path):
    payload = b"clean payload" * 32
    cases = {
        "zip": _zip_bytes(tmp_path),
        "7z": _seven_zip_bytes(),
        "7z-empty": b"7z\xbc\xaf\x27\x1c\x00\x04" + crc32(bytes(20)).to_bytes(4, "little") + bytes(20),
        "rar4": _rar4_bytes(),
        "rar5": _rar5_bytes(),
        "gzip": gzip.compress(payload),
        "bzip2": bz2.compress(payload),
        "xz": lzma.compress(payload),
        "zstd": zstandard.ZstdCompressor().compress(payload),
        "tar": _tar_bytes(),
        "tar.gz": gzip.compress(_tar_bytes()),
        "tar.bz2": bz2.compress(_tar_bytes()),
        "tar.xz": lzma.compress(_tar_bytes()),
    }
    for name, data in cases.items():
        path = _write_bytes(tmp_path / f"clean-{name}.bin", data)
        report = AnalysisEngine().analyze_path(str(path))

        expected = {"rar4": "rar", "rar5": "rar", "7z-empty": "7z",
                    "tar.gz": "gzip", "tar.bz2": "bzip2", "tar.xz": "xz"}.get(name, name)
        evidence = next(item for item in report.selected if item.format == expected)
        assert evidence.status == "extractable", name
        assert evidence.segments[0].start_offset == 0


@pytest.mark.parametrize("rar_bytes", [_rar4_bytes, _rar5_bytes])
def test_analysis_scheduler_finds_embedded_archive_segments(tmp_path, rar_bytes):
    samples = [("zip", _zip_bytes(tmp_path)), ("rar", rar_bytes()), ("7z", _seven_zip_bytes())]
    payload = b"shell"
    expected = []
    for fmt, data in samples:
        expected.append((fmt, len(payload), len(payload) + len(data)))
        payload += data + b"junk-between-archives"
    path = _write_bytes(tmp_path / "mixed.bin", payload)
    report = AnalysisEngine().analyze_path(str(path))
    actual = {(item.format, segment.start_offset, segment.end_offset)
              for item in report.evidences for segment in item.segments}
    assert set(expected) <= actual


def test_analysis_respects_shared_embedded_scan_switch(tmp_path):
    prefix = b"v" * (2 * 1024 * 1024)
    path = tmp_path / "middle_payload.mp4"
    path.write_bytes(prefix + _zip_bytes(tmp_path) + prefix)

    report = AnalysisEngine({"embedded_scan": {"enabled": False}}).analyze_path(str(path))

    assert report.selected == []
    assert report.prepass.get("source") != "embedded_scan"


def test_analysis_reuses_explicit_prepass_without_shared_rescan(tmp_path):
    prefix = b"v" * (2 * 1024 * 1024)
    path = tmp_path / "prepassed-middle-payload.mp4"
    path.write_bytes(prefix + _zip_bytes(tmp_path) + prefix)
    prepass = {
        "hits": [],
        "formats": [],
        "full_scan_complete": True,
        "full_scan_bytes": path.stat().st_size,
        "source": "test_prepass",
    }

    report = AnalysisEngine().analyze_path(str(path), initial_prepass=prepass)

    assert report.prepass == prepass
    assert report.selected == []
    # A head/tail signature prepass alone would read a full megabyte.
    assert report.read_bytes < 1024 * 1024

def test_analysis_reuses_complete_detection_prepass_without_shared_rescan(tmp_path):
    path = tmp_path / "payload.bin"
    payload = b"p" * (2 * 1024 * 1024) + _zip_bytes(tmp_path) + b"s" * (2 * 1024 * 1024)
    path.write_bytes(payload)
    scan = scan_embedded_archives(str(path), expected_size=path.stat().st_size)
    prepass = scan.to_prepass()
    assert prepass["source"] == "embedded_scan"

    reused = AnalysisEngine().analyze_path(str(path), initial_prepass=prepass)
    assert reused.prepass == prepass
    assert reused.read_bytes < 1024 * 1024
    assert [(item[0].format, item[1].start_offset) for item in reused.extractable_segments] == [
        ("zip", 2 * 1024 * 1024),
    ]

def test_analysis_reuses_detection_hit_map_and_preserves_same_format_segments(tmp_path):
    first = _zip_bytes(tmp_path)
    second_path = tmp_path / "second.zip"
    with zipfile.ZipFile(second_path, "w") as archive:
        archive.writestr("second.txt", "world")
    second = second_path.read_bytes()
    prefix = b"carrier-prefix"
    gap = b"between"
    payload = prefix + first + gap + second
    path = tmp_path / "two-zips.bin"
    path.write_bytes(payload)

    hits = []
    for name, signature in (("zip_local", b"PK\x03\x04"), ("zip_eocd", b"PK\x05\x06")):
        cursor = 0
        while (offset := payload.find(signature, cursor)) >= 0:
            hits.append({"name": name, "offset": offset, "source": "embedded_scan"})
            cursor = offset + 1
    prepass = {
        "hits": sorted(hits, key=lambda item: item["offset"]),
        "formats": ["zip"],
        "full_scan_complete": True,
        "full_scan_bytes": len(payload),
        "source": "embedded_scan",
    }
    report = AnalysisEngine().analyze_path(str(path), initial_prepass=prepass)
    zip_evidence = next(item for item in report.evidences if item.format == "zip")
    assert [segment.start_offset for segment in zip_evidence.segments] == [
        len(prefix), len(prefix) + len(first) + len(gap),
    ]
    assert report.prepass["source"] == "embedded_scan"


def test_zip_embedded_local_header_without_eocd_keeps_embedded_start(tmp_path):
    zip_data = _zip_bytes(tmp_path)
    payload = b"MZstub" + zip_data[:40]
    path = tmp_path / "zip_sfx_split_head.exe"
    path.write_bytes(payload)

    report = AnalysisEngine().analyze_path(str(path))
    zip_evidence = {item.format: item for item in report.evidences}["zip"]

    assert zip_evidence.status == "not_found"
    assert zip_evidence.segments == []



def test_zip_embedded_boundary_defers_payload_integrity(tmp_path):
    data = bytearray(_zip_bytes(tmp_path))
    data[14] ^= 0xFF
    prefix = b"carrier-prefix"
    path = _write_bytes(tmp_path / "crc_bad_carrier.bin", prefix + bytes(data))

    scan = scan_embedded_archives(str(path), expected_size=path.stat().st_size)
    zip_evidence = {
        item.format: item
        for item in AnalysisEngine().analyze_path(
            str(path),
            initial_prepass=scan.to_prepass(),
        ).evidences
    }["zip"]

    assert zip_evidence.status == "extractable"
    assert zip_evidence.segments[0].start_offset == len(prefix)
    assert zip_evidence.segments[0].end_offset == len(prefix) + len(data)
    assert "content_integrity_bad_or_unknown" not in zip_evidence.segments[0].damage_flags
    assert zip_evidence.details["integrity_confidence"] == "deferred"

def test_zip_bad_central_directory_recovers_from_local_header(tmp_path):
    data = bytearray(_zip_bytes(tmp_path))
    cd_offset = data.index(b"PK\x01\x02")
    data[cd_offset:cd_offset + 2] = b"XX"
    path = _write_bytes(tmp_path / "cd_bad.zip", bytes(data))

    zip_evidence = {item.format: item for item in AnalysisEngine().analyze_path(str(path)).evidences}["zip"]

    assert zip_evidence.status == "damaged"
    assert zip_evidence.confidence == 0.70
    assert zip_evidence.segments[0].end_offset is None
    assert "local_header_recovery" in zip_evidence.segments[0].damage_flags
    assert zip_evidence.segments[0].evidence == ["zip:local_header"]
    assert zip_evidence.details["boundary_confidence"] == "low"
    assert zip_evidence.details["directory_confidence"] == "low"


def test_rar_missing_end_block_is_probably_truncated(tmp_path):
    rar_data = _rar5_bytes()[:-len(_rar5_block(5))]
    path = _write_bytes(tmp_path / "truncated.rar", rar_data)

    rar = {item.format: item for item in AnalysisEngine().analyze_path(str(path)).evidences}["rar"]

    assert rar.status == "damaged"
    assert rar.confidence == 0.82
    assert rar.segments[0].end_offset is None
    assert "probably_truncated" in rar.segments[0].damage_flags
    assert rar.details["boundary_confidence"] == "low"


def test_rar_missing_main_header_marks_encrypted_unwalkable(tmp_path):
    rar_data = b"Rar!\x1a\x07\x01\x00" + _rar5_block(4)
    path = _write_bytes(tmp_path / "header_encrypted_like.rar", rar_data)

    rar = {item.format: item for item in AnalysisEngine().analyze_path(str(path)).evidences}["rar"]

    assert rar.status == "damaged"
    assert rar.confidence == 0.72
    assert rar.segments[0].end_offset is None
    assert "valid_encrypted_but_unwalkable" in rar.segments[0].damage_flags
    assert rar.details["password_required"] is True



def test_rar5_header_encrypted_candidate_never_uses_following_archive_as_end(tmp_path):
    encrypted = b"Rar!\x1a\x07\x01\x00" + _rar5_block(4)
    follower = _rar5_bytes()
    carrier_size = len(b"carrier")
    body = b"carrier" + encrypted + b"\x00" * 64 + follower
    follower_start = carrier_size + len(encrypted) + 64
    path = _write_bytes(tmp_path / "two-archives.bin", body)

    scan = scan_embedded_archives(str(path), expected_size=path.stat().st_size)
    first = next(
        candidate
        for candidate in scan.candidates
        if candidate.format == "rar" and candidate.offset == carrier_size
    )
    assert first.end_offset is None
    assert first.boundary_kind == "unresolved"
    assert first.extractable is False

    report = AnalysisEngine().analyze_path(
        str(path),
        initial_prepass=scan.to_prepass(),
    )
    segments = {
        (segment.start_offset, segment.end_offset)
        for evidence in report.evidences
        if evidence.format == "rar"
        for segment in evidence.segments
    }

    assert (carrier_size, follower_start) not in segments
    assert (follower_start, len(body)) in segments


def test_7z_start_header_damage_leaves_only_start_trusted(tmp_path):
    seven_data = bytearray(_seven_zip_bytes())
    seven_data[8] ^= 0xFF
    path = _write_bytes(tmp_path / "start_crc_bad.7z", bytes(seven_data))

    seven = {item.format: item for item in AnalysisEngine().analyze_path(str(path)).evidences}["7z"]

    assert seven.status == "weak"
    assert seven.segments[0].start_offset == 0
    assert seven.segments[0].end_offset is None
    assert "boundary_unreliable" in seven.segments[0].damage_flags
    assert seven.details["boundary_confidence"] == "none"



def test_damaged_7z_next_header_never_becomes_exact_embedded_evidence(tmp_path):
    seven_data = bytearray(_seven_zip_bytes())
    next_offset = int.from_bytes(seven_data[12:20], "little")
    seven_data[32 + next_offset] ^= 0xFF
    path = _write_bytes(tmp_path / "next_crc_bad.7z", bytes(seven_data))

    scan = scan_embedded_archives(str(path), expected_size=path.stat().st_size)
    seven = {
        item.format: item
        for item in AnalysisEngine().analyze_path(
            str(path),
            initial_prepass=scan.to_prepass(),
        ).evidences
    }["7z"]

    assert scan.candidates == ()
    assert seven.status != "extractable"

@pytest.mark.parametrize(
    ("extension", "build_data", "split_at", "expected_format", "confidence"),
    [
        ("zip", _zip_bytes, 37, "zip", 0.99),
        ("7z", lambda _tmp_path: _seven_zip_bytes(), 20, "7z", 0.97),
    ],
    ids=["zip", "seven-zip"],
)
def test_analysis_scheduler_uses_structure_for_clean_archives_across_split_volumes(
    tmp_path, extension, build_data, split_at, expected_format, confidence
):
    data = build_data(tmp_path)
    first = tmp_path / f"archive.{extension}.001"
    second = tmp_path / f"archive.{extension}.002"
    first.write_bytes(data[:split_at])
    second.write_bytes(data[split_at:])

    report = AnalysisEngine().analyze_paths([str(first), str(second)])
    evidence = {item.format: item for item in report.evidences}[expected_format]

    assert evidence.status == "extractable"
    assert evidence.confidence == confidence
    assert evidence.segments[0].start_offset == 0
    assert evidence.segments[0].end_offset == len(data)


def test_analysis_does_not_call_a_zstd_header_fragment_extractable(tmp_path):
    path = tmp_path / "fragment.zst"
    path.write_bytes(b"\x28\xb5\x2f\xfd\x20\x00")

    evidence = {
        item.format: item
        for item in AnalysisEngine().analyze_path(str(path)).evidences
    }["zstd"]

    assert evidence.status != "extractable"
    assert evidence.details["structure_validation_complete"] is False


@pytest.fixture
def tar_stream_samples(tmp_path):
    from tests.helpers.real_archives import create_compression_stream

    source = tmp_path / "payload.tar"
    buffer = BytesIO()
    payload = random.Random(20261027).randbytes(256 * 1024)
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        entry = tarfile.TarInfo("payload.bin")
        entry.size = len(payload)
        archive.addfile(entry, BytesIO(payload))
    source.write_bytes(buffer.getvalue())
    streams = {}
    for fmt in ("gzip", "bzip2", "xz", "zstd", "lz4"):
        path = tmp_path / (fmt + ".photo")
        create_compression_stream(source, path, fmt, **({"compression_level": 0} if fmt == "gzip" else {}))
        streams[fmt] = path
    return source, streams


def test_tar_is_recognized_only_at_the_logical_start_or_from_embedded_evidence(tmp_path, tar_stream_samples):
    # Proves that raw TAR headers in stored compression blocks cannot become
    # peer archives, without teaching the TAR module about any other format.
    # Existing clean-input tests do not cover this positioning boundary.
    source, streams = tar_stream_samples
    engine = AnalysisEngine()
    assert engine.analyze_path(str(source)).best_selected.format == "tar"
    for fmt, path in streams.items():
        report = engine.analyze_path(str(path))
        assert report.best_selected.format == fmt
        assert all("." not in item.format for item in report.evidences)
        assert next(item for item in report.evidences if item.format == "tar").status == "not_found"

    # A genuine nonzero TAR is available only through the existing scanner.
    carrier = tmp_path / "carrier.photo"
    carrier.write_bytes(b"carrier-prefix" + source.read_bytes() + b"carrier-suffix")
    ordinary = engine.analyze_path(str(carrier))
    assert next(item for item in ordinary.evidences if item.format == "tar").status == "not_found"
    scan = scan_embedded_archives(str(carrier))
    embedded = engine.analyze_path(str(carrier), initial_prepass=scan.to_prepass())
    assert embedded.best_selected.format == "tar"
    assert embedded.best_selected.segments[0].start_offset == len(b"carrier-prefix")


def test_outer_stream_damage_cannot_be_upgraded_by_a_readable_tar_prefix(tmp_path, tar_stream_samples):
    # Only this test puts a valid TAR prefix behind an incomplete outer trailer.
    # Removing it loses the regression that motivated deleting composite recognition.
    _, streams = tar_stream_samples
    engine = AnalysisEngine()
    for fmt, source in streams.items():
        data = source.read_bytes()[:-{"gzip": 8, "bzip2": 10, "xz": 12, "zstd": 4, "lz4": 4}[fmt]]
        path = tmp_path / (fmt + "-damaged.photo")
        path.write_bytes(data)
        report = engine.analyze_path(str(path))
        outer = next(item for item in report.evidences if item.format == fmt)
        assert outer.status == "damaged", (fmt, outer)
        assert outer.details.get("structure_validation_complete", False) is False
        assert report.best_selected is None, (fmt, report.selected)
        assert report.extractable_segments == ()

    # A present but incorrect GZIP CRC must also remain damaged even though its
    # complete DEFLATE structure and inner TAR header are both readable.
    data = bytearray(streams["gzip"].read_bytes())
    data[-8] ^= 1
    bad_crc = tmp_path / "crc.photo"
    bad_crc.write_bytes(data)
    report = engine.analyze_path(str(bad_crc))
    outer = next(item for item in report.evidences if item.format == "gzip")
    assert outer.status == "damaged"
    assert outer.details["integrity_status"] == "failed"
    assert report.best_selected is None


def test_analysis_module_config_can_disable_formats(tmp_path):
    path = tmp_path / "payload.bin"
    path.write_bytes(_zip_bytes(tmp_path) + b"Rar!\x1a\x07\x00")

    report = AnalysisEngine({
        "analysis": {
            "modules": [
                {"name": "zip", "enabled": True},
                {"name": "rar", "enabled": False},
                {"name": "seven_zip", "enabled": False},
            ],
        },
    }).analyze_path(str(path))

    assert [item.format for item in report.evidences] == ["zip"]


def test_shared_binary_view_reuses_cached_reads(tmp_path):
    path = tmp_path / "data.bin"
    path.write_bytes(b"abcdef")
    view = SharedBinaryView(str(path), cache_bytes=1024)

    assert view.read_at(0, 3) == b"abc"
    assert view.read_at(0, 3) == b"abc"

    stats = view.stats()
    assert stats.read_bytes == 3
    assert stats.cache_hits == 1
