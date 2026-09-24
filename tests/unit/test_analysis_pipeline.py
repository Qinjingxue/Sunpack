import time
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

from sunpack.core.analysis.embedded import scan_embedded_archives
from sunpack.core.analysis.result import ArchiveFormatEvidence
from sunpack.core.analysis.engine import AnalysisEngine
from sunpack.core.analysis.structure_pipeline.module import AnalysisModuleSpec
from sunpack.core.analysis.structure_pipeline.registry import get_analysis_module_registry
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


def test_clean_whole_input_formats_use_structure_evidence(tmp_path):
    payload = b"clean payload" * 32
    cases = {
        "zip": _zip_bytes(tmp_path),
        "7z": _seven_zip_bytes(),
        "rar4": _rar4_bytes(),
        "rar5": _rar5_bytes(),
        "gzip": gzip.compress(payload),
        "bzip2": bz2.compress(payload),
        "xz": lzma.compress(payload),
        "zstd": zstandard.ZstdCompressor().compress(payload),
    }
    for name, data in cases.items():
        path = _write_bytes(tmp_path / f"clean-{name}.bin", data)
        report = AnalysisEngine().analyze_path(str(path))

        assert report.selected, name


def test_analysis_scheduler_finds_embedded_archive_segments(tmp_path):
    zip_start = len(b"shell-a")
    zip_data = _zip_bytes(tmp_path)
    rar_data = _rar4_bytes()
    payload = (
        b"shell-a"
        + zip_data
        + b"shell-b"
        + rar_data
        + b"shell-c"
    )
    path = tmp_path / "mixed.bin"
    path.write_bytes(payload)

    report = AnalysisEngine().analyze_path(str(path))
    by_format = {item.format: item for item in report.evidences}

    assert by_format["zip"].status == "extractable"
    assert by_format["zip"].confidence == 0.99
    assert by_format["zip"].segments[0].start_offset == zip_start
    assert by_format["zip"].segments[0].end_offset == zip_start + len(zip_data)
    assert by_format["rar"].status == "extractable"
    assert by_format["rar"].confidence == 0.97
    assert by_format["rar"].segments[0].start_offset == payload.index(b"Rar!")
    assert by_format["rar"].segments[0].end_offset == payload.index(b"Rar!") + len(rar_data)
    assert by_format["7z"].status == "not_found"
    assert by_format["7z"].confidence == 0.0
    assert {item.format for item in report.selected} == {"zip", "rar"}


def test_analysis_consumes_embedded_discovery_prepass_for_middle_payload(tmp_path):
    prefix = b"v" * (2 * 1024 * 1024)
    zip_data = _zip_bytes(tmp_path)
    suffix = b"v" * (2 * 1024 * 1024)
    path = tmp_path / "middle_payload.mp4"
    path.write_bytes(prefix + zip_data + suffix)
    scan = scan_embedded_archives(str(path), expected_size=path.stat().st_size)

    report = AnalysisEngine().analyze_path(
        str(path),
        initial_prepass=scan.to_prepass(),
    )

    zip_evidence = next(item for item in report.selected if item.format == "zip")
    assert report.prepass["source"] == "embedded_scan"
    assert report.prepass["full_scan_complete"] is True
    assert zip_evidence.segments[0].start_offset == len(prefix)

def test_analysis_respects_shared_embedded_scan_switch(tmp_path):
    prefix = b"v" * (2 * 1024 * 1024)
    path = tmp_path / "middle_payload.mp4"
    path.write_bytes(prefix + _zip_bytes(tmp_path) + prefix)

    report = AnalysisEngine({"embedded_scan": {"enabled": False}}).analyze_path(str(path))

    assert report.selected == []
    assert report.prepass.get("source") != "embedded_scan"


def test_analysis_reuses_explicit_prepass_without_shared_rescan(tmp_path, monkeypatch):
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

    def unexpected_scan(*args, **kwargs):
        raise AssertionError("explicit complete prepass must bypass the shared scanner")

    monkeypatch.setattr(SharedBinaryView, "signature_prepass", unexpected_scan)
    report = AnalysisEngine().analyze_path(str(path), initial_prepass=prepass)

    assert report.prepass == prepass
    assert report.selected == []

def test_analysis_reuses_complete_detection_prepass_without_shared_rescan(tmp_path, monkeypatch):
    path = tmp_path / "payload.bin"
    payload = b"p" * (2 * 1024 * 1024) + _zip_bytes(tmp_path) + b"s" * (2 * 1024 * 1024)
    path.write_bytes(payload)
    scan = scan_embedded_archives(str(path), expected_size=path.stat().st_size)
    prepass = scan.to_prepass()
    assert prepass["source"] == "embedded_scan"

    def unexpected_scan(*args, **kwargs):
        raise AssertionError("complete discovery prepass must bypass analysis prepass scanning")

    monkeypatch.setattr(SharedBinaryView, "signature_prepass", unexpected_scan)
    reused = AnalysisEngine().analyze_path(str(path), initial_prepass=prepass)
    assert reused.prepass == prepass

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
    path = _write_bytes(tmp_path / "crc_bad.zip", bytes(data))

    zip_evidence = {
        item.format: item
        for item in AnalysisEngine().analyze_path(str(path)).evidences
    }["zip"]

    assert zip_evidence.status == "extractable"
    assert zip_evidence.segments[0].end_offset == len(data)
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


def test_analysis_scheduler_prefers_structural_boundary_over_next_signature(tmp_path):
    rar_data = _rar4_bytes()
    seven_data = _seven_zip_bytes()
    payload = b"shell" + rar_data + b"noise" + seven_data
    path = tmp_path / "mixed.bin"
    path.write_bytes(payload)

    report = AnalysisEngine().analyze_path(str(path))
    by_format = {item.format: item for item in report.evidences}

    assert by_format["rar"].segments[0].end_offset == len(b"shell") + len(rar_data)
    assert by_format["7z"].segments[0].start_offset == payload.index(b"7z\xbc\xaf\x27\x1c")
    assert by_format["7z"].confidence >= 0.97


@pytest.mark.parametrize(
    ("version", "build_rar", "expected_version"),
    [(4, _rar4_bytes, None), (5, _rar5_bytes, 5)],
    ids=["rar4", "rar5"],
)
def test_analysis_scheduler_walks_rar_blocks_to_endarc(tmp_path, version, build_rar, expected_version):
    rar_data = build_rar()
    payload = b"shell" + rar_data + b"tail-shell"
    path = tmp_path / f"rar{version}.bin"
    path.write_bytes(payload)

    report = AnalysisEngine().analyze_path(str(path))
    rar = {item.format: item for item in report.evidences}["rar"]

    assert rar.status == "extractable"
    assert rar.confidence == 0.97
    assert rar.segments[0].start_offset == len(b"shell")
    assert rar.segments[0].end_offset == len(b"shell") + len(rar_data)
    assert not rar.warnings
    if expected_version is not None:
        assert rar.details["version"] == expected_version
    assert rar.details["end_block_found"] is True


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



def test_rar5_header_encrypted_carrier_stays_unresolved_without_password(tmp_path):
    encrypted = b"Rar!\x1a\x07\x01\x00" + _rar5_block(4)
    fake_gzip = b"\x1f\x8b\x08"
    fake_bzip2 = b"BZh"
    prefix = b"carrier-shell"
    body = prefix + encrypted + b"\x00" * 32 + fake_gzip + b"\x00" * 32 + fake_bzip2
    path = _write_bytes(tmp_path / "encrypted-carrier.bin", body)

    report = AnalysisEngine().analyze_path(str(path))
    rar = {item.format: item for item in report.evidences}["rar"]
    segment = rar.segments[0]

    assert rar.details["header_encrypted"] is True
    assert segment.start_offset == len(prefix)
    assert segment.end_offset is None
    assert rar.details["boundary_confidence"] == "none"


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


def test_analysis_scheduler_uses_7z_start_header_for_segment_end(tmp_path):
    seven_data = _seven_zip_bytes()
    payload = b"shell" + seven_data + b"tail-shell"
    path = tmp_path / "seven.bin"
    path.write_bytes(payload)

    report = AnalysisEngine().analyze_path(str(path))
    seven = {item.format: item for item in report.evidences}["7z"]

    assert seven.status == "extractable"
    assert seven.segments[0].start_offset == len(b"shell")
    assert seven.segments[0].end_offset == len(b"shell") + len(seven_data)
    assert not seven.warnings
    assert seven.details["source"] == "embedded_scan"
    assert seven.details["boundary_confidence"] == "high"
    assert seven.details["integrity_confidence"] == "deferred"

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



def test_7z_next_header_damage_does_not_trigger_embedded_revalidation(tmp_path):
    seven_data = bytearray(_seven_zip_bytes())
    next_offset = int.from_bytes(seven_data[12:20], "little")
    seven_data[32 + next_offset] ^= 0xFF
    path = _write_bytes(tmp_path / "next_crc_bad.7z", bytes(seven_data))

    seven = {
        item.format: item
        for item in AnalysisEngine().analyze_path(str(path)).evidences
    }["7z"]

    assert seven.status == "extractable"
    assert seven.segments[0].end_offset == len(seven_data)
    assert "directory_integrity_bad_or_unknown" not in seven.segments[0].damage_flags
    assert seven.details["integrity_confidence"] == "deferred"

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


def test_analysis_scheduler_detects_tar(tmp_path):
    tar_data = _tar_bytes()
    path = _write_bytes(tmp_path / "payload.tar", tar_data)

    report = AnalysisEngine().analyze_path(str(path))
    tar = {item.format: item for item in report.evidences}["tar"]

    assert tar.status == "extractable"
    assert tar.confidence >= 0.86
    assert tar.segments[0].start_offset == 0
    assert tar.segments[0].end_offset is not None
    assert tar.details["entry_walk_ok"] is True


def test_analysis_scheduler_detects_compression_streams(tmp_path):
    samples = {
        "gzip": (tmp_path / "payload.gz", gzip.compress(b"plain payload")),
        "bzip2": (tmp_path / "payload.bz2", bz2.compress(b"plain payload")),
        "xz": (tmp_path / "payload.xz", lzma.compress(b"plain payload", format=lzma.FORMAT_XZ)),
        "zstd": (tmp_path / "payload.zst", zstandard.ZstdCompressor().compress(b"plain payload")),
    }

    for fmt, (path, data) in samples.items():
        path.write_bytes(data)
        evidence = {item.format: item for item in AnalysisEngine().analyze_path(str(path)).evidences}[fmt]
        assert evidence.status == "extractable"
        assert evidence.confidence >= 0.88
        assert evidence.segments[0].start_offset == 0


def test_analysis_does_not_call_a_zstd_header_fragment_extractable(tmp_path):
    path = tmp_path / "fragment.zst"
    path.write_bytes(b"\x28\xb5\x2f\xfd\x20\x00")

    evidence = {
        item.format: item
        for item in AnalysisEngine().analyze_path(str(path)).evidences
    }["zstd"]

    assert evidence.status != "extractable"
    assert evidence.details["structure_validation_complete"] is False


def test_analysis_scheduler_detects_compressed_tar_variants(tmp_path):
    tar_data = _tar_bytes()
    samples = {
        "tar.gz": (tmp_path / "payload.tar.gz", gzip.compress(tar_data)),
        "tar.bz2": (tmp_path / "payload.tar.bz2", bz2.compress(tar_data)),
        "tar.xz": (tmp_path / "payload.tar.xz", lzma.compress(tar_data, format=lzma.FORMAT_XZ)),
    }

    for fmt, (path, data) in samples.items():
        path.write_bytes(data)
        evidence = {item.format: item for item in AnalysisEngine().analyze_path(str(path)).evidences}[fmt]
        assert evidence.status == "extractable"
        assert evidence.confidence >= 0.93
        assert evidence.details["inner_tar_verified"] is True


def test_bzip2_compressed_tar_stream_probe_preserves_input_budget_failure(tmp_path):
    payload = random.Random(20260811).randbytes(1024 * 1024)
    buffer = BytesIO()
    info = tarfile.TarInfo("payload.bin")
    info.size = len(payload)
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        archive.addfile(info, BytesIO(payload))
    compressed = bz2.compress(buffer.getvalue())
    path = tmp_path / "payload.tar.bz2"
    path.write_bytes(compressed)
    view = SharedBinaryView(str(path))

    incomplete = view.probe_compressed_tar(format="bzip2", max_probe_bytes=len(compressed) // 4)
    complete = view.probe_compressed_tar(format="bzip2", max_probe_bytes=len(compressed))

    assert incomplete["tar_plausible"] is False
    assert incomplete["tar_probe_error"] == "decompression_probe_failed"
    assert complete["tar_plausible"] is True
    assert complete["inner_tar_verified"] is True


def test_tar_zst_requires_real_zstd_inner_tar(tmp_path):
    path = tmp_path / "payload.tar.zst"
    path.write_bytes(b"\x28\xb5\x2f\xfd\x20\x00")

    evidence = {item.format: item for item in AnalysisEngine().analyze_path(str(path)).evidences}["tar.zst"]

    assert evidence.status == "not_found"
    assert evidence.details["tar_probe_error"]


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


def test_shared_binary_view_enforces_read_budget(tmp_path):
    path = tmp_path / "data.bin"
    path.write_bytes(b"abcdef")
    view = SharedBinaryView(str(path), cache_bytes=0, max_read_bytes=2)

    try:
        view.read_at(0, 3)
    except RuntimeError as exc:
        assert "read budget" in str(exc)
    else:
        raise AssertionError("read budget should be enforced")


class _SlowModule:
    def __init__(self, name: str):
        self.spec = AnalysisModuleSpec(name=name, formats=(name,), signatures=(name.encode("ascii"),))

    def analyze(self, view, prepass, config):
        time.sleep(0.15)
        return ArchiveFormatEvidence(format=self.spec.name, confidence=0.0, status="not_found")


def test_analysis_scheduler_runs_modules_in_single_broker_job(tmp_path):
    registry = get_analysis_module_registry()
    first = _SlowModule("slow_a")
    second = _SlowModule("slow_b")
    registry.register(first)
    registry.register(second)
    path = tmp_path / "slow.bin"
    path.write_bytes(b"slow_a slow_b")

    start = time.perf_counter()
    AnalysisEngine({
        "analysis": {
            "modules": [
                {"name": "slow_a", "enabled": True},
                {"name": "slow_b", "enabled": True},
            ],
        },
    }).analyze_path(str(path))
    elapsed = time.perf_counter() - start

    # Module execution is owned by the bounded work broker.  Modules for one
    # archive share a job, while different archives can run concurrently;
    # there is no unbounded per-archive analysis pool anymore.
    assert elapsed >= 0.28
