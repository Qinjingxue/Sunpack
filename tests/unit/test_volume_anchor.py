from __future__ import annotations

import bz2
import struct
import zipfile

from sunpack.core.analysis.volume_anchor import probe_volume_anchor_paths


def test_large_ordinary_candidate_uses_bounded_head_and_tail_reads(tmp_path):
    candidate = tmp_path / "opaque.large.part"
    with candidate.open("wb") as stream:
        stream.truncate(32 * 1024 * 1024)

    evidence = probe_volume_anchor_paths([str(candidate)]).get(str(candidate))

    assert evidence is not None
    assert evidence.error == ""
    assert evidence.format == ""
    assert evidence.bytes_read <= 512 + 65_557


def test_leading_stream_structure_is_standalone_not_a_foreign_volume(tmp_path):
    candidate = tmp_path / "shared.zip.002.disguise.bin"
    candidate.write_bytes(bz2.compress(b"payload" * 1024))

    evidence = probe_volume_anchor_paths([str(candidate)]).get(str(candidate))

    assert evidence is not None
    assert evidence.structurally_confirmed
    assert evidence.format == "bzip2"
    assert evidence.standalone is True
    assert evidence.multivolume is False


def test_non_sfx_embedded_archive_signature_is_not_promoted(tmp_path):
    candidate = tmp_path / "raw.middle.part"
    candidate.write_bytes(b"not-an-sfx" + b"7z\xbc\xaf\x27\x1c" + b"\0" * 1024)

    evidence = probe_volume_anchor_paths([str(candidate)]).get(str(candidate))

    assert evidence is not None
    assert evidence.format == ""
    assert evidence.confidence == "none"


def test_small_zip_tail_is_read_past_the_initial_prefix(tmp_path):
    candidate = tmp_path / "small.zip"
    with zipfile.ZipFile(candidate, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("payload.bin", b"x" * 2048)

    evidence = probe_volume_anchor_paths([str(candidate)]).get(str(candidate))

    assert evidence is not None
    assert evidence.structurally_confirmed
    assert evidence.format == "zip"
    assert evidence.standalone is True
    assert evidence.bytes_read <= 512 + 22
    assert {"first", "terminal", "standalone"} <= set(evidence.anchor_roles)


def test_prefixed_single_disk_zip_is_not_promoted_to_multivolume(tmp_path):
    archive = tmp_path / "payload.jpg"
    source = tmp_path / "payload.zip"
    with zipfile.ZipFile(source, "w", compression=zipfile.ZIP_STORED) as stream:
        stream.writestr("payload.txt", "carrier")
    archive.write_bytes(b"fake-jpeg-prefix" + source.read_bytes())
    source.unlink()

    evidence = probe_volume_anchor_paths([str(archive)]).get(str(archive))

    assert evidence is not None
    assert evidence.structurally_confirmed
    assert evidence.format == "zip"
    assert evidence.standalone is False
    assert evidence.multivolume is False
    assert "zip:eocd_single_disk_without_local_header" in evidence.evidence


def test_nonempty_single_disk_eocd_only_chunk_is_terminal_not_empty_zip(tmp_path):
    candidate = tmp_path / "archive.zip.002"
    candidate.write_bytes(
        struct.pack(
            "<4s4H2LH",
            b"PK\x05\x06",
            0,
            0,
            1,
            1,
            56,
            45,
            0,
        )
    )

    evidence = probe_volume_anchor_paths([str(candidate)]).get(str(candidate))

    assert evidence is not None
    assert evidence.structurally_confirmed
    assert evidence.format == "zip"
    assert evidence.standalone is False
    assert evidence.multivolume is False
    assert "first" not in evidence.anchor_roles
    assert "terminal" in evidence.anchor_roles
    assert "zip:empty_eocd" not in evidence.evidence
    assert "zip:eocd_single_disk_without_local_header" in evidence.evidence


def test_modern_split_zip_first_marker_is_a_strong_volume_anchor(tmp_path):
    candidate = tmp_path / "archive.z01"
    name = b"x"
    local = struct.pack(
        "<4s5H3L2H",
        b"PK\x03\x04",
        20,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        len(name),
        0,
    )
    candidate.write_bytes(b"PK\x07\x08" + local + name)

    evidence = probe_volume_anchor_paths([str(candidate)]).get(str(candidate))

    assert evidence is not None
    assert evidence.structurally_confirmed
    assert evidence.format == "zip"
    assert evidence.multivolume is True
    assert evidence.internal_volume_number == 1
    assert "first" in evidence.anchor_roles
    assert "zip:split_marker" in evidence.evidence


def test_modern_split_zip_eocd_exposes_terminal_volume_number(tmp_path):
    candidate = tmp_path / "archive.zip"
    candidate.write_bytes(
        struct.pack(
            "<4s4H2LH",
            b"PK\x05\x06",
            3,
            3,
            0,
            0,
            0,
            0,
            0,
        )
    )

    evidence = probe_volume_anchor_paths([str(candidate)]).get(str(candidate))

    assert evidence is not None
    assert evidence.structurally_confirmed
    assert evidence.format == "zip"
    assert evidence.multivolume is True
    assert evidence.internal_volume_number == 4
    assert "terminal" in evidence.anchor_roles
    assert "zip:eocd_split_terminal" in evidence.evidence
