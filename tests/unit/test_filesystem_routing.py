from __future__ import annotations

import gzip
import io
import struct
import tarfile
import zipfile
from binascii import crc32

from sunpack.pipeline.coordinator.scan_session import DiscoveryScanSession
from sunpack.pipeline.coordinator.target_scan import build_candidates_for_targets
from tests.helpers.config_factory import make_config


def _basename(path: str) -> str:
    return path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]


def _routing_by_name(root):
    return {
        _basename(candidate.entry_path): (candidate.route, candidate.format_hint)
        for candidate in build_candidates_for_targets([str(root)], config=make_config())
    }


def test_filesystem_routes_native_archive_stream_and_residual_without_rescan(tmp_path):
    zip_path = tmp_path / "empty.zip"
    with zipfile.ZipFile(zip_path, "w"):
        pass

    gzip_path = tmp_path / "payload.gz"
    gzip_path.write_bytes(gzip.compress(b"payload"))

    tar_path = tmp_path / "payload.tar"
    with tarfile.open(tar_path, "w") as archive:
        info = tarfile.TarInfo("inside.txt")
        payload = b"hello"
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))

    residual_path = tmp_path / "plain.bin"
    residual_path.write_bytes(b"not an archive")

    split_name_path = tmp_path / "payload.7z.002"
    split_name_path.write_bytes(b"continuation bytes")

    routes = _routing_by_name(tmp_path)

    assert routes["empty.zip"] == ("relations", "zip")
    assert routes["payload.gz"] == ("detection", "gzip")
    assert routes["payload.tar"] == ("detection", "tar")
    assert routes["plain.bin"] == ("residual", "")
    assert routes["payload.7z.002"][0] == "residual"

def test_filesystem_routes_by_structure_not_extension(tmp_path):
    disguised_zip = tmp_path / "movie.ISO"
    with zipfile.ZipFile(disguised_zip, "w") as archive:
        archive.writestr("inside.txt", "hello")

    disguised_gzip = tmp_path / "payload.random"
    disguised_gzip.write_bytes(gzip.compress(b"payload"))

    routes = _routing_by_name(tmp_path)

    assert routes[disguised_zip.name] == ("relations", "zip")
    assert routes[disguised_gzip.name] == ("detection", "gzip")


def test_prefixed_and_suffixed_archive_carrier_stays_residual_for_embedded_scan(tmp_path):
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as archive:
        archive.writestr("inside.txt", "hello")

    carrier = tmp_path / "carrier.data"
    carrier.write_bytes(b"invalid-prefix" + zip_buffer.getvalue() + b"invalid-suffix")

    routes = _routing_by_name(tmp_path)

    assert routes[carrier.name][0] == "residual"


def test_discovery_candidate_projects_normalized_stream_name(tmp_path):
    payload = tmp_path / "payload.gz"
    payload.write_bytes(gzip.compress(b"payload"))

    session = DiscoveryScanSession(config=make_config({}))
    candidates = build_candidates_for_targets([str(tmp_path)], session=session)

    assert len(candidates) == 1
    assert candidates[0].entry_path == str(payload)
    assert candidates[0].logical_name == "payload"
    assert candidates[0].route == "detection"
    assert candidates[0].format_hint == "gzip"


def test_directory_without_relation_anchor_skips_relations_entirely(tmp_path, monkeypatch):
    (tmp_path / "payload.gz").write_bytes(gzip.compress(b"payload"))
    (tmp_path / "plain.bin").write_bytes(b"ordinary")

    session = DiscoveryScanSession(config=make_config({}))
    monkeypatch.setattr(
        session.relations,
        "build_candidate_groups",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("Relations must not run without a routed anchor")
        ),
    )

    candidates = build_candidates_for_targets([str(tmp_path)], session=session)

    assert {candidate.route for candidate in candidates} == {"detection", "residual"}


def _split_7z_bytes() -> bytes:
    next_header = b"\x01\x00"
    start_header = struct.pack("<QQI", 0, len(next_header), crc32(next_header) & 0xFFFFFFFF)
    return (
        b"7z\xbc\xaf\x27\x1c\x00\x04"
        + struct.pack("<I", crc32(start_header) & 0xFFFFFFFF)
        + start_header
        + next_header
    )


def test_relations_anchor_view_recovers_unrouted_split_members_from_raw_snapshot(tmp_path):
    archive = _split_7z_bytes()
    first = tmp_path / "payload.7z.001"
    second = tmp_path / "payload.7z.002"
    first.write_bytes(archive[:32])
    second.write_bytes(archive[32:])

    session = DiscoveryScanSession(config=make_config({}))
    candidates = build_candidates_for_targets([str(tmp_path)], session=session)
    split = next(candidate for candidate in candidates if candidate.is_split)
    assert split.route == "relations"
    assert split.archive_input.part_paths() == [str(first), str(second)]


def test_main_scan_routes_only_native_container_candidates_through_relations(tmp_path):
    with zipfile.ZipFile(tmp_path / "archive.zip", "w") as archive:
        archive.writestr("inside.txt", "hello")
    (tmp_path / "payload.gz").write_bytes(gzip.compress(b"payload"))
    (tmp_path / "plain.bin").write_bytes(b"ordinary file")

    session = DiscoveryScanSession(config=make_config({}))
    candidates = build_candidates_for_targets([str(tmp_path)], session=session)
    by_name = {
        _basename(candidate.entry_path): candidate
        for candidate in candidates
    }

    assert by_name["archive.zip"].route == "relations"
    assert by_name["archive.zip"].relation_anchor.get("relation_confirmed") is True

    assert by_name["payload.gz"].route == "detection"
    assert by_name["payload.gz"].format_hint == "gzip"
    assert by_name["payload.gz"].relation_anchor == {}

    assert by_name["plain.bin"].route == "residual"
    assert by_name["plain.bin"].relation_anchor == {}
