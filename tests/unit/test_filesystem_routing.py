from __future__ import annotations

import gzip
import io
import struct
import tarfile
import zipfile
from binascii import crc32

from sunpack.core.contracts.filesystem import (
    FILESYSTEM_ROUTE_DETECTION,
    FILESYSTEM_ROUTE_RELATIONS,
    FILESYSTEM_ROUTE_RESIDUAL,
)
from sunpack.pipeline.coordinator.scan_session import DiscoveryScanSession
from sunpack.pipeline.discovery.filesystem.directory_scanner import DirectoryScanner


def _basename(path: str) -> str:
    return path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]


def _routing_by_name(snapshot):
    routes = {
        _basename(path): (route, format_hint)
        for path, _size, route, format_hint, _reject_mask in snapshot.non_relation_file_routing_rows()
    }
    relation_names = {
        _basename(path)
        for path, _size, _mtime in snapshot.file_route_view(
            FILESYSTEM_ROUTE_RELATIONS
        ).iter_file_columns()
    }
    anchors = {
        _basename(path): anchor
        for path, _size, anchor in snapshot.iter_relation_anchor_rows()
    }
    for name in relation_names:
        routes[name] = ("relations", str((anchors.get(name) or {}).get("format") or ""))
    return routes


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

    snapshot = DirectoryScanner(str(tmp_path), include_raw_snapshot=True).scan()
    routes = _routing_by_name(snapshot)

    assert routes["empty.zip"] == ("relations", "zip")
    assert routes["payload.gz"] == ("detection", "gzip")
    assert routes["payload.tar"] == ("detection", "tar")
    assert routes["plain.bin"] == ("residual", "")
    assert routes["payload.7z.002"][0] == "residual"

    relation_view = snapshot.file_route_view(FILESYSTEM_ROUTE_RELATIONS)
    detection_view = snapshot.file_route_view(FILESYSTEM_ROUTE_DETECTION)
    residual_view = snapshot.file_route_view(FILESYSTEM_ROUTE_RESIDUAL)

    assert {_basename(path) for path, _, _ in relation_view.iter_file_columns()} == {
        "empty.zip",
    }
    assert {_basename(path) for path, _, _ in detection_view.iter_file_columns()} == {
        "payload.gz",
        "payload.tar",
    }
    assert {_basename(path) for path, _, _ in residual_view.iter_file_columns()} == {
        "plain.bin",
        "payload.7z.002",
    }


def test_filesystem_routes_by_structure_not_extension(tmp_path):
    disguised_zip = tmp_path / "movie.ISO"
    with zipfile.ZipFile(disguised_zip, "w") as archive:
        archive.writestr("inside.txt", "hello")

    disguised_gzip = tmp_path / "payload.random"
    disguised_gzip.write_bytes(gzip.compress(b"payload"))

    snapshot = DirectoryScanner(str(tmp_path), include_raw_snapshot=True).scan()
    routes = _routing_by_name(snapshot)

    assert routes[disguised_zip.name] == ("relations", "zip")
    assert routes[disguised_gzip.name] == ("detection", "gzip")


def test_prefixed_and_suffixed_archive_carrier_stays_residual_for_embedded_scan(tmp_path):
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as archive:
        archive.writestr("inside.txt", "hello")

    carrier = tmp_path / "carrier.data"
    carrier.write_bytes(b"invalid-prefix" + zip_buffer.getvalue() + b"invalid-suffix")

    snapshot = DirectoryScanner(str(tmp_path), include_raw_snapshot=True).scan()
    routes = _routing_by_name(snapshot)

    assert routes[carrier.name][0] == "residual"


def test_directory_without_relation_anchor_skips_relations_entirely(tmp_path, monkeypatch):
    (tmp_path / "payload.gz").write_bytes(gzip.compress(b"payload"))
    (tmp_path / "plain.bin").write_bytes(b"ordinary")

    session = DiscoveryScanSession(config={})
    monkeypatch.setattr(
        session.relations,
        "build_candidate_groups",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("Relations must not run without a routed anchor")
        ),
    )

    candidates = session.candidates_for_directory(str(tmp_path))

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

    session = DiscoveryScanSession(config={})
    snapshot = session.snapshot_for_directory(str(tmp_path))
    routes = _routing_by_name(snapshot)

    assert routes[first.name][0] == "relations"
    assert routes[second.name][0] == "residual"

    groups = session.relation_groups_for_directory(
        str(tmp_path),
        filesystem_routed=True,
    )
    split = next(group for group in groups if group.kind == "split_archive")
    assert split.input_paths == [str(first), str(second)]


def test_main_scan_routes_only_native_container_candidates_through_relations(tmp_path):
    with zipfile.ZipFile(tmp_path / "archive.zip", "w") as archive:
        archive.writestr("inside.txt", "hello")
    (tmp_path / "payload.gz").write_bytes(gzip.compress(b"payload"))
    (tmp_path / "plain.bin").write_bytes(b"ordinary file")

    session = DiscoveryScanSession(config={})
    candidates = session.candidates_for_directory(str(tmp_path))
    by_name = {
        bag.get("candidate.entry_path").rsplit("\\", 1)[-1].rsplit("/", 1)[-1]: bag
        for bag in bags
    }

    assert by_name["archive.zip"].route == "relations"
    assert by_name["archive.zip"].relation_anchor.get("relation_confirmed") is True

    assert by_name["payload.gz"].route == "detection"
    assert by_name["payload.gz"].format_hint == "gzip"
    assert by_name["payload.gz"].relation_anchor == {}

    assert by_name["plain.bin"].route == "residual"
    assert by_name["plain.bin"].relation_anchor == {}
