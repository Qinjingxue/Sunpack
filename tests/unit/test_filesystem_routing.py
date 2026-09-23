from __future__ import annotations

import gzip
import io
import tarfile
import zipfile

from sunpack.contracts.filesystem import (
    FILESYSTEM_ROUTE_DETECTION,
    FILESYSTEM_ROUTE_RELATIONS,
    FILESYSTEM_ROUTE_RESIDUAL,
)
from sunpack.coordinator.scan_session import DetectionScanSession
from sunpack.filesystem.directory_scanner import DirectoryScanner


def _routing_by_name(snapshot):
    return {
        path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]: (route, format_hint)
        for path, _size, route, format_hint, _reject_mask in snapshot.file_routing_rows()
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

    snapshot = DirectoryScanner(str(tmp_path), include_raw_snapshot=True).scan()
    routes = _routing_by_name(snapshot)

    assert routes["empty.zip"] == ("relations", "zip")
    assert routes["payload.gz"] == ("detection", "gzip")
    assert routes["payload.tar"] == ("detection", "tar")
    assert routes["plain.bin"] == ("residual", "")
    assert routes["payload.7z.002"][0] == "relations"

    relation_view = snapshot.file_route_view(FILESYSTEM_ROUTE_RELATIONS)
    detection_view = snapshot.file_route_view(FILESYSTEM_ROUTE_DETECTION)
    residual_view = snapshot.file_route_view(FILESYSTEM_ROUTE_RESIDUAL)

    assert {path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1] for path, _, _ in relation_view.iter_file_columns()} == {
        "empty.zip",
        "payload.7z.002",
    }
    assert {path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1] for path, _, _ in detection_view.iter_file_columns()} == {
        "payload.gz",
        "payload.tar",
    }
    assert {path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1] for path, _, _ in residual_view.iter_file_columns()} == {
        "plain.bin",
    }


def test_main_scan_routes_only_native_container_candidates_through_relations(tmp_path):
    with zipfile.ZipFile(tmp_path / "archive.zip", "w") as archive:
        archive.writestr("inside.txt", "hello")
    (tmp_path / "payload.gz").write_bytes(gzip.compress(b"payload"))
    (tmp_path / "plain.bin").write_bytes(b"ordinary file")

    session = DetectionScanSession(config={})
    bags = session.fact_bags_for_directory(str(tmp_path))
    by_name = {
        bag.get("candidate.entry_path").rsplit("\\", 1)[-1].rsplit("/", 1)[-1]: bag
        for bag in bags
    }

    assert by_name["archive.zip"].get("filesystem.route") == "relations"
    assert by_name["archive.zip"].get("relation.volume_anchor", {}).get("relation_confirmed") is True

    assert by_name["payload.gz"].get("filesystem.route") == "detection"
    assert by_name["payload.gz"].get("filesystem.format_hint") == "gzip"
    assert by_name["payload.gz"].get("relation.volume_anchor") is None

    assert by_name["plain.bin"].get("filesystem.route") == "residual"
    assert by_name["plain.bin"].get("relation.volume_anchor") is None
