from pathlib import Path

from sunpack.core.contracts.filesystem import FileEntry
from sunpack.pipeline.discovery.filesystem.directory_scanner import DirectoryScanner
from tests.helpers.config_factory import make_config


def _entries(snapshot):
    return [
        FileEntry(path=Path(path), is_dir=is_dir, size=size, mtime_ns=mtime_ns)
        for path, is_dir, size, mtime_ns in snapshot.iter_columns()
    ]


def _config(*, prune_dir_globs=None, path_globs=None):
    return make_config({
        "filesystem": {
            "directory_scan_mode": "*",
            "scan_filters": [
                {
                    "name": "directory_prune",
                    "enabled": True,
                    "prune_dir_globs": list(prune_dir_globs or []),
                    "path_globs": list(path_globs or []),
                }
            ],
        }
    })


def test_directory_prune_exact_name_stops_descending(tmp_path):
    archive = tmp_path / "ignored" / "deep" / "payload.zip"
    archive.parent.mkdir(parents=True)
    archive.write_bytes(b"PK\x03\x04payload")
    keep = tmp_path / "keep.zip"
    keep.write_bytes(b"PK\x03\x04payload")

    snapshot = DirectoryScanner(str(tmp_path), config=_config(prune_dir_globs=["ignored"])).scan()
    paths = {entry.path for entry in _entries(snapshot)}

    assert archive not in paths
    assert tmp_path / "ignored" not in paths
    assert keep in paths


def test_directory_prune_wildcard_matches_directory_name_case_insensitively(tmp_path):
    archive = tmp_path / "Node_Modules" / "payload.zip"
    archive.parent.mkdir()
    archive.write_bytes(b"PK\x03\x04payload")

    snapshot = DirectoryScanner(str(tmp_path), config=_config(prune_dir_globs=["node_*"])).scan()

    assert not snapshot


def test_directory_prune_path_glob_is_relative_to_scan_root(tmp_path):
    blocked = tmp_path / "cache" / "private" / "payload.zip"
    allowed = tmp_path / "other" / "cache" / "payload.zip"
    blocked.parent.mkdir(parents=True)
    allowed.parent.mkdir(parents=True)
    blocked.write_bytes(b"PK\x03\x04payload")
    allowed.write_bytes(b"PK\x03\x04payload")
    recycled = tmp_path / "$RECYCLE.BIN" / "payload.zip"
    recycled.parent.mkdir()
    recycled.write_bytes(b"PK\x03\x04payload")

    snapshot = DirectoryScanner(str(tmp_path), config=_config(
        path_globs=["cache/private/**", "$RECYCLE.BIN/**"]
    )).scan()
    paths = {entry.path for entry in _entries(snapshot)}

    assert blocked not in paths
    assert allowed in paths
    assert recycled not in paths
    assert recycled.parent not in paths


def test_game_like_tree_is_not_implicitly_protected(tmp_path):
    archive = tmp_path / "game" / "www" / "audio" / "bgm.7z"
    archive.parent.mkdir(parents=True)
    archive.write_bytes(b"7z\xbc\xaf\x27\x1c")
    (tmp_path / "game" / "game.exe").write_bytes(b"MZ")
    (tmp_path / "game" / "www" / "data").mkdir()

    snapshot = DirectoryScanner(str(tmp_path), config=_config()).scan()

    assert archive in {entry.path for entry in _entries(snapshot)}
