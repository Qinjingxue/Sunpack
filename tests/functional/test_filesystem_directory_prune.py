from pathlib import Path

from sunpack.core.contracts.filesystem import FileEntry
from sunpack.pipeline.discovery.filesystem.directory_scanner import DirectoryScanner
from sunpack_native import profile_directory_scan


def _entries(snapshot):
    return [
        FileEntry(path=Path(path), is_dir=is_dir, size=size, mtime_ns=mtime_ns)
        for path, is_dir, size, mtime_ns in snapshot.iter_columns()
    ]


def _config(*, prune_dir_globs=None, path_globs=None):
    return {
        "filesystem": {
            "directory_scan_mode": "recursive",
            "scan_filters": [
                {
                    "name": "directory_prune",
                    "enabled": True,
                    "prune_dir_globs": list(prune_dir_globs or []),
                    "path_globs": list(path_globs or []),
                }
            ],
        }
    }


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

    snapshot = DirectoryScanner(str(tmp_path), config=_config(path_globs=["cache/private/**"])).scan()
    paths = {entry.path for entry in _entries(snapshot)}

    assert blocked not in paths
    assert allowed in paths


def test_game_like_tree_is_not_implicitly_protected(tmp_path):
    archive = tmp_path / "game" / "www" / "audio" / "bgm.7z"
    archive.parent.mkdir(parents=True)
    archive.write_bytes(b"7z\xbc\xaf\x27\x1c")
    (tmp_path / "game" / "game.exe").write_bytes(b"MZ")
    (tmp_path / "game" / "www" / "data").mkdir()

    snapshot = DirectoryScanner(str(tmp_path), config=_config()).scan()

    assert archive in {entry.path for entry in _entries(snapshot)}


def test_profiled_scan_matches_normal_scan(tmp_path):
    kept = tmp_path / "kept" / "payload.zip"
    pruned = tmp_path / "ignored" / "payload.zip"
    kept.parent.mkdir()
    pruned.parent.mkdir()
    kept.write_bytes(b"PK\x03\x04payload")
    pruned.write_bytes(b"PK\x03\x04payload")
    config = _config(prune_dir_globs=["ignored"])
    scanner = DirectoryScanner(str(tmp_path), config=config)
    expected = scanner.scan()
    options = scanner._native_scan_options()

    profiled, profile = profile_directory_scan(
        str(tmp_path),
        scanner.max_depth,
        options["patterns"],
        options["prune_dir_globs"],
        options["blocked_extensions"],
        options["blocked_file_names"],
        options["size_ranges"],
        options["mtime_ranges"],
        options["whitelist_rules"],
    )

    paths, _is_dirs, _sizes, _mtimes_ns = profiled.materialize_columns()
    assert set(paths) == {
        str(entry.path) for entry in _entries(expected)
    }
    assert profile["accepted_entries"] == len(profiled)
    assert profile["pruned_directories"] == 1
    assert profile["entries_seen"] >= len(profiled)
    assert profile["scan_total_ns"] >= profile["directory_enumeration_ns"]
