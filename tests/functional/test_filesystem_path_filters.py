from sunpack.core.contracts.discovery_scope import DiscoveryScope
from pathlib import Path

from sunpack.core.contracts.filesystem import FileEntry
from sunpack.pipeline.discovery.filesystem.directory_scanner import DirectoryScanner
from tests.helpers.config_factory import make_config


def _entries(snapshot):
    return [
        FileEntry(path=Path(path), is_dir=is_dir, size=size, mtime_ns=mtime_ns)
        for path, is_dir, size, mtime_ns in snapshot.iter_columns()
    ]


def _config(*, path_globs=None):
    return make_config({
        "filesystem": {
            "scan_filters": [
                {
                    "name": "blacklist",
                    "enabled": True,
                    "path_globs": list(path_globs or []),
                }
            ],
        }
    })


def test_blacklist_path_exact_name_stops_descending(tmp_path):
    archive = tmp_path / "ignored" / "deep" / "payload.zip"
    archive.parent.mkdir(parents=True)
    archive.write_bytes(b"PK\x03\x04payload")
    keep = tmp_path / "keep.zip"
    keep.write_bytes(b"PK\x03\x04payload")

    snapshot = DirectoryScanner(str(tmp_path), scope=DiscoveryScope(str(tmp_path), recursive=True), config=_config(path_globs=["ignored"])).scan()
    paths = {entry.path for entry in _entries(snapshot)}

    assert archive not in paths
    assert tmp_path / "ignored" not in paths
    assert keep in paths


def test_blacklist_path_wildcard_matches_directory_name_case_insensitively(tmp_path):
    archive = tmp_path / "Node_Modules" / "payload.zip"
    archive.parent.mkdir()
    archive.write_bytes(b"PK\x03\x04payload")

    snapshot = DirectoryScanner(str(tmp_path), scope=DiscoveryScope(str(tmp_path), recursive=True), config=_config(path_globs=["node_*"])).scan()

    assert not snapshot


def test_blacklist_path_glob_is_relative_to_scan_root(tmp_path):
    blocked = tmp_path / "cache" / "private" / "payload.zip"
    allowed = tmp_path / "other" / "cache" / "payload.zip"
    blocked.parent.mkdir(parents=True)
    allowed.parent.mkdir(parents=True)
    blocked.write_bytes(b"PK\x03\x04payload")
    allowed.write_bytes(b"PK\x03\x04payload")
    recycled = tmp_path / "$RECYCLE.BIN" / "payload.zip"
    recycled.parent.mkdir()
    recycled.write_bytes(b"PK\x03\x04payload")

    snapshot = DirectoryScanner(str(tmp_path), scope=DiscoveryScope(str(tmp_path), recursive=True), config=_config(
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

    snapshot = DirectoryScanner(str(tmp_path), scope=DiscoveryScope(str(tmp_path), recursive=True), config=_config()).scan()

    assert archive in {entry.path for entry in _entries(snapshot)}


def test_path_rules_agree_across_scans_watch_and_output_inventories(tmp_path):
    """One shared tree catches drift between traversal, incremental watch and inventory filtering.

    Existing scanner tests cannot detect a watch or inventory bypass. Running
    the cases concurrently also checks that shared compiled rules stay immutable.
    """
    from concurrent.futures import ThreadPoolExecutor

    from sunpack_native import NativeWatchCatalog
    from sunpack.pipeline.extraction.output_inventory import collect_output_inventory
    from sunpack.runtime.watch.state import WatchStateStore

    root = tmp_path / "input"
    names = {
        "archives/root.zip", "archives/sub/deeper/Keep_01.ZIP",
        "archives/sub/deeper/keep_02.rar", "archives/sub/deeper/keep_03.zip",
        "archives/sub/deeper/regex[0-9]+.zip", "archives/skip_zone/keep_04.zip",
        "elsewhere/archives/keep_05.zip", "cache/private/keep_06.zip",
        "elsewhere/cache/private/keep_07.zip", "a/x/b/keep_08.zip",
        "a/b/keep_08.zip", "axb/keep_09.zip", "downloads/sub/keep_10.zip",
        "NODE_Modules/deep/keep_11.zip", "keep_12.zip",
    }
    for name in names:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"opaque")
    paths = [str(root / name) for name in sorted(names)]
    entries = [FileEntry(path=Path(path), is_dir=False, size=6) for path in paths]
    inventory = collect_output_inventory(str(root))
    scope = DiscoveryScope(str(root), recursive=True)
    cases = [
        ([{"name": "blacklist", "enabled": True,
           "path_globs": ["node_*", r"cache\private", "a*b"],
           "blocked_files": ["keep_0?.rar", "regex[0-9]+.zip"]}],
         names - {"NODE_Modules/deep/keep_11.zip", "cache/private/keep_06.zip",
                  "axb/keep_09.zip", "archives/sub/deeper/keep_02.rar",
                  "archives/sub/deeper/regex[0-9]+.zip"}),
        ([{"name": "whitelist", "enabled": True,
           "path_globs": ["archives/**", "downloads/**"],
           "allowed_files": ["keep_??.*", "root.zip"], "allowed_extensions": ["ZIP"]},
          {"name": "blacklist", "enabled": True, "path_globs": ["archives/skip_*"]}],
         {"archives/root.zip", "archives/sub/deeper/Keep_01.ZIP",
          "archives/sub/deeper/keep_03.zip", "downloads/sub/keep_10.zip"}),
        ([{"name": "whitelist", "enabled": True,
           "path_globs": ["downloads/sub/**"]}], {"downloads/sub/keep_10.zip"}),
        ([{"name": "whitelist", "enabled": True,
           "path_globs": ["**/archives/**", "a/**/b/**"]}],
         {name for name in names if name.startswith(("archives/", "elsewhere/archives/", "a/"))}),
        ([{"name": "whitelist", "enabled": True, "path_globs": ["archives"]}],
         {name for name in names if name.startswith(("archives/", "elsewhere/archives/"))}),
    ]

    def relative_files(snapshot):
        return {Path(path).relative_to(root).as_posix()
                for path, is_dir, *_ in snapshot.iter_columns() if not is_dir}

    def run_case(item):
        index, (filters, expected) = item
        config = make_config({"filesystem": {"scan_filters": filters}})
        options = DirectoryScanner.compile_scan_options(config)
        assert relative_files(DirectoryScanner(str(root), scope=scope, config=config).scan()) == expected
        assert relative_files(DirectoryScanner.snapshot_from_entries(str(root), entries, config=config)) == expected
        indices = DirectoryScanner.inventory_file_indices(str(root), paths, [6] * len(paths), config=config)
        assert {Path(paths[i]).relative_to(root).as_posix() for i in indices} == expected
        assert relative_files(DirectoryScanner.snapshot_from_output_inventory(
            str(root), inventory, scan_options=options,
        )) == expected
        state = WatchStateStore(str(tmp_path / f"state-{index}"))
        catalog = NativeWatchCatalog(state._native)
        try:
            # Targeted arrivals can start below the rule's matched directory.
            for path in paths:
                assert not options.catalog_update(catalog, scope.native, path)
            accepted = set()
            for path in paths:
                filtered, _raw = options.catalog_snapshot(catalog, scope.native, path)
                accepted.update(Path(value).relative_to(root).as_posix()
                                for value in filtered.file_columns()[0])
            assert accepted == expected
        finally:
            catalog.close()
            state.close()

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(run_case, enumerate(cases)))
