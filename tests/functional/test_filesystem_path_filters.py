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


def _config(*, paths=None):
    return make_config({
        "filesystem": {
            "scan_filters": [
                {
                    "name": "blacklist",
                    "enabled": True,
                    "paths": list(paths or []),
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

    snapshot = DirectoryScanner(str(tmp_path), scope=DiscoveryScope(str(tmp_path), recursive=True), config=_config(paths=[{'value':'ignored','regex':False}])).scan()
    paths = {entry.path for entry in _entries(snapshot)}

    assert archive not in paths
    assert tmp_path / "ignored" not in paths
    assert keep in paths


def test_blacklist_path_regex_matches_directory_name_case_sensitively(tmp_path):
    archive = tmp_path / "Node_Modules" / "payload.zip"
    archive.parent.mkdir()
    archive.write_bytes(b"PK\x03\x04payload")
    blocked = tmp_path / "nested" / "node_modules" / "payload.zip"
    blocked.parent.mkdir(parents=True)
    blocked.write_bytes(b"PK\x03\x04payload")

    snapshot = DirectoryScanner(str(tmp_path), scope=DiscoveryScope(str(tmp_path), recursive=True), config=_config(paths=[{'value':r'(?:\A|/)node_[^/]*(?:/|\z)','regex':True}])).scan()

    paths = {entry.path for entry in _entries(snapshot)}
    assert archive in paths
    assert blocked not in paths


def test_blacklist_literal_path_is_relative_to_scan_root(tmp_path):
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
        paths=[{'value':'cache/private','regex':False},{'value':'$RECYCLE.BIN','regex':False}]
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
        "中文/报告[1]+.zip", "unicode/Keep.txt", "unicode/ſample.zip",
    }
    for name in names:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"opaque")
    paths = [str(root / name) for name in sorted(names)]
    entries = [FileEntry(path=Path(path), is_dir=False, size=6) for path in paths]
    inventory = collect_output_inventory(str(root))
    scope = DiscoveryScope(str(root), recursive=True)
    def literal(value): return {"value": value, "regex": False}
    def regex(value): return {"value": value, "regex": True}
    cases = [
        ([{"name": "blacklist", "enabled": True,
           "paths": [regex(r"(?:\A|/)node_[^/]*(?:/|\z)"), literal(r"cache\private"), regex(r"(?:\A|/)a[^/]*b(?:/|\z)")],
           "full_names": [regex(r"keep_0[0-9]\.rar\z"), literal("regex[0-9]+.zip")]}],
         names - {"cache/private/keep_06.zip",
                  "axb/keep_09.zip", "archives/sub/deeper/keep_02.rar",
                  "archives/sub/deeper/regex[0-9]+.zip"}),
        ([{"name": "whitelist", "enabled": True,
           "paths": [regex(r"\A(?:archives|downloads)(?:/|\z)")],
           "full_names": [regex(r"(?:keep_[0-9]{2}|root)\.zip\z")]},
          {"name": "blacklist", "enabled": True, "paths": [regex(r"\Aarchives/skip_")]}],
         {"archives/root.zip",
          "archives/sub/deeper/keep_03.zip", "downloads/sub/keep_10.zip"}),
        ([{"name": "whitelist", "enabled": True,
           "paths": [literal("downloads/sub")]}], {"downloads/sub/keep_10.zip"}),
        ([{"name": "whitelist", "enabled": True,
           "paths": [regex(r"(?:\A|/)archives(?:/|\z)|\Aa/(?:[^/]+/)*b(?:/|\z)")]}],
         {name for name in names if name.startswith(("archives/", "elsewhere/archives/", "a/"))}),
        ([{"name": "whitelist", "enabled": True, "paths": [literal("archives")]}],
         {name for name in names if name.startswith(("archives/", "elsewhere/archives/"))}),
        ([{"name": "whitelist", "enabled": True, "paths": [regex(r"\Adownloads/sub\z")]}],
         {"downloads/sub/keep_10.zip"}),
        ([{"name": "whitelist", "enabled": True, "paths": [regex(r"\A中文/\p{L}+\[1\]\+\.zip\z")]}],
         {"中文/报告[1]+.zip"}),
        ([{"name": "whitelist", "enabled": True, "full_names": [literal("Keep.txt"), literal("sample.zip")]}],
         set()),
        ([{"name": "whitelist", "enabled": True, "full_names": [literal("Keep.txt"), literal("ſample.zip")]}],
         {"unicode/Keep.txt", "unicode/ſample.zip"}),
        ([{"name": "whitelist", "enabled": True, "paths": [regex(r"\Aarchives/.*Keep_[0-9]+\.ZIP\z")]}],
         {"archives/sub/deeper/Keep_01.ZIP"}),
        ([{"name": "whitelist", "enabled": True, "paths": [literal("a/*/b")]}],
         {"a/x/b/keep_08.zip"}),
        ([{"name": "whitelist", "enabled": True, "paths": [literal("archives/s?b")]}],
         {"archives/sub/deeper/Keep_01.ZIP", "archives/sub/deeper/keep_02.rar",
          "archives/sub/deeper/keep_03.zip", "archives/sub/deeper/regex[0-9]+.zip"}),
        ([{"name": "whitelist", "enabled": True,
           "files": [literal("keep_??")], "extensions": [literal("z?p")],
           "full_names": [literal("*_03.*"), regex(r"\AKeep_01\.ZIP\z")]}],
         {"archives/sub/deeper/keep_03.zip"}),
        ([{"name": "blacklist", "enabled": True, "paths": [literal("node_*")],
           "files": [literal("regex[0-9]+")], "extensions": [literal("r?r")],
           "full_names": [literal("keep_03.???")]}],
         names - {"archives/sub/deeper/regex[0-9]+.zip",
                  "archives/sub/deeper/keep_02.rar", "archives/sub/deeper/keep_03.zip"}),
        ([{"name": "whitelist", "enabled": True,
           "files": [literal("报告[?]+")], "extensions": [regex(r"\Az(?:ip|ipx)\z")]}],
         {"中文/报告[1]+.zip"}),
        ([{"name": "whitelist", "enabled": True, "paths": [literal("Archives/sub")]}], set()),
        ([{"name": "whitelist", "enabled": True, "paths": [literal("ARCHIVES/*")]}], set()),
        ([{"name": "whitelist", "enabled": True, "paths": [regex(r"\A中文/报告")]}],
         {"中文/报告[1]+.zip"}),
        ([{"name": "whitelist", "enabled": True, "full_names": [literal("keep_01.zip")]}], set()),
        ([{"name": "whitelist", "enabled": True, "full_names": [literal("Keep_01.ZIP")]}],
         {"archives/sub/deeper/Keep_01.ZIP"}),
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


def test_regex_cache_pressure_keeps_concurrent_batch_results():
    """The filesystem matrix never fills a lazy DFA cache. This small in-memory
    batch catches lost matches during cache clearing/fallback and concurrent
    reuse of one compiled rule, without directory or archive startup costs.
    """
    import random
    from concurrent.futures import ThreadPoolExecutor
    from sunpack_native import NativePathRule

    rng = random.Random(20261101)
    names = ["".join(rng.choice("01") for _ in range(64)) for _ in range(1024)]
    paths = [f"C:/input/{name}" for name in names]
    expected = [index for index, name in enumerate(names) if name[-19] == "1"]
    rule = NativePathRule([], [], [], [{"value": r"\A[01]*1[01]{18}\z", "regex": True}])

    def run(_):
        assert rule.accepted_indices("C:/input", paths, [False] * len(paths), True) == expected

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(run, range(8)))


def test_filename_parts_use_the_last_dot_and_handle_absent_or_empty_extensions():
    """The real tree cannot represent trailing dots on Windows. This native
    batch adds those boundaries and checks all three selectors without IO.
    """
    from sunpack_native import NativePathRule

    names = ["bundle.part01.rar.jpg", "archive.tar.gz", "README", "a.", ".zip",
             "报告[终]+.ZIP", "KEEP.ſAFETENSORS"]
    paths = [f"C:/input/{name}" for name in names]
    cases = [
        ({"files": [{"value": "bundle.part??.rar", "regex": False}]}, {names[0]}),
        ({"files": [{"value": "archive.tar", "regex": False}]}, {names[1]}),
        ({"files": [{"value": "README", "regex": False}]}, {names[2]}),
        ({"files": [{"value": "readme", "regex": False}]}, set()),
        ({"extensions": [{"value": r"\A\z", "regex": True}]}, {names[3]}),
        ({"extensions": [{"value": "zip", "regex": False}]}, {names[4]}),
        ({"extensions": [{"value": "ZIP", "regex": False}]}, {names[5]}),
        ({"files": [{"value": r"\A\z", "regex": True}]}, {names[4]}),
        ({"files": [{"value": "报告[?]+", "regex": False}]}, {names[5]}),
        ({"files": [{"value": "keep", "regex": False}],
          "extensions": [{"value": "safetensors", "regex": False}]}, set()),
        ({"files": [{"value": "KEEP", "regex": False}],
          "extensions": [{"value": "ſAFETENSORS", "regex": False}]}, {names[6]}),
        ({"full_names": [{"value": "*.rar.jpg", "regex": False}]}, {names[0]}),
        ({"extensions": [{"value": "*", "regex": False}]}, set(names) - {names[2]}),
    ]
    for fields, expected in cases:
        rule = NativePathRule(*(fields.get(field, []) for field in ("paths", "files", "extensions", "full_names")))
        indices = rule.accepted_indices("C:/input", paths, [False] * len(paths), True)
        assert {names[index] for index in indices} == expected
