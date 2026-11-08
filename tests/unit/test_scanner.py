from sunpack.core.contracts.discovery_scope import DiscoveryScope
from pathlib import Path

import pytest

from tests.helpers.directory_snapshot import FileEntry, snapshot_rows
from sunpack.pipeline.coordinator.target_scan import build_candidates_for_targets
from sunpack.pipeline.discovery.filesystem.directory_scanner import DirectoryScanner
from tests.helpers.config_factory import make_config


def _entries(snapshot):
    return [
        FileEntry(path=Path(path), is_dir=is_dir, size=size, mtime_ns=mtime_ns)
        for path, is_dir, size, mtime_ns in snapshot_rows(snapshot)
    ]


def test_directory_scanner_captures_files_and_directories(tmp_path):
    (tmp_path / "nested").mkdir()
    (tmp_path / "archive.zip").write_bytes(b"PK\x03\x04")
    (tmp_path / "nested" / "notes.txt").write_text("hello", encoding="utf-8")

    snapshot = DirectoryScanner(str(tmp_path), scope=DiscoveryScope(str(tmp_path), recursive=True), config=make_config({
        "filesystem": {
            
        }
    })).scan()
    names = {entry.path.name for entry in _entries(snapshot)}

    assert {"nested", "archive.zip", "notes.txt"} <= names
    entries = _entries(snapshot)
    assert any(entry.is_dir and entry.path.name == "nested" for entry in entries)
    assert any(not entry.is_dir and entry.path.name == "archive.zip" for entry in entries)
    assert next(entry for entry in entries if entry.path.name == "archive.zip").size == 4


@pytest.mark.parametrize(("sizes", "bounds", "expected"), [
    ((8, 16, 32), {"min_bytes": 10, "max_bytes": 31}, {"medium.zip"}),
    ((8, 16, 32), {"min_bytes": 10}, {"medium.zip", "large.zip"}),
    ((512 * 1024, 2 * 1024 * 1024, 11 * 1024 * 1024),
     {"min_bytes": 1048577, "max_bytes": 10485759}, {"medium.zip"}),
])
def test_directory_scanner_size_range_filters_integer_byte_bounds(tmp_path, sizes, bounds, expected):
    for name, size in zip(("small.zip", "medium.zip", "large.zip"), sizes):
        with (tmp_path / name).open("wb") as stream:
            stream.truncate(size)

    snapshot = DirectoryScanner(str(tmp_path), config=make_config({
        "filesystem": {
            "scan_filters": [{"name": "size_range", "enabled": True, **bounds}]
        }
    })).scan()

    assert {entry.path.name for entry in _entries(snapshot)} == expected


def test_directory_scanner_promotes_small_split_member_with_accepted_family_anchor(tmp_path):
    first = tmp_path / "payload.7z.001"
    second = tmp_path / "payload.7z.002"
    tail = tmp_path / "payload.7z.003"
    unrelated = tmp_path / "unrelated.7z.003"
    first.write_bytes(b"a" * 16)
    second.write_bytes(b"b" * 16)
    tail.write_bytes(b"tail")
    unrelated.write_bytes(b"noise")
    (tmp_path / "unrelated.7z.002").write_bytes(b"noise")

    snapshot = DirectoryScanner(str(tmp_path), config=make_config({
        "filesystem": {
            "scan_filters": [
                {"name": "size_range", "enabled": True, "min_bytes": 10},
            ]
        }
    })).scan()

    names = {entry.path.name for entry in _entries(snapshot)}
    assert {first.name, second.name, tail.name} <= names
    assert unrelated.name not in names
    assert "unrelated.7z.002" not in names


@pytest.mark.parametrize(
    ("anchor_name", "small_member_name"),
    [
        ("payload.7z.001", "payload.7z.002"),
        ("payload.zip.001", "payload.zip.002"),
        ("payload.zip.0000", "payload.zip.0001"),
        ("payload.rar.001", "payload.rar.002"),
        ("payload.part1.rar", "payload.part2.rar"),
        ("payload.part1.exe", "payload.part2.rar"),
        ("payload.rar", "payload.r00"),
        ("payload.001", "payload.002"),
        ("payload.7z", "payload.7z.002"),
        ("payload.zx01", "payload.zipx"),
        ("payload.zipx", "payload.zx01"),
        ("payload.zx01", "payload.zx02"),
    ],
)
def test_directory_scanner_size_deferred_supports_all_split_naming_families(
    tmp_path,
    anchor_name,
    small_member_name,
):
    (tmp_path / anchor_name).write_bytes(b"a" * 16)
    (tmp_path / small_member_name).write_bytes(b"tail")

    snapshot = DirectoryScanner(str(tmp_path), config=make_config({
        "filesystem": {
            "scan_filters": [
                {"name": "size_range", "enabled": True, "min_bytes": 10},
            ]
        }
    })).scan()

    names = {entry.path.name for entry in _entries(snapshot)}
    assert {anchor_name, small_member_name} <= names


def test_directory_scanner_never_promotes_hard_rejected_split_member(tmp_path):
    first = tmp_path / "payload.7z.001"
    blocked_tail = tmp_path / "payload.7z.002"
    first.write_bytes(b"a" * 16)
    blocked_tail.write_bytes(b"tail")

    snapshot = DirectoryScanner(str(tmp_path), config=make_config({
        "filesystem": {
            "scan_filters": [
                {'name': 'blacklist', 'enabled': True, 'full_names': [{'value': blocked_tail.name, 'regex': False}]},
                {"name": "size_range", "enabled": True, "min_bytes": 10},
            ]
        }
    })).scan()

    names = {entry.path.name for entry in _entries(snapshot)}
    assert first.name in names
    assert blocked_tail.name not in names


@pytest.mark.parametrize(("times", "start", "end"), [
    ((1_704_067_200, 1_735_689_600, 1_767_225_600), "2025-01-01T00:00Z", "2026-01-01T00:00Z"),
    ((1_735_689_600, 1_767_225_600, 1_798_761_600), "2025-03-20T01:30Z", "2026-04-30T01:40Z"),
])
def test_directory_scanner_mtime_range_filters_utc_minutes(tmp_path, times, start, end):
    import os

    old = tmp_path / "old.zip"
    keep = tmp_path / "keep.zip"
    new = tmp_path / "new.zip"
    old.write_bytes(b"old")
    keep.write_bytes(b"keep")
    new.write_bytes(b"new")
    for path, seconds in zip((old, keep, new), times):
        os.utime(path, ns=(seconds * 1_000_000_000, seconds * 1_000_000_000))

    snapshot = DirectoryScanner(str(tmp_path), config=make_config({
        "filesystem": {
            "scan_filters": [
                {"name": "mtime_range", "enabled": True, "start_utc": start, "end_utc": end},
            ]
        }
    })).scan()

    assert {entry.path.name for entry in _entries(snapshot)} == {"keep.zip"}


def test_directory_scanner_current_dir_only_scan_mode_skips_subdirectories(tmp_path):
    nested = tmp_path / "nested"
    nested.mkdir()
    (tmp_path / "root.zip").write_bytes(b"PK\x03\x04payload")
    (nested / "nested.zip").write_bytes(b"PK\x03\x04payload")

    snapshot = DirectoryScanner(str(tmp_path), config=make_config({
        "filesystem": {
            
            "scan_filters": [],
        }
    })).scan()

    names = {entry.path.name for entry in _entries(snapshot)}
    assert "root.zip" in names
    assert "nested" not in names
    assert "nested.zip" not in names


def test_directory_scanner_explicit_max_depth_overrides_scan_mode(tmp_path):
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "nested.zip").write_bytes(b"PK\x03\x04payload")

    snapshot = DirectoryScanner(str(tmp_path), scope=DiscoveryScope(str(tmp_path), max_depth=1), config=make_config({
        "filesystem": {
            
            "scan_filters": [],
        }
    })).scan()

    names = {entry.path.name for entry in _entries(snapshot)}
    assert "nested" in names
    assert "nested.zip" in names


def test_directory_scanner_path_filter_skips_file_before_stat(tmp_path, monkeypatch):
    blocked = tmp_path / "skip.py"
    blocked.write_text("print('skip')", encoding="utf-8")
    keep = tmp_path / "keep.zip"
    keep.write_bytes(b"PK\x03\x04payload")

    original_stat = type(blocked).stat

    def fail_if_blocked(self):
        if self == blocked:
            raise AssertionError("path-stage blacklist should reject before file stat")
        return original_stat(self)

    monkeypatch.setattr(type(blocked), "stat", fail_if_blocked)

    snapshot = DirectoryScanner(str(tmp_path), config=make_config({
        "filesystem": {
            "scan_filters": [
                {'name': 'blacklist', 'enabled': True, 'extensions': [{'value': 'py', 'regex': False}]},
            ]
        }
    })).scan()

    names = {entry.path.name for entry in _entries(snapshot)}
    assert "skip.py" not in names
    assert "keep.zip" in names


def test_directory_scanner_name_filters_and_switches(tmp_path):
    names = {"keep.zip", "skip.py", "skip.rar", "Thumbs.db", "Thumbs.zip",
             "sample.zip", "sample.rar", "other.zip"}
    for name in names:
        (tmp_path / name).write_bytes(b"fixture")
    zip_names = {name for name in names if name.endswith(".zip")}
    whitelist = {"name": "whitelist", "enabled": True,
                 "extensions": [{"value": "zip", "regex": False}]}
    blacklist = {"name": "blacklist", "enabled": True,
                 "extensions": [{"value": "py", "regex": False}]}
    for filters_enabled, filters, expected in (
        (True, [{**whitelist, "enabled": False}], names),
        (True, [whitelist], zip_names),
        (True, [{"name": "blacklist", "enabled": True,
                 "full_names": [{"value": "Thumbs.db", "regex": False}]}], names - {"Thumbs.db"}),
        (True, [{"name": "whitelist", "enabled": True,
                 "full_names": [{"value": "sample.zip", "regex": False}]}], {"sample.zip"}),
        (True, [{**whitelist, "extensions": whitelist["extensions"] + blacklist["extensions"]},
                blacklist], zip_names),
        (False, [blacklist], names),
    ):
        snapshot = DirectoryScanner(str(tmp_path), config=make_config({
            "filesystem": {"scan_filters_enabled": filters_enabled, "scan_filters": filters},
        })).scan()
        assert {entry.path.name for entry in _entries(snapshot)} == expected, (filters_enabled, filters)


def test_directory_scanner_whitelist_combines_path_and_extension_constraints(tmp_path):
    allowed_dir = tmp_path / "archives"
    blocked_dir = tmp_path / "other"
    allowed_dir.mkdir()
    blocked_dir.mkdir()
    (allowed_dir / "keep.zip").write_bytes(b"fixture")
    (allowed_dir / "skip.rar").write_bytes(b"fixture")
    (blocked_dir / "skip.zip").write_bytes(b"fixture")
    (tmp_path / "other.zip").write_bytes(b"fixture")
    for extensions, expected in (
        ([], {"archives", "keep.zip", "skip.rar"}),
        ([{"value": "zip", "regex": False}], {"archives", "keep.zip"}),
    ):
        snapshot = DirectoryScanner(
            str(tmp_path), scope=DiscoveryScope(str(tmp_path), recursive=True),
            config=make_config({"filesystem": {"scan_filters": [{
                "name": "whitelist", "enabled": True,
                "paths": [{"value": r"\Aarchives\z", "regex": True}], "extensions": extensions,
            }]}}),
        ).scan()
        assert {entry.path.name for entry in _entries(snapshot)} == expected, extensions


def test_directory_scanner_keeps_filter_rejected_files_in_raw_snapshot(tmp_path):
    blocked = tmp_path / "runtime.dll"
    blocked.write_bytes(b"x" * 16)
    archive = tmp_path / "keep.zip"
    archive.write_bytes(b"PK\x03\x04payload")

    snapshot = DirectoryScanner(str(tmp_path), config=make_config({
        "filesystem": {
            "scan_filters": [
                {'name': 'blacklist', 'enabled': True, 'extensions': [{'value': 'dll', 'regex': False}]},
            ]
        }
    })).scan()

    filtered_paths = {entry.path for entry in _entries(snapshot)}
    raw_paths, raw_is_dirs, _sizes, _mtimes = snapshot.raw_native_snapshot.materialize_columns()
    raw_file_paths = {
        Path(path)
        for path, is_dir in zip(raw_paths, raw_is_dirs)
        if not is_dir
    }
    assert blocked not in filtered_paths
    assert blocked in raw_file_paths
    assert archive in filtered_paths
    assert archive in raw_file_paths


def test_directory_scanner_blacklist_paths_match_whole_components(tmp_path):
    blocked_dir = tmp_path / "site-packages"
    blocked_dir.mkdir()
    (blocked_dir / "payload.zip").write_bytes(b"PK\x03\x04payload")
    same_name_file = tmp_path / "site-packages.zip"
    same_name_file.write_bytes(b"PK\x03\x04payload")

    snapshot = DirectoryScanner(str(tmp_path), config=make_config({
        "filesystem": {
            "scan_filters": [
                {'name': 'blacklist', 'enabled': True, 'paths': [{'value': 'site-packages', 'regex': False}]},
            ]
        }
    })).scan()

    names = {entry.path.name for entry in _entries(snapshot)}
    assert "site-packages" not in names
    assert "payload.zip" not in names
    assert "site-packages.zip" in names


def test_target_scan_reuses_session_for_duplicate_directories(tmp_path, monkeypatch):
    (tmp_path / "archive.zip").write_bytes(b"PK\x03\x04payload")

    scan_count = 0
    original_scan = DirectoryScanner.scan

    def counting_scan(self):
        nonlocal scan_count
        scan_count += 1
        return original_scan(self)

    monkeypatch.setattr(DirectoryScanner, "scan", counting_scan)

    candidates = build_candidates_for_targets([str(tmp_path), str(tmp_path)], config=make_config())

    assert len([candidate for candidate in candidates if candidate.entry_path == str(tmp_path / "archive.zip")]) == 1
    assert scan_count == 1


def test_default_detection_recognizes_disguised_content_without_extension_fallback(tmp_path):
    import gzip
    from sunpack.pipeline.coordinator.task_provider import ArchiveTaskProvider

    path = tmp_path / "fake.zip"
    path.write_bytes(b"not an archive")
    stream = tmp_path / "payload.opaque"
    stream.write_bytes(gzip.compress(b"actual archive content"))
    # Even a stale retired switch cannot disable the built-in mechanism.
    provider = ArchiveTaskProvider(make_config({"detection": {"enabled": False}}))
    tasks = provider.scan_targets([str(path), str(stream)])
    assert [task.main_path for task in tasks] == [str(stream)]
    assert tasks[0].discovery_source == "detection"
