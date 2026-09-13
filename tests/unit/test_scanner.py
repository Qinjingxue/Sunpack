from pathlib import Path

import pytest

from sunpack.contracts.filesystem import FileEntry
from sunpack.filesystem.directory_scanner import DirectoryScanner
from sunpack.detection import DetectionScheduler
from sunpack.coordinator.task_provider import ArchiveTaskProvider
from sunpack.coordinator.target_scan import build_fact_bags_for_targets
from tests.helpers.detection_config import with_detection_pipeline


def _entries(snapshot):
    return [
        FileEntry(path=Path(path), is_dir=is_dir, size=size, mtime_ns=mtime_ns)
        for path, is_dir, size, mtime_ns in snapshot.iter_columns()
    ]


def test_directory_scanner_captures_files_and_directories(tmp_path):
    (tmp_path / "nested").mkdir()
    (tmp_path / "archive.zip").write_bytes(b"PK\x03\x04")
    (tmp_path / "nested" / "notes.txt").write_text("hello", encoding="utf-8")

    snapshot = DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "directory_scan_mode": "recursive",
        }
    }).scan()
    names = {entry.path.name for entry in _entries(snapshot)}

    assert snapshot.root_path == tmp_path
    assert {"nested", "archive.zip", "notes.txt"} <= names
    entries = _entries(snapshot)
    assert any(entry.is_dir and entry.path.name == "nested" for entry in entries)
    assert any(not entry.is_dir and entry.path.name == "archive.zip" for entry in entries)


def test_directory_scanner_records_file_size(tmp_path):
    target = tmp_path / "archive.zip"
    target.write_bytes(b"PK\x03\x04payload")

    snapshot = DirectoryScanner(str(tmp_path)).scan()
    entry = next(entry for entry in _entries(snapshot) if entry.path == target)

    assert entry.size == target.stat().st_size


def test_directory_scanner_size_range_filters_files_outside_range(tmp_path):
    small = tmp_path / "small.zip"
    medium = tmp_path / "medium.zip"
    large = tmp_path / "large.zip"
    small.write_bytes(b"a" * 8)
    medium.write_bytes(b"b" * 16)
    large.write_bytes(b"c" * 32)

    snapshot = DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "scan_filters": [
                {"name": "size_range", "enabled": True, "gte": 10, "lt": 32},
            ]
        }
    }).scan()

    names = {entry.path.name for entry in _entries(snapshot)}
    assert "small.zip" not in names
    assert "medium.zip" in names
    assert "large.zip" not in names


def test_directory_scanner_size_range_accepts_human_expression(tmp_path):
    small = tmp_path / "small.zip"
    keep = tmp_path / "keep.zip"
    large = tmp_path / "large.zip"
    small.write_bytes(b"a" * 512 * 1024)
    keep.write_bytes(b"b" * 2 * 1024 * 1024)
    large.write_bytes(b"c" * 11 * 1024 * 1024)

    snapshot = DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "scan_filters": [
                {"name": "size_range", "enabled": True, "range": "1 MB < r < 10 MB"},
            ]
        }
    }).scan()

    names = {entry.path.name for entry in _entries(snapshot)}
    assert "small.zip" not in names
    assert "keep.zip" in names
    assert "large.zip" not in names


def test_directory_scanner_size_range_gte_filters(tmp_path):
    small = tmp_path / "small.zip"
    keep = tmp_path / "keep.zip"
    small.write_bytes(b"a" * 8)
    keep.write_bytes(b"b" * 16)

    snapshot = DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "scan_filters": [
                {"name": "size_range", "enabled": True, "gte": 10},
            ]
        }
    }).scan()

    names = {entry.path.name for entry in _entries(snapshot)}
    assert "small.zip" not in names
    assert "keep.zip" in names


def test_directory_scanner_promotes_small_split_member_with_accepted_family_anchor(tmp_path):
    first = tmp_path / "payload.7z.001"
    second = tmp_path / "payload.7z.002"
    tail = tmp_path / "payload.7z.003"
    unrelated = tmp_path / "unrelated.7z.003"
    first.write_bytes(b"a" * 16)
    second.write_bytes(b"b" * 16)
    tail.write_bytes(b"tail")
    unrelated.write_bytes(b"noise")

    snapshot = DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "scan_filters": [
                {"name": "size_range", "enabled": True, "gte": 10},
            ]
        }
    }).scan()

    names = {entry.path.name for entry in _entries(snapshot)}
    assert {first.name, second.name, tail.name} <= names
    assert unrelated.name not in names


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
    ],
)
def test_directory_scanner_size_deferred_supports_all_split_naming_families(
    tmp_path,
    anchor_name,
    small_member_name,
):
    (tmp_path / anchor_name).write_bytes(b"a" * 16)
    (tmp_path / small_member_name).write_bytes(b"tail")

    snapshot = DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "scan_filters": [
                {"name": "size_range", "enabled": True, "gte": 10},
            ]
        }
    }).scan()

    names = {entry.path.name for entry in _entries(snapshot)}
    assert {anchor_name, small_member_name} <= names


def test_directory_scanner_never_promotes_hard_rejected_split_member(tmp_path):
    first = tmp_path / "payload.7z.001"
    blocked_tail = tmp_path / "payload.7z.002"
    first.write_bytes(b"a" * 16)
    blocked_tail.write_bytes(b"tail")

    snapshot = DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "scan_filters": [
                {"name": "blacklist", "enabled": True, "blocked_files": [blocked_tail.name]},
                {"name": "size_range", "enabled": True, "gte": 10},
            ]
        }
    }).scan()

    names = {entry.path.name for entry in _entries(snapshot)}
    assert first.name in names
    assert blocked_tail.name not in names


def test_directory_scanner_does_not_promote_split_shaped_small_files_without_anchor(tmp_path):
    (tmp_path / "orphan.7z.002").write_bytes(b"small")
    (tmp_path / "orphan.7z.003").write_bytes(b"small")

    snapshot = DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "scan_filters": [
                {"name": "size_range", "enabled": True, "gte": 10},
            ]
        }
    }).scan()

    assert not {"orphan.7z.002", "orphan.7z.003"} & {
        entry.path.name for entry in _entries(snapshot)
    }


def test_snapshot_from_entries_preserves_anchored_small_split_member(tmp_path):
    entries = [
        FileEntry(path=tmp_path / "payload.7z.001", is_dir=False, size=16),
        FileEntry(path=tmp_path / "payload.7z.002", is_dir=False, size=4),
        FileEntry(path=tmp_path / "other.7z.002", is_dir=False, size=4),
    ]

    snapshot = DirectoryScanner.snapshot_from_entries(str(tmp_path), entries, config={
        "filesystem": {
            "scan_filters": [
                {"name": "size_range", "enabled": True, "gte": 10},
            ]
        }
    })

    names = {entry.path.name for entry in _entries(snapshot)}
    assert names == {"payload.7z.001", "payload.7z.002"}


def test_directory_scanner_mtime_range_filters_files_outside_range(tmp_path):
    old = tmp_path / "old.zip"
    keep = tmp_path / "keep.zip"
    new = tmp_path / "new.zip"
    old.write_bytes(b"old")
    keep.write_bytes(b"keep")
    new.write_bytes(b"new")
    old_ns = 1_700_000_000_000_000_000
    keep_ns = 1_800_000_000_000_000_000
    new_ns = 1_900_000_000_000_000_000
    import os
    os.utime(old, ns=(old_ns, old_ns))
    os.utime(keep, ns=(keep_ns, keep_ns))
    os.utime(new, ns=(new_ns, new_ns))

    snapshot = DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "scan_filters": [
                {"name": "mtime_range", "enabled": True, "gte": keep_ns, "lt": new_ns},
            ]
        }
    }).scan()

    names = {entry.path.name for entry in _entries(snapshot)}
    assert "old.zip" not in names
    assert "keep.zip" in names
    assert "new.zip" not in names


def test_directory_scanner_mtime_range_accepts_date_expression(tmp_path):
    old = tmp_path / "old.zip"
    keep = tmp_path / "keep.zip"
    new = tmp_path / "new.zip"
    old.write_bytes(b"old")
    keep.write_bytes(b"keep")
    new.write_bytes(b"new")

    from datetime import datetime
    import os

    def ns(value: str) -> int:
        return int(datetime.strptime(value, "%Y%m%d %H:%M").timestamp() * 1_000_000_000)

    os.utime(old, ns=(ns("20250101 00:00"), ns("20250101 00:00")))
    os.utime(keep, ns=(ns("20260101 00:00"), ns("20260101 00:00")))
    os.utime(new, ns=(ns("20270101 00:00"), ns("20270101 00:00")))

    snapshot = DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "scan_filters": [
                {"name": "mtime_range", "enabled": True, "date": "20260430 01:40 > d > 20250320 01:30"},
            ]
        }
    }).scan()

    names = {entry.path.name for entry in _entries(snapshot)}
    assert "old.zip" not in names
    assert "keep.zip" in names
    assert "new.zip" not in names


def test_directory_scanner_current_dir_only_scan_mode_skips_subdirectories(tmp_path):
    nested = tmp_path / "nested"
    nested.mkdir()
    (tmp_path / "root.zip").write_bytes(b"PK\x03\x04payload")
    (nested / "nested.zip").write_bytes(b"PK\x03\x04payload")

    snapshot = DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "directory_scan_mode": "-",
            "scan_filters": [],
        }
    }).scan()

    names = {entry.path.name for entry in _entries(snapshot)}
    assert "root.zip" in names
    assert "nested" not in names
    assert "nested.zip" not in names


def test_directory_scanner_custom_filters_fail_without_native_mapping(tmp_path):
    (tmp_path / "archive.zip").write_bytes(b"PK\x03\x04payload")

    class KeepAllFilter:
        name = "keep_all"
        stage = "path"

        def evaluate(self, candidate):
            from sunpack.filesystem.filters.base import keep
            return keep()

    with pytest.raises(RuntimeError, match="Native directory scan requires"):
        DirectoryScanner(str(tmp_path), filters=[KeepAllFilter()]).scan()


def test_directory_scanner_explicit_max_depth_overrides_scan_mode(tmp_path):
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "nested.zip").write_bytes(b"PK\x03\x04payload")

    snapshot = DirectoryScanner(str(tmp_path), max_depth=1, config={
        "filesystem": {
            "directory_scan_mode": "-",
            "scan_filters": [],
        }
    }).scan()

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

    snapshot = DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "scan_filters": [
                {"name": "blacklist", "enabled": True, "blocked_extensions": [".py"]},
            ]
        }
    }).scan()

    names = {entry.path.name for entry in _entries(snapshot)}
    assert "skip.py" not in names
    assert "keep.zip" in names


def test_directory_scanner_blacklist_blocks_exact_file_names(tmp_path):
    blocked = tmp_path / "Thumbs.db"
    blocked.write_bytes(b"not an archive")
    keep = tmp_path / "Thumbs.zip"
    keep.write_bytes(b"PK\x03\x04payload")

    snapshot = DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "scan_filters": [
                {"name": "blacklist", "enabled": True, "blocked_files": ["thumbs.db"]},
            ]
        }
    }).scan()

    names = {entry.path.name for entry in _entries(snapshot)}
    assert "Thumbs.db" not in names
    assert "Thumbs.zip" in names


def test_directory_scanner_scan_filters_global_switch_disables_filters(tmp_path):
    blocked = tmp_path / "skip.py"
    blocked.write_text("print('keep when filters are globally disabled')", encoding="utf-8")

    snapshot = DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "scan_filters_enabled": False,
            "scan_filters": [
                {"name": "blacklist", "enabled": True, "blocked_extensions": [".py"]},
            ],
        }
    }).scan()

    names = {entry.path.name for entry in _entries(snapshot)}
    assert "skip.py" in names


def test_directory_scanner_executes_built_in_filters_natively(tmp_path, monkeypatch):
    target = tmp_path / "archive.zip"
    target.write_bytes(b"PK\x03\x04payload")
    observed = []

    from sunpack.filesystem.filters.modules.blacklist import BlacklistScanFilter
    from sunpack.filesystem.filters.modules.mtime_range import MtimeRangeScanFilter
    from sunpack.filesystem.filters.modules.size_range import SizeRangeScanFilter
    from sunpack.filesystem.filters.modules.whitelist import WhitelistScanFilter

    originals = {
        "whitelist": WhitelistScanFilter.evaluate,
        "blacklist": BlacklistScanFilter.evaluate,
        "size_range": SizeRangeScanFilter.evaluate,
        "mtime_range": MtimeRangeScanFilter.evaluate,
    }

    def record(name, original):
        def wrapped(self, candidate):
            if candidate.path == target:
                observed.append(name)
            return original(self, candidate)
        return wrapped

    monkeypatch.setattr(WhitelistScanFilter, "evaluate", record("whitelist", originals["whitelist"]))
    monkeypatch.setattr(BlacklistScanFilter, "evaluate", record("blacklist", originals["blacklist"]))
    monkeypatch.setattr(SizeRangeScanFilter, "evaluate", record("size_range", originals["size_range"]))
    monkeypatch.setattr(MtimeRangeScanFilter, "evaluate", record("mtime_range", originals["mtime_range"]))

    DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "scan_filters": [
                {"name": "mtime_range", "enabled": True},
                {"name": "whitelist", "enabled": True},
                {"name": "size_range", "enabled": True},
                {"name": "blacklist", "enabled": True},
            ]
        }
    }).scan()

    assert observed == []


def test_directory_scanner_whitelist_disabled_does_not_filter(tmp_path):
    (tmp_path / "keep.zip").write_bytes(b"PK\x03\x04payload")
    (tmp_path / "other.rar").write_bytes(b"Rar!\x1a\x07\x00payload")

    snapshot = DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "scan_filters": [
                {"name": "whitelist", "enabled": False, "allowed_extensions": [".zip"]},
            ]
        }
    }).scan()

    names = {entry.path.name for entry in _entries(snapshot)}
    assert "keep.zip" in names
    assert "other.rar" in names


def test_directory_scanner_whitelist_keeps_only_allowed_extensions(tmp_path):
    (tmp_path / "keep.zip").write_bytes(b"PK\x03\x04payload")
    (tmp_path / "skip.rar").write_bytes(b"Rar!\x1a\x07\x00payload")

    snapshot = DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "scan_filters": [
                {"name": "whitelist", "enabled": True, "allowed_extensions": [".zip"]},
            ]
        }
    }).scan()

    names = {entry.path.name for entry in _entries(snapshot)}
    assert "keep.zip" in names
    assert "skip.rar" not in names


def test_directory_scanner_whitelist_keeps_only_allowed_path_globs(tmp_path):
    allowed_dir = tmp_path / "archives"
    blocked_dir = tmp_path / "other"
    allowed_dir.mkdir()
    blocked_dir.mkdir()
    (allowed_dir / "keep.zip").write_bytes(b"PK\x03\x04payload")
    (blocked_dir / "skip.zip").write_bytes(b"PK\x03\x04payload")

    snapshot = DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "directory_scan_mode": "recursive",
            "scan_filters": [
                {"name": "whitelist", "enabled": True, "path_globs": ["archives/**"]},
            ]
        }
    }).scan()

    names = {entry.path.name for entry in _entries(snapshot)}
    assert "archives" in names
    assert "keep.zip" in names
    assert "other" not in names
    assert "skip.zip" not in names


def test_directory_scanner_pushes_whitelist_directory_rules_to_native(tmp_path, monkeypatch):
    captured = {}

    def fake_scan(
        root_path,
        max_depth,
        patterns,
        prune_dirs,
        blocked_extensions,
        blocked_file_names,
        size_ranges,
        mtime_ranges,
        whitelist_rules,
    ):
        captured["whitelist_rules"] = whitelist_rules
        return object(), object()

    monkeypatch.setattr(
        "sunpack.filesystem.directory_scanner._NATIVE_SCAN_DIRECTORY_SNAPSHOTS",
        fake_scan,
    )

    DirectoryScanner(str(tmp_path), include_raw_snapshot=True, config={
        "filesystem": {
            "scan_filters": [
                {
                    "name": "whitelist",
                    "enabled": True,
                    "path_globs": ["archives/**"],
                    "prune_dir_globs": ["downloads"],
                },
            ]
        }
    }).scan()

    assert captured["whitelist_rules"] == [
        ([r"(^|/)archives($|/.*)"], [r"^downloads$"], [], [])
    ]


def test_directory_scanner_keeps_filter_rejected_files_in_raw_snapshot(tmp_path):
    blocked = tmp_path / "runtime.dll"
    blocked.write_bytes(b"x" * 16)
    archive = tmp_path / "keep.zip"
    archive.write_bytes(b"PK\x03\x04payload")

    snapshot = DirectoryScanner(str(tmp_path), include_raw_snapshot=True, config={
        "filesystem": {
            "scan_filters": [
                {
                    "name": "blacklist",
                    "enabled": True,
                    "blocked_extensions": [".dll"],
                },
            ]
        }
    }).scan()

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


def test_directory_scanner_whitelist_then_blacklist_both_apply(tmp_path):
    (tmp_path / "keep.zip").write_bytes(b"PK\x03\x04payload")
    (tmp_path / "skip.py").write_text("print('skip')", encoding="utf-8")
    (tmp_path / "skip.rar").write_bytes(b"Rar!\x1a\x07\x00payload")

    snapshot = DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "scan_filters": [
                {"name": "whitelist", "enabled": True, "allowed_extensions": [".zip", ".py"]},
                {"name": "blacklist", "enabled": True, "blocked_extensions": [".py"]},
            ]
        }
    }).scan()

    names = {entry.path.name for entry in _entries(snapshot)}
    assert "keep.zip" in names
    assert "skip.py" not in names
    assert "skip.rar" not in names


def test_directory_scanner_whitelist_empty_fields_are_not_restrictions(tmp_path):
    allowed_dir = tmp_path / "archives"
    allowed_dir.mkdir()
    (allowed_dir / "keep.zip").write_bytes(b"PK\x03\x04payload")
    (allowed_dir / "skip.rar").write_bytes(b"Rar!\x1a\x07\x00payload")
    (tmp_path / "other.zip").write_bytes(b"PK\x03\x04payload")

    snapshot = DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "directory_scan_mode": "recursive",
            "scan_filters": [
                {
                    "name": "whitelist",
                    "enabled": True,
                    "path_globs": ["archives/**"],
                    "prune_dir_globs": [],
                    "allowed_files": [],
                    "allowed_extensions": [".zip"],
                },
            ]
        }
    }).scan()

    names = {entry.path.name for entry in _entries(snapshot)}
    assert "archives" in names
    assert "keep.zip" in names
    assert "skip.rar" not in names
    assert "other.zip" not in names


def test_directory_scanner_whitelist_non_empty_fields_are_combined_as_constraints(tmp_path):
    (tmp_path / "sample.zip").write_bytes(b"PK\x03\x04payload")
    (tmp_path / "sample.rar").write_bytes(b"Rar!\x1a\x07\x00payload")
    (tmp_path / "other.zip").write_bytes(b"PK\x03\x04payload")

    snapshot = DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "scan_filters": [
                {
                    "name": "whitelist",
                    "enabled": True,
                    "allowed_files": ["sample.zip"],
                    "allowed_extensions": [".zip"],
                },
            ]
        }
    }).scan()

    names = {entry.path.name for entry in _entries(snapshot)}
    assert "sample.zip" in names
    assert "sample.rar" not in names
    assert "other.zip" not in names


def test_directory_scanner_directory_prune_prunes_directory(tmp_path):
    blocked_dir = tmp_path / "blocked"
    blocked_dir.mkdir()
    (blocked_dir / "payload.zip").write_bytes(b"PK\x03\x04payload")
    (tmp_path / "keep.zip").write_bytes(b"PK\x03\x04payload")

    snapshot = DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "scan_filters": [
                {"name": "directory_prune", "enabled": True, "prune_dir_globs": ["blocked"]},
            ]
        }
    }).scan()

    names = {entry.path.name for entry in _entries(snapshot)}
    assert "blocked" not in names
    assert "payload.zip" not in names
    assert "keep.zip" in names


def test_directory_scanner_directory_prune_supports_path_globs(tmp_path):
    blocked_dir = tmp_path / "$RECYCLE.BIN"
    blocked_dir.mkdir()
    (blocked_dir / "payload.zip").write_bytes(b"PK\x03\x04payload")
    (tmp_path / "keep.zip").write_bytes(b"PK\x03\x04payload")

    snapshot = DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "scan_filters": [
                {"name": "directory_prune", "enabled": True, "path_globs": ["$RECYCLE.BIN/**"]},
            ]
        }
    }).scan()

    names = {entry.path.name for entry in _entries(snapshot)}
    assert "$RECYCLE.BIN" not in names
    assert "payload.zip" not in names
    assert "keep.zip" in names


def test_directory_scanner_directory_prune_supports_prune_dir_globs(tmp_path):
    blocked_dir = tmp_path / "node_modules"
    blocked_dir.mkdir()
    (blocked_dir / "payload.zip").write_bytes(b"PK\x03\x04payload")
    (tmp_path / "keep.zip").write_bytes(b"PK\x03\x04payload")

    snapshot = DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "scan_filters": [
                {"name": "directory_prune", "enabled": True, "prune_dir_globs": ["node_*"]},
            ]
        }
    }).scan()

    names = {entry.path.name for entry in _entries(snapshot)}
    assert "node_modules" not in names
    assert "payload.zip" not in names
    assert "keep.zip" in names


def test_directory_scanner_directory_prune_globs_are_directory_only(tmp_path):
    blocked_dir = tmp_path / "site-packages"
    blocked_dir.mkdir()
    (blocked_dir / "payload.zip").write_bytes(b"PK\x03\x04payload")
    same_name_file = tmp_path / "site-packages.zip"
    same_name_file.write_bytes(b"PK\x03\x04payload")

    snapshot = DirectoryScanner(str(tmp_path), config={
        "filesystem": {
            "scan_filters": [
                {"name": "directory_prune", "enabled": True, "prune_dir_globs": ["site-packages"]},
            ]
        }
    }).scan()

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

    bags = build_fact_bags_for_targets([str(tmp_path), str(tmp_path)])

    assert len([bag for bag in bags if bag.get("file.path") == str(tmp_path / "archive.zip")]) == 1
    assert scan_count == 1


def test_archive_task_provider_detection_enabled_false_uses_standard_archive_fallback(tmp_path, monkeypatch):
    target = tmp_path / "archive.zip"
    target.write_bytes(b"PK\x03\x04payload")

    provider = ArchiveTaskProvider({
        "detection": {
            "enabled": False,
            "fact_collectors": [{"name": "file_facts", "enabled": True}],
            "processors": [{"name": "zip_structure", "enabled": True}],
            "rule_pipeline": {
                "precheck": [{"name": "zip_structure_accept", "enabled": True}],
            },
        },
        "filesystem": {"scan_filters": []},
    })

    def fail_if_rules_run(*_args, **_kwargs):
        raise AssertionError("detection.enabled=false should not evaluate detection rules")

    monkeypatch.setattr(provider.detector, "evaluate_bags", fail_if_rules_run)

    tasks = provider.scan_targets([str(tmp_path)])

    assert [task.main_path for task in tasks] == [str(target)]
