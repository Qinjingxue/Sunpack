"""Scope boundaries through real native planning, output routing and recovery.

These cases cover cross-directory execution and persistent directory identity;
existing shallow relation and in-memory output tests cannot detect either gap.
They reuse the small archive factory and WAL rather than a format Cartesian suite.
"""
import asyncio
import shutil
from pathlib import Path

import pytest

from sunpack.core.contracts.discovery_scope import DiscoveryScope
from sunpack.pipeline.coordinator.engine import PipelineEngine
from sunpack.pipeline.coordinator.scan_session import DiscoveryScanSession
from sunpack.pipeline.coordinator.task_provider import ArchiveTaskProvider
from sunpack.runtime.watch.output_roots import WatchOutputRoots
from sunpack.runtime.watch.state import WatchStateStore
from sunpack_native import NativeWatchCatalog
from sunpack.pipeline.discovery.filesystem.directory_scanner import DirectoryScanner
from sunpack.runtime.watch.roots import WatchRootEntry
from tests.helpers.config_factory import make_config
from tests.helpers.real_archives import ArchiveFixtureFactory


@pytest.mark.parametrize("archive_format", ["7z", "zip", "rar"])
def test_cross_directory_parts_share_one_scope_and_execute_beside_entry(tmp_path, archive_format, monkeypatch):
    case = ArchiveFixtureFactory().create(tmp_path / "fixture", "scope", archive_format,
        split=True, payload_size=256 * 1024, split_volume_size=100 * 1024,
        compression_level=0)
    root = tmp_path / "input"
    paths = []
    for index, part in enumerate(sorted(case.archive_dir.iterdir())):
        if not part.is_file():
            continue
        parent = root / str(index)
        parent.mkdir(parents=True)
        destination = parent / part.name
        shutil.copyfile(part, destination)
        paths.append(str(destination))
    assert len(paths) > 1
    config = make_config({"recursive_extract": "1", "post_extract": {"archive_cleanup_mode": "k"}})
    provider = ArchiveTaskProvider(config)
    assert not provider.scan_targets([str(root)])
    session = DiscoveryScanSession(config=config, scope=DiscoveryScope(str(root), recursive=True))
    tasks = provider.scan_targets([str(root)], scan_session=session)
    assert len(tasks) == 1 and set(tasks[0].all_parts) == set(paths)
    task = tasks[0]
    # The same range must survive the missing-volume retry boundary.
    with monkeypatch.context() as patch:
        patch.setattr(DirectoryScanner, "compile_scan_options", lambda *_: pytest.fail("retry re-enumerated its scope"))
        group = provider.resolve_volume_once([task.main_path], task.runtime["discovery_scope"], format_hint=archive_format, snapshot=task.runtime["discovery_snapshot"])
    assert group is not None and set(group.input_paths) == set(paths)

    async def execute():
        async with PipelineEngine(config) as engine:
            return await engine.run([str(root)], recursive=True)

    result = asyncio.run(execute()).summary
    assert result.success_count == 1 and not result.failed_tasks
    output = Path(result.target_results[0].output_dir)
    assert output.parent == Path(task.main_path).parent
    marker = next(output.rglob(case.marker_name))
    assert marker.read_text(encoding="utf-8") == case.marker_text








def test_targeted_catalog_updates_preserve_original_depth_pruning_and_conflicts(tmp_path):
    """Full-root scans cannot detect incremental scope widening or stale conflict rows."""
    from sunpack_native import NativeDirectoryScanOptions
    from sunpack.runtime.watch.state import WatchStateStore
    root = tmp_path / "input"
    paths = [root / "same.part1.fake", root / "child" / "same.part2.fake",
             root / "child" / "deeper" / "same.part3.fake",
             root / "skip" / "same.part4.fake", root / "same.blocked"]
    for path in paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"opaque")
    options = NativeDirectoryScanOptions([], ["skip"], [], ["same.blocked"], [], [], [])
    scope = DiscoveryScope(str(root), max_depth=1)
    state = WatchStateStore(str(tmp_path / "state.json"))
    catalog = NativeWatchCatalog(state._native)
    try:
        for target in (str(root / "child"), str(root / "skip"), str(paths[-1])):
            errors = options.catalog_update(catalog, scope.native, target, True)
            assert not errors
        errors = options.catalog_update(catalog, scope.native, str(paths[0]))
        assert not errors
        filtered, raw = options.catalog_snapshot(catalog, scope.native, str(paths[0]))
        assert set(raw.file_columns()[0]) == {str(paths[i]) for i in (0, 1, 4)}
        assert set(filtered.file_columns()[0]) == {str(paths[i]) for i in (0, 1)}
        narrower = DiscoveryScope(str(root), recursive=True, excluded_subtrees=[str(root / "child")])
        _, raw = options.catalog_snapshot(catalog, narrower.native, str(paths[0]))
        assert set(raw.file_columns()[0]) == {str(paths[0]), str(paths[-1])}
        errors = options.catalog_update(catalog, scope.native, str(paths[3]))
        assert not errors
        _, raw = options.catalog_snapshot(catalog, scope.native, str(paths[0]))
        assert str(paths[3]) not in raw.file_columns()[0]
    finally:
        state.close()





def test_deep_watch_catalog_and_internal_recovery_share_effective_policy(tmp_path, monkeypatch):
    """Watch's catalog bypasses the CLI scanner; nested recovery bypasses normal routing."""
    import sunpack.runtime.watch.scheduler as module
    from sunpack.runtime.watch.scanner import WatchCandidate
    root, output = tmp_path / "input", tmp_path / "output"
    root.mkdir()
    output.mkdir()
    archive = root / "sample.bin"
    archive.write_bytes(b"opaque")
    nested_root = output / "outer"
    nested_root.mkdir()
    nested = nested_root / "inner.bin"
    nested.write_bytes(b"opaque")
    calls = []
    class Engine:
        async def run(self, targets, **kwargs):
            calls.append((targets, kwargs))
    monkeypatch.setattr(module, "validate_ntfs_watch_roots", lambda roots: None)
    config = make_config({"filesystem": {"scan_filters": [
        {"name": "blacklist", "enabled": True, "blocked_extensions": [".bin"]}]},
        "watch": {"clipboard_monitor_enabled": False}})
    watcher = module.WatchScheduler(config, [str(root)], state_path=str(tmp_path / "state.json"),
        root_entries=[WatchRootEntry(str(root), str(output), deep_detect=True)], pipeline_engine=Engine())
    try:
        candidates, errors = watcher._scan_candidates([str(root)], recursive=False)
        assert not errors and [candidate.path for candidate in candidates] == [str(archive)]
        scope = watcher.scopes[next(iter(watcher.scopes))]
        filtered, _ = watcher._scan_options_for(scope).catalog_snapshot(watcher._catalog, scope.native, str(archive))
        assert filtered.file_columns()[0] == [str(archive)]
        candidate = WatchCandidate(str(nested), nested.stat().st_size, nested.stat().st_mtime)
        watcher.state.queue_active(candidate, source_input_root=str(root), internal_recovery=True,
            discovery_scope=DiscoveryScope(str(nested_root), recursive=True).to_record(),
            durable_owner=True, persist=True, durable=True)
        async def submit():
            request = await watcher._submit_candidate(candidate)
            assert request is not None
            await request.task
        asyncio.run(submit())
        [(_, request)] = calls
        assert request["discovery_scope"].root == str(nested_root)
        assert request["request_config"]["output"] == {"root": "", "common_root": "", "fixed_root": False}
    finally:
        watcher._close_blocking()





@pytest.mark.parametrize("archive_format", ["7z", "zip", "rar"])
def test_complete_same_named_local_volume_sets_remain_independent(tmp_path, archive_format):
    """Cross-directory single-family tests cannot catch global collision regressions.

    Two copies of one small real fixture are the strongest name/header collision;
    deleting this case leaves independent complete local sets uncovered.
    """
    case = ArchiveFixtureFactory().create(tmp_path / "fixture", "same", archive_format,
        split=True, payload_size=256 * 1024, split_volume_size=100 * 1024, compression_level=0)
    root = tmp_path / "input"
    expected = []
    for name in ("first", "second"):
        directory = root / name
        shutil.copytree(case.archive_dir, directory)
        expected.append({str(path) for path in directory.iterdir() if path.is_file()})
    config = make_config({})
    tasks = ArchiveTaskProvider(config).scan_targets([str(root)],
        scan_session=DiscoveryScanSession(config=config, scope=DiscoveryScope(str(root), recursive=True)))
    assert len(tasks) == 2
    assert {frozenset(task.all_parts) for task in tasks} == {frozenset(paths) for paths in expected}
