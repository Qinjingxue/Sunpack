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
@pytest.mark.parametrize("layout", ["complete", "missing", "unique", "ambiguous"])
def test_complete_same_named_local_volume_sets_remain_independent(tmp_path, archive_format, layout):
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
    if layout != "complete":
        tail = Path(sorted(expected[1])[-1])
        tails = []
        if layout in {"unique", "ambiguous"}:
            for name in (["third"] if layout == "unique" else ["third", "fourth"]):
                destination = root / name / tail.name
                destination.parent.mkdir()
                shutil.copyfile(tail, destination)
                tails.append(str(destination))
        expected[1].remove(str(tail))
        tail.unlink()
        if layout == "unique":
            expected[1].update(tails)
        else:
            expected = expected[:1]
    config = make_config({})
    provider = ArchiveTaskProvider(config)
    tasks = provider.scan_targets([str(root)],
        scan_session=DiscoveryScanSession(config=config, scope=DiscoveryScope(str(root), recursive=True)))
    actual = {frozenset(task.all_parts) for task in tasks}
    assert all(frozenset(paths) in actual for paths in expected)
    assert all(not (set(task.all_parts) & expected[0]) or set(task.all_parts) == expected[0] for task in tasks)
    if layout != "complete":
        async def execute():
            async with PipelineEngine(config) as engine:
                return (await engine.run([str(root)], recursive=True)).summary
        summary = asyncio.run(execute())
        assert summary.success_count == len(expected)
        assert bool(summary.failures) == (layout != "unique")
        if layout == "missing":
            # Force the ordering where another task has cleaned up its complete
            # local set before the incomplete task retries from the old snapshot.
            for path in expected[0]:
                Path(path).unlink(missing_ok=True)
            incomplete = next(task for task in tasks if Path(task.main_path).parent.name == "second")
            assert provider.resolve_volume_once(
                incomplete.all_parts, incomplete.runtime["discovery_scope"],
                format_hint=archive_format, snapshot=incomplete.runtime["discovery_snapshot"],
            ) is None




def test_output_roots_persist_and_external_replacements_are_inputs(tmp_path):
    """Persistence alone misses both online replacement and external move semantics."""
    root = tmp_path / "input"
    root.mkdir()
    output = root / "result"
    state_path = tmp_path / "state.json"
    scope = DiscoveryScope(str(root), recursive=True)
    state = WatchStateStore(str(state_path))
    outputs = WatchOutputRoots(state, (scope,))
    outputs.register(str(output))
    outputs.register(str(output / "nested"))
    assert outputs.protected(str(output / "child.zip"))
    assert len(state._native.runtime_keys("owned|")) == 1
    outputs.close()
    state.close()
    state = WatchStateStore(str(state_path))
    outputs = WatchOutputRoots(state, (scope,))
    try:
        assert outputs.protected(str(output / "child.zip"))
        moved = root / "external-move"
        output.rename(moved)
        output.mkdir()
        assert not outputs.protected(str(output / "child.zip"))
        assert not outputs.protected(str(moved / "child.zip"))
        options = DirectoryScanner.compile_scan_options({"filesystem": {"scan_filters_enabled": False}})
        (output / "same.001").write_bytes(b"new input")
        catalog = NativeWatchCatalog(state._native)
        assert not options.catalog_update(catalog, scope.native)
        _, raw = options.catalog_snapshot(catalog, scope.native, str(output / "same.001"))
        assert raw.file_columns()[0] == [str(output / "same.001")]
        outputs.reconcile(str(output), recursive=True)
        assert not state._native.runtime_keys("owned|")
    finally:
        outputs.close()
        state.close()


def test_catalog_checkpoint_wal_replay_and_damage_are_independent_of_task_wal(tmp_path):
    """One subprocess exit covers an uncheckpointed cache update and task independence."""
    import subprocess
    import sys
    from sunpack.runtime.watch.scanner import WatchCandidate
    root = tmp_path / "input"
    root.mkdir()
    first = root / "same.001"
    first.write_bytes(b"one")
    scope = DiscoveryScope(str(root), recursive=True)
    state = WatchStateStore(str(tmp_path / "state.json"))
    state.queue_active(WatchCandidate(str(first), 3, first.stat().st_mtime), persist=True, durable=True)
    options = DirectoryScanner.compile_scan_options({"filesystem": {"scan_filters_enabled": False}})
    catalog = NativeWatchCatalog(state._native, str(tmp_path))
    assert not options.catalog_update(catalog, scope.native)
    catalog.set_cursor(scope.native, "volume", 1, 20)
    catalog.close()
    state.close()
    script = r"""
import os,sys
from sunpack_native import NativeWatchState,NativeWatchCatalog,NativeDiscoveryScope,NativeDirectoryScanOptions
root,folder=sys.argv[1:]
second=os.path.join(root,'same.002')
with open(second,'wb') as stream: stream.write(b'two')
catalog=NativeWatchCatalog(NativeWatchState(),folder)
options=NativeDirectoryScanOptions([],[],[],[],[],[],[])
assert not options.catalog_update(catalog,NativeDiscoveryScope(root,None),second)
os._exit(0)
"""
    subprocess.run([sys.executable, "-c", script, str(root), str(tmp_path)], check=True, timeout=20)
    state = WatchStateStore(str(tmp_path / "state.json"))
    try:
        catalog = NativeWatchCatalog(state._native, str(tmp_path))
        _, raw = options.catalog_snapshot(catalog, scope.native, str(first))
        assert set(raw.file_columns()[0]) == {str(first), str(root / "same.002")}
        catalog.close()
        (tmp_path / "catalog.wal").write_bytes(b"broken tail")
        catalog = NativeWatchCatalog(state._native, str(tmp_path))
        assert catalog.cursor(scope.native) is None
        assert len(state.pending_work_items()) == 1
        assert not options.catalog_update(catalog, scope.native)
        _, raw = options.catalog_snapshot(catalog, scope.native, str(first))
        assert len(raw.file_columns()[0]) == 2
        catalog.close()
        (tmp_path / "catalog.wal").mkdir()
        catalog = NativeWatchCatalog(state._native, str(tmp_path))
        assert catalog.error
        assert not options.catalog_update(catalog, scope.native)
        assert len(state.pending_work_items()) == 1
        catalog.close()
    finally:
        state.close()


@pytest.mark.requires_watch_broker
def test_recursive_restart_replays_indexed_directories_without_initial_scan(tmp_path, monkeypatch):
    """A flat native cache test cannot catch restart admission or empty-subdirectory gaps."""
    import os
    import sunpack_native
    import sunpack.runtime.watch.scheduler as module
    from tests.unit.test_watch_scheduler import FakeObserver
    from tests.helpers.fake_pipeline_engine import FakePipelineEngine
    monkeypatch.setattr(module, "Observer", FakeObserver)
    root = tmp_path / "input"
    (root / "empty").mkdir(parents=True)
    unchanged, modified, removed = (root / name for name in ("old.001", "same.001", "same.002"))
    for path in (unchanged, modified, removed):
        path.write_bytes(b"old")
    config = make_config({"watch": {"clipboard_monitor_enabled": False}})
    def watcher():
        return module.WatchScheduler(config, [str(root)], state_path=str(tmp_path / "state.json"),
            root_entries=[WatchRootEntry(str(root), initial_scanned=True, recursive=True)],
            pipeline_engine=FakePipelineEngine(lambda config: None))
    async def cycle():
        first = watcher()
        await first.start()
        assert first.pending_count == 0
        await first.stop()
        first._close_blocking()
        stamp = modified.stat().st_mtime_ns
        modified.write_bytes(b"new")
        os.utime(modified, ns=(stamp, stamp))
        removed.unlink()
        arrived = root / "empty/same.003"
        arrived.write_bytes(b"tail")
        second = watcher()
        compiled = second._scan_options
        class OnlyIncremental:
            def __getattr__(self, name):
                return getattr(compiled, name)
            def catalog_update(self, catalog, scope, changed=None, *args):
                assert changed is not None, "normal restart enumerated the complete Scope"
                return compiled.catalog_update(catalog, scope, changed, *args)
            def catalog_refresh(self, catalog, scope, changed=None):
                assert changed is not None, "normal restart enumerated the complete Scope"
                return compiled.catalog_refresh(catalog, scope, changed)
        second._scan_options = OnlyIncremental()
        try:
            await second.start()
            assert set(second._pending) == {str(modified), str(arrived)}
            scope = next(iter(second.scopes.values()))
            _, raw = compiled.catalog_snapshot(second._catalog, scope.native, str(modified))
            assert set(raw.file_columns()[0]) == {str(modified), str(arrived)}
        finally:
            await second.stop()
            second._close_blocking()
        # Corrupt cache + unavailable journal rebuilds metadata, without re-admitting old input.
        (tmp_path / "catalog.snapshot").write_bytes(b"broken")
        monkeypatch.setattr(module, "watch_volume_cursor", lambda path: (_ for _ in ()).throw(OSError("unavailable")))
        third = watcher()
        try:
            await third.start()
            # Only the explicitly durable work from the second run may recover.
            assert str(unchanged) not in third._pending
        finally:
            await third.stop()
            third._close_blocking()
    sunpack_native.watch_broker_acquire()
    try:
        asyncio.run(cycle())
    finally:
        sunpack_native.watch_broker_release()


def test_watch_filters_reserved_flatten_work_and_persists_final_identity(tmp_path, monkeypatch):
    """External move tests cannot detect admission during SunPack's internal flatten."""
    import zipfile
    import sunpack.runtime.watch.scheduler as module
    import sunpack.pipeline.postprocess.internal.flatten as flatten
    root = tmp_path / "input"
    root.mkdir()
    archive = root / "wrapped.zip"
    with zipfile.ZipFile(archive, "w") as stream:
        stream.writestr("wrapper/payload.txt", "payload")
    config = make_config({"post_extract": {"archive_cleanup_mode": "k", "flatten_single_directory": True},
        "watch": {"clipboard_monitor_enabled": False}})
    monkeypatch.setattr(module, "validate_ntfs_watch_roots", lambda roots: None)
    original = flatten._native_flatten_single_branch_directories
    checked = []
    async def execute():
        async with PipelineEngine(config) as engine:
            watcher = module.WatchScheduler(config, [str(root)], state_path=str(tmp_path / "state.json"),
                root_entries=[WatchRootEntry(str(root), recursive=True)], pipeline_engine=engine)
            def protected_flatten(path, *, work_path=None):
                assert work_path is not None
                assert watcher.should_ignore_event_path(str(Path(work_path) / "nested.zip"))
                checked.append(work_path)
                return original(path, work_path=work_path)
            monkeypatch.setattr(flatten, "_native_flatten_single_branch_directories", protected_flatten)
            try:
                summary = (await engine.run([str(archive)])).summary
                assert summary.success_count == 1 and not any(result.status == "failed" for result in summary.cleanup_results)
                output = summary.target_results[0].output_dir
                assert (Path(output) / "payload.txt").read_text() == "payload"
                assert watcher.should_ignore_event_path(str(Path(output) / "nested.zip"))
                assert checked and not any(Path(work).exists() for work in checked)
            finally:
                watcher._close_blocking()
    asyncio.run(execute())


@pytest.mark.requires_watch_broker
def test_watch_volume_deletion_and_arrival_retry_the_existing_blocker(tmp_path, monkeypatch):
    """CLI split tests do not exercise the event bucket update and blocker wakeup."""
    from types import SimpleNamespace
    import sunpack_native
    import sunpack.runtime.watch.scheduler as module
    from sunpack.runtime.watch.scanner import watch_candidate_for_path
    from tests.functional.test_watch_password_retry import _wait_for_completed_watch_run
    case = ArchiveFixtureFactory().create(tmp_path / "fixture", "parts", "7z", split=True,
        payload_size=256*1024, split_volume_size=100*1024, compression_level=0)
    root = tmp_path / "input"
    shutil.copytree(case.archive_dir, root)
    parts = sorted(path for path in root.iterdir() if path.is_file())
    head, tail = parts[0], parts[-1]
    config = make_config({"post_extract": {"archive_cleanup_mode": "k"},
        "watch": {"clipboard_monitor_enabled": False, "quiet_min_seconds": 0.01, "quiet_max_seconds": 0.01}})
    async def execute():
        async with PipelineEngine(config) as engine:
            watcher = module.WatchScheduler(config, [str(root)], state_path=str(tmp_path / "state.json"),
                root_entries=[WatchRootEntry(str(root), recursive=True)], pipeline_engine=engine, cold_start_seconds=0)
            try:
                scope = next(iter(watcher.scopes.values()))
                watcher._scan_options.catalog_update(watcher._catalog, scope.native)
                candidate = watch_candidate_for_path(str(head))
                watcher.state.mark(str(head), candidate.size, candidate.mtime, file_id=candidate.file_id,
                    change_usn=candidate.change_usn, status="suspended_missing_volume",
                    failure_payload={"source_input_root": str(root)})
                tail.unlink()
                handler = module._WatchEventHandler(watcher)
                handler.on_deleted(SimpleNamespace(src_path=str(tail), is_directory=False))
                assert str(head) in watcher._pending
                failed = await _wait_for_completed_watch_run(watcher)
                assert failed.failed and watcher.state.latest_entry_for_path(str(head)).status == "suspended_missing_volume"
                shutil.copyfile(case.archive_dir / tail.name, tail)
                handler.on_created(SimpleNamespace(src_path=str(tail), is_directory=False))
                result = await _wait_for_completed_watch_run(watcher)
                remaining = await watcher.drain()
                assert result.succeeded + remaining.succeeded == 1
                assert not watcher.state.entry_items()
                assert len(list(root.rglob(case.marker_name))) == 1
            finally:
                watcher._close_blocking()
    sunpack_native.watch_broker_acquire()
    try:
        asyncio.run(execute())
    finally:
        sunpack_native.watch_broker_release()
