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
from sunpack.pipeline.coordinator.output_ownership import OutputOwnership
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


def test_catalog_and_output_identity_survive_restart_and_do_not_inherit_names(tmp_path, monkeypatch):
    import sunpack.runtime.watch.service as service
    root = tmp_path / "input"
    root.mkdir()
    (root / "sample.part1.fake").write_bytes(b"external")
    monkeypatch.setattr(service, "_read_watch_root_entries", lambda: [WatchRootEntry(str(root), recursive=True)])
    config = make_config({"watch": {"state_dir": str(tmp_path / "state")}})
    owner = OutputOwnership(config)
    store = owner.state_for()
    scope = DiscoveryScope(str(root), recursive=True)
    options = DirectoryScanner.compile_scan_options(config)
    operations, errors = options.catalog_update(store._native, scope.native)
    assert not errors
    store.commit_runtime(operations, durable=True)
    generated = root / "generated"
    owner.begin(str(generated), "request")
    (generated / "sample.part2.fake").write_bytes(b"generated")
    operations, errors = options.catalog_update(store._native, scope.native)
    assert not errors
    store.commit_runtime(operations, durable=True)
    _, raw = options.catalog_snapshot(store._native, scope.native, str(root / "sample.part1.fake"))
    assert raw.file_columns()[0] == [str(root / "sample.part1.fake")]
    owner.begin(str(generated / "inner"), "request")
    owner.seal(str(generated / "inner"), succeeded=True)
    owner.seal(str(generated), succeeded=True)
    owner.finish("request")
    assert len(store._native.runtime_keys("owned|")) == 1
    relocated = root / "moved"
    generated.rename(relocated)
    owner.relocate(str(generated), str(relocated))
    generated.mkdir()
    assert not owner.protected(str(generated / "new.zip"))
    assert owner.protected(str(relocated / "sample.part2.fake"))
    owner.close()
    restarted = OutputOwnership(config)
    try:
        assert restarted.protected(str(relocated / "sample.part2.fake"))
        shutil.rmtree(relocated)
        relocated.mkdir()
        restarted.reconcile(str(relocated))
        assert not restarted.protected(str(relocated / "new.zip"))
    finally:
        restarted.close()


def test_interrupted_output_recovery_is_identity_safe_and_releases_failed_owner(tmp_path, monkeypatch):
    """Path-only Watch recovery cannot catch replaced directories or failed WAL finish."""
    import sunpack.runtime.watch.service as service
    from sunpack.pipeline.coordinator.engine import _PathLeaseRegistry
    root = tmp_path / "input"
    root.mkdir()
    monkeypatch.setattr(service, "_read_watch_root_entries", lambda: [WatchRootEntry(str(root), recursive=True)])
    config = make_config({"watch": {"state_dir": str(tmp_path / "state")}})
    owner = OutputOwnership(config)
    partial, replaced, complete = (root / name for name in ("partial", "replaced", "complete"))
    owner.begin(str(partial), "crashed")
    owner.begin(str(replaced), "crashed")
    (partial / "payload").write_bytes(b"partial")
    replaced.rename(root / "moved-partial")
    replaced.mkdir()
    (replaced / "user-file").write_bytes(b"keep")
    owner.begin(str(complete), "crashed")
    owner.seal(str(complete), succeeded=True)
    owner.close()
    owner = OutputOwnership(config)
    registry = _PathLeaseRegistry(owner)
    try:
        store = owner.state_for()
        assert not partial.exists()
        assert (replaced / "user-file").read_bytes() == b"keep"
        assert not owner.recoverable_output(str(replaced))
        assert owner.recoverable_output(str(complete))
        owner.begin(str(root / "failed-finish"), "finished")
        with monkeypatch.context() as patch:
            def fail_commit(*_args, **_kwargs):
                raise OSError("WAL unavailable")
            patch.setattr(store, "commit_runtime", fail_commit)
            with pytest.raises(OSError, match="WAL unavailable"):
                owner.finish("finished")
        assert "finished" not in owner._active_owners
    finally:
        owner.close()
    assert owner.input_leases is None and owner._state is None
    assert registry.output_ownership is owner


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
    try:
        for target in (str(root / "child"), str(root / "skip"), str(paths[-1])):
            operations, errors = options.catalog_update(state._native, scope.native, target, True)
            assert not errors
            state.commit_runtime(operations)
        operations, errors = options.catalog_update(state._native, scope.native, str(paths[0]))
        assert not errors
        state.commit_runtime(operations)
        filtered, raw = options.catalog_snapshot(state._native, scope.native, str(paths[0]))
        assert set(raw.file_columns()[0]) == {str(paths[i]) for i in (0, 1, 4)}
        assert set(filtered.file_columns()[0]) == {str(paths[i]) for i in (0, 1)}
        narrower = DiscoveryScope(str(root), recursive=True, excluded_subtrees=[str(root / "child")])
        _, raw = options.catalog_snapshot(state._native, narrower.native, str(paths[0]))
        assert set(raw.file_columns()[0]) == {str(paths[0]), str(paths[-1])}
        operations, errors = options.catalog_update(state._native, scope.native, str(paths[3]))
        assert not errors
        state.commit_runtime(operations)
        _, raw = options.catalog_snapshot(state._native, scope.native, str(paths[0]))
        assert str(paths[3]) not in raw.file_columns()[0]
    finally:
        state.close()


def test_flatten_crash_retains_payload_at_each_rename_boundary(tmp_path, monkeypatch):
    """Extraction-abort tests do not cover completed data between flatten renames."""
    import sunpack.runtime.watch.service as service
    from sunpack.core.support.output_reservation import OutputReservationRegistry
    for phase in range(3):
        watch = tmp_path / str(phase)
        watch.mkdir()
        monkeypatch.setattr(service, "_read_watch_root_entries", lambda: [WatchRootEntry(str(watch), recursive=True)])
        config = make_config({"watch": {"state_dir": str(tmp_path / f"state-{phase}")}})
        owner = OutputOwnership(config)
        root = watch / "generated"
        owner.begin(str(root), "request")
        leaf = root / "wrapper" / "payload"
        leaf.mkdir(parents=True)
        (leaf / "marker.txt").write_text("complete", encoding="utf-8")
        owner.seal(str(root), succeeded=True)
        work = Path(owner.prepare_flatten(str(root), "request", OutputReservationRegistry()))
        if phase >= 1:
            root.rename(work)
        if phase == 2:
            (work / "wrapper" / "payload").rename(root)
        owner.close()  # Simulate process loss without request.finish().
        restarted = OutputOwnership(config)
        try:
            restarted.state_for()
            [marker] = list(watch.rglob("marker.txt"))
            assert marker.read_text(encoding="utf-8") == "complete"
            assert restarted.protected(str(marker))
        finally:
            restarted.close()


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
        filtered, _ = watcher._scan_options_for(scope).catalog_snapshot(watcher.state._native, scope.native, str(archive))
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


def test_foreground_outputs_outside_watch_scopes_never_write_watch_wal(tmp_path, monkeypatch):
    """Real recursion/flatten catches persistence accidentally added to any output phase.

    Scope/extraction tests check content, not journal cost. This one tiny nested
    input adds the missing assertion with both absent and unrelated Watch state.
    """
    import sunpack.runtime.watch.service as service
    from tests.helpers.fs_builder import make_zip
    source = tmp_path / "source.bin"
    source.write_bytes(make_zip({"wrapper/inner.bin": make_zip({"leaf/payload.txt": "complete"})}))
    watched = tmp_path / "unrelated"
    watched.mkdir()
    monkeypatch.setattr(service, "_read_watch_root_entries", lambda: [])
    config = make_config({"recursive_extract": "3", "watch": {"state_dir": str(tmp_path / "state")},
                          "post_extract": {"archive_cleanup_mode": "keep"}})

    async def run():
        async with PipelineEngine(config) as engine:
            for enabled in (False, True):
                owner = engine.output_ownership
                if enabled:
                    owner.retain_scopes([DiscoveryScope(str(watched), recursive=True)])
                store = owner._state
                before = store.applied_seq if store is not None else None
                result = await engine.run([str(source)], request_config={**config,
                    "output": {"root": str(tmp_path / str(enabled))}})
                assert result.summary.success_count == 2
                [payload] = list((tmp_path / str(enabled)).rglob("payload.txt"))
                assert payload.read_text() == "complete"
                assert owner._state is store
                assert (store.applied_seq if store is not None else None) == before
                assert not owner._memory._native.runtime_keys("owned|")
                assert not owner._active_owners
    asyncio.run(run())


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
