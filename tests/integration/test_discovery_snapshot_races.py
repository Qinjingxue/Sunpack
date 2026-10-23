"""Real archive inputs changing between snapshot, admission and volume retry.

Ordinary extraction tests never force these boundaries. Small real fixtures
and event gates cover the lifecycle without sleeps or probabilistic retries.
"""
import asyncio
import threading

import pytest
from sunpack_native import NativeWatchCatalog, NativeWatchState

from sunpack.core.contracts.discovery_scope import DiscoveryScope
from sunpack.core.contracts.failures import FailureKind
from sunpack.core.support.archive_sessions import release_archive_sessions_under_roots
from sunpack.core.support.resource_lifecycle import promotion_barrier
from sunpack.pipeline.coordinator.engine import PipelineEngine, _PathLeaseRegistry
from sunpack.pipeline.coordinator.scan_session import DiscoveryScanSession
from sunpack.pipeline.coordinator.task_provider import ArchiveTaskProvider
from sunpack.pipeline.discovery.filesystem.directory_scanner import DirectoryScanner
from sunpack.pipeline.extraction.internal.workflow.preflight import PreExtractInspector
from sunpack.pipeline.postprocess.internal.cleanup import ArchiveCleanup
from tests.helpers.config_factory import make_config
from tests.helpers.real_archives import ArchiveFixtureFactory, create_encrypted_rar_archive
from tests.real.plan1_real_archives.plan1_support import assert_expected_files_extracted


def _config(root, output):
    return make_config({
        "cli": {"quiet": True}, "recursive_extract": "1",
        "post_extract": {"archive_cleanup_mode": "d"},
        "output": {"root": str(output), "common_root": str(root), "fixed_root": True},
    })


def _pause_first(monkeypatch, owner, method):
    loop = asyncio.get_running_loop()
    paused, resume = asyncio.Event(), threading.Event()
    lock = threading.Lock()
    original = getattr(owner, method)
    selected = False

    def gated(*args, **kwargs):
        nonlocal selected
        result = original(*args, **kwargs)
        with lock:
            first = not selected
            selected = True
        if first:
            loop.call_soon_threadsafe(paused.set)
            assert resume.wait(15), "competing operation did not finish"
        return result

    monkeypatch.setattr(owner, method, gated)
    return paused, resume


@pytest.mark.parametrize("origin", ["watch", "foreground"])
@pytest.mark.parametrize("archive_format,split", [("zip", False), ("7z", True)])
def test_consumed_snapshot_is_retired_at_input_admission(tmp_path, monkeypatch, origin, archive_format, split):
    """Probe-only tests miss ordinary files and already confirmed groups.

    Removing this case leaves snapshot-to-admission cleanup untested; one
    small plain/numbered fixture covers both native candidate representations.
    """
    case = ArchiveFixtureFactory().create(
        tmp_path/"fixture", "consumed", archive_format, split=split,
        payload_size=128*1024, split_volume_size=64*1024, disguise_ext="jpg",
    )
    parts = sorted(case.archive_dir.iterdir())
    output = tmp_path/"output"

    async def scenario():
        paused, resume = _pause_first(monkeypatch, DiscoveryScanSession, "native_table_for_directory")
        async with PipelineEngine(_config(case.archive_dir, output)) as engine:
            scope = DiscoveryScope(str(case.archive_dir))
            older = asyncio.create_task(engine.run([str(case.entry_path)], origin=origin, discovery_scope=scope))
            try:
                await asyncio.wait_for(paused.wait(), 10)
                success = await asyncio.wait_for(engine.run([str(case.entry_path)], origin=origin, discovery_scope=scope), 10)
                assert success.summary.success_count == 1
                assert not any(path.exists() for path in parts)
            finally:
                resume.set()
                [late] = await asyncio.gather(older, return_exceptions=True)
            if isinstance(late, BaseException):
                raise late
            assert not late.summary.failures
            assert late.summary.success_count == 0
            assert_expected_files_extracted(case, output)
            assert all(len(list(output.rglob(name))) == 1 for name in case.metadata["expected_files"])
            assert not engine._path_leases._pins

    asyncio.run(scenario())


def test_waiting_snapshot_is_refreshed_after_owner_cleanup_without_blocking_other_inputs(tmp_path, monkeypatch):
    """An already deleted input never tests a lease waiter waking after cleanup.

    This also proves the guard starts before preflight and unrelated real work
    finishes while that guard is held; the additional tiny ZIP is justified.
    """
    factory = ArchiveFixtureFactory()
    case = factory.create(tmp_path, "shared", "zip", payload_size=16*1024)
    unrelated = factory.create(tmp_path, "unrelated", "zip", payload_size=16*1024)
    output = tmp_path/"output"

    async def scenario():
        paused, resume = _pause_first(monkeypatch, PreExtractInspector, "inspect")
        waiting = asyncio.Event()
        original = _PathLeaseRegistry._register_waiter

        def register_waiter(self, blockers):
            waiter = original(self, blockers)
            waiting.set()
            return waiter

        monkeypatch.setattr(_PathLeaseRegistry, "_register_waiter", register_waiter)
        async with PipelineEngine(_config(tmp_path, output)) as engine:
            first = asyncio.create_task(engine.run([str(case.entry_path)]))
            second = None
            try:
                await asyncio.wait_for(paused.wait(), 10)
                second = asyncio.create_task(engine.run([str(case.entry_path)]))
                await asyncio.wait_for(waiting.wait(), 10)
                other = await asyncio.wait_for(engine.run([str(unrelated.entry_path)]), 10)
                assert other.summary.success_count == 1
                assert case.entry_path.exists()
            finally:
                resume.set()
                responses = await asyncio.gather(first, *([second] if second is not None else []), return_exceptions=True)
            for response in responses:
                if isinstance(response, BaseException):
                    raise response
                assert not response.summary.failures
            assert [r.summary.success_count for r in responses] == [1, 0]
            assert not case.entry_path.exists()
            assert_expected_files_extracted(case, output)
            assert_expected_files_extracted(unrelated, output)
            assert not engine._path_leases._pins

    asyncio.run(scenario())


@pytest.mark.parametrize("removed_index", [0, 1])
@pytest.mark.parametrize("restored", [False, True])
def test_partially_departed_snapshot_rechecks_missing_members(tmp_path, monkeypatch, removed_index, restored):
    """All-gone cases cannot detect suppression of surviving incomplete sets.

    Testing the head and a middle member also catches raw probe exceptions.
    Restoring them before retry detects negative admission facts cached forever.
    """
    case = ArchiveFixtureFactory().create(tmp_path, "partial", "rar", split=True,
        payload_size=256*1024, split_volume_size=100*1024)
    parts = sorted(case.archive_dir.iterdir())
    removed = parts[removed_index]
    removed_data = removed.read_bytes() if restored else None

    async def scenario():
        paused, resume = _pause_first(monkeypatch, DiscoveryScanSession, "native_table_for_directory")
        loop = asyncio.get_running_loop()
        retrying, retry_resume = asyncio.Event(), threading.Event()
        original = ArchiveTaskProvider.resolve_volume_once

        def gated_retry(self, *args, **kwargs):
            loop.call_soon_threadsafe(retrying.set)
            assert retry_resume.wait(15)
            return original(self, *args, **kwargs)

        monkeypatch.setattr(ArchiveTaskProvider, "resolve_volume_once", gated_retry)
        async with PipelineEngine(_config(case.archive_dir, tmp_path/"output")) as engine:
            older = asyncio.create_task(engine.run([str(parts[-1])]))
            try:
                await asyncio.wait_for(paused.wait(), 10)

                def remove():
                    with promotion_barrier((removed,), cache_releasers=(release_archive_sessions_under_roots,), quiesce=False):
                        [result] = ArchiveCleanup("delete", quiet=True).cleanup_success_archives([[str(removed)]])
                        assert result.status == "deleted"

                await asyncio.to_thread(remove)
                resume.set()
                await asyncio.wait_for(retrying.wait(), 10)
                if restored:
                    await asyncio.to_thread(removed.write_bytes, removed_data)
            finally:
                resume.set()
                retry_resume.set()
                [response] = await asyncio.gather(older, return_exceptions=True)
            if isinstance(response, BaseException):
                raise response
            if restored:
                assert response.summary.success_count == 1
                assert not response.summary.failures
                assert_expected_files_extracted(case, tmp_path/"output")
            else:
                assert response.summary.success_count == 0
                assert any(f.contains(FailureKind.MISSING_VOLUME) for f in response.summary.failures)
                assert all(p.exists() for p in parts if p != removed)
            assert not engine._path_leases._pins

    asyncio.run(scenario())


@pytest.mark.parametrize("origin", ["watch", "foreground"])
@pytest.mark.parametrize("renamed_index", [0, 1])
def test_recovery_replaces_departed_temporary_names_with_published_members(tmp_path, monkeypatch, origin, renamed_index):
    """Same-name arrivals cannot detect an obsolete-path containment constraint.

    Publish a real head/middle member after discovery, before input admission.
    Recovery must retain surviving members and adopt the new physical name.
    """
    case = ArchiveFixtureFactory().create(tmp_path/"fixture", "publish", "rar",
        split=True, payload_size=256*1024, split_volume_size=100*1024, disguise_ext="jpg")
    parts = sorted(case.archive_dir.iterdir())
    final_path = parts[renamed_index]
    temporary = final_path.rename(final_path.with_name(final_path.name + ".downloading"))
    output = tmp_path/"output"

    async def scenario():
        paused, resume = _pause_first(monkeypatch, DiscoveryScanSession, "native_table_for_directory")
        async with PipelineEngine(_config(case.archive_dir, output)) as engine:
            run = asyncio.create_task(engine.run([str(parts[-1])], origin=origin,
                discovery_scope=DiscoveryScope(str(case.archive_dir))))
            try:
                await asyncio.wait_for(paused.wait(), 10)
                await asyncio.to_thread(temporary.rename, final_path)
            finally:
                resume.set()
                [result] = await asyncio.gather(run, return_exceptions=True)
            if isinstance(result, BaseException):
                raise result
            assert result.summary.success_count == 1
            assert not result.summary.failures
            assert not any(path.exists() for path in [*parts, temporary])
            assert_expected_files_extracted(case, output)
            assert not engine._path_leases._pins

    asyncio.run(scenario())


@pytest.mark.parametrize("origin", ["watch", "foreground"])
@pytest.mark.parametrize("archive_format,encrypted", [("rar", False), ("7z", False), ("zip", False), ("rar", True)])
def test_missing_volume_retry_sees_live_arrival_even_before_catalog_event(tmp_path, monkeypatch, origin, archive_format, encrypted):
    """A new request hides a retry that still consults its initial inventory.

    Move a real member back before retry begins, leaving Watch's catalog stale.
    The three volume handlers, encrypted headers and two inventory sources
    need this small matrix.
    """
    if encrypted:
        case = create_encrypted_rar_archive(tmp_path/"fixture", "arrival",
            password="arrival-password", header_encrypt=True, split=True,
            payload_size=256*1024, split_volume_size=100*1024)
        for part in case.archive_dir.iterdir():
            renamed = part.rename(part.with_name(part.name + ".jpg"))
            if part == case.entry_path:
                case.entry_path = renamed
    else:
        case = ArchiveFixtureFactory().create(tmp_path/"fixture", "arrival", archive_format,
            split=True, payload_size=256*1024, split_volume_size=100*1024, disguise_ext="jpg")
    parts = sorted(case.archive_dir.iterdir())
    middle = parts[1]
    held = tmp_path/"held-volume"
    middle.rename(held)
    output = tmp_path/"output"
    config = _config(case.archive_dir, output)
    if encrypted:
        config["user_passwords"] = ["wrong-candidate", "arrival-password"]
    scope = DiscoveryScope(str(case.archive_dir))
    catalog = None
    if origin == "watch":
        state = NativeWatchCatalog(NativeWatchState())
        options = DirectoryScanner.compile_scan_options(config)
        assert not options.catalog_update(state, scope.native)
        catalog = (state, options, str(case.entry_path))

    async def scenario():
        loop = asyncio.get_running_loop()
        paused, resume = asyncio.Event(), threading.Event()
        original = ArchiveTaskProvider.resolve_volume_once

        def retry_after_arrival(self, *args, **kwargs):
            loop.call_soon_threadsafe(paused.set)
            assert resume.wait(15)
            return original(self, *args, **kwargs)

        monkeypatch.setattr(ArchiveTaskProvider, "resolve_volume_once", retry_after_arrival)
        async with PipelineEngine(config) as engine:
            run = asyncio.create_task(engine.run([str(case.entry_path)], origin=origin, discovery_scope=scope, catalog=catalog))
            try:
                await asyncio.wait_for(paused.wait(), 10)
                await asyncio.to_thread(held.rename, middle)
                assert all(path.exists() for path in parts)
            finally:
                resume.set()
                [result] = await asyncio.gather(run, return_exceptions=True)
            if isinstance(result, BaseException):
                raise result
            assert result.summary.success_count == 1
            assert not result.summary.failures
            assert not any(path.exists() for path in parts)
            assert_expected_files_extracted(case, output)
            assert not engine._path_leases._pins

    asyncio.run(scenario())
