from __future__ import annotations
from sunpack.pipeline.coordinator.output_ownership import OutputOwnership

import asyncio
import zipfile
from types import SimpleNamespace

import pytest

from sunpack.core.passwords.relation_prober import (
    _shared_attempt_cache,
    clear_relation_probe_cache,
)
from sunpack.core.support.archive_knowledge_projection import (
    source_fingerprint,
)
from sunpack.core.support.archive_knowledge_writer import commit_task_knowledge
from sunpack.core.support.global_cache_manager import GLOBAL_CACHE
from sunpack.core.support.runtime_cache_cleanup import (
    clear_all_runtime_caches,
    runtime_cache_stats,
)
from sunpack.runtime.cli.runtime_host import RuntimeHost
from sunpack.runtime.watch.scheduler import WatchScheduler
from tests.helpers.archive_tasks import make_archive_task
from tests.helpers.config_factory import make_config

_TEST_LOOP = asyncio.new_event_loop()


@pytest.fixture(autouse=True)
def _reset_process_caches():
    GLOBAL_CACHE.clear_all()
    clear_relation_probe_cache()
    yield
    GLOBAL_CACHE.clear_all()
    clear_relation_probe_cache()


def test_clear_all_runtime_caches_clears_python_owned_caches(tmp_path):
    GLOBAL_CACHE.set("runtime-cache-test", ("key",), {"payload": "value"})
    archive_path = tmp_path / "archive.zip"
    archive_path.write_bytes(b"PK\x05\x06" + b"\0" * 18)
    task = make_archive_task(archive_path, format_hint="zip")
    knowledge = task.knowledge()
    knowledge.merge({"source": {"cache_probe": True}})
    commit_task_knowledge(task, knowledge)
    source_fingerprint(task)
    attempt_cache = _shared_attempt_cache()
    attempt_cache.remember_success("fingerprint", "password")
    attempt_cache.remember_negative("fingerprint", "wrong")

    stats = runtime_cache_stats()
    assert stats["global_cache"]["entries"] >= 1
    assert stats["relation_probe_cache"] == {"successes": 1, "negative": 1}
    assert "inspection" not in stats

    report = clear_all_runtime_caches()

    assert report["global_cache"]["entries"] >= 1
    assert report["relation_probe_cache"] == {"successes": 1, "negative": 1}
    assert "inspection" not in report
    assert GLOBAL_CACHE.stats()["entries"] == 0
    assert source_fingerprint(task)
    assert report["errors"] == []


class _CleanupOnlyEngine:
    recent_passwords = []

    def __init__(self):
        self.clear_calls = 0

    def is_idle(self):
        return True

    async def clear_runtime_caches(self):
        self.clear_calls += 1
        return {"before": {"reader": {"cache_entries": 1}}, "after": {"reader": {"cache_entries": 0}}}


class _BlockingCleanupEngine(_CleanupOnlyEngine):
    def __init__(self):
        super().__init__()
        self.cleanup_started = asyncio.Event()
        self.release_cleanup = asyncio.Event()

    async def clear_runtime_caches(self):
        self.clear_calls += 1
        self.cleanup_started.set()
        await self.release_cleanup.wait()
        return {"before": {}, "after": {}}


class _StatsCleanupEngine(_CleanupOnlyEngine):
    async def clear_runtime_caches(self):
        self.clear_calls += 1
        before = runtime_cache_stats()
        cleared = clear_all_runtime_caches()
        after = runtime_cache_stats()
        return {"before": before, "cleared": cleared, "after": after}


def test_watch_deadline_clears_only_after_idle_window(tmp_path):
    engine = _CleanupOnlyEngine()
    watcher = WatchScheduler(
        make_config({
            "watch": {
                "clipboard_monitor_enabled": False,
                "runtime_cache_cleanup_enabled": True,
                "runtime_cache_cleanup_idle_seconds": 10,
            }
        }),
        [str(tmp_path)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        cold_start_seconds=0,
        pipeline_engine=engine,
    )

    watcher._arm_idle_cache_cleanup()
    assert watcher.next_delay_seconds() == pytest.approx(10, abs=0.1)
    watcher._cache_cleanup_deadline = 0
    _TEST_LOOP.run_until_complete(watcher._maybe_clear_idle_caches())
    assert engine.clear_calls == 1
    assert watcher._cache_cleanup_deadline is None

    watcher._arm_idle_cache_cleanup()
    watcher._reset_idle_cache_cleanup()
    watcher._cache_cleanup_deadline = 0
    watcher._store_pending_locked("busy", object())
    _TEST_LOOP.run_until_complete(watcher._maybe_clear_idle_caches())
    assert engine.clear_calls == 1


@pytest.mark.parametrize("cache_cleanup_enabled", [False, True])
def test_ignored_log_history_expires_without_pipeline_activity(tmp_path, monkeypatch, cache_cleanup_enabled):
    # Store-only expiry tests cannot catch a sleeping Watch that never schedules
    # cleanup after ignored events. Exercise real admission and next deadlines.
    import sunpack.runtime.watch.scheduler as scheduler_module

    async def scenario():
        now = [100.0]
        monkeypatch.setattr(scheduler_module.time, "monotonic", lambda: now[0])
        wakeups = []
        engine = _CleanupOnlyEngine()
        watcher = WatchScheduler(
            make_config({"watch": {"clipboard_monitor_enabled": False,
                "runtime_cache_cleanup_enabled": cache_cleanup_enabled}}),
            [str(tmp_path)], out_dir=str(tmp_path / "out"),
            state_path=str(tmp_path / "state.json"),
            pipeline_engine=engine, wake_callback=lambda: wakeups.append("wake"),
        )
        try:
            watcher.enqueue(str(tmp_path / "missing.bin"))
            assert wakeups == ["wake"]
            assert watcher._cache_cleanup_deadline is None
            assert watcher.next_delay_seconds() == 300.0
            await watcher.set_external_activity(True)
            now[0] = 110.0
            await watcher.run_once()
            watcher.enqueue(str(tmp_path / "missing.bin"))
            assert len(wakeups) == 1
            assert watcher.log._last_throttled_write
            now[0] = 400.0
            await watcher.run_once()
            assert not watcher.log._last_throttled_write
            assert watcher.next_delay_seconds() is None
            assert engine.clear_calls == 0
            watcher.enqueue(str(tmp_path / "missing.bin"))
            assert len(wakeups) == 2
            assert watcher.next_delay_seconds() == 300.0
        finally:
            watcher._close_blocking()
        assert watcher.log.next_history_expiry is None
        assert not watcher.log._last_throttled_write

    asyncio.run(scenario())


@pytest.mark.parametrize("still_blocked", [False, True])
def test_failed_wal_retirement_schedules_one_idle_retry(tmp_path, monkeypatch, still_blocked):
    # Direct store retries cannot catch a finished checkpoint that leaves Watch
    # asleep, or a locked file turning retry scheduling into idle polling.
    from pathlib import Path
    from threading import Event
    from sunpack.runtime.watch.scanner import WatchCandidate
    import sunpack.runtime.watch.scheduler as scheduler_module

    async def scenario():
        now = [100.0]
        monkeypatch.setattr(scheduler_module.time, "monotonic", lambda: now[0])
        wake = Event()
        watcher = WatchScheduler(
            make_config({"watch": {"clipboard_monitor_enabled": False,
                "runtime_cache_cleanup_enabled": False, "runtime_cache_cleanup_idle_seconds": 10}}),
            [str(tmp_path)], out_dir=str(tmp_path / "out"),
            state_path=str(tmp_path / "state.json"),
            pipeline_engine=_CleanupOnlyEngine(), wake_callback=wake.set,
        )
        try:
            watcher.state.queue_active(WatchCandidate(str(tmp_path / "archive.bin"), 1, 1.0), durable=True)
            covered = watcher.state.journal_path
            real_unlink = Path.unlink
            blocked = True
            def unlink(path, *args, **kwargs):
                if path == covered and blocked:
                    raise PermissionError("simulated sharing violation")
                return real_unlink(path, *args, **kwargs)
            monkeypatch.setattr(Path, "unlink", unlink)
            watcher.state.save()
            assert wake.wait(2)
            assert watcher.next_delay_seconds() == 10.0
            blocked = still_blocked
            wake.clear()
            now[0] = 110.0
            await watcher.run_once()
            with watcher.state._checkpoint_condition:
                assert watcher.state._checkpoint_condition.wait_for(
                    lambda: not watcher.state._checkpoint_running, timeout=2,
                )
            assert covered.exists() is still_blocked
            assert watcher.next_delay_seconds() is None
            assert not wake.is_set()
        finally:
            watcher._close_blocking()

    asyncio.run(scenario())


def test_completed_family_cache_waits_for_watch_callbacks_and_foreground(tmp_path):
    from sunpack.pipeline.coordinator.engine import PipelineEngine

    async def scenario():
        config = make_config({"watch": {"clipboard_monitor_enabled": False}})
        async with PipelineEngine(config) as engine:
            watcher = WatchScheduler(config, [str(tmp_path)], out_dir=str(tmp_path / "out"),
                state_path=str(tmp_path / "state.json"), pipeline_engine=engine)
            parts = [tmp_path / "a.001", tmp_path / "a.002"]
            for part in parts:
                part.write_text("part")
            output = tmp_path / "output"
            output.mkdir()
            version = engine._path_leases.input_version_for(map(str, parts))
            engine._path_leases.output_ownership.remember_completed(version, str(output))
            watcher._inflight_path_counts["completion"] = 1
            watcher._cache_cleanup_deadline = 0
            await watcher._maybe_clear_idle_caches()
            assert engine._path_leases.completed_watch_output(version) == str(output)
            watcher._inflight_path_counts.clear()
            await watcher.set_external_activity(True)
            watcher._cache_cleanup_deadline = 0
            await watcher._maybe_clear_idle_caches()
            assert engine._path_leases.completed_watch_output(version) == str(output)
            await watcher.set_external_activity(False)
            watcher._cache_cleanup_deadline = 0
            await watcher._maybe_clear_idle_caches()
            assert engine._path_leases.completed_watch_output(version) == str(output)
            await watcher.aclose()

    asyncio.run(scenario())


def test_retained_sources_release_models_and_native_capacity_across_batches(tmp_path):
    from sunpack_native import reader_cache_stats
    from sunpack.pipeline.coordinator.engine import PipelineEngine
    from sunpack.runtime.watch.journal_commit import journal_stats

    # Existing one-shot clears cannot detect per-file retention across completed
    # batches. Exercise real detection/extraction with disguised retained ZIPs.
    async def scenario():
        root = tmp_path / "watch"
        root.mkdir()
        config = make_config({
            "watch": {"clipboard_monitor_enabled": False, "cold_start_seconds": 0,
                "quiet_min_seconds": 0, "quiet_max_seconds": 0},
            "post_extract": {"archive_cleanup_mode": "k"},
        })
        async with PipelineEngine(config) as engine:
            watcher = WatchScheduler(config, [str(root)], out_dir=str(tmp_path / "out"),
                state_path=str(tmp_path / "state.json"), pipeline_engine=engine)
            sources = []
            for batch in range(3):
                for offset in range(8):
                    index = batch * 8 + offset
                    source = root / f"archive-{index}.bin"
                    with zipfile.ZipFile(source, "w") as archive:
                        archive.writestr(f"payload-{index}.txt", f"payload-{index}" * 100)
                    sources.append(source)
                    watcher.enqueue(str(source))

                async def settle():
                    succeeded = 0
                    while watcher.pending_count or watcher._inflight_requests or watcher._completion_batches:
                        result = await watcher.run_once()
                        assert result.failed == 0, result.errors
                        succeeded += result.succeeded
                        if watcher.pending_count or watcher._inflight_requests:
                            await asyncio.sleep(0.001)
                    return succeeded

                assert await asyncio.wait_for(settle(), 15) == 8
                assert not watcher._quiet_trackers
                watcher._cache_cleanup_deadline = 0
                await watcher._maybe_clear_idle_caches()
                assert watcher.state._native.storage_capacities() == (0, 0)
                assert reader_cache_stats()["container_capacity"] == 0
                assert len(watcher.state._native.runtime_keys("done|")) == len(sources)
                assert len(watcher._latest_observations) == len(sources)
                for source in sources:
                    watcher.enqueue(str(source), event_type="modified")
                assert (await watcher.run_once()).processed == 0
            assert len(list((tmp_path / "out").rglob("payload-*.txt"))) == 24
            for source in sources:
                source.unlink()
                watcher.notify_path_departed(str(source))
            assert not watcher._latest_observations
            await watcher.aclose()
            await engine.aclose()
            assert not journal_stats(watcher.state._writer_stream)["registered"]

    asyncio.run(scenario())


def test_external_activity_resets_and_rearms_idle_cleanup(tmp_path):
    wakeups = []
    watcher = WatchScheduler(
        make_config({
            "watch": {
                "clipboard_monitor_enabled": False,
                "runtime_cache_cleanup_enabled": True,
                "runtime_cache_cleanup_idle_seconds": 10,
            }
        }),
        [str(tmp_path)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        cold_start_seconds=0,
        pipeline_engine=_CleanupOnlyEngine(),
        wake_callback=lambda: wakeups.append("wake"),
    )

    watcher._arm_idle_cache_cleanup()
    _TEST_LOOP.run_until_complete(watcher.set_external_activity(True))
    assert watcher._cache_cleanup_deadline is None

    _TEST_LOOP.run_until_complete(watcher.set_external_activity(False))
    assert watcher.next_delay_seconds() == pytest.approx(10, abs=0.1)
    assert wakeups == ["wake"]


def test_idle_maintenance_expires_cli_mode_when_cache_cleanup_is_disabled(tmp_path):
    from sunpack.runtime.cli.runtime_state import set_runtime_host

    async def scenario():
        engine = _CleanupOnlyEngine()
        watcher = WatchScheduler(
            make_config({
                "watch": {
                    "clipboard_monitor_enabled": False,
                    "runtime_cache_cleanup_enabled": False,
                    "runtime_cache_cleanup_idle_seconds": 10,
                }
            }),
            [str(tmp_path)],
            out_dir=str(tmp_path / "out"),
            state_path=str(tmp_path / "state.json"),
            cold_start_seconds=0,
            pipeline_engine=engine,
        )
        host = RuntimeHost()
        set_runtime_host(host)
        try:
            await host._set_configured_process_mode({"runtime": {"process_mode": "background"}})
            await host.set_cli_process_mode_override("high")
            assert host.process_mode == "high"

            watcher._arm_idle_cache_cleanup()
            watcher._cache_cleanup_deadline = 0
            await watcher._maybe_clear_idle_caches()

            assert host.process_mode == "background"
            assert host._cli_process_mode_override is None
            assert engine.clear_calls == 0
        finally:
            set_runtime_host(None)

    asyncio.run(scenario())


def test_cleanup_gate_waits_for_foreground_activity(tmp_path):
    async def scenario():
        engine = _CleanupOnlyEngine()
        watcher = WatchScheduler(
            make_config({
                "watch": {
                    "clipboard_monitor_enabled": False,
                    "runtime_cache_cleanup_enabled": True,
                    "runtime_cache_cleanup_idle_seconds": 10,
                }
            }),
            [str(tmp_path)],
            out_dir=str(tmp_path / "out"),
            state_path=str(tmp_path / "state.json"),
            cold_start_seconds=0,
            pipeline_engine=engine,
        )

        await watcher.set_external_activity(True)
        watcher._cache_cleanup_deadline = 0
        cleanup = asyncio.create_task(watcher._maybe_clear_idle_caches())
        await cleanup
        assert engine.clear_calls == 0

        await watcher.set_external_activity(False)
        watcher._cache_cleanup_deadline = 0
        await watcher._maybe_clear_idle_caches()
        assert engine.clear_calls == 1

    asyncio.run(scenario())


def test_external_activity_waits_for_cleanup_already_in_progress(tmp_path):
    async def scenario():
        engine = _BlockingCleanupEngine()
        watcher = WatchScheduler(
            make_config({
                "watch": {
                    "clipboard_monitor_enabled": False,
                    "runtime_cache_cleanup_enabled": True,
                    "runtime_cache_cleanup_idle_seconds": 10,
                }
            }),
            [str(tmp_path)],
            out_dir=str(tmp_path / "out"),
            state_path=str(tmp_path / "state.json"),
            cold_start_seconds=0,
            pipeline_engine=engine,
        )

        watcher._cache_cleanup_deadline = 0
        cleanup = asyncio.create_task(watcher._maybe_clear_idle_caches())
        await engine.cleanup_started.wait()

        foreground = asyncio.create_task(watcher.set_external_activity(True))
        await asyncio.sleep(0)
        assert not foreground.done()

        engine.release_cleanup.set()
        await cleanup
        await foreground
        assert watcher._cache_cleanup_deadline is None
        await watcher.set_external_activity(False)

    asyncio.run(scenario())


def test_foreground_lifecycle_clears_runtime_caches_after_idle(tmp_path):
    async def scenario():
        engine = _StatsCleanupEngine()
        watcher = WatchScheduler(
            make_config({
                "watch": {
                    "clipboard_monitor_enabled": False,
                    "runtime_cache_cleanup_enabled": True,
                    "runtime_cache_cleanup_idle_seconds": 10,
                }
            }),
            [str(tmp_path)],
            out_dir=str(tmp_path / "out"),
            state_path=str(tmp_path / "state.json"),
            cold_start_seconds=0,
            pipeline_engine=engine,
        )
        host = RuntimeHost()
        host._watch_service = SimpleNamespace(scheduler=watcher)
        host._watch_task = SimpleNamespace(done=lambda: False)

        await host.foreground_started()
        GLOBAL_CACHE.set("foreground-lifecycle", ("key",), {"payload": "value"})
        assert runtime_cache_stats()["global_cache"]["entries"] >= 1

        await host.foreground_finished()
        assert watcher._cache_cleanup_deadline is not None
        assert not watcher._runtime_cache_gate.locked()

        watcher._cache_cleanup_deadline = 0
        await watcher._maybe_clear_idle_caches()

        stats = runtime_cache_stats()
        assert engine.clear_calls == 1
        assert stats["global_cache"]["entries"] == 0
        assert stats["relation_probe_cache"] == {"successes": 0, "negative": 0}

    asyncio.run(scenario())


@pytest.mark.parametrize("replace_scheduler", [False, True])
def test_disconnect_during_foreground_admission_restores_idle_cleanup(tmp_path, replace_scheduler):
    from sunpack.runtime.cli.persistent_process import _PipeRequestProtocol
    from sunpack.runtime.cli.runtime_state import set_runtime_host

    async def scenario():
        engine = _BlockingCleanupEngine()
        config = make_config({"watch": {"clipboard_monitor_enabled": False}})

        def scheduler(name):
            return WatchScheduler(
                config, [str(tmp_path)], out_dir=str(tmp_path / "out"),
                state_path=str(tmp_path / name), pipeline_engine=engine,
            )

        watcher = scheduler("state.json")
        host = RuntimeHost()
        host._watch_service = SimpleNamespace(scheduler=watcher)
        host._watch_task = SimpleNamespace(done=lambda: False)
        set_runtime_host(host)
        watcher._cache_cleanup_deadline = 0
        cleanup = asyncio.create_task(watcher._maybe_clear_idle_caches())
        await engine.cleanup_started.wait()
        protocol = _PipeRequestProtocol(
            b"t" * 32, on_connected=lambda: None, on_closed=lambda: None,
            on_completed=lambda: None, on_shutdown=lambda: None,
        )

        class Transport:
            def write(self, _frame):
                pass

            def get_write_buffer_size(self):
                return 0

            def close(self):
                pass

        protocol.connection_made(Transport())
        request = protocol._request_task = asyncio.create_task(protocol._run_request({"argv": ["extract"]}))
        current = watcher
        try:
            await asyncio.sleep(0)
            assert watcher._external_activity_gate_acquiring
            if replace_scheduler:
                current = scheduler("replacement.json")
                host._watch_service.scheduler = current
                # WatchService hands an outstanding host gate to its successor.
                await current.set_external_activity(host._foreground_gate_requested)
            protocol.connection_lost(None)
            result = await asyncio.wait_for(asyncio.gather(request, return_exceptions=True), 1)
            assert isinstance(result[0], asyncio.CancelledError)
            engine.release_cleanup.set()
            await cleanup
            assert host._foreground_requests == 0
            assert not host._foreground_gate_requested
            for item in {watcher, current}:
                assert not item._external_activity_requested
                assert not item._runtime_cache_gate.locked()
            current._cache_cleanup_deadline = 0
            await current._maybe_clear_idle_caches()
            assert engine.clear_calls == 2
            # A following request can still acquire and release the same gate.
            await host.foreground_started()
            await host.foreground_finished()
            assert not current._runtime_cache_gate.locked()
        finally:
            engine.release_cleanup.set()
            request.cancel()
            protocol._output_task.cancel()
            await asyncio.gather(request, protocol._output_task, cleanup, return_exceptions=True)
            set_runtime_host(None)

    asyncio.run(scenario())


def test_external_activity_release_during_pending_acquire_leaves_gate_free(tmp_path):
    async def scenario():
        engine = _BlockingCleanupEngine()
        watcher = WatchScheduler(
            make_config({
                "watch": {
                    "clipboard_monitor_enabled": False,
                    "runtime_cache_cleanup_enabled": True,
                    "runtime_cache_cleanup_idle_seconds": 10,
                }
            }),
            [str(tmp_path)],
            out_dir=str(tmp_path / "out"),
            state_path=str(tmp_path / "state.json"),
            cold_start_seconds=0,
            pipeline_engine=engine,
        )

        watcher._cache_cleanup_deadline = 0
        cleanup = asyncio.create_task(watcher._maybe_clear_idle_caches())
        await engine.cleanup_started.wait()

        foreground = asyncio.create_task(watcher.set_external_activity(True))
        await asyncio.sleep(0)
        # A duplicate request while the first acquire waits must not queue a
        # second acquire that would hold the gate forever.
        duplicate = asyncio.create_task(watcher.set_external_activity(True))
        await asyncio.sleep(0)
        assert duplicate.done()
        await watcher.set_external_activity(False)

        engine.release_cleanup.set()
        await cleanup
        await foreground
        assert not watcher._runtime_cache_gate.locked()
        assert watcher._external_activity_gate_held is False

    asyncio.run(scenario())
