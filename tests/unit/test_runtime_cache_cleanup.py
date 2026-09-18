from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from sunpack.cli.runtime_host import RuntimeHost
from sunpack.contracts.archive_knowledge import ArchiveKnowledge
from sunpack.filesystem.watcher.scheduler import WatchScheduler
from sunpack.passwords.relation_prober import _shared_attempt_cache, clear_relation_probe_cache
from sunpack.support.archive_knowledge_projection import (
    clear_projection_cache,
    source_fingerprint,
)
from sunpack.support.global_cache_manager import GLOBAL_CACHE
from sunpack.support.runtime_cache_cleanup import clear_all_runtime_caches, runtime_cache_stats


_TEST_LOOP = asyncio.new_event_loop()


@pytest.fixture(autouse=True)
def _reset_process_caches():
    GLOBAL_CACHE.clear_all()
    clear_projection_cache()
    clear_relation_probe_cache()
    yield
    GLOBAL_CACHE.clear_all()
    clear_projection_cache()
    clear_relation_probe_cache()


def test_clear_all_runtime_caches_clears_python_owned_caches(tmp_path):
    GLOBAL_CACHE.set("runtime-cache-test", ("key",), {"payload": "value"})
    knowledge = ArchiveKnowledge({
        "_meta": {"revision": 1},
        "source": {"input": {"path": str(tmp_path / "archive.zip")}},
    })
    source_fingerprint(knowledge)
    attempt_cache = _shared_attempt_cache()
    attempt_cache.remember_success("fingerprint", "password")
    attempt_cache.remember_negative("fingerprint", "wrong")

    stats = runtime_cache_stats()
    assert stats["global_cache"]["entries"] >= 1
    assert stats["projection_cache"]["entries"] >= 1
    assert stats["relation_probe_cache"] == {"successes": 1, "negative": 1}
    assert "inspection" not in stats

    report = clear_all_runtime_caches()

    assert report["global_cache"]["entries"] >= 1
    assert report["projection_cache"]["entries"] >= 1
    assert report["relation_probe_cache"] == {"successes": 1, "negative": 1}
    assert "inspection" not in report
    assert GLOBAL_CACHE.stats()["entries"] == 0
    assert source_fingerprint(knowledge)
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
        {
            "watch": {
                "clipboard_monitor_enabled": False,
                "runtime_cache_cleanup_enabled": True,
                "runtime_cache_cleanup_idle_seconds": 10,
            }
        },
        [str(tmp_path)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        cold_start_seconds=0,
        initial_scan=False,
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
    watcher._pending["busy"] = object()
    _TEST_LOOP.run_until_complete(watcher._maybe_clear_idle_caches())
    assert engine.clear_calls == 1


def test_external_activity_resets_and_rearms_idle_cleanup(tmp_path):
    wakeups = []
    watcher = WatchScheduler(
        {
            "watch": {
                "clipboard_monitor_enabled": False,
                "runtime_cache_cleanup_enabled": True,
                "runtime_cache_cleanup_idle_seconds": 10,
            }
        },
        [str(tmp_path)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        cold_start_seconds=0,
        initial_scan=False,
        pipeline_engine=_CleanupOnlyEngine(),
        wake_callback=lambda: wakeups.append("wake"),
    )

    watcher._arm_idle_cache_cleanup()
    _TEST_LOOP.run_until_complete(watcher.set_external_activity(True))
    assert watcher._cache_cleanup_deadline is None

    _TEST_LOOP.run_until_complete(watcher.set_external_activity(False))
    assert watcher.next_delay_seconds() == pytest.approx(10, abs=0.1)
    assert wakeups == ["wake"]


def test_cleanup_gate_waits_for_foreground_activity(tmp_path):
    async def scenario():
        engine = _CleanupOnlyEngine()
        watcher = WatchScheduler(
            {
                "watch": {
                    "clipboard_monitor_enabled": False,
                    "runtime_cache_cleanup_enabled": True,
                    "runtime_cache_cleanup_idle_seconds": 10,
                }
            },
            [str(tmp_path)],
            out_dir=str(tmp_path / "out"),
            state_path=str(tmp_path / "state.json"),
            cold_start_seconds=0,
            initial_scan=False,
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
            {
                "watch": {
                    "clipboard_monitor_enabled": False,
                    "runtime_cache_cleanup_enabled": True,
                    "runtime_cache_cleanup_idle_seconds": 10,
                }
            },
            [str(tmp_path)],
            out_dir=str(tmp_path / "out"),
            state_path=str(tmp_path / "state.json"),
            cold_start_seconds=0,
            initial_scan=False,
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
            {
                "watch": {
                    "clipboard_monitor_enabled": False,
                    "runtime_cache_cleanup_enabled": True,
                    "runtime_cache_cleanup_idle_seconds": 10,
                }
            },
            [str(tmp_path)],
            out_dir=str(tmp_path / "out"),
            state_path=str(tmp_path / "state.json"),
            cold_start_seconds=0,
            initial_scan=False,
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
        assert stats["projection_cache"]["entries"] == 0
        assert stats["relation_probe_cache"] == {"successes": 0, "negative": 0}

    asyncio.run(scenario())
