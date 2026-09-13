from __future__ import annotations

import asyncio

import pytest
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
        quiet_seconds=0,
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
