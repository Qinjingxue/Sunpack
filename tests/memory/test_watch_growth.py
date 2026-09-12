from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from tests.helpers.watch_memory import (
    WatchMemoryHarness,
    WatchMemorySampler,
    count_output_files,
    create_small_zip,
    drive_watch_until,
    drive_watch_until_cache_cleanup,
    env_float,
    env_int,
    publish_files,
)
from tests.real.plan1_real_archives.plan1_support import plan1_config


def _watch_memory_config() -> dict:
    config = plan1_config(passwords=[])
    config["watch"] = {
        **(config.get("watch") or {}),
        "clipboard_monitor_enabled": False,
        "password_retry_debounce_seconds": 0,
        "cold_start_seconds": 0,
        "quiet_min_seconds": 0,
        "quiet_max_seconds": 0,
        "runtime_cache_cleanup_enabled": os.environ.get(
            "SUNPACK_WATCH_MEMORY_CACHE_CLEANUP_ENABLED",
            "1",
        ) != "0",
        "runtime_cache_cleanup_idle_seconds": env_float(
            "SUNPACK_WATCH_MEMORY_CACHE_CLEANUP_IDLE_SECONDS",
            10.0,
            minimum=0.0,
        ),
    }
    config["cli"] = {
        **(config.get("cli") or {}),
        "quiet": True,
        "verbose": False,
    }
    config["post_extract"] = {
        **(config.get("post_extract") or {}),
        "archive_cleanup_mode": "keep",
        "flatten_single_directory": False,
    }
    config["performance"] = {
        **(config.get("performance") or {}),
        "worker": {
            **((config.get("performance") or {}).get("worker") or {}),
            "max_queue_jobs": 64,
        },
    }
    return config


@pytest.mark.performance
def test_watch_memory_growth_with_many_completed_files(tmp_path, record_property):
    """Measure long-lived watch growth at batch checkpoints and during idle time.

    The default workload is intentionally opt-in and can be scaled without a
    code change:

    ``SUNPACK_WATCH_MEMORY_BATCHES`` (default 4),
    ``SUNPACK_WATCH_MEMORY_FILES_PER_BATCH`` (default 2),
    ``SUNPACK_WATCH_MEMORY_PAYLOAD_MIB`` (default 64),
    ``SUNPACK_WATCH_MEMORY_PAYLOAD_KIB`` (legacy override),
    ``SUNPACK_WATCH_MEMORY_INTERVAL_SECONDS`` (default 0.2), and
    ``SUNPACK_WATCH_MEMORY_TIMEOUT_SECONDS`` (default 90).
    ``SUNPACK_WATCH_MEMORY_MAX_ACTIVE_PIPELINES`` can be set to 1 to
    exclude Windows output contention from a run.

    The detailed JSON report includes RSS, private memory, child processes,
    reader cache, global cache namespaces, archive sessions, inspection cache,
    watch state, engine queues, handles, and threads at every checkpoint.
    """

    batches = env_int("SUNPACK_WATCH_MEMORY_BATCHES", 4)
    files_per_batch = env_int("SUNPACK_WATCH_MEMORY_FILES_PER_BATCH", 2)
    if "SUNPACK_WATCH_MEMORY_PAYLOAD_KIB" in os.environ:
        payload_size = env_int("SUNPACK_WATCH_MEMORY_PAYLOAD_KIB", 1, minimum=1) * 1024
    else:
        payload_size = env_int("SUNPACK_WATCH_MEMORY_PAYLOAD_MIB", 64, minimum=1) * 1024 * 1024
    interval = env_float("SUNPACK_WATCH_MEMORY_INTERVAL_SECONDS", 0.2, minimum=0.02)
    timeout = env_float("SUNPACK_WATCH_MEMORY_TIMEOUT_SECONDS", 90.0, minimum=1.0)
    max_slope = env_float(
        "SUNPACK_WATCH_MEMORY_MAX_SLOPE_MIB_PER_FILE",
        2.0,
        minimum=0.0,
    )
    settle_seconds = env_float(
        "SUNPACK_WATCH_MEMORY_SETTLE_SECONDS",
        0.1,
        minimum=0.0,
    )
    cleanup_wait_seconds = env_float(
        "SUNPACK_WATCH_MEMORY_CACHE_CLEANUP_WAIT_SECONDS",
        12.0,
        minimum=0.0,
    )
    trace_python = os.environ.get("SUNPACK_WATCH_MEMORY_TRACEMALLOC", "0") == "1"
    total_files = batches * files_per_batch
    corpus_root = tmp_path / "corpus"

    with WatchMemoryHarness.create(tmp_path, _watch_memory_config()) as harness:
        sampler = WatchMemorySampler(
            watcher=harness.watcher,
            engine=harness.engine,
            state_path=harness.state_path,
            interval_seconds=interval,
            trace_python=trace_python,
        )
        sampler.sample(files_seen=0, completed_files=0, label="baseline")
        sampler.start()
        published_count = 0
        try:
            for batch in range(batches):
                sources = []
                first_index = batch * files_per_batch
                for offset in range(files_per_batch):
                    index = first_index + offset
                    sources.append(
                        create_small_zip(
                            corpus_root / f"archive-{index:05d}.zip",
                            member_name=f"payload-{index:05d}.txt",
                            payload_size=payload_size,
                            seed=index,
                        )
                    )
                published = publish_files(harness.watcher, sources, harness.watch_root)
                for source in sources:
                    source.unlink()
                published_count += len(published)
                expected_outputs = published_count
                result = drive_watch_until(
                    harness.watcher,
                    lambda expected=expected_outputs: count_output_files(
                        harness.output_root, "payload-*.txt"
                    ) >= expected,
                    timeout_seconds=timeout,
                )
                assert result.failed == 0, result.errors
                completed = count_output_files(harness.output_root, "payload-*.txt")
                sampler.sample(
                    files_seen=published_count,
                    completed_files=completed,
                    label=f"after_batch_{batch + 1}",
                )
                if settle_seconds:
                    time.sleep(settle_seconds)
                sampler.sample(
                    files_seen=published_count,
                    completed_files=completed,
                    label=f"idle_batch_{batch + 1}",
                )
                if cleanup_wait_seconds:
                    drive_watch_until_cache_cleanup(
                        harness.watcher,
                        timeout_seconds=max(timeout, cleanup_wait_seconds + 5.0),
                    )
                    sampler.sample(
                        files_seen=published_count,
                        completed_files=completed,
                        label=f"after_cache_cleanup_{batch + 1}",
                    )

            assert published_count == total_files
            assert count_output_files(harness.output_root, "payload-*.txt") == total_files
        finally:
            sampler.stop()

        # Capture the release boundary separately from the warm idle curve.
        harness.close()
        sampler.sample(
            files_seen=published_count,
            completed_files=published_count,
            label="after-engine-close",
        )
        report = sampler.report()
        report_path = tmp_path / "watch-memory-report.json"
        report_path.write_text(sampler.json_report(), encoding="utf-8")

    record_property("watch_memory_summary", json.dumps(report, ensure_ascii=False))
    record_property("watch_memory_report", str(report_path))
    print("watch memory summary: " + json.dumps(report, ensure_ascii=False, sort_keys=True))

    assert report["completed_files"] == total_files
    assert report["parent_slope_mib_per_completed_file"] <= max_slope, report
    assert report["worker_slope_mib_per_completed_file"] <= max_slope, report
