"""Disposable process used by the WAL crash integration tests.

Fault gates exist only in this helper: the parent kills this process with
TerminateProcess while the production state/pipeline code is at a known boundary.
"""
from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
import json
from pathlib import Path
import sys
import threading
import time
from types import SimpleNamespace


def emit(**payload):
    print("WAL_TEST " + json.dumps(payload), flush=True)


def crash_gate(**payload):
    emit(kind="crash", **payload)
    threading.Event().wait()


def state_scenario(root, mode):
    from sunpack.runtime.watch.state import WatchStateStore

    state = WatchStateStore(str(root / "state.json"))
    if mode == "inspect":
        emit(kind="state", seq=state.applied_seq, checkpoint=state.checkpoint_seq,
             pending=[asdict(item) for item in state.pending_work_items()])
        return

    def put(index):
        state.queue_active(SimpleNamespace(path=str(root / f"source-{index}.dat"),
                           size=index + 1, mtime=1.0, file_id=str(index), change_usn=index),
                           durable_owner=True, persist=True, durable=True)

    if mode == "append":
        put(160)
        return
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(put, range(120)))
    if mode == "wal":
        crash_gate(seq=state.applied_seq)
        return
    captured = threading.Event()
    continued = threading.Event()
    original_write = state._write_snapshot_view
    original_retire = state._retire_segments_through

    def write(view):
        captured.set()
        assert continued.wait(30), "concurrent WAL writers did not finish"
        if mode == "before_snapshot":
            crash_gate(seq=state.applied_seq)
        original_write(view)

    def retire(boundary):
        if mode == "after_snapshot":
            crash_gate(seq=state.applied_seq)
        original_retire(boundary)
        if mode == "after_retire":
            crash_gate(seq=state.applied_seq)

    state._write_snapshot_view = write
    state._retire_segments_through = retire
    state.compact_if_needed(force=True)
    assert captured.wait(30), "checkpoint did not capture its snapshot"
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(put, range(120, 160)))
    continued.set()
    threading.Event().wait()


async def watch_scenario(root, mode):
    import sunpack_native
    from sunpack.core.config.loader import load_config
    from sunpack.core.passwords.internal import builtin
    from sunpack.pipeline.coordinator.engine import PipelineEngine
    from sunpack.runtime.watch.roots import WatchRootEntry
    from sunpack.runtime.watch.scheduler import WatchScheduler

    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    builtin.builtin_password_path = lambda: root / "builtin_passwords.txt"
    config = load_config()
    config["cli"]["quiet"] = True
    config["user_passwords"] = ["wrong-candidate"]
    if not manifest.get("unknown_password"):
        config["user_passwords"].append("wal-test-secret")
    config["builtin_passwords"] = []
    config["post_extract"].update(archive_cleanup_mode="keep", flatten_single_directory=False)
    config["watch"].update(clipboard_monitor_enabled=False,
                          directory_password_file_auto_create=False)
    input_roots = list(dict.fromkeys(str(Path(path).parent) for path in manifest["sources"]))
    output_roots = {path: str(root / "output" / str(index)) if len(input_roots) > 1
                    else str(root / "output") for index, path in enumerate(input_roots)}
    sunpack_native.watch_broker_acquire()
    try:
        async with PipelineEngine(config) as engine:
            watcher = WatchScheduler(config, input_roots,
                output_roots=output_roots,
                root_entries=[WatchRootEntry(path, output_roots[path], True) for path in input_roots],
                state_path=str(root / "state.json"), cold_start_seconds=0,
                initial_scan=False, pipeline_engine=engine)
            original = watcher._handle_pipeline_progress
            target_event = "task_output_started" if mode == "started" else "task_output_finished"
            started = set()
            progress_lock = threading.Lock()

            def progress(owner, notification, task, event, **kwargs):
                original(owner, notification, task, event, **kwargs)
                if mode == "concurrent" and event.get("event") == "task_output_started":
                    with progress_lock:
                        started.add(owner)
                        all_started = len(started) == len(manifest["sources"])
                    if all_started:
                        crash_gate(started=len(started),
                                   pending=[asdict(item) for item in watcher.state.pending_work_items()])
                if mode in {"started", "finished"} and event.get("event") == target_event:
                    output = Path(event["output_dir"])
                    if mode == "started":
                        # Sentinel stands for partial output that must be removed.
                        output.mkdir(parents=True, exist_ok=True)
                        (output / "crash-partial.txt").write_text("incomplete", encoding="utf-8")
                    crash_gate(event=target_event, output=str(output), owner=owner,
                               pending=[asdict(item) for item in watcher.state.pending_work_items()])

            watcher._handle_pipeline_progress = progress
            original_mark = watcher.state.mark

            def mark(*args, **kwargs):
                original_mark(*args, **kwargs)
                if mode == "blocked" and kwargs["status"] in {"failed_password", "suspended_missing_volume"}:
                    crash_gate(status=kwargs["status"],
                               entries=[asdict(item) for item in watcher.state.entry_items()])

            watcher.state.mark = mark
            await watcher.start()
            try:
                if mode in {"started", "finished", "concurrent", "blocked"}:
                    for source in manifest["sources"]:
                        watcher.enqueue(source, force=True)
                deadline = time.monotonic() + 60
                processed = 0
                while time.monotonic() < deadline:
                    result = await watcher.run_once()
                    processed += result.processed
                    with watcher._lock:
                        inflight = bool(watcher._inflight_requests)
                    if mode == "recover" and not inflight and not watcher.pending_count:
                        watcher.state.flush()
                        emit(kind="recovered", pending=watcher.state.pending_work_count,
                             entries=[asdict(item) for item in watcher.state.entry_items()])
                        return
                    if mode == "blocked" and processed and not inflight and not watcher.pending_count:
                        crash_gate(status="untracked_missing_volume", pending=watcher.state.pending_work_count,
                                   entries=[asdict(item) for item in watcher.state.entry_items()],
                                   sources=manifest["sources"])
                    await asyncio.sleep(0.01)
                raise RuntimeError("watch test did not settle")
            finally:
                await watcher.stop()
    finally:
        sunpack_native.watch_broker_release()


if __name__ == "__main__":
    family, directory, mode = sys.argv[1:]
    root = Path(directory)
    if family == "state":
        state_scenario(root, mode)
    else:
        asyncio.run(watch_scenario(root, mode))
