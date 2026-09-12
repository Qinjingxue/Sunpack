from __future__ import annotations

"""End-to-end benchmark for one real file arriving through watch mode."""

import argparse
import asyncio
import json
import os
import shutil
import statistics
import sys
import time
import types
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from benchmarks.harness.reporting import report_from_payload, render_report
from benchmarks.harness.workspace import BenchmarkWorkspace
from benchmarks.watch_broker import watch_broker_lease
from benchmarks.scenarios.extraction_large_archive import (
    RequestRuntimeProfiler,
    _timing_totals,
)
from sunpack.config.loader import load_config
from sunpack.coordinator.engine import PipelineEngine
from sunpack.coordinator.watch_group_coordinator import WatchGroupCoordinator
from sunpack.filesystem.watcher.scheduler import WatchScheduler


DEFAULT_SOURCE = Path(__file__).resolve().parents[2] / "testfiles" / "R3961.jpg"


def _now() -> float:
    return time.perf_counter()


def _wrap_scheduler_timers(watcher: WatchScheduler, destination: Path, timings: dict[str, float]) -> None:
    original_enqueue = watcher.enqueue

    def enqueue(self, path: str, *args: Any, **kwargs: Any):
        if Path(path).resolve() == destination.resolve() and "watchdog_first_enqueue" not in timings:
            timings["watchdog_first_enqueue"] = _now()
        return original_enqueue(path, *args, **kwargs)

    watcher.enqueue = types.MethodType(enqueue, watcher)

    original_submit = watcher._submit_candidate

    async def submit(self, candidate, *, group=None):
        if Path(candidate.path).resolve() == destination.resolve():
            timings.setdefault("processing_started", _now())
        return await original_submit(candidate, group=group)

    watcher._submit_candidate = types.MethodType(submit, watcher)

    original_complete = watcher._complete_candidate

    async def complete(self, request):
        result = await original_complete(request)
        if result.succeeded:
            timings["completed_finished"] = _now()
        return result

    watcher._complete_candidate = types.MethodType(complete, watcher)


def _phase_seconds(profiler: RequestRuntimeProfiler) -> dict[str, float]:
    if not profiler.request_timings:
        return {}
    # This scenario submits one target.  Keep the full per-label totals so
    # small phases are not hidden by a derived aggregate.
    return _timing_totals(profiler.request_timings[-1])


def _output_summary(root: Path, source_name: str) -> dict[str, Any]:
    excluded = {source_name, ".sunpack-passwords.txt", "state.json", "events.jsonl"}
    files = [
        path
        for path in root.rglob("*")
        if path.is_file()
        and path.name not in excluded
    ]
    return {
        "file_count": len(files),
        "total_bytes": sum(path.stat().st_size for path in files),
        "relative_files": [str(path.relative_to(root)) for path in files[:32]],
    }


async def _run_once(
    source: Path,
    workspace: BenchmarkWorkspace,
    *,
    passwords: list[str],
    quiet_seconds: float,
    timeout: float,
) -> dict[str, Any]:
    root = workspace.work / "watch"
    root.mkdir(parents=True, exist_ok=True)
    destination = root / source.name
    state_path = workspace.work / "state.json"

    config = load_config()
    config["cli"] = {**(config.get("cli") or {}), "quiet": True, "verbose": False}
    config["watch"] = {
        **(config.get("watch") or {}),
        "clipboard_monitor_enabled": False,
        "initial_scan": False,
        "runtime_cache_cleanup_enabled": False,
    }
    config["user_passwords"] = list(passwords)
    config["output"] = {**(config.get("output") or {}), "root": str(root)}

    engine = PipelineEngine(config)
    profiler = RequestRuntimeProfiler()
    profiler.install(engine)
    profiler.enabled = True
    timings: dict[str, float] = {"started": _now()}
    tick_seconds: list[float] = []
    watcher: WatchScheduler | None = None
    try:
        await engine.__aenter__()
        watcher = WatchScheduler(
            config,
            [str(root)],
            # A relative dot is resolved against the watched root, so the
            # result lands in the watch directory itself.
            out_dir=".",
            state_path=str(state_path),
            quiet_seconds=quiet_seconds,
            initial_scan=False,
            pipeline_engine=engine,
            group_coordinator=WatchGroupCoordinator(config),
        )
        _wrap_scheduler_timers(watcher, destination, timings)
        await watcher.start()

        copy_started = _now()
        shutil.copy2(source, destination)
        timings["copy_seconds"] = _now() - copy_started
        timings["copy_finished"] = _now()

        deadline = _now() + timeout
        completed = False
        terminal_status = ""
        while _now() < deadline:
            tick_started = _now()
            await watcher.run_once()
            tick_seconds.append(_now() - tick_started)
            if "completed_finished" in timings:
                completed = True
                break
            for path, entry in watcher.state.entries.items():
                if Path(path).resolve() == destination.resolve() and entry.status.startswith("failed"):
                    terminal_status = entry.status
                    break
            if terminal_status:
                break
            delay = watcher.next_delay_seconds()
            await asyncio.sleep(0.01 if delay is None else min(max(delay, 0.001), 0.05))
        else:
            raise TimeoutError(
                f"watch did not complete output before {timeout:g}s; "
                f"pending={watcher.pending_count}, timings={timings}"
            )

        timings["finished"] = timings.get("completed_finished", _now())
        watchdog_event = timings.get("watchdog_first_enqueue")
        totals = _phase_seconds(profiler)
        result = {
            "source": str(source),
            "source_bytes": source.stat().st_size,
            "watch_root": str(root),
            "timings_seconds": {
                "copy": timings.get("copy_seconds", 0.0),
                "watchdog_event_from_copy_start": (
                    watchdog_event - copy_started if watchdog_event is not None else 0.0
                ),
                "copy_to_watchdog_enqueue": (
                    max(0.0, watchdog_event - timings["copy_finished"])
                    if watchdog_event is not None else 0.0
                ),
                "watchdog_event_during_copy": bool(
                    watchdog_event is not None and watchdog_event <= timings["copy_finished"]
                ),
                "copy_to_processing_start": (
                    timings.get("processing_started", timings["copy_finished"])
                    - timings["copy_finished"]
                ),
                "quiet_and_dispatch": (
                    timings.get("processing_started", timings["copy_finished"])
                    - timings["copy_finished"]
                ),
                "pipeline_run": totals.get("pipeline_run", 0.0),
                "watch_completion": timings.get("completed_finished", 0.0) - timings["copy_finished"]
                if "completed_finished" in timings else 0.0,
                "end_to_end_copy_start_to_completion": (
                    timings["finished"] - copy_started
                ),
            },
            "pipeline_timing_seconds": totals,
            "watch_tick_seconds": {
                "count": len(tick_seconds),
                "total": sum(tick_seconds),
                "max": max(tick_seconds) if tick_seconds else 0.0,
            },
            "timestamps_relative_to_copy_start": {
                key: value - copy_started
                for key, value in timings.items()
                if key.endswith("_started") or key.endswith("_finished") or key == "watchdog_first_enqueue"
            },
            "output": _output_summary(root, source.name),
            "profiler_requests": len(profiler.request_timings),
            "completed": completed,
            "terminal_status": terminal_status,
        }
        return result
    finally:
        if watcher is not None:
            await watcher.stop()
        profiler.restore()
        await engine.aclose(graceful=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="End-to-end watch benchmark for one real file.")
    parser.add_argument("source", nargs="?", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--runs", type=int, default=1)
    parser.add_argument("--password", action="append", default=[])
    parser.add_argument(
        "--wrong-password-count",
        type=int,
        default=0,
        help="Prepend wrong-0000 ... wrong-NNNN before --password candidates.",
    )
    parser.add_argument("--quiet-seconds", type=float, default=1.0)
    parser.add_argument("--timeout", type=float, default=900.0)
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--keep-workdir", action="store_true")
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    source = args.source.resolve()
    if not source.is_file():
        parser.error(f"source file does not exist: {source}")
    if args.runs < 1:
        parser.error("--runs must be positive")
    if args.wrong_password_count < 0:
        parser.error("--wrong-password-count must be nonnegative")

    passwords = [f"wrong-{index:04d}" for index in range(args.wrong_password_count)]
    passwords.extend(args.password)

    samples: list[dict[str, Any]] = []
    with watch_broker_lease() as broker_metadata, BenchmarkWorkspace(
        "watch.real-file",
        results_root=args.results_root,
        keep_workdir=args.keep_workdir,
    ) as workspace:
        for _ in range(args.runs):
            samples.append(asyncio.run(_run_once(
                source,
                workspace,
                passwords=passwords,
                quiet_seconds=args.quiet_seconds,
                timeout=args.timeout,
            )))
        end_to_end = [row["timings_seconds"]["end_to_end_copy_start_to_completion"] for row in samples]
        report = {
            "watch_broker": broker_metadata,
            "parameters": {
                "source": str(source),
                "runs": args.runs,
                "quiet_seconds": args.quiet_seconds,
                "password_count": len(passwords),
                "explicit_password_count": len(args.password),
                "wrong_password_count": args.wrong_password_count,
                "timeout_seconds": args.timeout,
                "output_root_mode": "watch_root",
            },
            "samples": samples,
            "summary": {
                "median_end_to_end_seconds": statistics.median(end_to_end),
                "min_end_to_end_seconds": min(end_to_end),
                "max_end_to_end_seconds": max(end_to_end),
                "median_copy_seconds": statistics.median(
                    row["timings_seconds"]["copy"] for row in samples
                ),
                "median_pipeline_seconds": statistics.median(
                    row["timings_seconds"]["pipeline_run"] for row in samples
                ),
                "median_watch_completion_seconds": statistics.median(
                    row["timings_seconds"]["watch_completion"] for row in samples
                ),
                "successful_runs": sum(bool(row["completed"]) for row in samples),
                "terminal_statuses": [row["terminal_status"] for row in samples if row["terminal_status"]],
            },
        }
        rendered = render_report(report_from_payload("watch.real-file", report))
        workspace.write_result_text("report.json", rendered)
        print(rendered)
        if args.json_out:
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
