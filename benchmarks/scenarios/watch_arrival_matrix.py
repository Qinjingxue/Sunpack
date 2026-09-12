from __future__ import annotations

"""Compare watch arrival/move patterns and quiet-window policies."""

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
from benchmarks.scenarios.extraction_large_archive import RequestRuntimeProfiler, _timing_totals
from sunpack.config.loader import load_config
from sunpack.coordinator.engine import PipelineEngine
from sunpack.coordinator.watch_group_coordinator import WatchGroupCoordinator
from sunpack.filesystem.watcher.scheduler import WatchScheduler


DEFAULT_SOURCE = Path(__file__).resolve().parents[2] / "testfiles" / "R3961.jpg"
DEFAULT_MODES = (
    "fast_direct",
    "atomic_move",
    "slow_direct",
    "slow_rename",
    "interrupted_resume",
    "delete_reappear",
)


def _now() -> float:
    return time.perf_counter()


def _same_path(left: str | Path, right: str | Path) -> bool:
    return Path(left).resolve() == Path(right).resolve()


def _output_summary(root: Path, source_name: str) -> dict[str, Any]:
    excluded = {source_name, ".sunpack-passwords.txt", "state.json", "events.jsonl"}
    files = [
        path for path in root.rglob("*")
        if path.is_file()
        and path.name not in excluded
    ]
    return {
        "file_count": len(files),
        "total_bytes": sum(path.stat().st_size for path in files),
    }


def _install_instrumentation(
    watcher: WatchScheduler,
    destination: Path,
    timings: dict[str, Any],
    attempts: list[dict[str, Any]],
) -> None:
    original_enqueue = watcher.enqueue

    def enqueue(self, path: str, *args: Any, **kwargs: Any):
        event_type = str(kwargs.get("event_type") or "unknown")
        timings.setdefault("enqueue_events", []).append({
            "at": _now(),
            "path": str(path),
            "name": Path(path).name,
            "event_type": event_type,
            "is_destination": _same_path(path, destination),
        })
        if _same_path(path, destination):
            timings.setdefault("destination_enqueue_times", []).append(_now())
        return original_enqueue(path, *args, **kwargs)

    watcher.enqueue = types.MethodType(enqueue, watcher)

    original_submit = watcher._submit_candidate

    async def submit(self, candidate, *, group=None):
        attempt = {
            "candidate": str(candidate.path),
            "candidate_name": Path(candidate.path).name,
            "processing_started": _now(),
        }
        attempts.append(attempt)
        return await original_submit(candidate, group=group)

    watcher._submit_candidate = types.MethodType(submit, watcher)

    original_complete = watcher._complete_candidate

    async def complete(self, request):
        started = _now()
        try:
            result = await original_complete(request)
            return result
        finally:
            entry = None
            for path, current in watcher.state.entries.items():
                if _same_path(path, request.candidate.path):
                    entry = current
                    break
            attempts.append({
                "candidate": str(request.candidate.path),
                "candidate_name": Path(request.candidate.path).name,
                "completion_started": started,
                "completion_finished": _now(),
                "state_status": getattr(entry, "status", "") if entry is not None else "done_or_cleared",
            })

    watcher._complete_candidate = types.MethodType(complete, watcher)

async def _pump(watcher: WatchScheduler) -> float:
    started = _now()
    await watcher.run_once()
    return _now() - started


async def _write_chunks(
    watcher: WatchScheduler,
    source: Path,
    destination: Path,
    *,
    chunk_size: int,
    delay_seconds: float,
    interrupt_after_chunks: int | None = None,
    resume: bool = False,
) -> bool:
    existing_size = destination.stat().st_size if resume and destination.exists() else 0
    mode = "ab" if existing_size else "wb"
    chunks = 0
    with source.open("rb") as reader, destination.open(mode) as writer:
        if existing_size:
            reader.seek(existing_size)
        while chunk := reader.read(chunk_size):
            writer.write(chunk)
            writer.flush()
            os.fsync(writer.fileno())
            chunks += 1
            await _pump(watcher)
            if interrupt_after_chunks is not None and chunks >= interrupt_after_chunks:
                return False
            if delay_seconds > 0:
                await asyncio.sleep(delay_seconds)
    return True


async def _arrive(
    watcher: WatchScheduler,
    source: Path,
    root: Path,
    mode: str,
    *,
    chunk_size: int,
    delay_seconds: float,
    timings: dict[str, Any],
) -> None:
    destination = root / source.name
    temp = root / f"{source.name}.downloading"
    arrival_started = _now()
    timings["arrival_mode"] = mode
    if mode == "fast_direct":
        shutil.copy2(source, destination)
    elif mode == "atomic_move":
        staging = root.parent / f"{source.name}.staging"
        shutil.copy2(source, staging)
        os.replace(staging, destination)
    elif mode == "slow_direct":
        await _write_chunks(
            watcher, source, destination,
            chunk_size=chunk_size, delay_seconds=delay_seconds,
        )
    elif mode == "slow_rename":
        await _write_chunks(
            watcher, source, temp,
            chunk_size=chunk_size, delay_seconds=delay_seconds,
        )
        os.replace(temp, destination)
    elif mode == "interrupted_resume":
        await _write_chunks(
            watcher, source, temp,
            chunk_size=chunk_size, delay_seconds=delay_seconds,
            interrupt_after_chunks=1,
        )
        timings["interruption_finished"] = _now()
        await asyncio.sleep(max(0.05, delay_seconds * 4))
        await _write_chunks(
            watcher, source, temp,
            chunk_size=chunk_size, delay_seconds=delay_seconds, resume=True,
        )
        os.replace(temp, destination)
    elif mode == "delete_reappear":
        await _write_chunks(
            watcher, source, destination,
            chunk_size=chunk_size, delay_seconds=delay_seconds,
            interrupt_after_chunks=1,
        )
        destination.unlink()
        await _pump(watcher)
        timings["partial_deleted"] = _now()
        await asyncio.sleep(max(0.05, delay_seconds * 4))
        await _write_chunks(
            watcher, source, destination,
            chunk_size=chunk_size, delay_seconds=delay_seconds,
        )
    else:
        raise ValueError(f"unknown arrival mode: {mode}")
    timings["arrival_finished"] = _now()
    timings["arrival_seconds"] = timings["arrival_finished"] - arrival_started
    await _pump(watcher)


async def _wait_for_completion(
    watcher: WatchScheduler,
    timings: dict[str, Any],
    *,
    timeout_seconds: float,
    tick_seconds: list[float],
) -> None:
    deadline = _now() + timeout_seconds
    while _now() < deadline:
        tick_seconds.append(await _pump(watcher))
        if any(
            row.get("state_status") in {"done_or_cleared", "done"}
            for row in timings.get("attempts", [])
        ) and watcher.pending_count == 0 and not watcher._inflight_requests:
            return
        delay = watcher.next_delay_seconds()
        await asyncio.sleep(0.01 if delay is None else min(max(delay, 0.001), 0.05))
    raise TimeoutError(
        f"watch did not complete output in {timeout_seconds:g}s; "
        f"pending={watcher.pending_count}"
    )


async def _run_case(
    source: Path,
    workspace: BenchmarkWorkspace,
    *,
    label: str,
    mode: str,
    quiet_seconds: float,
    passwords: list[str],
    chunk_size: int,
    delay_seconds: float,
    timeout_seconds: float,
) -> dict[str, Any]:
    root = workspace.work / label / "watch"
    root.mkdir(parents=True, exist_ok=True)
    destination = root / source.name
    state_path = workspace.work / label / "state.json"
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
    watcher: WatchScheduler | None = None
    timings: dict[str, Any] = {"case_started": _now()}
    attempts: list[dict[str, Any]] = []
    timings["attempts"] = attempts
    tick_seconds: list[float] = []
    try:
        await engine.__aenter__()
        watcher = WatchScheduler(
            config,
            [str(root)],
            out_dir=".",
            state_path=str(state_path),
            quiet_seconds=quiet_seconds,
            initial_scan=False,
            pipeline_engine=engine,
            group_coordinator=WatchGroupCoordinator(config),
        )
        _install_instrumentation(watcher, destination, timings, attempts)
        await watcher.start()
        await _arrive(
            watcher, source, root, mode,
            chunk_size=chunk_size, delay_seconds=delay_seconds, timings=timings,
        )
        await _wait_for_completion(
            watcher, timings, timeout_seconds=timeout_seconds, tick_seconds=tick_seconds,
        )
        timings["case_finished"] = _now()
        pipeline_by_request = [_timing_totals(row) for row in profiler.request_timings]
        pipeline_total = sum(row.get("pipeline_run", 0.0) for row in pipeline_by_request)
        first_processing = next(
            (row["processing_started"] for row in attempts if "processing_started" in row),
            None,
        )
        completed_attempts = [
            row for row in attempts
            if row.get("state_status") in {"done_or_cleared", "done"}
        ]
        failed_attempts = [
            row for row in attempts
            if row.get("state_status") not in {None, "", "done_or_cleared", "done"}
        ]
        return {
            "mode": mode,
            "quiet_seconds_argument": quiet_seconds,
            "cold_start_seconds": quiet_seconds,
            "configured_quiet_min_seconds": float(config["watch"].get("quiet_min_seconds", 1.25)),
            "source_bytes": source.stat().st_size,
            "timings_seconds": {
                "arrival": timings["arrival_seconds"],
                "arrival_to_first_processing": (
                    first_processing - timings["arrival_finished"]
                    if first_processing is not None else None
                ),
                "pipeline_total_all_attempts": pipeline_total,
                "arrival_start_to_completion": timings["case_finished"] - timings["case_started"],
                "post_arrival_to_completion": timings["case_finished"] - timings["arrival_finished"],
            },
            "attempt_count": len(profiler.request_timings),
            "completed_attempt_count": len(completed_attempts),
            "failed_or_terminal_attempt_count": len(failed_attempts),
            "attempts": attempts,
            "pipeline_seconds_by_request": pipeline_by_request,
            "enqueue_event_count": len(timings.get("enqueue_events", [])),
            "destination_enqueue_count": len(timings.get("destination_enqueue_times", [])),
            "tick_seconds": {
                "count": len(tick_seconds),
                "total": sum(tick_seconds),
                "max": max(tick_seconds) if tick_seconds else 0.0,
            },
            "output": _output_summary(root, source.name),
            "success": bool(completed_attempts),
            "interruption_used": "interruption_finished" in timings,
            "partial_deleted": "partial_deleted" in timings,
        }
    finally:
        if watcher is not None:
            await watcher.stop()
        profiler.restore()
        await engine.aclose(graceful=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Watch arrival and quiet-window matrix benchmark.")
    parser.add_argument("source", nargs="?", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--modes", default=",".join(DEFAULT_MODES))
    parser.add_argument("--quiet-values", default="0,1.25")
    parser.add_argument("--runs", type=int, default=1)
    parser.add_argument("--wrong-password-count", type=int, default=100)
    parser.add_argument("--password", action="append", default=[])
    parser.add_argument("--chunk-mib", type=float, default=16.0)
    parser.add_argument("--chunk-delay-ms", type=float, default=10.0)
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    source = args.source.resolve()
    if not source.is_file():
        parser.error(f"source file does not exist: {source}")
    if args.runs < 1 or args.wrong_password_count < 0:
        parser.error("runs must be positive and wrong-password-count nonnegative")
    modes = tuple(value.strip() for value in args.modes.split(",") if value.strip())
    unknown = sorted(set(modes) - set(DEFAULT_MODES))
    if unknown:
        parser.error(f"unknown modes: {', '.join(unknown)}")
    quiet_values = tuple(float(value.strip()) for value in args.quiet_values.split(",") if value.strip())
    passwords = [f"wrong-{index:04d}" for index in range(args.wrong_password_count)]
    passwords.extend(args.password or ["⑨"])
    chunk_size = max(1, int(args.chunk_mib * 1024 * 1024))
    delay_seconds = max(0.0, args.chunk_delay_ms / 1000.0)

    samples: list[dict[str, Any]] = []
    with watch_broker_lease() as broker_metadata, BenchmarkWorkspace("watch.arrival-matrix", results_root=args.results_root) as workspace:
        for run_index in range(args.runs):
            for quiet_index, quiet_seconds in enumerate(quiet_values):
                for mode in modes:
                    label = f"run-{run_index}-quiet-{quiet_index}-{mode}"
                    samples.append(asyncio.run(_run_case(
                        source,
                        workspace,
                        label=label,
                        mode=mode,
                        quiet_seconds=quiet_seconds,
                        passwords=passwords,
                        chunk_size=chunk_size,
                        delay_seconds=delay_seconds,
                        timeout_seconds=args.timeout,
                    )))
        grouped: dict[str, dict[str, list[float]]] = {}
        for sample in samples:
            group = grouped.setdefault(sample["mode"], {})
            key = str(sample["quiet_seconds_argument"])
            group.setdefault(key, []).append(sample["timings_seconds"]["arrival_start_to_completion"])
        summary = {
            mode: {
                quiet: {
                    "runs": len(values),
                    "median_total_seconds": statistics.median(values),
                    "min_total_seconds": min(values),
                    "max_total_seconds": max(values),
                    "successful_runs": sum(
                        1 for sample in samples
                        if sample["mode"] == mode
                        and str(sample["quiet_seconds_argument"]) == quiet
                        and sample["success"]
                    ),
                    "median_attempt_count": statistics.median(
                        sample["attempt_count"]
                        for sample in samples
                        if sample["mode"] == mode
                        and str(sample["quiet_seconds_argument"]) == quiet
                    ),
                }
                for quiet, values in quiet_groups.items()
            }
            for mode, quiet_groups in grouped.items()
        }
        report = {
            "watch_broker": broker_metadata,
            "parameters": {
                "source": str(source),
                "modes": list(modes),
                "quiet_values": list(quiet_values),
                "runs": args.runs,
                "password_count": len(passwords),
                "wrong_password_count": args.wrong_password_count,
                "chunk_mib": args.chunk_mib,
                "chunk_delay_ms": args.chunk_delay_ms,
            },
            "samples": samples,
            "summary": summary,
        }
        rendered = render_report(report_from_payload("watch.arrival-matrix", report))
        workspace.write_result_text("report.json", rendered)
        print(rendered)
        if args.json_out:
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
