from __future__ import annotations

"""Benchmark split-volume watch arrival order and quiet-window policies."""

import argparse
import asyncio
import hashlib
import json
import os
import random
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


TESTFILES_ROOT = Path(__file__).resolve().parents[2] / "testfiles"
DEFAULT_SOURCE_NAMES = (
    "【びよびよ研究室】 アリス＆ケイ びよびよ 【元データ PSDファイル 】.7z.001",
    "【びよびよ研究室】 アリス＆ケイ びよびよ 【元データ PSDファイル 】.7z.002",
    "【びよびよ研究室】 アリス＆ケイ びよびよ 【元データ PSDファイル 】.7z.003",
    "【びよびよ研究室】 アリス＆ケイ びよびよ 【元データ PSDファイル 】.7z.004",
)
DEFAULT_MODES = (
    "shuffle_rename",
    "shuffle_direct",
    "interleaved_rename",
    "interleaved_direct",
    "head_first_rename",
)


def _now() -> float:
    return time.perf_counter()


def _source_sort_key(path: Path) -> tuple[str, int]:
    suffix = path.name.rsplit(".7z.", 1)[-1]
    return path.name[: -len(suffix)], int(suffix) if suffix.isdigit() else 0


def _arrival_order(sources: list[Path], policy: str) -> list[Path]:
    ordered = sorted(sources, key=_source_sort_key)
    head = next((path for path in ordered if path.name.casefold().endswith(".7z.001")), None)
    if head is None:
        raise ValueError("split sources must include a .7z.001 head volume")
    other = [path for path in ordered if path != head]
    random.Random(0x5EED).shuffle(other)
    if policy == "non_head_then_head":
        return [*other, head]
    if policy == "head_first":
        return [head, *other]
    raise ValueError(f"unknown split arrival policy: {policy}")


def _manifest(root: Path, source_names: set[str]) -> list[dict[str, Any]]:
    excluded = source_names | {"state.json", "events.jsonl", ".sunpack-passwords.txt"}
    rows: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name in excluded:
            continue
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        rows.append({
            "path": path.relative_to(root).as_posix(),
            "bytes": path.stat().st_size,
            "sha256": digest.hexdigest(),
        })
    return rows


def _install_instrumentation(
    watcher: WatchScheduler,
    source_names: set[str],
    timings: dict[str, Any],
    attempts: list[dict[str, Any]],
) -> None:
    original_enqueue = watcher.enqueue

    def enqueue(self, path: str, *args: Any, **kwargs: Any):
        name = Path(path).name
        timings.setdefault("enqueue_events", []).append({
            "at": _now(),
            "path": str(path),
            "name": name,
            "event_type": str(kwargs.get("event_type") or "unknown"),
            "is_source_volume": name in source_names,
        })
        return original_enqueue(path, *args, **kwargs)

    watcher.enqueue = types.MethodType(enqueue, watcher)

    original_submit = watcher._submit_candidate

    async def submit(self, candidate, *, group=None):
        attempts.append({
            "candidate": str(candidate.path),
            "candidate_name": Path(candidate.path).name,
            "processing_started": _now(),
        })
        return await original_submit(candidate, group=group)

    watcher._submit_candidate = types.MethodType(submit, watcher)

    original_complete = watcher._complete_candidate

    async def complete(self, request):
        started = _now()
        try:
            return await original_complete(request)
        finally:
            entry = None
            for path, current in watcher.state.entries.items():
                if os.path.normcase(os.path.abspath(path)) == os.path.normcase(os.path.abspath(request.candidate.path)):
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


async def _write_volume(
    watcher: WatchScheduler,
    source: Path,
    destination: Path,
    *,
    chunk_size: int,
    delay_seconds: float,
    event_type: str,
) -> None:
    with source.open("rb") as reader, destination.open("wb") as writer:
        while chunk := reader.read(chunk_size):
            writer.write(chunk)
            writer.flush()
            os.fsync(writer.fileno())
            watcher.enqueue(str(destination), event_type="modified")
            await _pump(watcher)
            if delay_seconds > 0:
                await asyncio.sleep(delay_seconds)
    watcher.enqueue(str(destination), event_type=event_type)
    await _pump(watcher)


async def _arrive_one_by_one(
    watcher: WatchScheduler,
    order: list[Path],
    root: Path,
    *,
    rename: bool,
    chunk_size: int,
    delay_seconds: float,
    timings: dict[str, Any],
) -> None:
    for source in order:
        destination = root / source.name
        target = root / f"{source.name}.downloading" if rename else destination
        await _write_volume(
            watcher, source, target,
            chunk_size=chunk_size,
            delay_seconds=delay_seconds,
            event_type="moved" if rename else "modified",
        )
        if rename:
            os.replace(target, destination)
            watcher.notify_path_departed(str(target))
            watcher.enqueue(str(destination), event_type="moved", src_path=str(target))
            await _pump(watcher)
        timings.setdefault("volume_arrivals", []).append({
            "name": source.name,
            "finished": _now(),
        })


async def _arrive_interleaved(
    watcher: WatchScheduler,
    order: list[Path],
    root: Path,
    *,
    rename: bool,
    chunk_size: int,
    delay_seconds: float,
    timings: dict[str, Any],
) -> None:
    states = []
    for source in order:
        destination = root / source.name
        target = root / f"{source.name}.downloading" if rename else destination
        states.append({
            "source": source,
            "destination": destination,
            "target": target,
            "reader": source.open("rb"),
            "writer": target.open("wb"),
        })
    try:
        active = list(states)
        while active:
            for state in list(active):
                chunk = state["reader"].read(chunk_size)
                if chunk:
                    state["writer"].write(chunk)
                    state["writer"].flush()
                    os.fsync(state["writer"].fileno())
                    watcher.enqueue(str(state["target"]), event_type="modified")
                    await _pump(watcher)
                    if delay_seconds > 0:
                        await asyncio.sleep(delay_seconds)
                    continue
                state["writer"].close()
                state["reader"].close()
                if rename:
                    os.replace(state["target"], state["destination"])
                    watcher.notify_path_departed(str(state["target"]))
                    watcher.enqueue(
                        str(state["destination"]),
                        event_type="moved",
                        src_path=str(state["target"]),
                    )
                else:
                    watcher.enqueue(str(state["destination"]), event_type="modified")
                await _pump(watcher)
                timings.setdefault("volume_arrivals", []).append({
                    "name": state["source"].name,
                    "finished": _now(),
                })
                active.remove(state)
    finally:
        for state in states:
            for key in ("reader", "writer"):
                handle = state[key]
                if not handle.closed:
                    handle.close()


async def _arrive(
    watcher: WatchScheduler,
    sources: list[Path],
    root: Path,
    mode: str,
    *,
    chunk_size: int,
    delay_seconds: float,
    timings: dict[str, Any],
) -> None:
    policy = "head_first" if mode == "head_first_rename" else "non_head_then_head"
    order = _arrival_order(sources, policy)
    timings["arrival_order"] = [path.name for path in order]
    started = _now()
    if mode == "shuffle_rename":
        await _arrive_one_by_one(
            watcher, order, root, rename=True,
            chunk_size=chunk_size, delay_seconds=delay_seconds, timings=timings,
        )
    elif mode == "shuffle_direct":
        await _arrive_one_by_one(
            watcher, order, root, rename=False,
            chunk_size=chunk_size, delay_seconds=delay_seconds, timings=timings,
        )
    elif mode == "interleaved_rename":
        await _arrive_interleaved(
            watcher, order, root, rename=True,
            chunk_size=chunk_size, delay_seconds=delay_seconds, timings=timings,
        )
    elif mode == "interleaved_direct":
        await _arrive_interleaved(
            watcher, order, root, rename=False,
            chunk_size=chunk_size, delay_seconds=delay_seconds, timings=timings,
        )
    elif mode == "head_first_rename":
        await _arrive_one_by_one(
            watcher, order, root, rename=True,
            chunk_size=chunk_size, delay_seconds=delay_seconds, timings=timings,
        )
    else:
        raise ValueError(f"unknown split arrival mode: {mode}")
    timings["arrival_finished"] = _now()
    timings["arrival_seconds"] = timings["arrival_finished"] - started
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
        f"split watch did not complete in {timeout_seconds:g}s; "
        f"pending={watcher.pending_count}, inflight={len(watcher._inflight_requests)}"
    )


async def _run_case(
    sources: list[Path],
    workspace: BenchmarkWorkspace,
    *,
    run_index: int,
    label: str,
    mode: str,
    quiet_seconds: float,
    chunk_size: int,
    delay_seconds: float,
    timeout_seconds: float,
) -> dict[str, Any]:
    root = workspace.work / label / "watch"
    root.mkdir(parents=True, exist_ok=True)
    source_names = {path.name for path in sources}
    state_path = workspace.work / label / "state.json"
    config = load_config()
    config["cli"] = {**(config.get("cli") or {}), "quiet": True, "verbose": False}
    config["watch"] = {
        **(config.get("watch") or {}),
        "clipboard_monitor_enabled": False,
        "initial_scan": False,
        "runtime_cache_cleanup_enabled": False,
    }
    config["user_passwords"] = []
    config["builtin_passwords"] = []
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
        _install_instrumentation(watcher, source_names, timings, attempts)
        await watcher.start()
        await _arrive(
            watcher, sources, root, mode,
            chunk_size=chunk_size, delay_seconds=delay_seconds, timings=timings,
        )
        first_processing = None
        await _wait_for_completion(
            watcher, timings, timeout_seconds=timeout_seconds, tick_seconds=tick_seconds,
        )
        for row in attempts:
            if "processing_started" in row:
                first_processing = row["processing_started"]
                break
        timings["case_finished"] = _now()
        pipeline_by_request = [_timing_totals(row) for row in profiler.request_timings]
        pipeline_total = sum(row.get("pipeline_run", 0.0) for row in pipeline_by_request)
        manifest = _manifest(root, source_names)
        completed_attempts = [
            row for row in attempts
            if row.get("state_status") in {"done_or_cleared", "done"}
        ]
        failed_attempts = [
            row for row in attempts
            if row.get("state_status") not in {None, "", "done_or_cleared", "done"}
        ]
        manifest_json = json.dumps(manifest, ensure_ascii=False, sort_keys=True).encode("utf-8")
        return {
            "run_index": run_index,
            "mode": mode,
            "quiet_seconds_argument": quiet_seconds,
            "cold_start_seconds": quiet_seconds,
            "configured_quiet_min_seconds": float(config["watch"].get("quiet_min_seconds", 1.25)),
            "sources": [{"name": path.name, "bytes": path.stat().st_size} for path in sources],
            "arrival_order": timings.get("arrival_order", []),
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
            "volume_arrival_count": len(timings.get("volume_arrivals", [])),
            "tick_seconds": {
                "count": len(tick_seconds),
                "total": sum(tick_seconds),
                "max": max(tick_seconds) if tick_seconds else 0.0,
            },
            "output": {
                "file_count": len(manifest),
                "total_bytes": sum(row["bytes"] for row in manifest),
                "manifest": manifest,
                "manifest_sha256": hashlib.sha256(manifest_json).hexdigest(),
            },
            "success": bool(completed_attempts and manifest),
        }
    finally:
        if watcher is not None:
            await watcher.stop()
        profiler.restore()
        await engine.aclose(graceful=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Watch split-volume arrival and quiet-window benchmark.")
    parser.add_argument("sources", nargs="*", type=Path)
    parser.add_argument("--modes", default=",".join(DEFAULT_MODES))
    parser.add_argument("--quiet-values", default="0,1.25")
    parser.add_argument("--runs", type=int, default=1)
    parser.add_argument("--chunk-mib", type=float, default=4.0)
    parser.add_argument("--chunk-delay-ms", type=float, default=50.0)
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    sources = [
        path.resolve()
        for path in (args.sources or [TESTFILES_ROOT / name for name in DEFAULT_SOURCE_NAMES])
    ]
    missing = [str(path) for path in sources if not path.is_file()]
    if missing:
        parser.error(f"source files do not exist: {', '.join(missing)}")
    if len(sources) < 2 or args.runs < 1:
        parser.error("at least two split sources and positive runs are required")
    modes = tuple(value.strip() for value in args.modes.split(",") if value.strip())
    unknown = sorted(set(modes) - set(DEFAULT_MODES))
    if unknown:
        parser.error(f"unknown modes: {', '.join(unknown)}")
    quiet_values = tuple(float(value.strip()) for value in args.quiet_values.split(",") if value.strip())
    chunk_size = max(1, int(args.chunk_mib * 1024 * 1024))
    delay_seconds = max(0.0, args.chunk_delay_ms / 1000.0)

    samples: list[dict[str, Any]] = []
    with watch_broker_lease() as broker_metadata, BenchmarkWorkspace("watch.split-arrival", results_root=args.results_root) as workspace:
        for run_index in range(args.runs):
            for quiet_index, quiet_seconds in enumerate(quiet_values):
                for mode in modes:
                    label = f"run-{run_index}-quiet-{quiet_index}-{mode}"
                    samples.append(asyncio.run(_run_case(
                        sources, workspace,
                        run_index=run_index,
                        label=label,
                        mode=mode,
                        quiet_seconds=quiet_seconds,
                        chunk_size=chunk_size,
                        delay_seconds=delay_seconds,
                        timeout_seconds=args.timeout,
                    )))

        grouped: dict[str, dict[str, list[dict[str, Any]]]] = {}
        for sample in samples:
            grouped.setdefault(sample["mode"], {}).setdefault(
                str(sample["quiet_seconds_argument"]), []
            ).append(sample)
        for mode_samples in grouped.values():
            for quiet_samples in mode_samples.values():
                quiet_samples.sort(key=lambda sample: sample["timings_seconds"]["arrival_start_to_completion"])
        comparisons: list[dict[str, Any]] = []
        for mode in modes:
            for run_index in range(args.runs):
                q0 = next((sample for sample in samples if sample["run_index"] == run_index and sample["mode"] == mode and sample["quiet_seconds_argument"] == 0.0), None)
                q125 = next((sample for sample in samples if sample["run_index"] == run_index and sample["mode"] == mode and sample["quiet_seconds_argument"] == 1.25), None)
                if q0 is not None and q125 is not None:
                    equal = q0["output"]["manifest_sha256"] == q125["output"]["manifest_sha256"]
                    q0["correctness_matches_quiet_1_25"] = equal
                    q125["correctness_matches_quiet_1_25"] = equal
                    comparisons.append({"mode": mode, "run": run_index, "manifest_equal": equal})
        summary = {
            mode: {
                quiet: {
                    "runs": len(rows),
                    "median_total_seconds": statistics.median(row["timings_seconds"]["arrival_start_to_completion"] for row in rows),
                    "min_total_seconds": min(row["timings_seconds"]["arrival_start_to_completion"] for row in rows),
                    "max_total_seconds": max(row["timings_seconds"]["arrival_start_to_completion"] for row in rows),
                    "successful_runs": sum(1 for row in rows if row["success"]),
                    "median_attempt_count": statistics.median(row["attempt_count"] for row in rows),
                    "median_failed_or_terminal_attempt_count": statistics.median(row["failed_or_terminal_attempt_count"] for row in rows),
                }
                for quiet, rows in quiet_groups.items()
            }
            for mode, quiet_groups in grouped.items()
        }
        report = {
            "watch_broker": broker_metadata,
            "parameters": {
                "sources": [str(path) for path in sources],
                "modes": list(modes),
                "quiet_values": list(quiet_values),
                "runs": args.runs,
                "password_count": 0,
                "chunk_mib": args.chunk_mib,
                "chunk_delay_ms": args.chunk_delay_ms,
            },
            "samples": samples,
            "summary": summary,
            "correctness_comparisons": comparisons,
        }
        rendered = render_report(report_from_payload("watch.split-arrival", report))
        workspace.write_result_text("report.json", rendered)
        print(rendered)
        if args.json_out:
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
