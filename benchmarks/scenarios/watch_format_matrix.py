from __future__ import annotations

"""Watch-mode format matrix: internal per-stage latency for every archive format.

Formats come from the shared extraction format-matrix corpus builder, so ZIP,
7z, split 7z, RAR, split RAR, TAR, gzip, bzip2, xz, zstd and the compressed-TAR
aliases all arrive through the production watch path (``WatchScheduler`` ->
``PipelineEngine``).  Each case is dropped into its own watched directory and the
internal stages of every submitted request are recorded with the same
``RequestRuntimeProfiler`` that ``extraction large-archive-profile`` uses, so the
per-format numbers here are directly comparable with the CLI profile.

Variants reproduce the input shapes the project must handle:

``plain``       the archive arrives under its own name;
``disguised``   the same bytes arrive behind a ``.jpg`` extension;
``carrier``     ``[garbage][archive][garbage]`` with a disguised extension;
``encrypted``   a regenerated archive with real encryption and password
                candidates (wrong candidates first, so password resolution is
                measured rather than skipped);
``nested``      an archive that contains another archive, so the recursive pass
                runs inside the same watch request.

Split formats (``7z-split``, ``rar-split``) only run ``plain`` because renaming
or re-wrapping individual volumes changes the volume chain itself.
"""

import argparse
import asyncio
import os
import random
import shutil
import statistics
import sys
import time
import types
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from benchmarks.harness import BenchmarkWorkspace, PhaseReporter, render_report, report_from_payload
from benchmarks.watch_broker import watch_broker_lease
from benchmarks.scenarios.extraction_format_matrix import (
    DEFAULT_CACHE_ROOT,
    GENERATED_FORMATS,
    MIN_SCANNABLE_ARCHIVE_BYTES,
    _cached_corpus,
    _run_7z,
    _run_rar,
)
from benchmarks.scenarios.extraction_large_archive import RequestRuntimeProfiler, _timing_totals
from sunpack.config.loader import load_config
from sunpack.coordinator.engine import PipelineEngine
from sunpack.coordinator.watch_group_coordinator import WatchGroupCoordinator
from sunpack.filesystem.watcher.scheduler import WatchScheduler


SCENARIO = "watch.format-matrix"
SPLIT_FORMATS = frozenset({"7z-split", "rar-split"})
ALL_VARIANTS = ("plain", "disguised", "carrier", "encrypted", "nested")
VARIANT_HELP = {
    "plain": "archive under its own name (split volume sets arrive head first)",
    "disguised": "same bytes behind a .jpg extension",
    "carrier": "[garbage][archive][garbage] behind a .jpg extension",
    "encrypted": "regenerated encrypted archive with wrong passwords first",
    "nested": "archive containing another archive (recursive pass in one request)",
}
DEFAULT_VARIANTS = ("plain", "disguised", "carrier")
ENCRYPTABLE_FORMATS = ("zip", "7z", "rar")
PASSWORD = "watch-matrix-secret"
WRONG_PASSWORDS = ("watch-matrix-wrong-0001", "watch-matrix-wrong-0002")
CARRIER_PREFIX_BYTES = 512 * 1024
CARRIER_SUFFIX_BYTES = 256 * 1024
# Durable watch-state statuses that mean the candidate is waiting for a new
# password source or a missing volume instead of finishing on its own.
BLOCKED_STATUSES = frozenset({"failed_password", "suspended_missing_volume"})
DEFAULT_WORKLOADS = ("many_small",)

# The watch stages this scenario reports by name.  Everything the profiler
# records is kept in ``stage_seconds``; these are the columns that make the
# per-format table readable.
HEADLINE_STAGES = (
    "pipeline_run",
    "pipeline_runtime_create",
    "pipeline_runtime_execute",
    "pipeline_nested_scan",
    "pipeline_direct_scan",
    "input_planning",
    "pipeline_plan_task_isolated",
    "batch_execute",
    "extract_total",
    "sevenzip_worker",
    "verify_total",
    "output_scan",
    "pipeline_final_report",
)


def _now() -> float:
    return time.perf_counter()


def _path_key(value: str | Path) -> str:
    return os.path.normcase(os.path.abspath(str(value)))


def _volume_sort_key(path: Path) -> tuple[str, int]:
    name = path.name
    if ".part" in name:
        head, _, tail = name.rpartition(".part")
        return head, int(tail.split(".", 1)[0]) if tail.split(".", 1)[0].isdigit() else 0
    head, _, tail = name.rpartition(".")
    return head, int(tail) if tail.isdigit() else 0


def _volume_files(path: Path, archive_format: str) -> list[Path]:
    if archive_format == "7z-split":
        head = path.name.rsplit(".", 1)[0]
        return sorted(path.parent.glob(f"{head}.*"), key=_volume_sort_key)
    if archive_format == "rar-split":
        prefix = path.name.split(".part", 1)[0]
        return sorted(path.parent.glob(f"{prefix}.part*.rar"), key=_volume_sort_key)
    return [path]


@dataclass(frozen=True)
class WatchFeed:
    """One watch case: the files that arrive plus the config they arrive with."""

    key: str
    workload: str
    archive_format: str
    variant: str
    files: tuple[Path, ...]
    passwords: tuple[str, ...] = ()
    note: str = ""
    flatten: bool = True

    @property
    def total_bytes(self) -> int:
        return sum(path.stat().st_size for path in self.files)


@dataclass
class CaseBuild:
    feeds: list[WatchFeed] = field(default_factory=list)
    skipped: dict[str, str] = field(default_factory=dict)


def _write_carrier(target: Path, source: Path, prefix_bytes: int, suffix_bytes: int) -> None:
    rng = random.Random(0xC0FFEE)
    with target.open("wb") as sink:
        sink.write(rng.randbytes(prefix_bytes))
        with source.open("rb") as stream:
            shutil.copyfileobj(stream, sink, 1024 * 1024)
        sink.write(rng.randbytes(suffix_bytes))


def _build_encrypted(item: dict[str, Any], key: str, build_root: Path, payload_root: Path) -> Path | None:
    archive_format = item["format"]
    source = payload_root / ("many-small" if item["workload"] == "many_small" else "few-large")
    if not source.is_dir():
        return None
    if archive_format == "7z":
        # Header encryption hides entry names as well, so the password has to be
        # resolved before the archive can even be listed.
        target = build_root / f"{key}-encrypted.7z"
        created = _run_7z(["a", "-y", "-t7z", f"-p{PASSWORD}", "-mhe=on", str(target), str(source)])
    elif archive_format == "zip":
        target = build_root / f"{key}-encrypted.zip"
        created = _run_7z(["a", "-y", "-tzip", f"-p{PASSWORD}", str(target), str(source)])
    elif archive_format == "rar":
        target = build_root / f"{key}-encrypted.rar"
        created = _run_rar(["a", "-idq", "-r", "-ep1", f"-p{PASSWORD}", str(target), str(source)])
    else:
        return None
    return target if created and target.is_file() else None


def _build_nested(item: dict[str, Any], key: str, build_root: Path) -> Path | None:
    inner = Path(item["path"])
    stage = build_root / f"{key}-inner"
    stage.mkdir(parents=True, exist_ok=True)
    inner_copy = stage / inner.name
    shutil.copy2(inner, inner_copy)
    target = build_root / f"{key}-nested.zip"
    if _run_7z(["a", "-y", "-tzip", str(target), str(inner_copy)]) and target.is_file():
        return target
    return None


def _build_feed(
    item: dict[str, Any],
    variant: str,
    build_root: Path,
    payload_root: Path,
) -> tuple[WatchFeed | None, str]:
    workload = str(item["workload"])
    archive_format = str(item["format"])
    key = f"{workload}-{archive_format}"
    display_key = f"{workload}:{archive_format}:{variant}"
    members = _volume_files(Path(item["path"]), archive_format)
    if not members:
        return None, "no archive members were generated"

    if variant == "plain":
        return WatchFeed(display_key, workload, archive_format, variant, tuple(members)), ""

    if archive_format in SPLIT_FORMATS:
        return None, f"{archive_format} volumes cannot be re-wrapped without changing the volume chain"

    source = members[0]
    if variant == "disguised":
        target = build_root / f"{key}-disguised.jpg"
        shutil.copy2(source, target)
    elif variant == "carrier":
        target = build_root / f"{key}-carrier.jpg"
        _write_carrier(target, source, CARRIER_PREFIX_BYTES, CARRIER_SUFFIX_BYTES)
    elif variant == "encrypted":
        if archive_format not in ENCRYPTABLE_FORMATS:
            return None, f"{archive_format} cannot be created encrypted by the bundled tools"
        target = _build_encrypted(item, key, build_root, payload_root)
        if target is None:
            return None, "bundled tools could not create the encrypted archive"
    elif variant == "nested":
        target = _build_nested(item, key, build_root)
        if target is None:
            return None, "bundled 7-Zip could not create the nested archive"
    else:
        return None, f"unknown variant {variant!r}"

    if target.stat().st_size < MIN_SCANNABLE_ARCHIVE_BYTES:
        return None, (
            f"{target.name} is {target.stat().st_size}B, below the "
            f"{MIN_SCANNABLE_ARCHIVE_BYTES}B recognition floor"
        )
    passwords = (*WRONG_PASSWORDS, PASSWORD) if variant == "encrypted" else ()
    return WatchFeed(display_key, workload, archive_format, variant, (target,), passwords), ""


def _build_feeds(
    corpus: dict[str, dict[str, Any]],
    *,
    workspace: BenchmarkWorkspace,
    workloads: tuple[str, ...],
    formats: tuple[str, ...],
    variants: tuple[str, ...],
    flatten_modes: tuple[bool, ...] = (True,),
) -> CaseBuild:
    build_root = workspace.work / "variants"
    build_root.mkdir(parents=True, exist_ok=True)
    payload_root = workspace.corpus / "payloads"
    build = CaseBuild()
    for key, item in sorted(corpus.items()):
        if item["workload"] not in workloads or item["format"] not in formats:
            continue
        for variant in variants:
            feed, reason = _build_feed(item, variant, build_root, payload_root)
            if feed is None:
                build.skipped[f"{item['workload']}:{item['format']}:{variant}"] = reason
                continue
            for flatten in flatten_modes:
                build.feeds.append(
                    replace(
                        feed,
                        key=f"{feed.key}:flatten-{'on' if flatten else 'off'}",
                        flatten=flatten,
                    )
                )
    return build


def _install_watch_instrumentation(
    watcher: WatchScheduler,
    fed_keys: set[str],
    timings: dict[str, Any],
    attempts: list[dict[str, Any]],
) -> None:
    original_enqueue = watcher.enqueue

    def enqueue(self, path: str, *args: Any, **kwargs: Any):
        if _path_key(path) in fed_keys:
            timings.setdefault("enqueue_events", []).append({
                "at": _now(),
                "path": str(path),
                "event_type": str(kwargs.get("event_type") or "unknown"),
            })
        return original_enqueue(path, *args, **kwargs)

    watcher.enqueue = types.MethodType(enqueue, watcher)

    original_submit = watcher._submit_candidate

    async def submit(self, candidate, *, group=None):
        attempt = {
            "candidate": str(candidate.path),
            "candidate_name": Path(candidate.path).name,
            "processing_started": _now(),
            "input_paths": list(group.input_paths) if group is not None else [str(candidate.path)],
        }
        attempts.append(attempt)
        return await original_submit(candidate, group=group)

    watcher._submit_candidate = types.MethodType(submit, watcher)

    original_complete = watcher._complete_candidate

    async def complete(self, request):
        started = _now()
        try:
            result = await original_complete(request)
        finally:
            response = None
            task = request.task
            if task.done() and not task.cancelled():
                try:
                    response = task.result()
                except BaseException:
                    response = None
            for attempt in reversed(attempts):
                if attempt.get("candidate") == str(request.candidate.path) and "completion_started" not in attempt:
                    attempt.update({
                        "completion_started": started,
                        "completion_finished": _now(),
                        "reply": _attempt_outcome(response),
                    })
                    break
        return result

    watcher._complete_candidate = types.MethodType(complete, watcher)


def _attempt_outcome(response: Any) -> dict[str, Any]:
    summary = getattr(response, "summary", None)
    if summary is None:
        return {}
    rows = []
    for item in list(getattr(summary, "target_results", []) or []):
        outcome = getattr(item, "outcome_kind", "")
        rows.append({
            "input": str(getattr(item, "input_path", "")),
            "outcome": str(getattr(outcome, "value", outcome)),
            "output_dir": str(getattr(item, "output_dir", "")),
            "error": str(getattr(item, "error", ""))[:300],
        })
    return {
        "success_count": int(getattr(summary, "success_count", 0) or 0),
        "partial_success_count": int(getattr(summary, "partial_success_count", 0) or 0),
        "failed_task_count": len(list(getattr(summary, "failed_tasks", []) or [])),
        "target_results": rows,
    }


def _output_summary(root: Path, fed_names: set[str]) -> dict[str, Any]:
    excluded = fed_names | {"state.json", "events.jsonl", "sunpack-passwords.txt"}
    files = [
        path for path in root.rglob("*")
        if path.is_file() and path.name not in excluded
    ]
    return {
        "file_count": len(files),
        "total_bytes": sum(path.stat().st_size for path in files),
    }


def _state_statuses(watcher: WatchScheduler, fed_keys: set[str]) -> list[str]:
    rows = []
    for path, entry in watcher.state.entries.items():
        if _path_key(path) in fed_keys:
            rows.append(str(getattr(entry, "status", "") or "unknown"))
    return sorted(set(rows))


def _headline_seconds(timings: dict[str, float]) -> dict[str, float]:
    def total(label: str) -> float:
        return float(timings.get(label, 0.0))

    planning = total("input_planning")
    if planning <= 0.0:
        planning = sum(
            seconds for label, seconds in timings.items() if label.startswith("planning_")
        )
    headline = {label: round(total(label), 6) for label in HEADLINE_STAGES}
    headline.update({
        "planning_total": round(planning, 6),
        "extract_and_verify": round(total("extract_total") + total("verify_total"), 6),
        "pipeline_run_outer_residual": round(
            total("pipeline_run") - total("pipeline_runtime_create") - total("pipeline_runtime_execute"),
            6,
        ),
    })
    return headline


async def _run_case(
    feed: WatchFeed,
    workspace: BenchmarkWorkspace,
    *,
    label: str,
    cold_start_seconds: float,
    timeout_seconds: float,
) -> dict[str, Any]:
    root = workspace.work / label / "watch"
    root.mkdir(parents=True, exist_ok=True)
    state_path = workspace.work / label / "state.json"

    config = load_config()
    config["cli"] = {**(config.get("cli") or {}), "quiet": True, "verbose": False}
    config["post_extract"] = {
        **(config.get("post_extract") or {}),
        # Post-extract flattening is the dominant per-file tail of one watch
        # request, so it stays switchable for A/B measurement.
        "flatten_single_directory": bool(feed.flatten),
    }
    config["watch"] = {
        **(config.get("watch") or {}),
        "clipboard_monitor_enabled": False,
        "initial_scan": False,
        "runtime_cache_cleanup_enabled": False,
    }
    config["user_passwords"] = list(feed.passwords)
    config["output"] = {**(config.get("output") or {}), "root": str(root)}

    engine = PipelineEngine(config)
    profiler = RequestRuntimeProfiler()
    profiler.install(engine)
    profiler.enabled = True
    timings: dict[str, Any] = {"case_started": _now()}
    attempts: list[dict[str, Any]] = []
    tick_seconds: list[float] = []
    fed_keys = {_path_key(path) for path in feed.files}
    fed_names = {path.name for path in feed.files}
    watcher: WatchScheduler | None = None
    run_results: list[dict[str, Any]] = []
    try:
        engine_started = _now()
        await engine.__aenter__()
        timings["engine_ready"] = _now()
        watcher = WatchScheduler(
            config,
            [str(root)],
            # A relative dot is resolved against the watched root, so outputs
            # land in the watch directory itself, exactly like production watch.
            out_dir=".",
            state_path=str(state_path),
            cold_start_seconds=cold_start_seconds,
            initial_scan=False,
            pipeline_engine=engine,
            group_coordinator=WatchGroupCoordinator(config),
        )
        _install_watch_instrumentation(watcher, fed_keys, timings, attempts)
        await watcher.start()

        feed_started = _now()
        for source in feed.files:
            shutil.copy2(source, root / source.name)
            # Let the observer deliver each volume's event before the next one
            # lands, so a split group is coalesced by the quiet policy instead
            # of by a single blocking copy.
            await asyncio.sleep(0)
        feed_finished = _now()

        deadline = _now() + timeout_seconds
        timed_out = False
        idle_ticks = 0
        while _now() < deadline:
            tick_started = _now()
            result = await watcher.run_once()
            tick_seconds.append(_now() - tick_started)
            if result.processed or result.succeeded or result.failed or result.errors:
                run_results.append({
                    "processed": int(result.processed),
                    "succeeded": int(result.succeeded),
                    "failed": int(result.failed),
                    "errors": [str(item)[:300] for item in result.errors],
                })
            idle = watcher.pending_count == 0 and not watcher._inflight_requests
            idle_ticks = idle_ticks + 1 if idle else 0
            if idle_ticks >= 2 and any("completion_started" in row for row in attempts):
                break
            if idle_ticks >= 60 and not attempts:
                # Nothing was ever dispatched: a watch filter or the quiet policy
                # dropped every candidate.  Report it instead of burning the full
                # per-case timeout on a case that can never complete.
                break
            delay = watcher.next_delay_seconds()
            await asyncio.sleep(0.01 if delay is None else min(max(delay, 0.001), 0.05))
        else:
            timed_out = True

        finished = _now()
        statuses = _state_statuses(watcher, fed_keys)
        replies = [row["reply"] for row in attempts if row.get("reply")]
        outcomes = [
            str(item.get("outcome", ""))
            for reply in replies
            for item in reply.get("target_results", [])
        ]
        # A successful watch request clears its state entry, so the durable
        # status list is informational only; the terminal outcome comes from the
        # completed pipeline reply itself.
        final_reply = replies[-1] if replies else {}
        stage_seconds = [_timing_totals(row) for row in profiler.request_timings]
        merged: dict[str, float] = {}
        for row in stage_seconds:
            for stage, seconds in row.items():
                merged[stage] = round(merged.get(stage, 0.0) + seconds, 6)
        first_processing = next(
            (row["processing_started"] for row in attempts if "processing_started" in row),
            None,
        )
        return {
            "case": feed.key,
            "workload": feed.workload,
            "format": feed.archive_format,
            "variant": feed.variant,
            "flatten": feed.flatten,
            "source_bytes": feed.total_bytes,
            "arrival": "volume_set" if len(feed.files) > 1 else "single_file",
            "note": feed.note,
            "timings_seconds": {
                "engine_startup": timings["engine_ready"] - engine_started,
                "feed": feed_finished - feed_started,
                "feed_to_first_processing": (
                    first_processing - feed_finished if first_processing is not None else None
                ),
                "post_feed_to_completion": finished - feed_finished,
                "case_wall": finished - timings["case_started"],
            },
            "request_count": len(profiler.request_timings),
            "attempts": attempts,
            "timed_out": timed_out,
            "dispatched": bool(attempts),
            "state_statuses": statuses,
            "blocked_statuses": sorted({status for status in statuses if status in BLOCKED_STATUSES}),
            "outcomes": outcomes,
            "success_count": int(final_reply.get("success_count", 0) or 0),
            "failed_task_count": int(final_reply.get("failed_task_count", 0) or 0),
            "completed": any("completion_started" in row for row in attempts),
            "succeeded": bool(final_reply.get("success_count")) and not timed_out,
            "stage_seconds": merged,
            "stage_seconds_by_request": stage_seconds,
            "headline_seconds": _headline_seconds(merged),
            "watch_ticks": {
                "count": len(tick_seconds),
                "total": sum(tick_seconds),
                "max": max(tick_seconds) if tick_seconds else 0.0,
            },
            "run_results": run_results,
            "output": _output_summary(root, fed_names),
        }
    finally:
        if watcher is not None:
            await watcher.stop()
        profiler.restore()
        await engine.aclose(graceful=True)


def _median(values: list[float]) -> float | None:
    usable = [value for value in values if value is not None]
    return round(statistics.median(usable), 6) if usable else None


def _aggregate(samples: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for sample in samples:
        grouped.setdefault(sample["case"], []).append(sample)
    rows: dict[str, Any] = {}
    for case, runs in sorted(grouped.items()):
        stages = sorted({stage for run in runs for stage in run["stage_seconds"]})
        rows[case] = {
            "workload": runs[0]["workload"],
            "format": runs[0]["format"],
            "variant": runs[0]["variant"],
            "flatten": bool(runs[0].get("flatten", True)),
            "runs": len(runs),
            "successful_runs": sum(1 for run in runs if run["succeeded"]),
            "median_source_bytes": _median([run["source_bytes"] for run in runs]),
            "median_seconds": {
                **{
                    key: _median([run["timings_seconds"][key] for run in runs])
                    for key in (
                        "engine_startup",
                        "feed",
                        "feed_to_first_processing",
                        "post_feed_to_completion",
                        "case_wall",
                    )
                },
                "pipeline_run": _median([run["headline_seconds"]["pipeline_run"] for run in runs]),
                "input_planning": _median([run["headline_seconds"]["planning_total"] for run in runs]),
                "batch_execute": _median([run["headline_seconds"]["batch_execute"] for run in runs]),
                "extract_total": _median([run["headline_seconds"]["extract_total"] for run in runs]),
                "verify_total": _median([run["headline_seconds"]["verify_total"] for run in runs]),
                "output_scan": _median([run["headline_seconds"]["output_scan"] for run in runs]),
                "sevenzip_worker": _median([run["headline_seconds"]["sevenzip_worker"] for run in runs]),
            },
            "median_stage_seconds": {
                stage: _median([run["stage_seconds"].get(stage, 0.0) for run in runs])
                for stage in stages
            },
        }
    return rows


def _render_table(aggregates: dict[str, Any]) -> str:
    header = (
        f"{'case':<34} {'form':<9} {'flat':>4} {'e2e_s':>8} {'dispatch':>9} {'pipeline':>9} "
        f"{'plan':>8} {'batch':>8} {'extract':>8} {'verify':>8} {'scan':>8} {'worker':>8} {'ok':>4}"
    )
    lines = [header, "-" * len(header)]
    for case, row in aggregates.items():
        seconds = row["median_seconds"]
        lines.append(
            f"{case:<34} {row['variant']:<9} "
            f"{'on' if row.get('flatten', True) else 'off':>4} "
            f"{(seconds['case_wall'] or 0.0):8.3f} "
            f"{(seconds['feed_to_first_processing'] or 0.0):9.3f} "
            f"{(seconds['pipeline_run'] or 0.0):9.3f} "
            f"{(seconds['input_planning'] or 0.0):8.3f} "
            f"{(seconds['batch_execute'] or 0.0):8.3f} "
            f"{(seconds['extract_total'] or 0.0):8.3f} "
            f"{(seconds['verify_total'] or 0.0):8.3f} "
            f"{(seconds['output_scan'] or 0.0):8.3f} "
            f"{(seconds['sevenzip_worker'] or 0.0):8.3f} "
            f"{row['successful_runs']:>2}/{row['runs']:<2}"
        )
    return "\n".join(lines)


def _parse_csv(values: list[str] | None, allowed: tuple[str, ...], label: str) -> tuple[str, ...]:
    if not values:
        return allowed
    selected: list[str] = []
    for value in values:
        for item in str(value).split(","):
            name = item.strip()
            if not name:
                continue
            if name not in allowed:
                raise SystemExit(f"unknown {label} {name!r}; choose from: {', '.join(allowed)}")
            if name not in selected:
                selected.append(name)
    return tuple(selected)


def _parse_flatten_modes(values: list[str] | None) -> tuple[bool, ...]:
    modes: list[bool] = []
    for value in values or ["on"]:
        for item in str(value).split(","):
            name = item.strip().lower()
            if not name:
                continue
            if name not in {"on", "off"}:
                raise SystemExit(f"unknown flatten mode {name!r}; choose from: on, off")
            mode = name == "on"
            if mode not in modes:
                modes.append(mode)
    return tuple(modes) or (True,)


def main() -> int:
    parser = argparse.ArgumentParser(description="Watch-mode per-format internal stage matrix.")
    parser.add_argument("--formats", action="append", help=f"comma separated; default: all of {', '.join(GENERATED_FORMATS)}")
    parser.add_argument("--variants", action="append", help=f"comma separated; default: {','.join(DEFAULT_VARIANTS)}")
    parser.add_argument("--workloads", action="append", help=f"comma separated; default: {','.join(DEFAULT_WORKLOADS)}")
    parser.add_argument(
        "--flatten-modes",
        action="append",
        help="comma separated on/off; runs every case once per mode (default: on).",
    )
    parser.add_argument("--runs", type=int, default=3, help="Measured rounds per case.")
    parser.add_argument("--warmups", type=int, default=0, help="Extra rounds whose samples are marked warmup.")
    parser.add_argument("--quiet-seconds", type=float, default=1.0)
    parser.add_argument("--timeout", type=float, default=180.0, help="Per-case wall-clock limit.")
    parser.add_argument("--small-files", type=int, default=1200)
    parser.add_argument("--large-files", type=int, default=2)
    parser.add_argument("--large-file-mib", type=int, default=2)
    parser.add_argument("--cache-root", type=Path, default=DEFAULT_CACHE_ROOT)
    parser.add_argument("--no-corpus-cache", action="store_true")
    parser.add_argument("--rebuild-corpus-cache", action="store_true")
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--keep-workdir", action="store_true")
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--no-progress", action="store_true")
    args = parser.parse_args()

    formats = _parse_csv(args.formats, tuple(GENERATED_FORMATS), "format")
    variants = _parse_csv(args.variants, ALL_VARIANTS, "variant")
    workloads = _parse_csv(args.workloads, ("many_small", "few_large"), "workload")
    flatten_modes = _parse_flatten_modes(args.flatten_modes)
    if args.runs < 1:
        parser.error("--runs must be positive")
    if args.warmups < 0:
        parser.error("--warmups must be nonnegative")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")

    reporter = PhaseReporter(enabled=not args.no_progress)
    samples: list[dict[str, Any]] = []
    with watch_broker_lease() as broker_metadata, BenchmarkWorkspace(
        SCENARIO,
        results_root=args.results_root,
        keep_workdir=args.keep_workdir,
    ) as workspace:
        with reporter.phase("corpus", "loading or building the shared format corpus"):
            if args.no_corpus_cache:
                from benchmarks.scenarios.extraction_format_matrix import create_corpus

                corpus, corpus_skipped = create_corpus(
                    workspace.corpus,
                    {},
                    max(1, args.small_files),
                    max(1, args.large_files),
                    max(1, args.large_file_mib),
                    progress=reporter.note,
                )
                cache_info: dict[str, Any] = {"enabled": False, "hit": False}
            else:
                corpus, corpus_skipped, cache_info = _cached_corpus(
                    workspace.corpus,
                    cache_root=args.cache_root,
                    small_files=max(1, args.small_files),
                    large_files=max(1, args.large_files),
                    large_file_mib=max(1, args.large_file_mib),
                    rebuild=args.rebuild_corpus_cache,
                )
        with reporter.phase("variants", "building disguised, carrier, encrypted and nested inputs"):
            build = _build_feeds(
                corpus,
                workspace=workspace,
                workloads=workloads,
                formats=formats,
                variants=variants,
                flatten_modes=flatten_modes,
            )
        if not build.feeds:
            raise SystemExit("no watch cases were generated; check --formats/--variants/--workloads")
        reporter.note(
            f"watch matrix: {len(build.feeds)} cases, "
            f"{len(build.skipped)} skipped variants, {args.warmups + args.runs} rounds"
        )

        rounds = args.warmups + args.runs
        for round_index in range(rounds):
            ordered = build.feeds if round_index % 2 == 0 else list(reversed(build.feeds))
            for feed in ordered:
                label = f"r{round_index}-{feed.key.replace(':', '-')}"
                with reporter.phase("case"):
                    sample = asyncio.run(_run_case(
                        feed,
                        workspace,
                        label=label,
                        cold_start_seconds=args.quiet_seconds,
                        timeout_seconds=args.timeout,
                    ))
                sample["round"] = round_index
                sample["warmup"] = round_index < args.warmups
                samples.append(sample)
                reporter.note(
                    f"{'warmup' if sample['warmup'] else 'run'} {feed.key} "
                    f"pipeline={sample['headline_seconds']['pipeline_run']:.3f}s "
                    f"extract={sample['headline_seconds']['extract_total']:.3f}s "
                    f"outcome={','.join(sample['outcomes']) or 'none'} "
                    f"state={','.join(sample['state_statuses']) or 'cleared'}"
                    f"{' TIMEOUT' if sample['timed_out'] else ''}"
                )

        measured = [sample for sample in samples if not sample["warmup"]]
        aggregates = _aggregate(measured)
        table = _render_table(aggregates)
        with reporter.phase("report", "building the report payload"):
            report = {
                "watch_broker": broker_metadata,
                "parameters": {
                    "formats": list(formats),
                    "variants": list(variants),
                    "workloads": list(workloads),
                    "flatten_modes": ["on" if mode else "off" for mode in flatten_modes],
                    "runs": args.runs,
                    "warmups": args.warmups,
                    "quiet_seconds": args.quiet_seconds,
                    "timeout_seconds": args.timeout,
                    "small_files": max(1, args.small_files),
                    "large_files": max(1, args.large_files),
                    "large_file_mib": max(1, args.large_file_mib),
                    "password_candidates": list(WRONG_PASSWORDS) + [PASSWORD],
                    "carrier_prefix_bytes": CARRIER_PREFIX_BYTES,
                    "carrier_suffix_bytes": CARRIER_SUFFIX_BYTES,
                },
                "corpus_cache": cache_info,
                "skipped_variants": build.skipped,
                "corpus_skipped": corpus_skipped,
                "cases": [
                    {
                        "case": feed.key,
                        "workload": feed.workload,
                        "format": feed.archive_format,
                        "variant": feed.variant,
                        "flatten": feed.flatten,
                        "files": [str(path) for path in feed.files],
                        "bytes": feed.total_bytes,
                    }
                    for feed in build.feeds
                ],
                "samples": samples,
                "aggregates": aggregates,
                "table": table,
            }
            rendered = render_report(report_from_payload(SCENARIO, report))
            workspace.write_result_text("report.json", rendered)
            if args.json_out:
                args.json_out.parent.mkdir(parents=True, exist_ok=True)
                args.json_out.write_text(rendered, encoding="utf-8")
        print(rendered)
        reporter.note("per-format watch stage medians (seconds):")
        for line in table.splitlines():
            reporter.note(f"  {line}")
        failures = [
            sample for sample in measured
            if not sample["succeeded"] or sample["timed_out"]
        ]
        if failures:
            reporter.note(f"{len(failures)} measured runs did not reach a terminal success state")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
