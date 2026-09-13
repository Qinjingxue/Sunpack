"""Reusable watch-mode memory workload and observation helpers.

The helpers in this module deliberately exercise the real ``WatchScheduler``
and ``PipelineEngine``.  They are kept under ``tests/helpers`` because the
workload is a test contract, while the process/cache observations are useful
to both long-running tests and diagnostic benchmark runs.
"""

from __future__ import annotations

import gc
import json
import math
import os
import shutil
import threading
import time
import tracemalloc
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from statistics import mean
from typing import Any, Callable, Iterable

import psutil

from sunpack.coordinator.engine import PipelineEngine
from sunpack.coordinator.watch_group_coordinator import WatchGroupCoordinator
from sunpack.filesystem.watcher.scheduler import WatchRunResult, WatchScheduler


def _mib(value: int | float) -> float:
    return float(value) / 1024**2


def env_int(name: str, default: int, *, minimum: int = 1) -> int:
    try:
        return max(minimum, int(os.environ.get(name, default)))
    except (TypeError, ValueError):
        return max(minimum, default)


def env_float(name: str, default: float, *, minimum: float = 0.0) -> float:
    try:
        return max(minimum, float(os.environ.get(name, default)))
    except (TypeError, ValueError):
        return max(minimum, default)


def create_small_zip(
    path: Path,
    *,
    member_name: str,
    payload_size: int = 1024,
    seed: int = 0,
) -> Path:
    """Create a deterministic stored ZIP without retaining the payload in RAM."""

    path.parent.mkdir(parents=True, exist_ok=True)
    payload_size = max(1, int(payload_size))
    pattern = f"sunpack-watch-{seed:08d}\n".encode("ascii")
    block = (pattern * ((1024 * 1024 // len(pattern)) + 1))[: 1024 * 1024]
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        info = zipfile.ZipInfo(member_name)
        info.compress_type = zipfile.ZIP_STORED
        with archive.open(info, "w", force_zip64=payload_size > 0xFFFFFFFF) as writer:
            remaining = payload_size
            while remaining:
                chunk_size = min(remaining, len(block))
                writer.write(block[:chunk_size])
                remaining -= chunk_size
    return path


def publish_files(
    watcher: WatchScheduler,
    source_paths: Iterable[Path],
    destination_root: Path,
    *,
    event_type: str = "created",
) -> list[Path]:
    """Publish ready files into a watch root and enqueue deterministic events."""

    destination_root.mkdir(parents=True, exist_ok=True)
    published: list[Path] = []
    for source in source_paths:
        destination = destination_root / source.name
        temporary = destination.with_name(f".{destination.name}.publishing")
        shutil.copyfile(source, temporary)
        os.replace(temporary, destination)
        watcher.enqueue(str(destination), event_type=event_type)
        published.append(destination)
    return published


def _watch_is_idle(watcher: WatchScheduler) -> bool:
    with watcher._lock:
        return not watcher._inflight_requests and not watcher._completion_requests


def drive_watch_until(
    watcher: WatchScheduler,
    condition: Callable[[], bool],
    *,
    timeout_seconds: float = 60.0,
    poll_seconds: float = 0.01,
) -> WatchRunResult:
    """Run the watch scheduler until a condition and all pipeline work settle."""

    deadline = time.perf_counter() + max(0.1, timeout_seconds)
    combined = WatchRunResult()
    while time.perf_counter() < deadline:
        result = watcher.run_once()
        combined.processed += result.processed
        combined.succeeded += result.succeeded
        combined.failed += result.failed
        combined.pending = result.pending
        combined.errors.extend(result.errors)
        if condition() and watcher.pending_count == 0 and _watch_is_idle(watcher):
            return combined
        time.sleep(max(0.0, poll_seconds))
    raise TimeoutError(
        "watch workload did not settle: "
        f"pending={watcher.pending_count}, "
        f"inflight={len(watcher._inflight_requests)}, "
        f"completion={len(watcher._completion_requests)}"
    )


def drive_watch_until_cache_cleanup(
    watcher: WatchScheduler,
    *,
    timeout_seconds: float = 30.0,
    poll_seconds: float = 0.01,
) -> None:
    """Keep driving the manual scheduler until its idle cleanup has run."""

    deadline = time.perf_counter() + max(0.1, timeout_seconds)
    while time.perf_counter() < deadline:
        watcher.run_once()
        with watcher._lock:
            active = bool(
                watcher._pending
                or watcher._inflight_requests
                or watcher._completion_requests
            )
            cleanup_pending = watcher._cache_cleanup_deadline is not None
        engine_idle = True
        is_idle = getattr(watcher.pipeline_engine, "is_idle", None)
        if callable(is_idle):
            engine_idle = bool(is_idle())
        if not active and engine_idle and not cleanup_pending:
            return
        time.sleep(max(0.0, poll_seconds))
    raise TimeoutError("watch cache cleanup did not settle")


def count_output_files(root: Path, pattern: str = "*.txt") -> int:
    return sum(1 for path in root.rglob(pattern) if path.is_file())


@dataclass
class WatchMemoryHarness:
    """A real watch scheduler with deterministic manual event delivery."""

    watch_root: Path
    output_root: Path
    state_path: Path
    config: dict[str, Any]
    engine: PipelineEngine
    watcher: WatchScheduler

    @classmethod
    def create(
        cls,
        root: Path,
        config: dict[str, Any],
        *,
        label: str = "watch-memory",
        quiet_seconds: float = 0.0,
    ) -> "WatchMemoryHarness":
        base = root / label
        watch_root = base / "watch"
        output_root = base / "out"
        state_path = base / "state.json"
        watch_root.mkdir(parents=True, exist_ok=True)
        output_root.mkdir(parents=True, exist_ok=True)
        engine = PipelineEngine(config).start()
        watcher = WatchScheduler(
            config,
            [str(watch_root)],
            out_dir=str(output_root),
            state_path=str(state_path),
            quiet_seconds=quiet_seconds,
            initial_scan=False,
            pipeline_engine=engine,
            group_coordinator=WatchGroupCoordinator(config),
        )
        return cls(watch_root, output_root, state_path, config, engine, watcher)

    def close(self) -> None:
        try:
            self.watcher.stop()
        finally:
            completion_pool = getattr(self.watcher, "_completion_pool", None)
            if completion_pool is not None and not getattr(completion_pool, "_shutdown", False):
                completion_pool.shutdown(wait=True, cancel_futures=False)
            self.engine.close()

    def __enter__(self) -> "WatchMemoryHarness":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()


def _children(process: psutil.Process) -> list[psutil.Process]:
    result = []
    for child in process.children(recursive=True):
        try:
            if child.is_running():
                result.append(child)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return result


def _memory_info(process: psutil.Process) -> tuple[int, int]:
    try:
        info = process.memory_info()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return 0, 0
    return int(getattr(info, "rss", 0) or 0), int(getattr(info, "private", 0) or 0)


def _cache_stats() -> dict[str, Any]:
    try:
        from sunpack.support.global_cache_manager import GLOBAL_CACHE

        with GLOBAL_CACHE._lock:
            namespaces = {
                str(namespace): len(cache)
                for namespace, cache in GLOBAL_CACHE._caches.items()
            }
            capacities = {
                str(namespace): int(
                    GLOBAL_CACHE._capacities.get(namespace, GLOBAL_CACHE.default_capacity)
                )
                for namespace in GLOBAL_CACHE._caches
            }
        return {
            "entries": int(sum(namespaces.values())),
            "namespaces": namespaces,
            "capacities": capacities,
        }
    except (ImportError, AttributeError, TypeError):
        return {}


def _archive_session_count() -> int:
    try:
        from sunpack.support import archive_sessions

        with archive_sessions._LOCK:
            return len(archive_sessions._SESSIONS)
    except (ImportError, AttributeError, TypeError):
        return 0


def _reader_stats() -> dict[str, Any]:
    try:
        from sunpack_native import reader_cache_stats

        return {
            str(key): value
            for key, value in dict(reader_cache_stats()).items()
            if isinstance(value, (int, float, str, bool))
        }
    except (ImportError, AttributeError, TypeError):
        return {}


def _projection_stats() -> dict[str, Any]:
    try:
        from sunpack.support.archive_knowledge_projection import projection_cache_stats

        return dict(projection_cache_stats())
    except (ImportError, AttributeError, TypeError):
        return {}


def _relation_password_cache_stats() -> dict[str, int]:
    try:
        from sunpack.passwords import relation_prober

        cache = relation_prober._RELATION_PROBE_CACHE
        if cache is None:
            return {"successes": 0, "negative": 0}
        with cache._lock:
            return {
                "successes": len(cache._successes),
                "negative": len(cache._negative),
            }
    except (ImportError, AttributeError, TypeError):
        return {}


def _native_worker_stats(engine: PipelineEngine | None) -> dict[str, Any]:
    """Observe the single native worker and its native-owned job lifecycle."""

    try:
        services = getattr(engine, "_services", None)
        runner = getattr(services, "sevenzip_runner", None)
        holder = getattr(runner, "_worker_holder", None)
        if holder is None:
            return {}
        with holder._lock:
            worker = holder._worker
            if worker is None:
                return {"worker_alive": False, "closed": bool(holder._closed)}
            with worker._dispatch_lock:
                states = [dict(state) for state in worker._job_states.values()]
            return {
                "worker_alive": bool(worker.is_alive()),
                "worker_epoch": worker.worker_epoch,
                "active_jobs": len(states),
                "job_states": sorted(state.get("state", "") for state in states),
                "closed": bool(holder._closed),
            }
    except (AttributeError, TypeError, ValueError):
        return {}


def _known_cache_stats(engine: PipelineEngine | None) -> dict[str, Any]:
    """Collect counters for caches that are explicit in the implementation."""

    return {
        "global": _cache_stats(),
        "reader": _reader_stats(),
        "projection": _projection_stats(),
        "archive_sessions": _archive_session_count(),
        "relation_password": _relation_password_cache_stats(),
        "native_worker": _native_worker_stats(engine),
    }


def _state_stats(watcher: WatchScheduler, state_path: Path) -> dict[str, Any]:
    state = watcher.state
    result = {
        "pending_work": len(state.pending_work),
        "entries": len(state.entries),
        "groups": len(state.groups),
        "password_generation": int(state.password_generation),
    }
    try:
        result["state_file_bytes"] = state_path.stat().st_size
    except OSError:
        result["state_file_bytes"] = 0
    try:
        result["state_journal_bytes"] = state.journal_path.stat().st_size
    except OSError:
        result["state_journal_bytes"] = 0
    result["state_storage_bytes"] = (
        result["state_file_bytes"] + result["state_journal_bytes"]
    )
    try:
        result["event_log_bytes"] = state_path.with_name("events.jsonl").stat().st_size
    except OSError:
        result["event_log_bytes"] = 0
    cleanup_events = {"scheduled": 0, "started": 0, "finished": 0}
    try:
        with state_path.with_name("events.jsonl").open("r", encoding="utf-8") as handle:
            for line in handle:
                try:
                    event = json.loads(line).get("event")
                except (TypeError, ValueError):
                    continue
                if event == "cache_cleanup_scheduled":
                    cleanup_events["scheduled"] += 1
                elif event == "cache_cleanup_started":
                    cleanup_events["started"] += 1
                elif event == "cache_cleanup_finished":
                    cleanup_events["finished"] += 1
    except (OSError, UnicodeError):
        pass
    result["cache_cleanup"] = cleanup_events
    return result


def _engine_stats(engine: PipelineEngine | None) -> dict[str, Any]:
    if engine is None:
        return {}
    result: dict[str, Any] = {}
    queue = getattr(engine, "_queue", None)
    if queue is not None:
        result["queue_size"] = int(queue.qsize())
    dispatch_condition = getattr(engine, "_dispatch_condition", None)
    if dispatch_condition is not None:
        with dispatch_condition:
            result["request_threads"] = len(getattr(engine, "_request_threads", ()))
    return result


@dataclass(frozen=True)
class WatchMemorySample:
    label: str
    files_seen: int
    completed_files: int
    elapsed_seconds: float
    parent_rss_mib: float
    parent_private_mib: float
    worker_rss_mib: float
    worker_private_mib: float
    total_rss_mib: float
    peak_parent_rss_mib: float
    peak_worker_rss_mib: float
    child_count: int
    threads: int
    handles: int
    children: tuple[dict[str, Any], ...] = ()
    reader: dict[str, Any] = field(default_factory=dict)
    global_cache: dict[str, Any] = field(default_factory=dict)
    projection_cache: dict[str, Any] = field(default_factory=dict)
    archive_sessions: int = 0
    known_caches: dict[str, Any] = field(default_factory=dict)
    watch_state: dict[str, Any] = field(default_factory=dict)
    engine: dict[str, Any] = field(default_factory=dict)
    python_traced_mib: float = 0.0
    python_peak_mib: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        # Compatibility aliases for the original Plan 7 memory timeline.
        payload.update(
            {
                "installed_volumes": self.files_seen,
                "completed_archives": self.completed_files,
                "parent_rss": int(self.parent_rss_mib * 1024**2),
                "worker_rss": int(self.worker_rss_mib * 1024**2),
            }
        )
        return payload


class WatchMemorySampler:
    """Continuous process-tree sampler with watch/cache/native diagnostics.

    ``sample`` retains the argument names used by the older Plan 7 helper so
    existing watch tests can use the extracted implementation unchanged.
    """

    def __init__(
        self,
        *,
        watcher: WatchScheduler | None = None,
        engine: PipelineEngine | None = None,
        state_path: Path | None = None,
        interval_seconds: float = 0.1,
        trace_python: bool = False,
    ) -> None:
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be positive")
        self.watcher = watcher
        self.engine = engine
        self.state_path = state_path
        self.interval_seconds = interval_seconds
        self.process = psutil.Process(os.getpid())
        self.samples: list[WatchMemorySample] = []
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._started = 0.0
        self._files_seen = 0
        self._completed_files = 0
        self._peak_parent_rss = 0
        self._peak_worker_rss = 0
        self._trace_python = bool(trace_python)
        self._owns_tracemalloc = False
        if self._trace_python and not tracemalloc.is_tracing():
            tracemalloc.start(10)
            self._owns_tracemalloc = True

    def _take(self, *, label: str, collect: bool) -> WatchMemorySample:
        if collect:
            gc.collect()
        parent_rss, parent_private = _memory_info(self.process)
        children = _children(self.process)
        child_rows = []
        worker_rss = 0
        worker_private = 0
        for child in children:
            rss, private = _memory_info(child)
            worker_rss += rss
            worker_private += private
            try:
                name = child.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                name = ""
            child_rows.append({
                "pid": int(child.pid),
                "name": str(name),
                "rss_mib": round(_mib(rss), 3),
                "private_mib": round(_mib(private), 3),
            })
        with self._lock:
            self._peak_parent_rss = max(self._peak_parent_rss, parent_rss)
            self._peak_worker_rss = max(self._peak_worker_rss, worker_rss)
            files_seen = self._files_seen
            completed_files = self._completed_files
            started = self._started
        traced = peak = 0
        if tracemalloc.is_tracing():
            traced, peak = tracemalloc.get_traced_memory()
        try:
            threads = self.process.num_threads()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            threads = 0
        try:
            handles = self.process.num_handles()
        except (AttributeError, psutil.NoSuchProcess, psutil.AccessDenied):
            handles = 0
        state = {}
        if self.watcher is not None:
            state = _state_stats(self.watcher, self.state_path or Path("state.json"))
        sample = WatchMemorySample(
            label=label,
            files_seen=files_seen,
            completed_files=completed_files,
            elapsed_seconds=(time.perf_counter() - started) if started else 0.0,
            parent_rss_mib=round(_mib(parent_rss), 3),
            parent_private_mib=round(_mib(parent_private), 3),
            worker_rss_mib=round(_mib(worker_rss), 3),
            worker_private_mib=round(_mib(worker_private), 3),
            total_rss_mib=round(_mib(parent_rss + worker_rss), 3),
            peak_parent_rss_mib=round(_mib(self._peak_parent_rss), 3),
            peak_worker_rss_mib=round(_mib(self._peak_worker_rss), 3),
            child_count=len(children),
            threads=int(threads),
            handles=int(handles),
            children=tuple(child_rows),
            reader=_reader_stats(),
            global_cache=_cache_stats(),
            projection_cache=_projection_stats(),
            archive_sessions=_archive_session_count(),
            known_caches=_known_cache_stats(self.engine),
            watch_state=state,
            engine=_engine_stats(self.engine),
            python_traced_mib=round(_mib(traced), 3),
            python_peak_mib=round(_mib(peak), 3),
        )
        with self._lock:
            self.samples.append(sample)
        return sample

    def sample(
        self,
        *,
        installed_volumes: int | None = None,
        completed_archives: int | None = None,
        files_seen: int | None = None,
        completed_files: int | None = None,
        elapsed: float | None = None,
        label: str = "",
        collect: bool = True,
    ) -> dict[str, Any]:
        del elapsed  # elapsed is retained for Plan 7 call compatibility.
        with self._lock:
            if files_seen is not None:
                self._files_seen = int(files_seen)
            elif installed_volumes is not None:
                self._files_seen = int(installed_volumes)
            if completed_files is not None:
                self._completed_files = int(completed_files)
            elif completed_archives is not None:
                self._completed_files = int(completed_archives)
        return self._take(label=label, collect=collect).to_dict()

    def start(self) -> None:
        with self._lock:
            if self._thread is not None:
                raise RuntimeError("sampler is already running")
            self._started = time.perf_counter()
        self._stop.clear()
        self._take(label="sampler-start", collect=True)
        self._thread = threading.Thread(
            target=self._run,
            name="sunpack-watch-memory-sampler",
            daemon=True,
        )
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            self._take(label="sample", collect=False)

    def stop(self) -> list[WatchMemorySample]:
        thread = self._thread
        if thread is None:
            return list(self.samples)
        self._stop.set()
        thread.join(timeout=max(1.0, self.interval_seconds * 2))
        self._thread = None
        self._take(label="sampler-stop", collect=True)
        if self._owns_tracemalloc:
            tracemalloc.stop()
            self._owns_tracemalloc = False
        return list(self.samples)

    def __enter__(self) -> "WatchMemorySampler":
        self.start()
        return self

    def __exit__(self, *_exc) -> None:
        self.stop()

    def report(self) -> dict[str, Any]:
        with self._lock:
            rows = list(self.samples)
        return summarize_watch_memory(rows)

    def json_report(self) -> str:
        return json.dumps(
            {"summary": self.report(), "samples": [row.to_dict() for row in self.samples]},
            ensure_ascii=False,
            indent=2,
            default=str,
        )

    def summary(self) -> dict[str, Any]:
        """Compatibility summary used by the existing Plan 7 tests."""

        rows = list(self.samples)
        completion_rows = [row for row in rows if row.label.startswith("after_")] or rows[1:]
        first = completion_rows[0] if completion_rows else rows[0]
        final = completion_rows[-1] if completion_rows else rows[-1]
        return {
            "samples": len(rows),
            "arrival_samples": sum(
                1 for row in rows if row.label.startswith("arrived_")
            ),
            "completion_samples": sum(
                1 for row in rows if row.label.startswith("after_")
            ),
            "parent_growth": int((final.parent_rss_mib - first.parent_rss_mib) * 1024**2),
            "worker_growth": int((final.worker_rss_mib - first.worker_rss_mib) * 1024**2),
            "child_count_range": [
                min(row.child_count for row in completion_rows),
                max(row.child_count for row in completion_rows),
            ],
            "final_parent_rss": int(final.parent_rss_mib * 1024**2),
            "final_worker_rss": int(final.worker_rss_mib * 1024**2),
        }


def _linear_slope(rows: list[WatchMemorySample], field: str) -> float:
    points = [(float(row.completed_files), float(getattr(row, field))) for row in rows]
    points = [(x, y) for x, y in points if math.isfinite(x) and math.isfinite(y)]
    if len(points) < 2 or len({x for x, _ in points}) < 2:
        return 0.0
    x_mean = mean(x for x, _ in points)
    y_mean = mean(y for _, y in points)
    denominator = sum((x - x_mean) ** 2 for x, _ in points)
    if denominator <= 0:
        return 0.0
    return sum((x - x_mean) * (y - y_mean) for x, y in points) / denominator


def summarize_watch_memory(rows: list[WatchMemorySample]) -> dict[str, Any]:
    if not rows:
        return {"samples": 0}
    baseline = rows[0]
    completed_rows = [
        row for row in rows
        if row.completed_files >= baseline.completed_files
        and row.label.startswith(("after_", "idle_", "sampler-stop"))
    ] or rows[1:]
    final = completed_rows[-1] if completed_rows else rows[-1]
    parent_values = [row.parent_rss_mib for row in rows]
    worker_values = [row.worker_rss_mib for row in rows]
    checkpoints = [
        row for row in rows
        if row.label.startswith(("baseline", "after_", "idle_", "sampler-stop", "after-engine"))
    ]

    def checkpoint_row(row: WatchMemorySample) -> dict[str, Any]:
        global_cache = row.known_caches.get("global", {})
        reader = row.known_caches.get("reader", {})
        return {
            "label": row.label,
            "files_seen": row.files_seen,
            "completed_files": row.completed_files,
            "parent_rss_mib": row.parent_rss_mib,
            "worker_rss_mib": row.worker_rss_mib,
            "global_cache_entries": global_cache.get("entries", 0),
            "global_cache_namespaces": global_cache.get("namespaces", {}),
            "reader_cache_entries": reader.get("cache_entries", 0),
            "reader_cache_bytes": int(reader.get("hot_cache_bytes", 0) or 0)
            + int(reader.get("general_cache_bytes", 0) or 0),
            "archive_sessions": row.archive_sessions,
            "watch_state": row.watch_state,
            "engine": row.engine,
        }

    return {
        "samples": len(rows),
        "files_seen": final.files_seen,
        "completed_files": final.completed_files,
        "parent_residual_growth_bytes": int(
            (final.parent_rss_mib - baseline.parent_rss_mib) * 1024**2
        ),
        "worker_residual_growth_bytes": int(
            (final.worker_rss_mib - baseline.worker_rss_mib) * 1024**2
        ),
        "parent_rss_start_mib": baseline.parent_rss_mib,
        "parent_rss_final_mib": final.parent_rss_mib,
        "parent_rss_peak_mib": max(parent_values),
        "worker_rss_start_mib": baseline.worker_rss_mib,
        "worker_rss_final_mib": final.worker_rss_mib,
        "worker_rss_peak_mib": max(worker_values),
        "final_parent_rss_bytes": int(final.parent_rss_mib * 1024**2),
        "final_worker_rss_bytes": int(final.worker_rss_mib * 1024**2),
        "parent_slope_mib_per_completed_file": round(
            _linear_slope(completed_rows, "parent_rss_mib"), 6
        ),
        "worker_slope_mib_per_completed_file": round(
            _linear_slope(completed_rows, "worker_rss_mib"), 6
        ),
        "total_slope_mib_per_completed_file": round(
            _linear_slope(completed_rows, "total_rss_mib"), 6
        ),
        "child_count_range": [
            min(row.child_count for row in rows),
            max(row.child_count for row in rows),
        ],
        "threads_range": [
            min(row.threads for row in rows),
            max(row.threads for row in rows),
        ],
        "handles_range": [
            min(row.handles for row in rows),
            max(row.handles for row in rows),
        ],
        "reader_final": final.reader,
        "global_cache_final": final.global_cache,
        "projection_cache_final": final.projection_cache,
        "archive_sessions_final": final.archive_sessions,
        "known_caches_final": final.known_caches,
        "checkpoint_series": [checkpoint_row(row) for row in checkpoints],
        "watch_state_final": final.watch_state,
        "engine_final": final.engine,
        "python_traced_final_mib": final.python_traced_mib,
        "python_peak_mib": max(row.python_peak_mib for row in rows),
    }


__all__ = [
    "WatchMemoryHarness",
    "WatchMemorySample",
    "WatchMemorySampler",
    "count_output_files",
    "create_small_zip",
    "drive_watch_until",
    "env_float",
    "env_int",
    "publish_files",
    "summarize_watch_memory",
]
