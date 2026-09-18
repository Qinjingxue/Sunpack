from __future__ import annotations

import argparse
import io
import json
import math
import os
import random
import shutil
import statistics
import sys
import tempfile
import threading
import time
import zipfile
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable


# A source checkout commonly keeps the rebuilt native module in .venv while
# watchdog/psutil remain in the base interpreter. Make both available without
# requiring another environment mutation.
_BASE_SITE_PACKAGES = Path(sys.base_prefix) / "Lib" / "site-packages"
if _BASE_SITE_PACKAGES.is_dir() and str(_BASE_SITE_PACKAGES) not in sys.path:
    sys.path.append(str(_BASE_SITE_PACKAGES))
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import psutil

import sunpack.filesystem.watcher.scheduler as scheduler_module
from sunpack.filesystem.watcher.scheduler import WatchScheduler
from sunpack.platform.windows.elevation import is_process_elevated


CONTENT_REASON_MASK = 0x00000001 | 0x00000002 | 0x00000004


@dataclass(frozen=True)
class Scenario:
    name: str
    description: str
    writer: Callable[["ScenarioContext"], None]
    maximum_premature_attempts: int = 0
    timeout_seconds: float = 20.0
    synthetic_events: int = 0


@dataclass
class ScenarioContext:
    root: Path
    final_path: Path
    payload: bytes
    chunk_bytes: int
    delay_seconds: float


@dataclass
class ScenarioResult:
    name: str
    description: str
    passed: bool = False
    final_ready: bool = False
    final_zip_valid: bool = False
    premature_attempts: int = 0
    temporary_attempts: int = 0
    total_ready_attempts: int = 0
    event_count: int = 0
    event_types: dict[str, int] = field(default_factory=dict)
    observation_calls: int = 0
    observation_seconds: float = 0.0
    journal_delta_queries: int = 0
    journal_known_deltas: int = 0
    journal_content_deltas: int = 0
    journal_non_close_content_deltas: int = 0
    journal_reason_mask: int = 0
    journal_errors: dict[str, int] = field(default_factory=dict)
    write_seconds: float = 0.0
    stable_latency_seconds: float | None = None
    total_seconds: float = 0.0
    cpu_seconds: float = 0.0
    peak_rss_delta_bytes: int = 0
    synthetic_events_per_second: float | None = None
    maximum_premature_attempts: int = 0
    errors: list[str] = field(default_factory=list)


@dataclass
class ObservationMetrics:
    calls: int = 0
    seconds: float = 0.0
    delta_queries: int = 0
    known_deltas: int = 0
    content_deltas: int = 0
    non_close_content_deltas: int = 0
    reason_mask: int = 0
    errors: Counter[str] = field(default_factory=Counter)


def _zip_payload(megabytes: float) -> bytes:
    size = max(64 * 1024, int(megabytes * 1024 * 1024))
    random_bytes = random.Random(0x5A17).randbytes(size)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("payload/random.bin", random_bytes)
        archive.writestr("metadata.txt", "SunPack watch validation\n")
    return buffer.getvalue()


def _fsync(stream) -> None:
    stream.flush()
    os.fsync(stream.fileno())


def _write_append(ctx: ScenarioContext, *, reopen: bool = False, pause_at_half: float = 0.0) -> None:
    halfway = len(ctx.payload) // 2
    paused = False
    offset = 0
    while offset < len(ctx.payload):
        end = min(len(ctx.payload), offset + ctx.chunk_bytes)
        mode = "ab" if reopen or offset else "wb"
        with ctx.final_path.open(mode) as stream:
            stream.write(ctx.payload[offset:end])
            _fsync(stream)
        offset = end
        if pause_at_half and not paused and offset >= halfway:
            paused = True
            time.sleep(pause_at_half)
        else:
            time.sleep(ctx.delay_seconds)


def _atomic_move(ctx: ScenarioContext) -> None:
    staging = ctx.root.parent / f"{ctx.root.name}-complete.zip"
    staging.write_bytes(ctx.payload)
    os.replace(staging, ctx.final_path)


def _copy_complete(ctx: ScenarioContext) -> None:
    source = ctx.root.parent / f"{ctx.root.name}-copy-source.zip"
    source.write_bytes(ctx.payload)
    old = time.time() - 86400.0
    os.utime(source, (old, old))
    shutil.copy2(source, ctx.final_path)


def _slow_append(ctx: ScenarioContext) -> None:
    _write_append(ctx)


def _close_reopen(ctx: ScenarioContext) -> None:
    _write_append(ctx, reopen=True)


def _preallocated(ctx: ScenarioContext, *, preserve_mtime: bool = False) -> None:
    with ctx.final_path.open("wb") as stream:
        stream.truncate(len(ctx.payload))
        _fsync(stream)
    fixed_ns = int((time.time() - 7200.0) * 1_000_000_000)
    if preserve_mtime:
        os.utime(ctx.final_path, ns=(fixed_ns, fixed_ns))
    with ctx.final_path.open("r+b") as stream:
        for offset in range(0, len(ctx.payload), ctx.chunk_bytes):
            stream.seek(offset)
            stream.write(ctx.payload[offset : offset + ctx.chunk_bytes])
            _fsync(stream)
            if preserve_mtime:
                os.utime(ctx.final_path, ns=(fixed_ns, fixed_ns))
            time.sleep(ctx.delay_seconds)


def _preallocated_sequential(ctx: ScenarioContext) -> None:
    _preallocated(ctx)


def _same_size_mtime_preserved(ctx: ScenarioContext) -> None:
    _preallocated(ctx, preserve_mtime=True)


def _parallel_ranges(ctx: ScenarioContext) -> None:
    with ctx.final_path.open("wb") as stream:
        stream.truncate(len(ctx.payload))
        _fsync(stream)
    offsets = list(range(0, len(ctx.payload), ctx.chunk_bytes))
    groups = [offsets[index::4] for index in range(4)]
    barrier = threading.Barrier(len(groups))

    def worker(group: list[int]) -> None:
        barrier.wait()
        with ctx.final_path.open("r+b") as stream:
            for offset in reversed(group):
                stream.seek(offset)
                stream.write(ctx.payload[offset : offset + ctx.chunk_bytes])
                _fsync(stream)
                time.sleep(ctx.delay_seconds / 2.0)

    threads = [threading.Thread(target=worker, args=(group,), daemon=True) for group in groups]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


def _temporary_rename(ctx: ScenarioContext) -> None:
    temporary = ctx.final_path.with_suffix(ctx.final_path.suffix + ".crdownload")
    temporary_context = ScenarioContext(
        root=ctx.root,
        final_path=temporary,
        payload=ctx.payload,
        chunk_bytes=ctx.chunk_bytes,
        delay_seconds=ctx.delay_seconds,
    )
    _write_append(temporary_context, reopen=True)
    os.replace(temporary, ctx.final_path)


def _aria2_sidecar(ctx: ScenarioContext) -> None:
    sidecar = ctx.final_path.with_suffix(ctx.final_path.suffix + ".aria2")
    offset = 0
    with ctx.final_path.open("wb") as stream:
        while offset < len(ctx.payload):
            end = min(len(ctx.payload), offset + ctx.chunk_bytes)
            stream.write(ctx.payload[offset:end])
            _fsync(stream)
            sidecar.write_text(json.dumps({"completed": end, "total": len(ctx.payload)}), encoding="utf-8")
            offset = end
            time.sleep(ctx.delay_seconds)
    sidecar.unlink(missing_ok=True)


def _long_pause(ctx: ScenarioContext) -> None:
    _write_append(ctx, reopen=True, pause_at_half=3.2)


def _timestamp_restore(ctx: ScenarioContext) -> None:
    _write_append(ctx)
    old = time.time() - 30 * 86400.0
    os.utime(ctx.final_path, (old, old))


def _locked_finalization(ctx: ScenarioContext) -> None:
    with ctx.final_path.open("wb") as stream:
        for offset in range(0, len(ctx.payload), ctx.chunk_bytes):
            stream.write(ctx.payload[offset : offset + ctx.chunk_bytes])
            _fsync(stream)
            time.sleep(ctx.delay_seconds / 2.0)
        time.sleep(3.2)


def _event_storm(ctx: ScenarioContext) -> None:
    ctx.final_path.write_bytes(ctx.payload)


def scenario_matrix() -> list[Scenario]:
    return [
        Scenario("atomic_move", "同卷完整 ZIP 原子移动进入监控目录", _atomic_move),
        Scenario("copy2_timestamp", "完整 ZIP 复制并恢复源时间戳", _copy_complete),
        Scenario("slow_append", "下载器持续追加写入最终文件名", _slow_append),
        Scenario("close_reopen", "下载器每个分块关闭并重新打开文件", _close_reopen),
        Scenario("preallocated", "预分配完整大小后原位覆盖", _preallocated_sequential),
        Scenario("parallel_ranges", "多线程分段覆盖预分配文件", _parallel_ranges, maximum_premature_attempts=1),
        Scenario("browser_temp_rename", "浏览器临时扩展名下载完成后重命名", _temporary_rename),
        Scenario("aria2_sidecar", "最终文件写入并持续更新 aria2 边车文件", _aria2_sidecar),
        Scenario("long_network_pause", "下载中出现超过默认静默窗口的网络停顿", _long_pause, maximum_premature_attempts=2, timeout_seconds=40.0),
        Scenario("timestamp_restore", "内容完成后恢复远端旧时间戳", _timestamp_restore),
        Scenario("same_size_mtime", "同大小覆盖且每块恢复固定 mtime", _same_size_mtime_preserved, maximum_premature_attempts=1),
        Scenario("writer_lock", "内容写完后写句柄继续占用一段时间", _locked_finalization),
        Scenario("event_storm", "完整文件上的大量重复 Watch 事件", _event_storm, synthetic_events=5000),
    ]


def _zip_is_valid(path: Path) -> bool:
    try:
        with zipfile.ZipFile(path) as archive:
            return archive.testzip() is None and bool(archive.infolist())
    except (OSError, zipfile.BadZipFile, EOFError):
        return False


def _watch_config() -> dict:
    return {
        "watch": {
            "clipboard_monitor_enabled": False,
            "cold_start_seconds": 1.0,
            "quiet_min_seconds": 1.25,
            "quiet_max_seconds": 20.0,
            "boundary_confirmation_seconds": 0.5,
            "observer_stop_timeout_seconds": 2.0,
        }
    }


def _start_detection_scheduler(watcher: WatchScheduler) -> None:
    # This benchmark drives _pop_ready itself so it can measure the exact
    # completion boundary without running the extraction pipeline.  The public
    # async start method delegates this same operation through WorkBroker.
    watcher._start_blocking()


def _stop_detection_scheduler(watcher: WatchScheduler) -> None:
    watcher._stop_blocking()


def run_scenario(base: Path, scenario: Scenario, payload: bytes, *, chunk_bytes: int, delay_seconds: float) -> ScenarioResult:
    scenario_root = base / scenario.name / "in"
    scenario_root.mkdir(parents=True, exist_ok=True)
    final_path = scenario_root / "download.zip"
    state_path = base / scenario.name / ".sunpack_watch" / "state.json"
    result = ScenarioResult(
        name=scenario.name,
        description=scenario.description,
        maximum_premature_attempts=scenario.maximum_premature_attempts,
    )
    observations = ObservationMetrics()
    event_types: Counter[str] = Counter()
    original_observer = scheduler_module._watch_candidate_for_path

    def measured_observer(path: str, *, since_usn: int = 0):
        started = time.perf_counter()
        candidate = original_observer(path, since_usn=since_usn)
        observations.calls += 1
        observations.seconds += time.perf_counter() - started
        if candidate is not None and since_usn > 0 and candidate.change_usn > since_usn:
            observations.delta_queries += 1
            if candidate.change_reasons_known:
                observations.known_deltas += 1
                observations.reason_mask |= candidate.change_reasons
                if candidate.change_reasons & CONTENT_REASON_MASK:
                    observations.content_deltas += 1
                if candidate.change_reasons_without_close & CONTENT_REASON_MASK:
                    observations.non_close_content_deltas += 1
            elif candidate.change_reason_error:
                observations.errors[candidate.change_reason_error] += 1
        return candidate

    scheduler_module._watch_candidate_for_path = measured_observer
    watcher = WatchScheduler(
        _watch_config(),
        [str(scenario_root)],
        out_dir=str(base / scenario.name / "out"),
        state_path=str(state_path),
        cold_start_seconds=1.0,
        initial_scan=False,
        observer_stop_timeout_seconds=2.0,
        pipeline_engine=object(),
    )
    original_enqueue = watcher.enqueue

    def measured_enqueue(path: str, *, force: bool = False, event_type: str = "unknown", src_path: str = ""):
        event_types[event_type] += 1
        return original_enqueue(path, force=force, event_type=event_type, src_path=src_path)

    watcher.enqueue = measured_enqueue
    context = ScenarioContext(scenario_root, final_path, payload, chunk_bytes, delay_seconds)
    writer_error: list[str] = []
    writer_started = threading.Event()
    content_finished = threading.Event()
    writer_finished = threading.Event()
    writer_started_at = [0.0]
    content_finished_at = [0.0]
    writer_finished_at = [0.0]

    def writer() -> None:
        writer_started_at[0] = time.perf_counter()
        writer_started.set()
        try:
            scenario.writer(context)
            content_finished_at[0] = time.perf_counter()
            content_finished.set()
            if scenario.synthetic_events:
                storm_started = time.perf_counter()
                for _ in range(scenario.synthetic_events):
                    watcher.enqueue(str(final_path), event_type="modified")
                storm_elapsed = time.perf_counter() - storm_started
                result.synthetic_events_per_second = scenario.synthetic_events / max(storm_elapsed, 1e-9)
        except Exception as exc:
            writer_error.append(f"{type(exc).__name__}: {exc}")
        finally:
            writer_finished_at[0] = time.perf_counter()
            writer_finished.set()

    process = psutil.Process()
    rss_before = process.memory_info().rss
    peak_rss = rss_before
    cpu_before = sum(process.cpu_times()[:2])
    suite_started = time.perf_counter()
    thread = threading.Thread(target=writer, name=f"watch-validation-{scenario.name}", daemon=True)
    _start_detection_scheduler(watcher)
    try:
        time.sleep(0.15)
        thread.start()
        deadline = time.perf_counter() + scenario.timeout_seconds
        completed = False
        while time.perf_counter() < deadline:
            peak_rss = max(peak_rss, process.memory_info().rss)
            for candidate in watcher._pop_ready(time.time()):
                result.total_ready_attempts += 1
                candidate_path = Path(candidate.path)
                valid = _zip_is_valid(candidate_path)
                is_final = os.path.normcase(os.path.abspath(candidate.path)) == os.path.normcase(os.path.abspath(final_path))
                finished = content_finished.is_set()
                if not is_final:
                    result.temporary_attempts += 1
                if not finished or not valid or not is_final:
                    result.premature_attempts += 1
                if is_final and finished and valid:
                    result.final_ready = True
                    result.final_zip_valid = True
                    result.stable_latency_seconds = max(0.0, time.perf_counter() - content_finished_at[0])
                    if not scenario.synthetic_events or writer_finished.is_set():
                        completed = True
                        break
            if result.final_ready and writer_finished.is_set():
                completed = True
            if completed:
                break
            if writer_error:
                break
            time.sleep(0.01)
        thread.join(timeout=2.0)
        if thread.is_alive():
            result.errors.append("writer thread did not stop")
        result.errors.extend(writer_error)
        if final_path.exists() and not result.final_zip_valid:
            result.final_zip_valid = _zip_is_valid(final_path)
        if not result.final_ready:
            result.errors.append("final archive was not declared ready before timeout")
    finally:
        _stop_detection_scheduler(watcher)
        scheduler_module._watch_candidate_for_path = original_observer
    result.write_seconds = max(0.0, writer_finished_at[0] - writer_started_at[0]) if writer_started.is_set() else 0.0
    result.total_seconds = time.perf_counter() - suite_started
    result.cpu_seconds = max(0.0, sum(process.cpu_times()[:2]) - cpu_before)
    result.peak_rss_delta_bytes = max(0, peak_rss - rss_before)
    result.event_count = sum(event_types.values())
    result.event_types = dict(sorted(event_types.items()))
    result.observation_calls = observations.calls
    result.observation_seconds = observations.seconds
    result.journal_delta_queries = observations.delta_queries
    result.journal_known_deltas = observations.known_deltas
    result.journal_content_deltas = observations.content_deltas
    result.journal_non_close_content_deltas = observations.non_close_content_deltas
    result.journal_reason_mask = observations.reason_mask
    result.journal_errors = dict(observations.errors.most_common())
    result.passed = (
        result.final_ready
        and result.final_zip_valid
        and result.premature_attempts <= scenario.maximum_premature_attempts
        and not result.errors
    )
    return result


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * percentile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] * (1.0 - fraction) + ordered[upper] * fraction


def build_report(mode: str, results: list[ScenarioResult], started_at: str, total_seconds: float) -> dict:
    latencies = [item.stable_latency_seconds for item in results if item.stable_latency_seconds is not None]
    observation_calls = sum(item.observation_calls for item in results)
    observation_seconds = sum(item.observation_seconds for item in results)
    return {
        "schema_version": 1,
        "started_at": started_at,
        "mode": mode,
        "process_elevated": is_process_elevated(),
        "python": sys.executable,
        "platform": sys.platform,
        "total_seconds": total_seconds,
        "summary": {
            "scenario_count": len(results),
            "passed": sum(item.passed for item in results),
            "failed": sum(not item.passed for item in results),
            "premature_attempts": sum(item.premature_attempts for item in results),
            "temporary_attempts": sum(item.temporary_attempts for item in results),
            "events": sum(item.event_count for item in results),
            "observation_calls": observation_calls,
            "observation_seconds": observation_seconds,
            "observation_calls_per_second": observation_calls / max(observation_seconds, 1e-9),
            "journal_delta_queries": sum(item.journal_delta_queries for item in results),
            "journal_known_deltas": sum(item.journal_known_deltas for item in results),
            "journal_content_deltas": sum(item.journal_content_deltas for item in results),
            "journal_non_close_content_deltas": sum(
                item.journal_non_close_content_deltas for item in results
            ),
            "stable_latency_median_seconds": statistics.median(latencies) if latencies else None,
            "stable_latency_p95_seconds": _percentile(latencies, 0.95),
            "stable_latency_max_seconds": max(latencies) if latencies else None,
            "peak_scenario_rss_delta_bytes": max((item.peak_rss_delta_bytes for item in results), default=0),
        },
        "scenarios": [asdict(item) for item in results],
    }


def report_markdown(report: dict) -> str:
    summary = report["summary"]
    median = summary["stable_latency_median_seconds"]
    p95 = summary["stable_latency_p95_seconds"]
    maximum = summary["stable_latency_max_seconds"]
    latency_summary = (
        f"{median:.3f}s / {p95:.3f}s / {maximum:.3f}s"
        if median is not None and p95 is not None and maximum is not None
        else "n/a"
    )
    lines = [
        "# SunPack Watch validation",
        "",
        f"- Mode: `{report['mode']}`",
        f"- Elevated: `{report['process_elevated']}`",
        f"- Passed: `{summary['passed']}/{summary['scenario_count']}`",
        f"- Premature attempts: `{summary['premature_attempts']}`",
        f"- Events / observations: `{summary['events']} / {summary['observation_calls']}`",
        f"- Journal-known deltas: `{summary['journal_known_deltas']}/{summary['journal_delta_queries']}`",
        f"- Journal content / non-close content deltas: `{summary['journal_content_deltas']} / {summary['journal_non_close_content_deltas']}`",
        f"- Stable latency median / p95 / max: `{latency_summary}`",
        f"- Total runtime: `{report['total_seconds']:.3f}s`",
        "",
        "| Scenario | Pass | Premature | Events | Observations | Journal known | Stable latency | CPU |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for item in report["scenarios"]:
        latency = item["stable_latency_seconds"]
        lines.append(
            f"| {item['name']} | {'yes' if item['passed'] else 'no'} | {item['premature_attempts']} | "
            f"{item['event_count']} | {item['observation_calls']} | "
            f"{item['journal_known_deltas']}/{item['journal_delta_queries']} | "
            f"{latency:.3f}s | {item['cpu_seconds']:.3f}s |"
            if latency is not None
            else f"| {item['name']} | no | {item['premature_attempts']} | {item['event_count']} | "
            f"{item['observation_calls']} | {item['journal_known_deltas']}/{item['journal_delta_queries']} | n/a | {item['cpu_seconds']:.3f}s |"
        )
        for error in item["errors"]:
            lines.append(f"\n> `{item['name']}`: {error}")
    comparison = report.get("baseline_comparison")
    if comparison is not None:
        lines.extend(
            [
                "",
                "## Direct-USN baseline comparison",
                "",
                f"- Passed: `{comparison['passed']}`",
                f"- Complete Journal coverage: `{comparison['journal_coverage_complete']}`",
                f"- No premature processing: `{comparison['no_premature_processing']}`",
                f"- Premature attempts did not regress: `{comparison['premature_attempts_not_regressed']}`",
                "",
                "| Scenario | Baseline | Broker | Delta | Pass |",
                "|---|---:|---:|---:|---:|",
            ]
        )
        for item in comparison["scenarios"]:
            if "error" in item:
                lines.append(f"| {item['name']} | n/a | n/a | n/a | no ({item['error']}) |")
            else:
                lines.append(
                    f"| {item['name']} | {item['baseline_latency_seconds']:.3f}s | "
                    f"{item['current_latency_seconds']:.3f}s | {item['delta_seconds']:+.3f}s | "
                    f"{'yes' if item['passed'] else 'no'} |"
                )
    lines.append("")
    return "\n".join(lines)


def build_baseline_comparison(
    current: dict,
    baseline: dict,
    *,
    maximum_regression_seconds: float,
    maximum_regression_ratio: float,
) -> dict:
    baseline_scenarios = {item["name"]: item for item in baseline.get("scenarios", [])}
    comparisons = []
    for item in current["scenarios"]:
        peer = baseline_scenarios.get(item["name"])
        if peer is None:
            comparisons.append({"name": item["name"], "passed": False, "error": "missing baseline scenario"})
            continue
        current_latency = item.get("stable_latency_seconds")
        baseline_latency = peer.get("stable_latency_seconds")
        if current_latency is None or baseline_latency is None:
            comparisons.append({"name": item["name"], "passed": False, "error": "missing latency"})
            continue
        allowed = baseline_latency * (1.0 + maximum_regression_ratio) + maximum_regression_seconds
        comparisons.append(
            {
                "name": item["name"],
                "passed": bool(item.get("passed")) and current_latency <= allowed,
                "baseline_latency_seconds": baseline_latency,
                "current_latency_seconds": current_latency,
                "delta_seconds": current_latency - baseline_latency,
                "allowed_latency_seconds": allowed,
            }
        )
    current_summary = current["summary"]
    baseline_summary = baseline.get("summary", {})
    current_premature = int(current_summary["premature_attempts"])
    baseline_premature = int(baseline_summary.get("premature_attempts", 0))
    premature_attempts_not_regressed = current_premature <= baseline_premature
    return {
        "baseline_mode": baseline.get("mode", "unknown"),
        "maximum_regression_seconds": maximum_regression_seconds,
        "maximum_regression_ratio": maximum_regression_ratio,
        "journal_coverage_complete": current_summary["journal_known_deltas"] == current_summary["journal_delta_queries"],
        "no_premature_processing": current_premature == 0,
        "baseline_premature_attempts": baseline_premature,
        "current_premature_attempts": current_premature,
        "premature_attempts_not_regressed": premature_attempts_not_regressed,
        "scenarios": comparisons,
        "passed": (
            current_summary["failed"] == 0
            and premature_attempts_not_regressed
            and current_summary["journal_known_deltas"] == current_summary["journal_delta_queries"]
            and bool(comparisons)
            and all(item["passed"] for item in comparisons)
        ),
    }


def run_suite(args: argparse.Namespace) -> tuple[dict, Path]:
    broker_release = None
    if args.transport == "broker":
        from sunpack_native import watch_broker_acquire, watch_broker_is_connected, watch_broker_release

        watch_broker_acquire()
        if not watch_broker_is_connected():
            raise RuntimeError("SunPack Watch Broker did not establish its lifecycle lease")
        broker_release = watch_broker_release
    started_at = datetime.now(timezone.utc).isoformat()
    suite_started = time.perf_counter()
    payload = _zip_payload(args.payload_mb)
    scenarios = scenario_matrix()
    if args.scenario:
        selected = set(args.scenario)
        scenarios = [item for item in scenarios if item.name in selected]
    unknown = set(args.scenario or []) - {item.name for item in scenario_matrix()}
    if unknown:
        raise ValueError(f"unknown scenarios: {', '.join(sorted(unknown))}")
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    resumed: dict[str, ScenarioResult] = {}
    if args.resume and output.is_file():
        previous_report = json.loads(output.read_text(encoding="utf-8"))
        resumed = {
            str(item["name"]): ScenarioResult(**item)
            for item in previous_report.get("scenarios", [])
            if item.get("passed")
        }
    work_parent = Path(args.work_root).resolve() if args.work_root else output.parent / "work"
    work_parent.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix=f"sunpack-watch-{args.transport}-", dir=work_parent) as raw_base:
            base = Path(raw_base)
            results = []
            for index, scenario in enumerate(scenarios, 1):
                if scenario.name in resumed:
                    print(f"[{index}/{len(scenarios)}] {scenario.name} (resumed)", flush=True)
                    results.append(resumed[scenario.name])
                    continue
                print(f"[{index}/{len(scenarios)}] {scenario.name}", flush=True)
                results.append(
                    run_scenario(
                        base,
                        scenario,
                        payload,
                        chunk_bytes=args.chunk_kb * 1024,
                        delay_seconds=args.chunk_delay,
                    )
                )
    finally:
        if broker_release is not None:
            broker_release()
    report = build_report(args.transport, results, started_at, sum(item.total_seconds for item in results))
    if args.baseline:
        baseline_path = Path(args.baseline).resolve()
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
        report["baseline_path"] = str(baseline_path)
        report["baseline_comparison"] = build_baseline_comparison(
            report,
            baseline,
            maximum_regression_seconds=args.max_latency_regression_seconds,
            maximum_regression_ratio=args.max_latency_regression_ratio,
        )
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temporary, output)
    output.with_suffix(".md").write_text(report_markdown(report), encoding="utf-8")
    return report, output


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run real Windows/NTFS SunPack Watch validation scenarios.")
    parser.add_argument("--transport", choices=("broker", "direct"), default="broker")
    parser.add_argument("--output", required=True, help="JSON output path")
    parser.add_argument("--work-root", default="")
    parser.add_argument("--payload-mb", type=float, default=2.0)
    parser.add_argument("--chunk-kb", type=int, default=128)
    parser.add_argument("--chunk-delay", type=float, default=0.05)
    parser.add_argument("--scenario", action="append", default=[])
    parser.add_argument("--baseline", default="", help="Previous elevated/direct-USN report to compare against")
    parser.add_argument("--max-latency-regression-seconds", type=float, default=0.5)
    parser.add_argument("--max-latency-regression-ratio", type=float, default=0.05)
    parser.add_argument("--resume", action="store_true", help="Reuse passing scenarios from an existing output report")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    report, output = run_suite(args)
    print(json.dumps(report["summary"], ensure_ascii=False, indent=2), flush=True)
    print(output, flush=True)
    comparison = report.get("baseline_comparison")
    passed = report["summary"]["failed"] == 0 and (comparison is None or comparison["passed"])
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
