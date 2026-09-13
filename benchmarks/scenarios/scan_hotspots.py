r"""Profile SunPack scan hot spots on large, messy directories.

Examples:
    python -m benchmarks scan hotspots C:\Users\29402\Desktop --mode filesystem --max-depth 1
    python -m benchmarks scan hotspots C:\Users\29402\Desktop --mode candidates --rss-stop-mib 1200
    python -m benchmarks scan hotspots C:\Users\29402\Desktop --mode full --json-out benchmarks\results\scan-hotspots.json --profile-out benchmarks\results\scan-hotspots.prof
"""

from __future__ import annotations

import argparse
import cProfile
import gc
import io
import json
import os
import pstats
import sys
import threading
import time
import tracemalloc
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import psutil
from benchmarks.harness import render_report, report_from_payload


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


class ResourceStop(RuntimeError):
    pass


def mib(value: int | float | None) -> float:
    return float(value or 0) / 1024 / 1024


def now() -> float:
    return time.perf_counter()


def process() -> psutil.Process:
    return psutil.Process(os.getpid())


def rss_bytes() -> int:
    return process().memory_info().rss


def read_bytes() -> int:
    try:
        return int(process().io_counters().read_bytes)
    except (AttributeError, OSError, psutil.Error):
        return 0


def cpu_times_total() -> float:
    try:
        times = process().cpu_times()
        return float(times.user + times.system)
    except psutil.Error:
        return 0.0


@dataclass
class Hotspot:
    label: str
    count: int = 0
    total_sec: float = 0.0
    max_sec: float = 0.0
    total_read_bytes: int = 0
    max_read_bytes: int = 0
    max_rss_delta: int = 0
    max_output_count: int | None = None
    examples: list[dict[str, Any]] = field(default_factory=list)

    def record(self, elapsed: float, read_delta: int, rss_delta: int, output_count: int | None, example: dict[str, Any]) -> None:
        self.count += 1
        self.total_sec += elapsed
        self.max_sec = max(self.max_sec, elapsed)
        self.total_read_bytes += max(0, read_delta)
        self.max_read_bytes = max(self.max_read_bytes, max(0, read_delta))
        self.max_rss_delta = max(self.max_rss_delta, rss_delta)
        if output_count is not None:
            self.max_output_count = output_count if self.max_output_count is None else max(self.max_output_count, output_count)
        if len(self.examples) < 5 or elapsed >= self.max_sec:
            self.examples.append(example)
            self.examples = sorted(self.examples, key=lambda item: item.get("elapsed_sec", 0), reverse=True)[:5]

    def as_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "count": self.count,
            "total_sec": round(self.total_sec, 6),
            "avg_ms": round((self.total_sec / self.count) * 1000, 3) if self.count else 0,
            "max_sec": round(self.max_sec, 6),
            "total_read_mib": round(mib(self.total_read_bytes), 3),
            "max_read_mib": round(mib(self.max_read_bytes), 3),
            "max_rss_delta_mib": round(mib(self.max_rss_delta), 3),
            "max_output_count": self.max_output_count,
            "examples": self.examples,
        }


class HotspotRecorder:
    def __init__(self, *, rss_stop_mib: float | None = None, slow_call_sec: float = 1.0):
        self.rss_stop_mib = rss_stop_mib
        self.slow_call_sec = slow_call_sec
        self.hotspots: dict[str, Hotspot] = {}

    def guard(self, label: str) -> None:
        current = mib(rss_bytes())
        if self.rss_stop_mib is not None and current >= self.rss_stop_mib:
            raise ResourceStop(f"RSS {current:.1f} MiB reached limit {self.rss_stop_mib:.1f} MiB in {label}")

    def wrap(self, owner: Any, name: str, label: str | None = None) -> None:
        original = getattr(owner, name)
        metric_label = label or f"{getattr(owner, '__name__', owner.__class__.__name__)}.{name}"
        recorder = self

        def wrapper(*args, **kwargs):
            recorder.guard(metric_label + ":before")
            before_rss = rss_bytes()
            before_read = read_bytes()
            started = now()
            ok = False
            try:
                result = original(*args, **kwargs)
                ok = True
                return result
            finally:
                elapsed = now() - started
                after_rss = rss_bytes()
                after_read = read_bytes()
                output_count = result_count(locals().get("result")) if ok else None
                example = {
                    "elapsed_sec": round(elapsed, 6),
                    "rss_after_mib": round(mib(after_rss), 3),
                    "rss_delta_mib": round(mib(after_rss - before_rss), 3),
                    "read_delta_mib": round(mib(after_read - before_read), 3),
                    "output_count": output_count,
                    "args": summarize_args(args, kwargs),
                }
                self.hotspots.setdefault(metric_label, Hotspot(metric_label)).record(
                    elapsed,
                    after_read - before_read,
                    after_rss - before_rss,
                    output_count,
                    example,
                )
                if elapsed >= self.slow_call_sec:
                    print(
                        f"slow label={metric_label} sec={elapsed:.3f} "
                        f"rss_mib={mib(after_rss):.1f} read_mib={mib(after_read - before_read):.1f} "
                        f"out={output_count} args={example['args']}",
                        flush=True,
                    )
                recorder.guard(metric_label + ":after")

        setattr(owner, name, wrapper)

    def report(self, top: int) -> list[dict[str, Any]]:
        rows = [hotspot.as_dict() for hotspot in self.hotspots.values()]
        rows.sort(key=lambda item: (item["total_sec"], item["max_sec"]), reverse=True)
        return rows[:top]


class Sampler:
    def __init__(self, interval: float):
        self.interval = max(0.05, float(interval))
        self.samples: list[dict[str, Any]] = []
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._start = 0.0

    def start(self) -> None:
        self._start = now()
        self._thread = threading.Thread(target=self._run, name="scan-hotspot-sampler", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    def _run(self) -> None:
        proc = process()
        proc.cpu_percent(None)
        while not self._stop.wait(self.interval):
            try:
                self.samples.append({
                    "t_sec": round(now() - self._start, 3),
                    "rss_mib": round(mib(proc.memory_info().rss), 3),
                    "read_mib": round(mib(proc.io_counters().read_bytes), 3),
                    "cpu_percent": proc.cpu_percent(None),
                })
            except psutil.Error:
                return

    def summary(self) -> dict[str, Any]:
        if not self.samples:
            return {}
        max_rss = max(item["rss_mib"] for item in self.samples)
        max_read = max(item["read_mib"] for item in self.samples)
        min_read = min(item["read_mib"] for item in self.samples)
        max_cpu = max(item["cpu_percent"] for item in self.samples)
        return {
            "sample_count": len(self.samples),
            "peak_rss_mib": max_rss,
            "read_delta_mib": round(max_read - min_read, 3),
            "peak_cpu_percent": max_cpu,
            "last_samples": self.samples[-10:],
        }


def result_count(result: Any) -> int | None:
    if result is None:
        return None
    if isinstance(result, tuple):
        return result_count(result[0])
    if isinstance(result, dict):
        return len(result)
    if isinstance(result, (list, set)):
        return len(result)
    try:
        return len(result)
    except TypeError:
        pass
    iter_columns = getattr(result, "iter_columns", None)
    if callable(iter_columns):
        return sum(1 for _ in iter_columns())
    entries = getattr(result, "entries", None)
    if entries is not None:
        return len(entries)
    return None


def summarize_args(args: tuple[Any, ...], kwargs: dict[str, Any]) -> str:
    parts: list[str] = []
    for arg in args[:3]:
        if isinstance(arg, (str, Path)):
            parts.append(str(arg))
            continue
        root_path = getattr(arg, "root_path", None)
        if root_path is not None:
            parts.append(f"{arg.__class__.__name__}(root={root_path})")
            continue
        fact_name = getattr(arg, "fact_name", None)
        if fact_name is not None:
            parts.append(f"{arg.__class__.__name__}(fact={fact_name})")
            continue
        parts.append(arg.__class__.__name__)
    if kwargs:
        parts.append("kwargs=" + ",".join(sorted(kwargs.keys())))
    return " | ".join(parts)


def load_runtime_config() -> dict:
    from sunpack.config.loader import load_config

    return load_config()


def install_wrappers(recorder: HotspotRecorder) -> None:
    import sunpack.filesystem.directory_scanner as directory_scanner
    import sunpack.coordinator.scan_session as scan_session
    import sunpack.coordinator.target_scan as target_scan
    import sunpack.detection.scheduler as detection_scheduler
    import sunpack.coordinator.task_provider as task_provider
    import sunpack.coordinator.task_scan as task_scan
    import sunpack.relations.scheduler as relations_scheduler
    import sunpack.relations.internal.group_builder as group_builder
    import sunpack.detection.pipeline.facts.batch_provider as batch_provider
    import sunpack.detection.pipeline.processors.runner as processor_runner
    import sunpack.detection.pipeline.rules.manager as rule_manager

    recorder.wrap(directory_scanner, "_NATIVE_SCAN_DIRECTORY_SNAPSHOT", "native.scan_directory_snapshot")
    recorder.wrap(directory_scanner.DirectoryScanner, "scan", "filesystem.DirectoryScanner.scan")
    recorder.wrap(directory_scanner.DirectoryScanner, "_scan_native", "filesystem.DirectoryScanner._scan_native")
    recorder.wrap(directory_scanner.DirectoryScanner, "_apply_ordered_filters", "filesystem.apply_ordered_filters")
    recorder.wrap(directory_scanner, "apply_filter_to_entries", "filesystem.apply_filter_to_entries")

    recorder.wrap(relations_scheduler.RelationsScheduler, "build_candidate_groups", "relations.build_candidate_groups")
    recorder.wrap(group_builder.RelationsGroupBuilder, "build_candidate_groups", "relations.builder.build_candidate_groups")

    recorder.wrap(scan_session, "_native_batch_file_head_facts", "native.batch_file_head_facts")
    recorder.wrap(scan_session.DetectionScanSession, "snapshot_for_directory", "session.snapshot_for_directory")
    recorder.wrap(scan_session.DetectionScanSession, "shallow_snapshot_for_directory", "session.shallow_snapshot_for_directory")
    recorder.wrap(scan_session.DetectionScanSession, "relation_groups_for_directory", "session.relation_groups_for_directory")
    recorder.wrap(scan_session.DetectionScanSession, "fact_bags_for_directory", "session.fact_bags_for_directory")
    recorder.wrap(scan_session.DetectionScanSession, "file_head_facts_for_paths", "session.file_head_facts_for_paths")
    recorder.wrap(scan_session.DetectionScanSession, "directory_identity_for_path", "session.directory_identity_for_path")

    recorder.wrap(target_scan, "build_fact_bags_for_targets", "coordinator.build_candidate_fact_bags")
    recorder.wrap(detection_scheduler.DetectionScheduler, "evaluate_pool", "detection.evaluate_pool")
    recorder.wrap(detection_scheduler.DetectionScheduler, "evaluate_bags", "detection.evaluate_bags")
    recorder.wrap(detection_scheduler.DetectionScheduler, "_ensure_pool_facts", "detection.ensure_pool_facts")

    recorder.wrap(task_provider.ArchiveTaskProvider, "scan_targets", "task_provider.scan_targets")
    recorder.wrap(task_scan.ArchiveTaskScanner, "scan_targets", "task_scanner.scan_targets")

    recorder.wrap(batch_provider.BatchFactProvider, "_prefetch_file_head_facts", "facts.prefetch_file_head_facts")
    recorder.wrap(batch_provider.BatchFactProvider, "prefill_facts", "facts.prefill_facts")
    recorder.wrap(batch_provider.BatchFactProvider, "prefill_fact", "facts.prefill_fact")
    recorder.wrap(processor_runner.ProcessingCoordinator, "ensure_facts", "processors.ensure_facts")
    recorder.wrap(processor_runner.ProcessingCoordinator, "ensure_fact", "processors.ensure_fact")
    recorder.wrap(rule_manager.RuleManager, "evaluate_pool", "rules.evaluate_pool")
    recorder.wrap(rule_manager.RuleManager, "_run_precheck", "rules.run_precheck")


def summarize_scan_session(session: Any | None) -> dict[str, Any]:
    if session is None:
        return {}
    return {
        "snapshots": len(getattr(session, "_snapshots", {}) or {}),
        "scene_snapshots": len(getattr(session, "_scene_snapshots", {}) or {}),
        "relation_groups": len(getattr(session, "_relation_groups", {}) or {}),
        "fact_bags": len(getattr(session, "_fact_bags", {}) or {}),
        "file_head_facts": len(getattr(session, "_file_head_facts", {}) or {}),
        "scan_roots": list(getattr(session, "_scan_roots", []) or []),
    }


def run_mode(mode: str, target: str, max_depth: int | None, config: dict) -> tuple[Any, dict[str, Any]]:
    target_path = str(Path(target).resolve())
    session = None
    extra: dict[str, Any] = {}

    if mode == "filesystem":
        from sunpack.filesystem.directory_scanner import DirectoryScanner

        result = DirectoryScanner(target_path, max_depth=max_depth, config=config).scan()
        columns = list(result.iter_columns())
        extra["entries"] = len(result)
        extra["files"] = sum(1 for _path, is_dir, _size, _mtime in columns if not is_dir)
        extra["dirs"] = sum(1 for _path, is_dir, _size, _mtime in columns if is_dir)
        extra["total_file_size_mib"] = round(mib(sum(int(size or 0) for _path, is_dir, size, _mtime in columns if not is_dir)), 3)
        return result, extra

    if mode in {"candidates", "evaluate"}:
        from sunpack.detection.scheduler import DetectionScheduler
        from sunpack.coordinator.scan_session import DetectionScanSession
        from sunpack.coordinator.target_scan import build_fact_bags_for_targets

        scheduler = DetectionScheduler(config)
        session = DetectionScanSession(config=config)
        bags = build_fact_bags_for_targets([target_path], session=session, config=config)
        extra["candidate_bags"] = len(bags)
        if mode == "candidates":
            extra["scan_session"] = summarize_scan_session(session)
            return bags, extra
        detections = scheduler.evaluate_bags(bags, scan_session=session)
        extra["detections"] = len(detections)
        extra["extractable"] = sum(1 for item in detections if item.decision.should_extract)
        extra["scan_session"] = summarize_scan_session(session)
        return detections, extra

    if mode == "full":
        from sunpack.coordinator.scanner import ScanOrchestrator

        orchestrator = ScanOrchestrator(config)
        result = orchestrator.scan_targets([target_path])
        provider = orchestrator.task_scanner.provider
        session = getattr(orchestrator.task_scanner, "last_scan_session", None)
        if session is None:
            session = getattr(provider.detector, "_active_scan_session", None)
        extra["tasks"] = len(result)
        extra["scan_session"] = summarize_scan_session(session)
        return result, extra

    raise ValueError(f"Unsupported mode: {mode}")


def profile_summary(profile: cProfile.Profile, sort: str, limit: int) -> str:
    output = io.StringIO()
    stats = pstats.Stats(profile, stream=output).strip_dirs().sort_stats(sort)
    stats.print_stats(limit)
    return output.getvalue()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="File or directory to scan.")
    parser.add_argument("--mode", choices=["filesystem", "candidates", "evaluate", "full"], default="full")
    parser.add_argument("--max-depth", type=int, default=None, help="Only used by --mode filesystem.")
    parser.add_argument("--rss-stop-mib", type=float, default=None, help="Abort between instrumented calls after this RSS.")
    parser.add_argument("--sample-interval", type=float, default=0.5)
    parser.add_argument("--slow-call-sec", type=float, default=1.0)
    parser.add_argument("--top", type=int, default=40)
    parser.add_argument("--profile-out", default="", help="Optional cProfile binary output path.")
    parser.add_argument("--json-out", default="", help="Optional JSON summary output path.")
    parser.add_argument("--no-cprofile", action="store_true")
    parser.add_argument("--tracemalloc", action="store_true")
    args = parser.parse_args()

    os.chdir(REPO_ROOT)
    config = load_runtime_config()
    recorder = HotspotRecorder(rss_stop_mib=args.rss_stop_mib, slow_call_sec=args.slow_call_sec)
    install_wrappers(recorder)

    gc.collect()
    start_rss = rss_bytes()
    start_read = read_bytes()
    start_cpu = cpu_times_total()
    started = now()
    sampler = Sampler(args.sample_interval)
    profile = cProfile.Profile()
    stopped = None
    result = None
    extra: dict[str, Any] = {}

    if args.tracemalloc:
        tracemalloc.start(25)
    sampler.start()
    try:
        if args.no_cprofile:
            result, extra = run_mode(args.mode, args.target, args.max_depth, config)
        else:
            result, extra = profile.runcall(run_mode, args.mode, args.target, args.max_depth, config)
    except ResourceStop as exc:
        stopped = str(exc)
    finally:
        sampler.stop()

    elapsed = now() - started
    end_rss = rss_bytes()
    end_read = read_bytes()
    end_cpu = cpu_times_total()
    trace_summary = {}
    if args.tracemalloc:
        current, peak = tracemalloc.get_traced_memory()
        top_allocs = []
        for stat in tracemalloc.take_snapshot().statistics("lineno")[:20]:
            frame = stat.traceback[0]
            top_allocs.append({
                "size_mib": round(mib(stat.size), 3),
                "count": stat.count,
                "location": f"{frame.filename}:{frame.lineno}",
            })
        tracemalloc.stop()
        trace_summary = {
            "current_mib": round(mib(current), 3),
            "peak_mib": round(mib(peak), 3),
            "top_allocations": top_allocs,
        }

    cprofile_text = "" if args.no_cprofile else profile_summary(profile, "cumulative", args.top)
    if args.profile_out and not args.no_cprofile:
        profile_path = Path(args.profile_out)
        profile_path.parent.mkdir(parents=True, exist_ok=True)
        profile.dump_stats(str(profile_path))

    summary = {
        "target": str(Path(args.target).resolve()),
        "mode": args.mode,
        "stopped": stopped,
        "elapsed_sec": round(elapsed, 6),
        "rss_start_mib": round(mib(start_rss), 3),
        "rss_end_mib": round(mib(end_rss), 3),
        "rss_delta_mib": round(mib(end_rss - start_rss), 3),
        "read_delta_mib": round(mib(end_read - start_read), 3),
        "cpu_time_delta_sec": round(end_cpu - start_cpu, 6),
        "result_count": result_count(result),
        "extra": extra,
        "sampler": sampler.summary(),
        "hotspots": recorder.report(args.top),
        "tracemalloc": trace_summary,
    }

    rendered = render_report(report_from_payload("scan.hotspots", summary))
    if args.json_out:
        json_path = Path(args.json_out)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(rendered, encoding="utf-8")

    print(rendered)
    print("\n== Instrumented hot spots ==")
    for row in summary["hotspots"]:
        print(
            f"{row['total_sec']:9.3f}s count={row['count']:6d} "
            f"avg={row['avg_ms']:9.3f}ms max={row['max_sec']:8.3f}s "
            f"read={row['total_read_mib']:9.1f}MiB rss+max={row['max_rss_delta_mib']:8.1f}MiB "
            f"out_max={row['max_output_count']} {row['label']}"
        )
        for example in row["examples"][:2]:
            print(f"    example {example}")
    if trace_summary:
        print("\n== Top allocations ==")
        for row in trace_summary.get("top_allocations", [])[:10]:
            print(f"{row['size_mib']:8.1f} MiB {row['count']:8d} {row['location']}")
    if cprofile_text:
        print("\n== cProfile cumulative ==")
        print(cprofile_text)

    return 2 if stopped else 0


if __name__ == "__main__":
    raise SystemExit(main())
