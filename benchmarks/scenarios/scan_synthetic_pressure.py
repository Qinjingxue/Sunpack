"""Profile the mixed-corpus pressure scan by pipeline layer.

This is a diagnostic script, not a pass/fail benchmark. It uses the exact corpus
and configuration from test_pressure so measurements explain that test directly.
"""
from __future__ import annotations

import argparse
import cProfile
import json
import pstats
import shutil
import time
import tracemalloc
import sys
from contextlib import contextmanager
from pathlib import Path

import psutil

from benchmarks.harness import benchmark_temp_dir, render_report, report_from_payload

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sunpack.coordinator.scanner import ScanOrchestrator
from tests.helpers.performance_fixtures import build_pressure_corpus, pressure_scan_config


@contextmanager
def timed_calls(specs: list[tuple[str, object, str]]):
    records: dict[str, dict[str, float | int]] = {}
    originals = []
    for label, owner, attribute in specs:
        original = getattr(owner, attribute)
        originals.append((owner, attribute, original))

        def wrapper(*args, __label=label, __original=original, **kwargs):
            before = time.perf_counter()
            try:
                return __original(*args, **kwargs)
            finally:
                elapsed = time.perf_counter() - before
                record = records.setdefault(__label, {"calls": 0, "seconds": 0.0})
                record["calls"] += 1
                record["seconds"] += elapsed

        setattr(owner, attribute, wrapper)
    try:
        yield records
    finally:
        for owner, attribute, original in reversed(originals):
            setattr(owner, attribute, original)


def layer_specs():
    from sunpack.coordinator.discovery import ArchiveDiscoveryPipeline
    from sunpack.coordinator.scan_session import DiscoveryScanSession
    from sunpack.coordinator.task_provider import ArchiveTaskProvider
    from sunpack.detection.confirmation import FormatConfirmation
    from sunpack.detection.scheduler import DetectionScheduler
    from sunpack.embedded.discovery import EmbeddedDiscovery
    from sunpack.filesystem.directory_scanner import DirectoryScanner
    from sunpack.relations.internal.group_builder import RelationsGroupBuilder
    from sunpack.relations.resolver import RelationResolver

    return [
        ("provider.discover_targets", ArchiveTaskProvider, "discover_targets"),
        ("provider.scan_targets", ArchiveTaskProvider, "scan_targets"),
        ("session.snapshot", DiscoveryScanSession, "snapshot_for_directory"),
        ("session.relations", DiscoveryScanSession, "relation_groups_for_directory"),
        ("session.candidates", DiscoveryScanSession, "candidates_for_directory"),
        ("filesystem.scan", DirectoryScanner, "scan"),
        ("relations.build", RelationsGroupBuilder, "build_candidate_groups"),
        ("relations.resolve", RelationResolver, "resolve"),
        ("detection.confirm_candidate", DetectionScheduler, "confirm"),
        ("detection.confirm_stage", FormatConfirmation, "confirm"),
        ("embedded.discover", EmbeddedDiscovery, "discover"),
        ("discovery.compose", ArchiveDiscoveryPipeline, "discover"),
    ]


def run_once(profile_path: Path | None, trace_memory: bool) -> dict:
    process = psutil.Process()
    root = benchmark_temp_dir("sunpack-pressure-profile-")
    try:
        build_started = time.perf_counter()
        expected = build_pressure_corpus(root)
        build_seconds = time.perf_counter() - build_started
        rss_before = process.memory_info().rss
        if trace_memory:
            tracemalloc.start(25)
        profile = cProfile.Profile()
        with timed_calls(layer_specs()) as layers:
            started = time.perf_counter()
            profile.enable()
            results = ScanOrchestrator(pressure_scan_config()).scan(str(root))
            profile.disable()
            elapsed = time.perf_counter() - started
        current = peak = 0
        allocations = []
        if trace_memory:
            current, peak = tracemalloc.get_traced_memory()
            allocations = [str(item) for item in tracemalloc.take_snapshot().statistics("lineno")[:20]]
            tracemalloc.stop()
        if profile_path:
            profile.dump_stats(str(profile_path))
        stats = pstats.Stats(profile)
        functions = []
        for (filename, line, name), values in stats.stats.items():
            cc, nc, total, cumulative, _callers = values
            functions.append({
                "function": f"{Path(filename).name}:{line}({name})",
                "calls": nc,
                "self_seconds": total,
                "cumulative_seconds": cumulative,
            })
        functions.sort(key=lambda item: item["cumulative_seconds"], reverse=True)
        return {
            "elapsed_seconds": elapsed,
            "corpus_build_seconds": build_seconds,
            "result_count": len(results),
            "correct": sorted(Path(item.main_path).name for item in results) == expected,
            "rss_delta_mib": (process.memory_info().rss - rss_before) / 1024**2,
            "tracemalloc_current_mib": current / 1024**2,
            "tracemalloc_peak_mib": peak / 1024**2,
            "layers": layers,
            "top_functions": functions[:40],
            "top_allocations": allocations,
        }
    finally:
        shutil.rmtree(root, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--json-out", default="")
    parser.add_argument("--profile-out", default="")
    parser.add_argument("--tracemalloc", action="store_true")
    args = parser.parse_args()
    rows = []
    for index in range(max(1, args.runs)):
        profile_path = Path(args.profile_out) if args.profile_out and index == 0 else None
        rows.append(run_once(profile_path, args.tracemalloc))
    payload = {"runs": rows}
    rendered = render_report(report_from_payload("scan.synthetic-pressure", payload))
    print(rendered)
    if args.json_out:
        output = Path(args.json_out)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")


if __name__ == "__main__":
    main()
