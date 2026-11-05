"""Paired, fresh-process tracker cost; run separately from the risk replay."""
from __future__ import annotations

import argparse
import gc
import inspect
import json
import statistics
import subprocess
import sys
import time
import tracemalloc
from pathlib import Path
from types import ModuleType

from sunpack_native import fast_hash128

from benchmarks.harness.reporting import report_from_payload, render_report
from benchmarks.harness.workspace import BenchmarkWorkspace
from benchmarks.quiet_window.corpus import generate
from sunpack.runtime.watch import quiet_policy


def _load(path):
    source = path.read_text(encoding="utf-8")
    module = ModuleType("sunpack_quiet_cost_baseline")
    module.__file__ = str(path)
    sys.modules[module.__name__] = module
    exec(compile(source, str(path), "exec"), module.__dict__)
    return module


def _observe(module, traces, repetitions):
    policy = module.AdaptiveQuietPolicy()
    started = time.process_time_ns()
    for _ in range(repetitions):
        for trace in traces:
            trackers = {file.key: module.AdaptiveQuietTracker(policy) for file in trace.files}
            for event in trace.observations:
                trackers[event.key].observe(event.at, size=event.size, mtime=event.mtime,
                                            change_usn=event.usn, content_changed=event.content_changed,
                                            learn_interval=event.learn_interval)
    return time.process_time_ns() - started


def _memory(module, count):
    gc.collect()
    tracemalloc.start()
    policy = module.AdaptiveQuietPolicy()
    before = tracemalloc.get_traced_memory()[0]
    trackers = [module.AdaptiveQuietTracker(policy) for _ in range(count)]
    for tracker in trackers:
        for index in range(14):
            now = index * 0.1
            tracker.observe(now, size=index, mtime=now)
    live, peak = tracemalloc.get_traced_memory()
    del tracker, trackers
    gc.collect()
    released = tracemalloc.get_traced_memory()[0]
    tracemalloc.stop()
    return {"live_bytes_per_tracker": (live - before) / count,
            "peak_traced_bytes": peak - before, "retained_after_release_bytes": released - before}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-source", type=Path, required=True)
    parser.add_argument("--processes", type=int, default=7)
    parser.add_argument("--observations", type=int, default=500_000, help="Minimum timed observations per candidate per process.")
    parser.add_argument("--trackers", type=int, default=4096)
    parser.add_argument("--pin-report", type=Path)
    parser.add_argument("--worker", type=int, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if min(args.processes, args.observations, args.trackers) <= 0:
        parser.error("counts must be positive")
    if args.worker is not None:
        baseline = _load(args.baseline_source)
        # All complex writers; multipart programs need four volumes. Writer
        # preparation and JSON IO are outside the tracker-only timer.
        traces = tuple(generate(1, ("development",), ("immediate",), (1, 4)))
        events = sum(len(trace.observations) for trace in traces)
        repetitions = max(1, (args.observations + events - 1) // events)
        order = [("baseline", baseline), ("candidate", quiet_policy)]
        if args.worker % 2:
            order.reverse()
        for _, module in order:
            _observe(module, traces, 2)
        result = {name: {"cpu_ns_per_observation": _observe(module, traces, repetitions) / (events * repetitions)}
                  for name, module in order}
        for name, module in order:
            result[name].update(_memory(module, args.trackers))
        result.update(process=args.worker, timed_observations=events * repetitions,
                      content_observations=sum(event.content_changed for trace in traces for event in trace.observations) * repetitions)
        print(json.dumps(result))
        return 0
    scenario = "scheduling.watch-quiet-cost"
    with BenchmarkWorkspace(scenario) as workspace:
        source_paths = {"baseline": args.baseline_source, "candidate": Path(inspect.getsourcefile(quiet_policy))}
        identities = {}
        for name, path in source_paths.items():
            source = path.read_text(encoding="utf-8")
            identities[name] = fast_hash128(source.encode("utf-8"))
            workspace.write_result_text(f"{name}.py.txt", source)
        for name in ("cost.py", "corpus.py", "writers.py"):
            workspace.write_result_text(name + ".txt", Path(__file__).with_name(name).read_text(encoding="utf-8"))
        samples = []
        for index in range(args.processes):
            command = [sys.executable, "-m", "benchmarks.quiet_window.cost", "--worker", str(index),
                       "--baseline-source", str(args.baseline_source.resolve()),
                       "--observations", str(args.observations), "--trackers", str(args.trackers)]
            row = json.loads(subprocess.check_output(command, text=True))
            samples.append(row)
            print(f"quiet-cost: process {index + 1}/{args.processes}", flush=True)
        ratios = [row["candidate"]["cpu_ns_per_observation"] / row["baseline"]["cpu_ns_per_observation"] for row in samples]
        summary = {name: {key: statistics.median(row[name][key] for row in samples) for key in samples[0][name]}
                   for name in ("baseline", "candidate")}
        summary.update(paired_cpu_ratio_median=statistics.median(ratios),
                       paired_cpu_ratio_range=[min(ratios), max(ratios)], artifacts=str(workspace.result_dir))
        payload = {"parameters": {"source_xxh128": identities, "processes": args.processes,
                                  "minimum_observations": args.observations, "live_trackers": args.trackers,
                                  "workload": "development-seed-0/all-complex-writers/immediate/widths-1-and-4",
                                  "scope": "tracker-observe-and-construction; allocation measured separately"},
                   "samples": samples, "summary": summary}
        rendered = render_report(report_from_payload(scenario, payload))
        workspace.write_result_text("report.json", rendered)
        if args.pin_report:
            args.pin_report.parent.mkdir(parents=True, exist_ok=True)
            args.pin_report.write_text(rendered, encoding="utf-8")
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
