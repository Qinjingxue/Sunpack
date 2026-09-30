from __future__ import annotations

"""Compare the committed broker and working tree with identical queue loads."""

import argparse
import asyncio
import hashlib
import os
import statistics
import subprocess
import sys
from pathlib import Path
from types import ModuleType

from benchmarks.harness import BenchmarkReport, BenchmarkWorkspace, measure, write_report
from sunpack.pipeline.coordinator import async_work as candidate
from sunpack.core.support.work_context import WorkContext


REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_PATH = "sunpack/pipeline/coordinator/async_work.py"
STAGES = ("background_source_cleanup", "discover_detect", "input_plan",
          "extract_continuation", "output_promotion", "extractor_close")


def _baseline(ref: str) -> tuple[ModuleType, str, str]:
    revision = subprocess.check_output(
        ["git", "rev-parse", "--verify", f"{ref}^{{commit}}"], cwd=REPO_ROOT, text=True,
    ).strip()
    source = subprocess.check_output(
        ["git", "show", f"{revision}:{SOURCE_PATH}"], cwd=REPO_ROOT, text=True, encoding="utf-8",
    )
    module = ModuleType("sunpack_broker_queue_baseline")
    module.__file__ = f"{revision}:{SOURCE_PATH}"
    sys.modules[module.__name__] = module
    exec(compile(source, module.__file__, "exec"), module.__dict__)
    return module, revision, hashlib.sha256(source.encode("utf-8")).hexdigest()


def _items(count: int, mixed: bool):
    # Selection only touches context.stage and sequence. Use the production
    # work-item/context records; no filesystem or archive payload is involved.
    return [candidate._WorkItem(
        context=WorkContext(request_id="r", file_id=str(index),
                            stage=STAGES[index % len(STAGES)] if mixed else "discover_detect"),
        operation=None, future=None, token=None, sequence=index + 1,
    ) for index in range(count)]


def _queue(module, items):
    jobs = module._RequestQueue().jobs
    for item in items:
        jobs.append(item)
    return jobs


def _selection_call(module, items, repeats):
    # Exclude queue construction from the single-selection measurement.
    queues = [_queue(module, items) for _ in range(repeats)]
    broker = object.__new__(module.AsyncWorkBroker)
    broker._sequence = len(items) * 2 + 31
    return lambda: [broker._take_prioritized(jobs).sequence for jobs in queues]


def _drain_call(module, items):
    def run():
        jobs = _queue(module, items)
        broker = object.__new__(module.AsyncWorkBroker)
        broker._sequence = len(items) * 2 + 31
        order = []
        while jobs:
            order.append(broker._take_prioritized(jobs).sequence)
        return order
    return run


def _broker_call(module, count, requests, capacity):
    async def run():
        broker = module.AsyncWorkBroker(thread_capacity=capacity, max_pending_jobs=count)
        try:
            result = await asyncio.gather(*(
                broker.run(
                    STAGES[index % len(STAGES)], str(index), lambda value: value, index,
                    request_id=f"request-{index % requests}",
                    origin="watch" if (index % requests) % 2 else "foreground",
                ) for index in range(count)
            ))
            assert broker.pending_jobs == broker.active_jobs == 0
            assert broker._pending_slots._value == broker.max_pending_jobs
            return result
        finally:
            await broker.close()
    return lambda: asyncio.run(run())


def _compare(report, baseline, *, label, kind, count, mixed, requests,
             capacity, repeats, runs, warmups):
    items = _items(count, mixed)
    rows = {"before": [], "after": []}
    for iteration in range(-warmups, runs):
        # Alternate A/B order to reduce ordering and thermal bias.
        order = (("before", baseline), ("after", candidate))
        if iteration % 2:
            order = tuple(reversed(order))
        values = {}
        for implementation, module in order:
            if kind == "selection":
                call = _selection_call(module, items, repeats)
            elif kind == "enqueue_and_drain":
                call = _drain_call(module, items)
            else:
                call = _broker_call(module, count, requests, capacity)
            measured = measure(call, runs=1)[0]
            values[implementation] = measured.value
            if iteration >= 0:
                rows[implementation].append(measured)
                report.samples.append({
                    "case": label, "implementation": implementation,
                    "iteration": iteration, "operations": repeats if kind == "selection" else count,
                    "wall_ms": measured.wall_ms, "cpu_ms": measured.cpu_ms,
                })
        assert values["before"] == values["after"], f"dispatch/results differ in {label}"
        if kind == "broker":
            assert values["after"] == list(range(count))
    divisor = repeats if kind == "selection" else 1
    before = statistics.median(row.wall_ms for row in rows["before"]) / divisor
    after = statistics.median(row.wall_ms for row in rows["after"]) / divisor
    result = {
        "case": label, "kind": kind, "jobs": count,
        "mixed_stages": mixed, "requests": requests, "thread_capacity": capacity,
        "before_median_ms": before, "after_median_ms": after,
        "speedup": before / after, "time_reduction_percent": (1 - after / before) * 100,
        "before_median_cpu_ms": statistics.median(row.cpu_ms for row in rows["before"]) / divisor,
        "after_median_cpu_ms": statistics.median(row.cpu_ms for row in rows["after"]) / divisor,
        "dispatch_order_or_results_equal": True,
    }
    report.summary["cases"].append(result)
    print(f"{label}: {before:.6f} -> {after:.6f} ms ({before / after:.2f}x)", flush=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-ref", required=True, help="Git commit containing the before implementation.")
    parser.add_argument("--sizes", default="1,8,128,512,2048,4096")
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--selection-repeats", type=int, default=32)
    parser.add_argument("--broker-jobs", type=int, default=1024)
    parser.add_argument("--thread-capacity", type=int, default=4)
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args(argv)
    sizes = [int(value) for value in args.sizes.split(",")]
    if (not sizes or min(sizes) < 1 or args.runs < 1 or args.warmups < 0
            or min(args.selection_repeats, args.broker_jobs, args.thread_capacity) < 1):
        parser.error("sizes, runs, repeats, broker jobs and thread capacity must be positive; warmups nonnegative")
    baseline, revision, source_hash = _baseline(args.baseline_ref)
    candidate_source = (REPO_ROOT / SOURCE_PATH).read_text(encoding="utf-8")
    report = BenchmarkReport(
        scenario="scheduling.broker-queue",
        parameters={
            "baseline_revision": revision, "baseline_source_sha256": source_hash,
            "candidate_source_sha256": hashlib.sha256(candidate_source.encode("utf-8")).hexdigest(),
            "sizes": sizes, "runs": args.runs, "warmups": args.warmups,
            "selection_repeats": args.selection_repeats, "broker_jobs": args.broker_jobs,
            "thread_capacity": args.thread_capacity, "logical_processors": os.cpu_count(),
            "method": "Exact committed baseline versus working-tree production methods; alternating A/B, same metadata. Single selection excludes queue construction; batch includes enqueue and drain; broker includes executor and event-loop lifecycle. No archive IO/decoding measured.",
        },
        summary={"cases": []},
    )
    with BenchmarkWorkspace(report.scenario, results_root=args.results_root) as workspace:
        try:
            for count in sizes:
                for mixed in (False, True):
                    shape = "mixed" if mixed else "same-stage"
                    for kind in ("selection", "enqueue_and_drain"):
                        _compare(report, baseline, label=f"{kind}/{shape}/{count}", kind=kind,
                                 count=count, mixed=mixed, requests=1, capacity=args.thread_capacity,
                                 repeats=args.selection_repeats, runs=args.runs, warmups=args.warmups)
            for requests in (1, min(32, args.broker_jobs)):
                _compare(report, baseline, label=f"broker/{args.broker_jobs}/{requests}-requests", kind="broker",
                         count=args.broker_jobs, mixed=True, requests=requests, capacity=args.thread_capacity,
                         repeats=1, runs=args.runs, warmups=args.warmups)
        finally:
            write_report(report, workspace.result_dir / "report.json")
            if args.json_out:
                write_report(report, args.json_out)
            print(f"report: {workspace.result_dir / 'report.json'}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
