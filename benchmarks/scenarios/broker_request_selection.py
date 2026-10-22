from __future__ import annotations

"""Compare committed and working-tree production request scheduling."""

import argparse
import asyncio
import gc
import os
import statistics
import subprocess
import threading
import time
import tracemalloc
from collections import deque

from benchmarks.harness import BenchmarkReport, BenchmarkWorkspace, measure, write_report
from benchmarks.scenarios.broker_queue import REPO_ROOT, SOURCE_PATH, _baseline
from sunpack.pipeline.coordinator import async_work as candidate


def _micro(module, size: int, shape: str, repeats: int):
    broker = object.__new__(module.AsyncWorkBroker)
    ids = [f"watch-{index}" for index in range(size)]
    origins = ["watch"] * size
    if shape == "foreground-tail":
        origins[-1] = "foreground"
    elif shape == "foreground-head":
        origins[0] = "foreground"
    broker._queues = {key: module._RequestQueue(origin=origin) for key, origin in zip(ids, origins)}
    if hasattr(module, "_RequestOrder"):
        broker._request_order = module._RequestOrder()
        for key, origin in zip(ids, origins):
            broker._request_order.append(key, origin)
        selected_origin = "watch" if shape == "all-watch" else "foreground"
        restore = lambda key: broker._request_order.append(key, selected_origin)
    else:
        broker._request_order = deque(ids)
        restore = (broker._request_order.appendleft if shape == "foreground-head"
                   else broker._request_order.append)
    select = broker._pop_next_request_id

    def run():
        for _ in range(repeats):
            restore(select())
    return run


def _order_memory(module, size: int, shape: str):
    # Isolate scheduler metadata; request IDs and job records are shared input.
    ids = [f"request-{index}" for index in range(size)]
    gc.collect()
    tracemalloc.start()
    try:
        if hasattr(module, "_RequestOrder"):
            order = module._RequestOrder()
            for key in ids:
                order.append(key, "foreground" if shape == "foreground" else "watch")
            if shape == "promoted":
                for key in reversed(ids):
                    order.promote(key)
        else:
            order = deque(ids)
        populated, peak = tracemalloc.get_traced_memory()
        while order:
            order.popleft()
        # Drop interpreter tuple freelists before interpreting retained bytes
        # as scheduler metadata; this is separate from all timing samples.
        gc.collect()
        drained, _ = tracemalloc.get_traced_memory()
        del order
        gc.collect()
        destroyed, _ = tracemalloc.get_traced_memory()
        return {"populated_bytes": populated, "peak_bytes": peak,
                "drained_bytes": drained, "destroyed_bytes": destroyed}
    finally:
        tracemalloc.stop()


async def _broker(module, count: int, shape: str, capacity: int, *, diagnostic: bool = False):
    """One fixed admission burst; real executor, run, dispatch and completion.

    Event barriers saturate all worker slots before the burst is admitted.
    There are no new admissions after release, so stable priority order is
    known in advance. Both arms use their actual production selector.
    """
    broker = module.AsyncWorkBroker(thread_capacity=capacity)
    gate = threading.Event()
    ready = asyncio.Event()
    loop = asyncio.get_running_loop()
    entered = 0
    tasks = []
    blockers = []
    observed = []
    timings = {"selection_ns": 0, "notify_ns": 0, "selection_calls": 0}

    def started():
        nonlocal entered
        entered += 1
        if entered == capacity:
            ready.set()

    def block():
        loop.call_soon_threadsafe(started)
        if not gate.wait(60):
            raise TimeoutError("benchmark admission barrier timed out")

    def identity(value):
        return value

    try:
        blockers = [asyncio.create_task(broker.run(
            "discover_detect", "", block, request_id=f"blocker-{index}", origin="watch",
        )) for index in range(capacity)]
        await asyncio.wait_for(ready.wait(), timeout=60)
        tail_cli = min(8, max(1, count // 16)) if shape == "mixed-tail" else 0
        foreground = set(range(count - tail_cli, count))
        if shape == "foreground-distinct":
            foreground = set(range(count))
        request_ids = ["shared-watch" if shape == "watch-shared" else f"request-{index}"
                       for index in range(count)]
        expected = [request_ids[index] for index in range(count) if index in foreground]
        expected += [request_ids[index] for index in range(count) if index not in foreground]
        # Capture the dispatch order in both arms; other production methods
        # and thread capacity remain identical.
        production_select = broker._pop_next_request_id
        def select():
            stamp = time.perf_counter_ns() if diagnostic else 0
            value = production_select()
            if diagnostic:
                timings["selection_ns"] += time.perf_counter_ns() - stamp
                timings["selection_calls"] += 1
            observed.append(value)
            return value
        broker._pop_next_request_id = select
        if diagnostic:
            notify = broker._notify_state_changed
            def timed_notify():
                stamp = time.perf_counter_ns()
                notify()
                timings["notify_ns"] += time.perf_counter_ns() - stamp
            broker._notify_state_changed = timed_notify

        wall_start = time.perf_counter_ns()
        cpu_start = time.process_time_ns()
        tasks = [asyncio.create_task(broker.run(
            "discover_detect", "", identity, index, request_id=request_ids[index],
            origin="foreground" if index in foreground else "watch",
        )) for index in range(count)]
        # All run() tasks were scheduled before this callback. The capacity
        # and pending bound guarantee they reach their future await first.
        admitted = loop.create_future()
        loop.call_soon(admitted.set_result, None)
        await admitted
        assert broker.pending_jobs == count
        admission_ms = (time.perf_counter_ns() - wall_start) / 1e6
        timings["selection_ns"] = timings["notify_ns"] = 0
        drain_start = time.perf_counter_ns()
        gate.set()
        results = await asyncio.gather(*tasks)
        await asyncio.gather(*blockers)
        finished = time.perf_counter_ns()
        assert results == list(range(count))
        assert observed == expected, "before and after must dispatch in identical order"
        assert broker.pending_jobs == broker.active_jobs == 0
        assert broker._pending_slots._value == broker.max_pending_jobs
        return {
            "admission_ms": admission_ms,
            "drain_ms": (finished - drain_start) / 1e6,
            "total_ms": (finished - wall_start) / 1e6,
            "cpu_ms": (time.process_time_ns() - cpu_start) / 1e6,
            **({key.replace("_ns", "_ms"): value / 1e6 if key.endswith("_ns") else value
                for key, value in timings.items()} if diagnostic else {}),
        }
    finally:
        gate.set()
        await asyncio.gather(*tasks, *blockers, return_exceptions=True)
        await broker.close()
        broker.__dict__.pop("_pop_next_request_id", None)
        broker.__dict__.pop("_notify_state_changed", None)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-ref", required=True)
    parser.add_argument("--sizes", default="1,8,32,128,512,2048,4096")
    parser.add_argument("--broker-sizes", default="128,512,2048,4064")
    parser.add_argument("--thread-capacity", type=int, default=32)
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--warmups", type=int, default=1)
    args = parser.parse_args(argv)
    sizes = [int(value) for value in args.sizes.split(",")]
    broker_sizes = [int(value) for value in args.broker_sizes.split(",")]
    if (min(*sizes, *broker_sizes, args.runs, args.thread_capacity) < 1 or args.warmups < 0
            or max(broker_sizes) + args.thread_capacity > 4096):
        parser.error("positive sizes/runs/capacity required; broker jobs plus capacity must fit 4096")
    baseline, revision = _baseline(args.baseline_ref)
    implementations = (("before", baseline), ("after", candidate))
    report = BenchmarkReport(
        scenario="scheduling.broker-request-selection",
        parameters={**vars(args), "logical_processors": os.cpu_count(),
                    "pending_bound": 4096,
                    "baseline_revision": revision,
                    "candidate_diff": subprocess.check_output(
                        ["git", "diff", "--", SOURCE_PATH], cwd=REPO_ROOT, text=True, encoding="utf-8"),
                    "method": "Exact committed versus working-tree production scheduling; alternating A/B. Real broker burst, event barriers, identical dispatch order/results, default pending bound. No archive IO or new admissions after release. Micro includes requeue; CPU uses process_time_ns."},
        summary={"micro": [], "broker": [], "diagnostic": [], "order_memory": []},
    )
    with BenchmarkWorkspace(report.scenario) as workspace:
        try:
            for size in (1, 32, 4096):
                for shape in ("watch", "foreground", "promoted"):
                    for label, module in implementations:
                        value = _order_memory(module, size, shape)
                        report.summary["order_memory"].append({
                            "size": size, "shape": shape, "implementation": label, **value,
                        })
            for size in sizes:
                repeats = max(128, min(20000, 1_000_000 // size))
                for shape in ("all-watch", "foreground-tail", "foreground-head"):
                    rows = {"before": [], "after": []}
                    for iteration in range(-args.warmups, args.runs):
                        for label, module in (implementations if iteration % 2 == 0 else reversed(implementations)):
                            measured = measure(_micro(module, size, shape, repeats), runs=1)[0]
                            if iteration >= 0:
                                rows[label].append(measured)
                                report.samples.append({"kind": "micro", "size": size, "shape": shape,
                                                       "implementation": label, "iteration": iteration, "repeats": repeats,
                                                       "wall_ms": measured.wall_ms, "cpu_ms": measured.cpu_ms})
                    row = {"size": size, "shape": shape, "repeats": repeats,
                           "before_us": statistics.median(r.wall_ms for r in rows["before"]) * 1000 / repeats,
                           "after_us": statistics.median(r.wall_ms for r in rows["after"]) * 1000 / repeats}
                    report.summary["micro"].append(row)
                    print(f"select/{shape}/{size}: {row['before_us']:.3f} -> {row['after_us']:.3f} us", flush=True)
            for count in broker_sizes:
                for shape in ("watch-shared", "watch-distinct", "mixed-tail", "foreground-distinct"):
                    rows = {"before": [], "after": []}
                    for iteration in range(-args.warmups, args.runs):
                        for label, module in (implementations if iteration % 2 == 0 else reversed(implementations)):
                            value = asyncio.run(_broker(module, count, shape, args.thread_capacity))
                            if iteration >= 0:
                                rows[label].append(value)
                                report.samples.append({"kind": "broker", "jobs": count, "shape": shape,
                                                       "implementation": label, "iteration": iteration, **value})
                    row = {"jobs": count, "shape": shape}
                    for label, _ in implementations:
                        row[label] = {key: statistics.median(value[key] for value in rows[label])
                                      for key in rows[label][0]}
                    row["drain_reduction_percent"] = 100 * (1 - row["after"]["drain_ms"] / row["before"]["drain_ms"])
                    report.summary["broker"].append(row)
                    print(f"broker/{shape}/{count}: {row['before']['drain_ms']:.2f} -> "
                          f"{row['after']['drain_ms']:.2f} ms drain ({row['drain_reduction_percent']:.1f}%)", flush=True)
            for shape in ("watch-distinct", "mixed-tail"):
                count = max(broker_sizes)
                for label, module in implementations:
                    value = asyncio.run(_broker(module, count, shape, args.thread_capacity, diagnostic=True))
                    report.summary["diagnostic"].append({"jobs": count, "shape": shape, "implementation": label, **value})
                    print(f"diagnostic/{shape}/{label}: {value}", flush=True)
        finally:
            write_report(report, workspace.result_dir / "report.json")
            print(f"report: {workspace.result_dir / 'report.json'}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
