"""Measure event-log submission, deletion storms, compaction and restart retention."""
from __future__ import annotations

import argparse
import gc
import statistics
import time
from pathlib import Path

from benchmarks.harness import BenchmarkReport, BenchmarkWorkspace, ProcessSampler, write_report
from sunpack_native import NativeEventLog
from tests.display_history import storage_bytes


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tasks", type=int, default=5000)
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--cold-starts", type=int, default=40)
    parser.add_argument("--lifetime-batches", type=int, default=12)
    parser.add_argument("--compaction-tasks", type=int, nargs="+", default=[])
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args(argv)
    if min(args.tasks, args.rounds, args.cold_starts, args.lifetime_batches) < 1:
        parser.error("tasks, rounds, cold-starts and lifetime-batches must be positive")
    if any(count < 1 for count in args.compaction_tasks):
        parser.error("compaction-tasks must be positive")
    report = BenchmarkReport("scheduling.event-log", parameters={
        "tasks": args.tasks, "rounds": args.rounds, "cold_starts": args.cold_starts,
        "lifetime_batches": args.lifetime_batches,
        "compaction_tasks": args.compaction_tasks,
        "method": "Installed native extension; rebuild it after changing Rust sources. Submission and final drain timed separately. No extraction, Broker, sleeps or GUI process. The benchmark reports native writer faults.",
    })
    sampler = ProcessSampler()
    with BenchmarkWorkspace(report.scenario, results_root=args.results_root) as workspace:
        report.summary["initial_memory"] = sampler.take().to_dict()
        for count in args.compaction_tasks:
            path = workspace.work / f"compaction-{count}" / "events.json"
            log = NativeEventLog(str(path))
            latencies = []
            try:
                log.recover()
                for index in range(count):
                    log.write({"event": "failed_password", "path": str(path.parent / f"task-{index}.opaque")})
                log.flush()
                initial_bytes = storage_bytes(path)
                # Submit diagnostic traffic proportional to the stored live
                # data. Each call's latency includes projection lock
                # contention; it is an upper bound, not pure lock-wait time.
                events = (initial_bytes // 2 + 262144) // 3800 + 64
                started = time.perf_counter()
                for index in range(events):
                    before = time.perf_counter()
                    log.write({"event": "diagnostic", "padding": "x" * 4096})
                    latencies.append((time.perf_counter() - before) * 1000)
                submitted = time.perf_counter()
                log.flush()
                ordered = sorted(latencies)
                report.samples.append({
                    "phase": "compaction_contention", "active_tasks": count,
                    "events": events, "max_submit_ms": max(ordered),
                    "p99_submit_ms": ordered[min(len(ordered)-1, int(len(ordered)*0.99))],
                    "median_submit_ms": statistics.median(ordered),
                    "submit_ms": (submitted-started)*1000,
                    "drain_total_ms": (time.perf_counter()-started)*1000,
                    "initial_file_bytes": initial_bytes, "file_bytes": storage_bytes(path),
                    "memory": sampler.take().to_dict(),
                })
            finally:
                log.close()
        for index in range(args.rounds):
            path = workspace.work / str(index) / "events.json"
            log = NativeEventLog(str(path))
            sources = [str(path.parent / f"task-{i}.opaque") for i in range(args.tasks)]
            try:
                log.recover()
                for source in sources:
                    log.write({"event": "processing_started", "path": source})
                log.flush()
                active = sampler.take().to_dict()
                start = time.perf_counter()
                for source in sources:
                    log.write({"event": "candidate_departed", "path": source})
                submitted = time.perf_counter()
                log.flush()
                drained = time.perf_counter()
                report.samples.append({
                    "phase": "deletion_storm", "submit_ms": (submitted-start)*1000,
                    "drain_total_ms": (drained-start)*1000, "file_bytes": storage_bytes(path),
                    "active_memory": active, "retired_memory": sampler.take().to_dict(),
                })
            finally:
                log.close()

        # Repeated logical families keep membership payloads while replacing
        # provisional cards; completed families move into bounded history.
        path = workspace.work / "groups" / "events.json"
        log = NativeEventLog(str(path))
        try:
            log.recover()
            start = time.perf_counter()
            for index in range(args.tasks):
                members = [str(path.parent / f"family-{index}.{part}") for part in range(3)]
                log.write({"event": "pipeline_sources_claimed", "processing": True,
                           "owner": str(index), "groups": [{"path": members[0], "members": members}]})
                log.write({"event": "task_retired", "path": members[-1]})
                log.write({"event": "done", "path": members[0]})
            submitted = time.perf_counter()
            log.flush()
            report.samples.append({"phase": "grouped_compaction", "submit_ms": (submitted-start)*1000,
                                   "drain_total_ms": (time.perf_counter()-start)*1000,
                                   "file_bytes": storage_bytes(path)})
        finally:
            log.close()

        # Keep the same coordinator alive across unrelated logical families;
        # one closed logger cannot reveal accumulating active-map/handle state.
        path = workspace.work / "lifetime" / "events.json"
        log = NativeEventLog(str(path))
        try:
            log.recover()
            for batch in range(args.lifetime_batches):
                faults = []
                families = [[str(path.parent / f"{batch}-{i}.{part}") for part in range(3)]
                            for i in range(min(args.tasks, 1000))]
                for index, members in enumerate(families):
                    log.write({"event": "pipeline_sources_claimed", "processing": True,
                               "owner": str(index), "groups": [{"path": members[0], "members": members}]})
                try:
                    log.flush()
                except OSError as error:
                    faults.append({"phase": "active", "error": str(error)})
                active = sampler.take().to_dict()
                for index, members in enumerate(families):
                    log.write({"event": "pipeline_sources_released", "owner": str(index), "paths": members})
                try:
                    log.flush()
                except OSError as error:
                    faults.append({"phase": "retired", "error": str(error)})
                report.samples.append({"phase": "steady_lifetime", "batch": batch,
                                       "active_memory": active, "retired_memory": sampler.take().to_dict(),
                                       "file_bytes": storage_bytes(path), "faults": faults})
        finally:
            log.close()

        path = workspace.work / "runtime.state.events.json"
        sizes, errors = [], []
        for index in range(args.cold_starts):
            log = NativeEventLog(str(path), 7, False)
            try:
                log.write({"event": "host_started", "index": index, "padding": "x" * 2048})
                log.flush()
            except OSError as error:
                errors.append({"restart": index, "error": str(error)})
            finally:
                log.close()
            sizes.append(storage_bytes(path) if path.exists() else 0)
        deletion = [s for s in report.samples if s["phase"] == "deletion_storm"]
        gc.collect()
        report.summary.update({
            "median_submit_ms": statistics.median(s["submit_ms"] for s in deletion),
            "median_drain_total_ms": statistics.median(s["drain_total_ms"] for s in deletion),
            "restart_file_bytes": sizes, "restart_errors": errors,
            "after_close_memory": sampler.take().to_dict(),
        })
        write_report(report, workspace.result_dir / "report.json")
        if args.json_out:
            write_report(report, args.json_out)
        print(f"report: {workspace.result_dir / 'report.json'}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
