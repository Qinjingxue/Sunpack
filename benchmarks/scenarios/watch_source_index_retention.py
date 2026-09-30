from __future__ import annotations

"""Check source-index lifetime across unique metadata batches, without archive IO."""

import argparse
import gc
import hashlib
import os
import sys
import threading
import tracemalloc
import weakref
from pathlib import Path
from types import SimpleNamespace

from benchmarks.harness import BenchmarkReport, BenchmarkWorkspace, ProcessSampler, measure, write_report
from sunpack.runtime.watch import scheduler
from sunpack.runtime.watch.scanner import WatchCandidate


def _scheduler():
    watcher = object.__new__(scheduler.WatchScheduler)
    watcher._lock = threading.Lock()
    watcher._claim_gate = threading.RLock()
    watcher._pending = {}
    watcher._pending_by_key = {}
    watcher._active_states = {}
    watcher._active_claims = {}
    watcher._claims_by_owner = {}
    watcher._dirty_during_claim = {}
    watcher.log = SimpleNamespace(write=lambda *args, **kwargs: None)
    watcher.enqueue = lambda *args, **kwargs: None
    return watcher


def _cycle(watcher, count, batch):
    paths = [os.path.abspath(f"retention-{batch}-{index}.disguised") for index in range(count)]
    with watcher._lock:
        for path in paths:
            watcher._store_pending_locked(path, WatchCandidate(path, 10, 1.0, "file", 1))
    pending_refs = [weakref.ref(bucket) for bucket in watcher._pending_by_key.values()]
    candidate_refs = [weakref.ref(item) for item in watcher._pending.values()]
    owners = [f"owner-{batch}-{index}" for index in range(0, count, 8)]
    for offset, owner in zip(range(0, count, 8), owners):
        watcher._claim_pipeline_sources(owner, paths[offset:offset + 8])
    owner_refs = [weakref.ref(bucket) for bucket in watcher._claims_by_owner.values()]
    with watcher._claim_gate:
        for path in paths[::32]:
            assert watcher._defer_claimed_path_locked(path)
    watcher._claim_pipeline_sources("transferred", paths[::4])
    owner_refs.append(weakref.ref(watcher._claims_by_owner["transferred"]))
    for owner in owners:
        watcher._release_pipeline_source_claims(owner)
    watcher._release_pipeline_source_claims("transferred")
    assert all(reference() is None for reference in [*pending_refs, *owner_refs, *candidate_refs])
    assert watcher._pending == watcher._pending_by_key == watcher._active_states == {}
    assert watcher._active_claims == watcher._claims_by_owner == watcher._dirty_during_claim == {}
    empty_bytes = sys.getsizeof({})
    assert sys.getsizeof(watcher._pending_by_key) == sys.getsizeof(watcher._claims_by_owner) == empty_bytes
    return {
        "pending_buckets_collected": len(pending_refs), "owner_buckets_collected": len(owner_refs),
        "candidates_collected": len(candidate_refs), "all_weakrefs_dead": True,
        "pending_index_table_bytes": empty_bytes, "owner_index_table_bytes": empty_bytes,
    }


def _destroy_populated_scheduler(count):
    watcher = _scheduler()
    paths = [os.path.abspath(f"destroy-{index}.disguised") for index in range(count)]
    for path in paths:
        watcher._store_pending_locked(path, WatchCandidate(path, 10, 1.0, "file", 1))
    watcher._claim_pipeline_sources("owner", paths[::2])
    references = [weakref.ref(bucket) for bucket in watcher._pending_by_key.values()]
    references.extend(weakref.ref(bucket) for bucket in watcher._claims_by_owner.values())
    watcher_ref = weakref.ref(watcher)
    del watcher
    assert watcher_ref() is None
    assert all(reference() is None for reference in references)
    return {"scheduler_collected": True, "remaining_buckets_collected": len(references)}


def _scheduler_live_bytes():
    selected = tracemalloc.take_snapshot().filter_traces((
        tracemalloc.Filter(True, scheduler.__file__, all_frames=True),
    ))
    return sum(trace.size for trace in selected.traces)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--paths", type=int, default=4096)
    parser.add_argument("--batches", type=int, default=12)
    parser.add_argument("--warmups", type=int, default=2)
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args(argv)
    if min(args.paths, args.batches) < 1 or args.warmups < 0:
        parser.error("paths/batches must be positive; warmups nonnegative")
    report = BenchmarkReport(
        scenario="memory.watch-source-indexes",
        parameters={
            "paths_per_batch": args.paths, "batches": args.batches, "warmups": args.warmups,
            "scheduler_source_sha256": hashlib.sha256(
                Path(scheduler.__file__).read_text(encoding="utf-8").encode("utf-8"),
            ).hexdigest(),
            "method": "Unique paths and owners each batch; production pending/claim/dirty-transfer/release methods. Weakrefs verify buckets and candidates die before GC. Snapshot bytes select scheduler allocations across all recorded frames; includes original pending/claim table capacities. Empty index table sizes and populated scheduler destruction also verified. Timing runs with tracemalloc and is diagnostic, not a performance comparison; RSS may include allocator reserves. No archive IO, log/state persistence, or deferred-event observation.",
        },
    )
    watcher = _scheduler()
    sampler = ProcessSampler()
    with BenchmarkWorkspace(report.scenario, results_root=args.results_root) as workspace:
        try:
            tracemalloc.start(12)
            for batch in range(-args.warmups, args.batches):
                row = measure(lambda: _cycle(watcher, args.paths, batch), runs=1)[0]
                gc.collect()
                retained = _scheduler_live_bytes()
                process = sampler.take()
                if batch >= 0:
                    report.samples.append({
                        "batch": batch, "wall_ms_with_tracing": row.wall_ms, **row.value,
                        "scheduler_live_bytes": retained,
                        "rss_mib": process.rss_mib, "private_mib": process.private_mib,
                    })
                    print(f"batch {batch}: indexes=128 B, scheduler={retained} B, "
                          f"RSS={process.rss_mib:.2f} MiB; all bucket/candidate weakrefs dead", flush=True)
            report.summary = {
                "checked_source_candidates": args.paths * (args.batches + args.warmups),
                "all_batches_empty_and_buckets_collected": True,
                "scheduler_live_bytes_first": report.samples[0]["scheduler_live_bytes"],
                "scheduler_live_bytes_last": report.samples[-1]["scheduler_live_bytes"],
                "populated_scheduler_destruction": _destroy_populated_scheduler(args.paths),
            }
        finally:
            tracemalloc.stop()
            write_report(report, workspace.result_dir / "report.json")
            if args.json_out:
                write_report(report, args.json_out)
            print(f"report: {workspace.result_dir / 'report.json'}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
