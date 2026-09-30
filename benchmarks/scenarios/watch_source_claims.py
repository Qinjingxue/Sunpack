from __future__ import annotations

"""Compare watch source ownership with an exact committed scheduler baseline."""

import argparse
import gc
import hashlib
import os
import statistics
import subprocess
import sys
import threading
import tracemalloc
from pathlib import Path
from types import ModuleType, SimpleNamespace

from benchmarks.harness import BenchmarkReport, BenchmarkWorkspace, measure, write_report
from sunpack.runtime.watch import scheduler as candidate
from sunpack.runtime.watch.scanner import WatchCandidate


REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_PATH = "sunpack/runtime/watch/scheduler.py"


def _baseline(ref):
    revision = subprocess.check_output(
        ["git", "rev-parse", "--verify", f"{ref}^{{commit}}"], cwd=REPO_ROOT, text=True,
    ).strip()
    source = subprocess.check_output(
        ["git", "show", f"{revision}:{SOURCE_PATH}"], cwd=REPO_ROOT, text=True, encoding="utf-8",
    )
    module = ModuleType("sunpack_watch_source_claims_baseline")
    module.__file__ = f"{revision}:{SOURCE_PATH}"
    sys.modules[module.__name__] = module
    exec(compile(source, module.__file__, "exec"), module.__dict__)
    return module, revision, hashlib.sha256(source.encode("utf-8")).hexdigest()


def _store(module, watcher, path, item):
    if module is candidate:
        watcher._store_pending_locked(path, item)
    else:
        watcher._pending[path] = item


def _template(module, items):
    watcher = object.__new__(module.WatchScheduler)
    watcher._pending = {}
    watcher._active_states = {}
    watcher._active_claims = {}
    if module is candidate:
        watcher._pending_by_key = {}
        watcher._claims_by_owner = {}
    for index, item in enumerate(items):
        _store(module, watcher, item.path, item)
        watcher._active_states[item.path] = module._ActiveCandidateState(0, 0)
        # Independent unrelated volume claims. Bulk fixture construction is
        # excluded from individual-operation timings; lifecycle timing below
        # includes registration and removal of every measured source.
        # Claimed sources and pending candidates are disjoint in a live
        # scheduler: publication retires pending events for a claimed source.
        key = module.path_key(f"{item.path}.claimed")
        owner = f"unrelated-{index // 8}"
        watcher._active_claims[key] = owner
        if module is candidate:
            watcher._claims_by_owner.setdefault(owner, set()).add(key)
    return watcher


def _fork(module, template):
    watcher = object.__new__(module.WatchScheduler)
    watcher._lock = threading.Lock()
    watcher._claim_gate = threading.RLock()
    watcher._pending = template._pending.copy()
    watcher._active_states = template._active_states.copy()
    watcher._active_claims = template._active_claims.copy()
    # Unrelated buckets are immutable in these workloads. Target buckets are
    # created by production helpers and never shared across measurements.
    if module is candidate:
        watcher._pending_by_key = template._pending_by_key.copy()
        watcher._claims_by_owner = template._claims_by_owner.copy()
    watcher._dirty_during_claim = {}
    watcher.replayed = []
    watcher.completed = []
    watcher.cleared = []
    watcher.matched = []
    watcher.log = SimpleNamespace(write=lambda *args, **kwargs: None)
    watcher.enqueue = lambda path, **kwargs: watcher.replayed.append((path, kwargs))
    watcher.state = SimpleNamespace(
        complete_work=watcher.completed.extend, clear_entries=watcher.cleared.extend,
        complete_work_if_matches=watcher.matched.append,
    )
    return watcher


def _prepare(module, template, targets, kind, repeats):
    paths = [item.path for item in targets]
    if kind == "lifecycle":
        watcher = _fork(module, template)

        def run():
            for _ in range(repeats):
                with watcher._lock:
                    for item in targets:
                        _store(module, watcher, item.path, item)
                        _store(module, watcher, item.path, item)  # Metadata update.
                        watcher._active_states[item.path] = module._ActiveCandidateState(0, 0)
                watcher._claim_pipeline_sources("owner-a", paths)
                with watcher._claim_gate:
                    for path in paths:
                        assert watcher._defer_claimed_path_locked(path)
                watcher._claim_pipeline_sources("owner-b", paths[::2])
                watcher._release_pipeline_source_claims("owner-a")
                watcher._release_pipeline_source_claims("owner-b")
                watcher._retire_claimed_paths(paths, targets[0])
        return run, [watcher]

    watchers = [_fork(module, template) for _ in range(repeats)]
    for watcher in watchers:
        if kind == "release":
            watcher._claim_pipeline_sources("target-owner", paths)
            with watcher._claim_gate:
                for path in paths:
                    assert watcher._defer_claimed_path_locked(path)
        else:
            for item in targets if kind == "claim" else targets[::2]:
                _store(module, watcher, item.path, item)
                watcher._active_states[item.path] = module._ActiveCandidateState(0, 0)

    def run():
        for watcher in watchers:
            if kind == "claim":
                watcher._claim_pipeline_sources("target-owner", paths)
            elif kind == "release":
                watcher._release_pipeline_source_claims("target-owner")
            else:
                watcher._retire_claimed_paths(paths, targets[0])
    return run, watchers


def _snapshot(watcher):
    # Validation is outside the timed region. Compare metadata and ordered
    # dirty-event replay, and validate both new indexes against their tables.
    assert not {
        candidate.path_key(os.path.abspath(path)) for path in watcher._pending
    }.intersection(watcher._active_claims)
    if isinstance(watcher, candidate.WatchScheduler):
        pending_index = {}
        for path in watcher._pending:
            pending_index.setdefault(candidate.path_key(os.path.abspath(path)), set()).add(path)
        claims_index = {}
        for key, owner in watcher._active_claims.items():
            claims_index.setdefault(owner, set()).add(key)
        assert watcher._pending_by_key == pending_index
        assert watcher._claims_by_owner == claims_index
    return (
        watcher._pending, set(watcher._active_states), watcher._active_claims,
        watcher._dirty_during_claim, watcher.replayed, watcher.completed,
        watcher.cleared, watcher.matched,
    )


def _index_allocation_bytes(template):
    # Trace only additional index allocations. Existing pending/claim records
    # stay outside tracing, avoiding class dictionary/free-list warmup bias.
    # No tracer is active during latency measurements.
    gc.collect()  # Flush object free lists before comparing retained allocations.
    tracemalloc.start()
    try:
        pending_by_key = {}
        claims_by_owner = {}
        for path in template._pending:
            key = candidate.path_key(os.path.abspath(path))
            pending_by_key.setdefault(key, set()).add(path)
        for key, owner in template._active_claims.items():
            claims_by_owner.setdefault(owner, set()).add(key)
        retained, _ = tracemalloc.get_traced_memory()
        assert len(pending_by_key) == len(template._pending)
        return retained
    finally:
        tracemalloc.stop()


def _compare(report, baseline, templates, targets, *, count, kind, runs, warmups, repeats):
    label = f"{kind}/{count}-unrelated/{len(targets)}-sources"
    samples = {"before": [], "after": []}
    for iteration in range(-warmups, runs):
        order = (("before", baseline), ("after", candidate))
        if iteration % 2:
            order = tuple(reversed(order))
        results = {}
        for name, module in order:
            call, watchers = _prepare(module, templates[name], targets, kind, repeats)
            row = measure(call, runs=1)[0]
            results[name] = [_snapshot(watcher) for watcher in watchers]
            if iteration >= 0:
                samples[name].append(row)
                report.samples.append({
                    "case": label, "implementation": name, "iteration": iteration,
                    "operations": repeats, "wall_ms": row.wall_ms, "cpu_ms": row.cpu_ms,
                })
        assert results["before"] == results["after"], f"ownership/replay differ: {label}"
    before = statistics.median(row.wall_ms for row in samples["before"]) / repeats
    after = statistics.median(row.wall_ms for row in samples["after"]) / repeats
    report.summary["cases"].append({
        "case": label, "kind": kind, "unrelated_pending_paths": count,
        "unrelated_claimed_paths": count, "source_paths": len(targets),
        "before_median_ms": before, "after_median_ms": after,
        "speedup": before / after, "time_reduction_percent": (1 - after / before) * 100,
        "state_and_replay_equal": True,
    })
    print(f"{label}: {before:.6f} -> {after:.6f} ms ({before / after:.2f}x)", flush=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-ref", required=True)
    parser.add_argument("--sizes", default="0,128,4096,32768")
    parser.add_argument("--sources", type=int, default=8)
    parser.add_argument("--runs", type=int, default=7)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--repeats", type=int, default=16)
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args(argv)
    sizes = [int(value) for value in args.sizes.split(",")]
    if (not sizes or min(sizes) < 0 or min(args.sources, args.runs, args.repeats) < 1
            or args.warmups < 0):
        parser.error("sizes/warmups must be nonnegative; sources/runs/repeats positive")
    baseline, revision, source_hash = _baseline(args.baseline_ref)
    report = BenchmarkReport(
        scenario="scheduling.watch-source-claims",
        parameters={
            "baseline_revision": revision, "baseline_source_sha256": source_hash,
            "candidate_source_sha256": hashlib.sha256(
                (REPO_ROOT / SOURCE_PATH).read_text(encoding="utf-8").encode("utf-8"),
            ).hexdigest(),
            "sizes": sizes, "sources": args.sources, "runs": args.runs,
            "warmups": args.warmups, "repeats": args.repeats,
            "logical_processors": os.cpu_count(),
            "method": "Exact committed source versus working tree, alternating A/B; production locks and path normalization. Claim/release/retire exclude fixture preparation. Lifecycle includes pending insertion, metadata replacement, claim, dirty events, partial ownership transfer, both releases and retirement. No filesystem, log persistence or archive decoding; state and ordered replay equality checked outside timing.",
        },
        summary={"cases": [], "metadata_allocations": []},
    )
    targets = [WatchCandidate(os.path.abspath(f"bench-target-{index}.disguised"),
                              10, 1.0, f"target-{index}", 1) for index in range(args.sources)]
    with BenchmarkWorkspace(report.scenario, results_root=args.results_root) as workspace:
        try:
            for count in sizes:
                items = [WatchCandidate(os.path.abspath(f"bench-unrelated-{index}.001"),
                                        10, 1.0, str(index), 1) for index in range(count)]
                templates = {"before": _template(baseline, items), "after": _template(candidate, items)}
                report.summary["metadata_allocations"].append({
                    "pending_paths": count, "claimed_paths": count,
                    "added_index_bytes": _index_allocation_bytes(templates["before"]),
                    "method": "Tracemalloc retained allocations while constructing only pending/owner indexes; existing source records excluded.",
                })
                for kind in ("claim", "release", "retire", "lifecycle"):
                    _compare(report, baseline, templates, targets, count=count, kind=kind,
                             runs=args.runs, warmups=args.warmups, repeats=args.repeats)
        finally:
            write_report(report, workspace.result_dir / "report.json")
            if args.json_out:
                write_report(report, args.json_out)
            print(f"report: {workspace.result_dir / 'report.json'}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
