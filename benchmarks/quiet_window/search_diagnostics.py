"""Post-selection constant sensitivity and frozen numerical-policy reference.

This reports perturbations without changing the frozen recommendation or using
validation/audit results for another selection round.
"""
from __future__ import annotations

import argparse
import json
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

from sunpack_native import fast_hash128_file

from benchmarks.harness.workspace import BenchmarkWorkspace
from benchmarks.quiet_window.expressions import BOUNDS, Expression
from benchmarks.quiet_window.search import BURSTS, LATENCY, REPO, combine, evaluate_block, violation, write_json
from benchmarks.quiet_window.statistics import interval


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("selection", type=Path, help="A completed selection-frozen.json, not validation output.")
    parser.add_argument("--seeds", default="0,7")
    parser.add_argument("--jobs", type=int, default=8)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--skip-audit-reference", action="store_true", help="Only development sensitivity; otherwise also compare the already-frozen numeric winner.")
    args = parser.parse_args(argv)
    root = args.selection.resolve().parent
    plan = json.loads((root / "search-plan.json").read_text(encoding="utf-8"))
    for path, identity in plan["sources"].items():
        if fast_hash128_file(str(REPO / path)) != identity:
            raise ValueError(f"evaluation source changed since selection: {path}")
    frozen = json.loads(args.selection.read_text(encoding="utf-8"))
    winner = Expression.from_record(frozen["winner"])
    seeds = tuple(int(value) for value in args.seeds.split(","))
    if not seeds or len(set(seeds)) != len(seeds) or any(seed < 0 or seed >= plan["arguments"]["development_seeds"] for seed in seeds):
        parser.error("choose distinct development seeds used by the original search")
    candidates = {}
    parameters = dict(winner.parameters)
    for name, value in parameters.items():
        alternatives = (value * .95, value * 1.05) if name in ("A", "P") else (value - .01, value + .01)
        for alternative in alternatives:
            low, high = BOUNDS[name]
            if low <= alternative <= high:
                item = Expression.make(winner.tree, **{**parameters, name: alternative})
                if item.identity != winner.identity:
                    candidates[item.identity] = item
    baseline_id = plan["initial_candidates"][0]["id"]
    baseline = combine(json.loads((root / "scores" / f"{baseline_id}-development-{seed}.json").read_text(encoding="utf-8")) for seed in seeds)
    original = combine(json.loads((root / "scores" / f"{winner.identity}-development-{seed}.json").read_text(encoding="utf-8")) for seed in seeds)
    with BenchmarkWorkspace("scheduling.watch-quiet-sensitivity") as workspace:
        blocks = {}
        with ProcessPoolExecutor(max_workers=args.jobs) as pool:
            pending = {pool.submit(evaluate_block, item.record(), str(root / "corpus" / f"development-{seed}.jsonl.gz"),
                                   str(workspace.result_dir / f"{item.identity}-{seed}.json"), str(workspace.work / "metadata")): (item.identity, seed)
                       for seed in seeds for item in candidates.values()}
            for index, future in enumerate(as_completed(pending), 1):
                blocks[pending[future]] = future.result()
                print(f"sensitivity: {index}/{len(pending)}", flush=True)
        report = {"selected_policy": winner.record(), "development_seeds": seeds,
                  "selection_unchanged": True, "original": original, "baseline": baseline, "perturbations": []}
        for item in candidates.values():
            result = combine(blocks[(item.identity, seed)] for seed in seeds)
            report["perturbations"].append({"policy": item.record(), "result": result,
                                            "burst_violation": violation(result, baseline, plan["arguments"]["burst_ratio"])})
        if not args.skip_audit_reference:
            reference = Expression.from_record(frozen.get("numeric_winner", frozen["parameter_control"]))
            audit_seeds = tuple(range(plan["arguments"]["audit_seed_start"],
                                      plan["arguments"]["audit_seed_start"] + plan["arguments"]["audit_seeds"]))
            audit_blocks = {}
            for seed in audit_seeds:
                cached = root / "scores" / f"{reference.identity}-heldout-{seed}.json"
                if cached.exists():
                    audit_blocks[seed] = json.loads(cached.read_text(encoding="utf-8"))
            with ProcessPoolExecutor(max_workers=args.jobs) as pool:
                pending = {pool.submit(evaluate_block, reference.record(), str(root / "corpus" / f"heldout-{seed}.jsonl.gz"),
                                       str(workspace.result_dir / f"reference-audit-{seed}.json"), str(workspace.work / "metadata")): seed
                           for seed in audit_seeds if seed not in audit_blocks}
                for index, future in enumerate(as_completed(pending), 1):
                    audit_blocks[pending[future]] = future.result()
                    print(f"frozen-reference-audit: {index}/{len(pending)}", flush=True)
            winner_blocks = {seed: json.loads((root / "scores" / f"{winner.identity}-heldout-{seed}.json").read_text(encoding="utf-8")) for seed in audit_seeds}
            report["audit_reference"] = {"policy": reference.record(), "result": combine(audit_blocks.values()),
                                         "selected_before_validation": True, "selection_unchanged": True,
                                         "paired_winner_minus_reference": {metric: interval([
                                             winner_blocks[seed]["metrics"][metric] - audit_blocks[seed]["metrics"][metric]
                                             for seed in audit_seeds]) for metric in (LATENCY, *BURSTS)}}
        write_json(workspace.result_dir / "report.json", report)
        write_json(args.output, report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
