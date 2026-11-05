"""Reproducible, bounded symbolic/constant search using production admission.

Run via `python -m benchmarks scheduling watch-quiet-search`. CPU, IO, total
errors and pipeline work are never used to accept or rank a candidate.
"""
from __future__ import annotations

import argparse
import ast
import gzip
import inspect
import json
import math
import os
import shutil
import time
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from types import SimpleNamespace

from sunpack_native import fast_hash128, fast_hash128_file

from benchmarks.harness.workspace import BenchmarkWorkspace
from benchmarks.quiet_window.corpus import CHANNELS, WIDTHS, Trace, generate
from benchmarks.quiet_window.expressions import BOUNDS, UNARY, Expression, grammar, initial_candidates, neighbours
from benchmarks.quiet_window.scheduler_replay import prepare_metadata, replay_scheduler
from benchmarks.quiet_window.statistics import BURST_WINDOWS, EVALUATION_CONTRACT, interval, macro, summarize_files
from benchmarks.scenarios.watch_quiet_window import compressed_writer
from sunpack.runtime.watch import quiet_policy, scheduler, state


REPO = Path(__file__).resolve().parents[2]
TIES = ("observation_first", "timer_first")
LATENCY = "mean_ready_to_valid_proposal_seconds"
BURSTS = tuple(f"invalid_burst_{label}_{suffix}" for label, _ in BURST_WINDOWS
               for suffix in ("per_input", "all_inputs"))
WORST = tuple(f"invalid_burst_{label}_{suffix}" for label, _ in BURST_WINDOWS
              for suffix in ("input_max_per_trace", "all_inputs"))
_TRACE_CACHE = {}


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False), encoding="utf-8")
    temporary.replace(path)


def combine(blocks):
    blocks = list(blocks)
    result = {"metrics": macro([block["metrics"] for block in blocks]),
              "missing": sum(block["missing"] for block in blocks),
              "ready": sum(block["ready"] for block in blocks),
              "traces_with_ties": sum(block["traces_with_ties"] for block in blocks)}
    for axis in ("family", "width"):
        groups = defaultdict(list)
        for block in blocks:
            for key, metrics in block[axis].items():
                groups[key].append(metrics)
        result[axis] = {key: macro(rows) for key, rows in sorted(groups.items())}
    result["worst"] = {key: max(block["worst"].get(key, 0) for block in blocks)
                       for key in sorted({key for block in blocks for key in block["worst"]})}
    return result


class Accumulator:
    def __init__(self):
        self.family = defaultdict(list)
        self.width = defaultdict(list)
        self.worst = defaultdict(int)
        self.missing = self.ready = self.count = 0

    def add(self, family, width, inputs):
        metrics = summarize_files(inputs)
        self.family[family].append(metrics)
        self.width[str(width)].append(metrics)
        self.ready += metrics["complete_arrival_files"]
        self.missing += metrics["complete_arrival_files"] - metrics["valid_proposal_files"]
        self.count += 1
        for metric in WORST:
            for key in (f"all/{metric}", f"family/{family}/{metric}", f"width/{width}/{metric}"):
                self.worst[key] = max(self.worst[key], metrics[metric])

    def result(self):
        family = {key: macro(rows) for key, rows in sorted(self.family.items())}
        return {"metrics": macro(list(family.values())), "family": family,
                "width": {key: macro(rows) for key, rows in sorted(self.width.items())},
                "worst": dict(self.worst), "missing": self.missing, "ready": self.ready,
                "traces_with_ties": self.count}


def evaluate_block(record, corpus, cache, metadata, timeline=None):
    expression = Expression.from_record(record)
    path = Path(cache)
    if path.exists() and timeline is None:
        return json.loads(path.read_text(encoding="utf-8"))
    key = str(corpus)
    if key not in _TRACE_CACHE:
        # A worker retains one immutable seed block, never all trial histories.
        _TRACE_CACHE.clear()
        with gzip.open(corpus, "rt", encoding="utf-8") as stream:
            _TRACE_CACHE[key] = tuple(Trace.from_record(json.loads(line)) for line in stream)
    mapping = expression.function()
    values = [mapping(0.), *(mapping(10 ** (index / 4)) for index in range(-36, 37))]
    if values[0] != 0 or any(not math.isfinite(value) or value < 0 for value in values) or values != sorted(values):
        raise ValueError(f"invalid expression: {expression.source}")

    class Policy(quiet_policy.AdaptiveQuietPolicy):
        def target_seconds(self, interval):
            return mapping(interval)

    policy = Policy()
    factory = lambda: SimpleNamespace(tracker=quiet_policy.AdaptiveQuietTracker(policy))
    root = Path(metadata) / str(os.getpid())
    if not root.exists():
        prepare_metadata(root)
    accumulator = Accumulator()
    output = compressed_writer(Path(timeline)) if timeline is not None else None
    if output:
        stream = output.__enter__()
    try:
        for trace in _TRACE_CACHE[key]:
            for tie in TIES:
                result = replay_scheduler(trace, factory, tie_order=tie, metadata_root=root)
                accumulator.add(trace.family, trace.width, result["inputs"])
                if output:
                    stream.write(json.dumps({"trace": trace.key, "variant": expression.identity,
                                             "tie_order": tie, "inputs": result["inputs"]}, separators=(",", ":")) + "\n")
    finally:
        if output:
            output.__exit__(None, None, None)
    result = accumulator.result()
    write_json(path, result)
    return result


def violation(result, baseline, ratio):
    """Peak budgets are offline feasibility bounds, never retry limits."""
    excess = [1. if result["missing"] else 0.]
    # Equal-family input peaks AND aggregate pressure. Width-specific rows
    # prevent broad macro averages from hiding a concurrency regression.
    for current, reference in [(result["metrics"], baseline["metrics"]), *(
            (result["width"][key], value) for key, value in baseline["width"].items())]:
        for name in BURSTS:
            allowance = reference[name] * ratio
            excess.append(max(0., current[name] - allowance) / max(1., allowance))
    # A single additional attempt is the integer resolution of a peak. This
    # also defines an absolute budget when the baseline has zero errors.
    for key, reference in baseline["worst"].items():
        allowance = max(reference + 1, math.ceil(reference * ratio))
        excess.append(max(0., result["worst"][key] - allowance) / max(1., allowance))
    return max(excess)


def pareto(expressions, results):
    keys = (LATENCY, *BURSTS)
    eligible = [item for item in expressions if not results[item.identity]["missing"]]
    return [item for item in eligible if not any(
        all(results[other.identity]["metrics"][key] <= results[item.identity]["metrics"][key] for key in keys)
        and any(results[other.identity]["metrics"][key] < results[item.identity]["metrics"][key] for key in keys)
        for other in eligible if other.identity != item.identity)]


def select(expressions, results, baseline, ratio, count, *, diverse=False):
    def rank(item):
        result = results[item.identity]
        v = violation(result, baseline, ratio)
        return (bool(result["missing"]), v > 1e-12, v if v > 1e-12 else 0.,
                result["metrics"][LATENCY], max(result["metrics"][key] for key in BURSTS), item.complexity, item.identity)
    ordered = sorted(expressions, key=rank)
    if not diverse:
        return ordered[:count]
    chosen, trees = [], set()
    for item in ordered:
        if repr(item.tree) not in trees:
            chosen.append(item)
            trees.add(repr(item.tree))
        if len(chosen) == count:
            return chosen
    return chosen


def incumbent_family(expression):
    tree = expression.tree
    return tree in ("baseline", "zero", "x", ("log", "x")) or (
        not isinstance(tree, str) and tree[0] == "add"
        and set(map(repr, tree[1:])) == {repr("x"), repr(("log", "x"))})


def rescore(paths, destination):
    groups = defaultdict(Accumulator)
    seen = set()
    for path in paths:
        with gzip.open(path, "rt", encoding="utf-8") as stream:
            for line in stream:
                row = json.loads(line)
                split, seed, family, channel, width = row["trace"].split("/")
                algorithm = row.get("variant", row.get("algorithm"))
                identity = (row["trace"], algorithm, row["tie_order"])
                if identity in seen:
                    raise ValueError(f"duplicate outcome; rescore separately when policy labels coincide: {identity}")
                seen.add(identity)
                groups[(split, algorithm, seed)].add(family, int(width), row.get("inputs", row.get("files")))
    report = {}
    for split, algorithm in sorted({(key[0], key[1]) for key in groups}):
        blocks = {seed: group.result() for (s, a, seed), group in groups.items() if s == split and a == algorithm}
        report[f"{split}/{algorithm}"] = {**combine(blocks.values()), "seed_blocks": blocks}
    write_json(destination, {"contract": EVALUATION_CONTRACT, "sources": [str(path.resolve()) for path in paths],
                             "windows_nanoseconds": dict(BURST_WINDOWS), "results": report})
    print(f"rescored: {destination}", flush=True)
    return 0


def freeze_sources(destination):
    paths = [Path(inspect.getsourcefile(module)) for module in (quiet_policy, scheduler, state)]
    paths += [REPO / "benchmarks/quiet_window" / name for name in (
        "search.py", "expressions.py", "statistics.py", "corpus.py", "writers.py", "replay.py", "scheduler_replay.py")]
    paths += [REPO / "native/sunpack_native/src/scan" / name for name in ("catalog.rs", "directory.rs")]
    identities = {}
    for path in paths:
        relative = path.relative_to(REPO)
        target = destination / "implementation" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
        identities[str(relative)] = fast_hash128_file(str(path))
    return identities


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rescore", nargs="+", type=Path, help="Only rescore previously recorded admission timelines.")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--candidates", type=int, default=192)
    parser.add_argument("--rounds", type=int, default=2)
    parser.add_argument("--beam", type=int, default=8)
    parser.add_argument("--promote", type=int, default=24)
    parser.add_argument("--finalists", type=int, default=8)
    parser.add_argument("--jobs", type=int, default=8, help="Independent offline processes; production concurrency is unchanged.")
    parser.add_argument("--burst-ratio", type=float, default=1.10)
    parser.add_argument("--development-seeds", type=int, default=8)
    parser.add_argument("--validation-seeds", type=int, default=8)
    parser.add_argument("--audit-seed-start", type=int, help="Default: unused heldout seeds after all prior search audits, at least 8.")
    parser.add_argument("--audit-seeds", type=int, default=8)
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--resume", type=Path, help="Reuse compatible seed-block scores from an earlier search; create a new frozen plan.")
    parser.add_argument("--selection-rule", choices=("latency", "paired-simplicity"), default="latency")
    args = parser.parse_args(argv)
    if args.rescore:
        if not args.output:
            parser.error("--rescore requires --output")
        return rescore(args.rescore, args.output)
    if (min(args.candidates, args.beam, args.promote, args.finalists, args.jobs) < 1 or args.candidates < 12
            or args.rounds < 0 or min(args.development_seeds, args.validation_seeds, args.audit_seeds) < 3
            or (args.audit_seed_start is not None and args.audit_seed_start < 8)
            or not math.isfinite(args.burst_ratio) or args.burst_ratio < 1):
        parser.error("invalid search budget, burst ratio, or independent audit seed range")
    with BenchmarkWorkspace("scheduling.watch-quiet-search", results_root=args.results_root) as workspace:
        destination = workspace.result_dir
        used_audit_seeds = {int(path.stem.rsplit("-heldout-", 1)[1])
                            for path in (workspace.results_root / "scheduling.watch-quiet-search").glob("*/scores/*-heldout-*.json")}
        if args.audit_seed_start is None:
            args.audit_seed_start = max(8, max(used_audit_seeds, default=7) + 1)
        elif set(range(args.audit_seed_start, args.audit_seed_start + args.audit_seeds)) & used_audit_seeds:
            parser.error("audit seed blocks have already been evaluated; choose unused seeds or omit --audit-seed-start")
        if args.resume:
            prior = json.loads((args.resume / "search-plan.json").read_text(encoding="utf-8"))
            for path, identity in prior["sources"].items():
                if Path(path).name not in ("search.py", "expressions.py") and fast_hash128_file(str(REPO / path)) != identity:
                    raise ValueError(f"cannot reuse scores after evaluation source change: {path}")
            old_path = args.resume / "implementation/benchmarks/quiet_window/search.py"
            old_source = old_path.read_text(encoding="utf-8")
            new_source = Path(__file__).read_text(encoding="utf-8")
            for name in ("Accumulator", "evaluate_block", "combine"):
                def definition(source):
                    return ast.get_source_segment(source, next(node for node in ast.parse(source).body if getattr(node, "name", None) == name))
                if definition(old_source) != definition(new_source):
                    raise ValueError(f"cannot reuse scores after scorer change: {name}")
        candidates = initial_candidates(args.candidates)
        baseline = candidates[0]
        previous = candidates[2]
        if args.resume and (args.resume / "screen.json").exists():
            earlier = json.loads((args.resume / "screen.json").read_text(encoding="utf-8"))
            known = {item.identity for item in candidates}
            for row in earlier.values():
                item = Expression.from_record(row["policy"])
                if item.source != row["policy"]["expression"] or item.identity != row["policy"]["id"]:
                    raise ValueError("cached expression identity changed")
                if item.identity not in known:
                    known.add(item.identity)
                    candidates.append(item)
        config = {"contract": "sunpack.quiet-function-search/1", "metric_contract": EVALUATION_CONTRACT,
                  "arguments": vars(args), "operators": (*UNARY, "add", "mul"), "max_tree_operations": 3,
                  "grammar_structures": len(grammar()), "constant_bounds": BOUNDS, "constant_significant_digits": 3,
                  "shape": "nonnegative-monotone;f(0)=0", "ranking": "zero-missing;burst-feasible;minimum-first-valid-latency;optional-paired-simplicity",
                  "paired_simplicity": "among feasible lower-complexity candidates whose development seed-paired 95% bootstrap difference from the numeric winner contains zero, prefer minimum complexity then latency;regularization heuristic,not a significance guarantee",
                  "burst_constraints": "macro-and-each-width-means<=ratio*baseline;each-family/width/overall-worst<=max(baseline+1,ceil(ratio*baseline))",
                  "excluded_objectives": ["CPU", "IO", "inflight-work", "total-invalid-attempts"],
                  "cache_reuse": "matching-expression-source-id-and-unchanged-scorer;linear-controls-recomputed" if args.resume else None,
                  "sources": freeze_sources(destination), "initial_candidates": [item.record() for item in candidates]}
        # Convert argparse Paths before recording a finite JSON manifest.
        config["arguments"] = {key: str(value) if isinstance(value, Path) else value for key, value in vars(args).items()}
        write_json(destination / "search-plan.json", config)
        corpora = {}

        def corpus(split, seed):
            key = (split, seed)
            if key not in corpora:
                path = destination / "corpus" / f"{split}-{seed}.jsonl.gz"
                path.parent.mkdir(exist_ok=True)
                previous_corpus = args.resume / "corpus" / path.name if args.resume else None
                if previous_corpus and previous_corpus.exists():
                    identities = json.loads((args.resume / "corpus-identities.json").read_text(encoding="utf-8"))
                    if fast_hash128_file(str(previous_corpus)) != identities[f"{split}/{seed}"]:
                        raise ValueError("cached corpus identity changed")
                    shutil.copy2(previous_corpus, path)
                else:
                    with compressed_writer(path) as stream:
                        for trace in generate(1, (split,), CHANNELS, WIDTHS, seed_start=seed):
                            stream.write(json.dumps(trace.record(), separators=(",", ":")) + "\n")
                corpora[key] = path
                write_json(destination / "corpus-identities.json", {f"{s}/{n}": fast_hash128_file(str(p)) for (s,n),p in corpora.items()})
            return corpora[key]

        # Writers are generated once; every policy gets a fresh native catalog
        # and tracker lifecycle. Identical policies reuse exact seed-block scores.
        blocks = {}
        with ProcessPoolExecutor(max_workers=args.jobs) as pool:
            def evaluate(items, split, seeds, stage, timelines=False):
                started = time.monotonic()
                pending = {}
                for seed in seeds:
                    path = corpus(split, seed)
                    for item in items:
                        key = (item.identity, split, seed)
                        cache = destination / "scores" / f"{item.identity}-{split}-{seed}.json"
                        timeline = destination / "timelines" / f"{item.identity}-{split}-{seed}.jsonl.gz" if timelines else None
                        if timeline:
                            timeline.parent.mkdir(exist_ok=True)
                        previous_score = args.resume / "scores" / cache.name if args.resume else None
                        previous_timeline = args.resume / "timelines" / timeline.name if args.resume and timeline else None
                        reusable_timeline = previous_timeline and previous_timeline.exists()
                        if key not in blocks and item.tree != "x" and previous_score and previous_score.exists() and (not timelines or reusable_timeline):
                            blocks[key] = json.loads(previous_score.read_text(encoding="utf-8"))
                            write_json(cache, blocks[key])
                        if reusable_timeline and not timeline.exists():
                            shutil.copy2(previous_timeline, timeline)
                        if key not in blocks or (timelines and not timeline.exists()):
                            future = pool.submit(evaluate_block, item.record(), str(path), str(cache),
                                                 str(workspace.work / "metadata"), str(timeline) if timeline else None)
                            pending[future] = key
                total = len(pending)
                print(f"{stage}: {len(items)} policies, {total} new seed-block evaluations", flush=True)
                for index, future in enumerate(as_completed(pending), 1):
                    key = pending[future]
                    blocks[key] = future.result()
                    if index % 8 == 0 or index == total:
                        print(f"{stage}: {index}/{total}, elapsed={time.monotonic()-started:.1f}s", flush=True)
                return {item.identity: combine(blocks[(item.identity, split, seed)] for seed in seeds) for item in items}

            results = evaluate(candidates, "development", [0], "screen")
            seen = {item.identity for item in candidates}
            for round_index in range(args.rounds):
                leaders = select(candidates, results, results[baseline.identity], args.burst_ratio, args.beam, diverse=True)
                near_boundary = [item for item in candidates if not results[item.identity]["missing"]
                                 and 0 < violation(results[item.identity], results[baseline.identity], args.burst_ratio) <= .5]
                leaders += sorted(near_boundary, key=lambda item: results[item.identity]["metrics"][LATENCY])[:2]
                # Give the incumbent function family its own constant refinement.
                parameter_family = [item for item in candidates if not isinstance(item.tree, str) and item.tree[0] == "add"
                                    and set(map(repr, item.tree[1:])) == {repr("x"), repr(("log", "x"))}]
                if parameter_family:
                    leaders += select(parameter_family, results, results[baseline.identity], args.burst_ratio, 1)
                new = []
                for leader in leaders:
                    for item in neighbours(leader, round_index):
                        if item.identity not in seen:
                            seen.add(item.identity)
                            new.append(item)
                if not new:
                    break
                results.update(evaluate(new, "development", [0], f"refine-{round_index+1}"))
                candidates.extend(new)
            write_json(destination / "screen.json", {item.identity: {"policy": item.record(), **results[item.identity]} for item in candidates})
            promoted = select(candidates, results, results[baseline.identity], args.burst_ratio, args.promote)
            promoted += select(candidates, results, results[baseline.identity], args.burst_ratio, args.beam, diverse=True)
            controls = [baseline, previous]
            parameter_family = [item for item in candidates if not isinstance(item.tree, str) and item.tree[0] == "add"
                                and set(map(repr, item.tree[1:])) == {repr("x"), repr(("log", "x"))}]
            parameter_best = select(parameter_family, results, results[baseline.identity], args.burst_ratio, 1)[0]
            controls.append(parameter_best)
            promoted = list({item.identity: item for item in [*promoted, *controls]}.values())
            results3 = evaluate(promoted, "development", list(range(3)), "promote")
            finalists = select(promoted, results3, results3[baseline.identity], args.burst_ratio, args.finalists)
            finalists = list({item.identity: item for item in [*finalists, *controls]}.values())
            dev_seeds = list(range(args.development_seeds))
            full = evaluate(finalists, "development", dev_seeds, "development-full")
            winner = select(finalists, full, full[baseline.identity], args.burst_ratio, 1)[0]
            numeric_winner = winner
            parameter_best = select([item for item in finalists if incumbent_family(item)], full,
                                    full[baseline.identity], args.burst_ratio, 1)[0]
            simplicity = {}
            if args.selection_rule == "paired-simplicity":
                eligible = [winner]
                for item in finalists:
                    if item.complexity >= numeric_winner.complexity or violation(full[item.identity], full[baseline.identity], args.burst_ratio) > 1e-12:
                        continue
                    paired = interval([blocks[(item.identity, "development", seed)]["metrics"][LATENCY]
                                       - blocks[(numeric_winner.identity, "development", seed)]["metrics"][LATENCY] for seed in dev_seeds])
                    simplicity[item.identity] = paired
                    if paired["ci95"][0] <= 0 <= paired["ci95"][1]:
                        eligible.append(item)
                winner = min(eligible, key=lambda item: (item.complexity, full[item.identity]["metrics"][LATENCY], item.identity))
            frontier = pareto(finalists, full)
            write_json(destination / "development.json", {item.identity: {"policy": item.record(), **full[item.identity]} for item in finalists})
            frozen = {"winner": winner.record(), "numeric_winner": numeric_winner.record(), "parameter_control": parameter_best.record(),
                      "simplicity_development_comparison": simplicity, "selection_rule": args.selection_rule,
                      "pareto": [item.record() for item in frontier], "selected_before_validation": True,
                      "development_evaluations": len({key for key in blocks if key[1] == "development"}),
                      "expressions_evaluated": len(candidates)}
            write_json(destination / "selection-frozen.json", frozen)
            winner.export_policy(REPO / "sunpack/runtime/watch/quiet_policy.py", destination / "winner_policy.py")
            selected = list({item.identity: item for item in [baseline, previous, parameter_best, winner, numeric_winner]}.values())
            validation = evaluate(selected, "validation", list(range(args.validation_seeds)), "validation", timelines=True)
            audit_seeds = list(range(args.audit_seed_start, args.audit_seed_start + args.audit_seeds))
            audit_items = list({item.identity: item for item in [baseline, winner, parameter_best, numeric_winner]}.values())
            audit = evaluate(audit_items, "heldout", audit_seeds, "fresh-audit", timelines=True)
            # Export all winner development timelines after selection; they are
            # independently rescored by the same public metric implementation.
            evaluate([baseline, winner] if winner != baseline else [baseline], "development", dev_seeds, "freeze-timelines", timelines=True)
            report = {**frozen, "plan": "search-plan.json", "directory": str(destination),
                      "development": full, "validation": validation, "fresh_audit": audit,
                      "validation_feasible": violation(validation[winner.identity], validation[baseline.identity], args.burst_ratio) <= 1e-12,
                      "audit_feasible": violation(audit[winner.identity], audit[baseline.identity], args.burst_ratio) <= 1e-12,
                      "paired_seed_block_differences": {}}
            for label, split, seeds in (("development", "development", dev_seeds),
                                         ("validation", "validation", list(range(args.validation_seeds))), ("fresh_audit", "heldout", audit_seeds)):
                report["paired_seed_block_differences"][label] = {metric: interval([
                    blocks[(winner.identity, split, seed)]["metrics"][metric] - blocks[(baseline.identity, split, seed)]["metrics"][metric]
                    for seed in seeds]) for metric in (LATENCY, *BURSTS)}
            write_json(destination / "report.json", report)
            if args.output:
                write_json(args.output, report)
            print(f"winner: {winner.source}\nreport: {destination / 'report.json'}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
