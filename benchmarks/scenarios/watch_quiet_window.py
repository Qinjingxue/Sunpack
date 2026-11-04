from __future__ import annotations

import argparse
import gzip
import inspect
import io
import json
import random
import shutil
import subprocess
import time
from collections import Counter, defaultdict
from contextlib import contextmanager
from pathlib import Path

from sunpack_native import fast_hash128, fast_hash128_file

from benchmarks.harness.reporting import report_from_payload, render_report
from benchmarks.harness.workspace import BenchmarkWorkspace
from benchmarks.quiet_window.corpus import CHANNELS, CONTRACT, FAMILIES, SPLITS, WIDTHS, Trace, generate
from benchmarks.quiet_window.replay import estimators, replay
from benchmarks.quiet_window.statistics import METRICS, interval, macro, paired_comparison, summarize_files
from sunpack.runtime.watch import quiet_policy


SCENARIO = "scheduling.watch-quiet-window"
REPO = Path(__file__).resolve().parents[2]


@contextmanager
def compressed_writer(path: Path):
    # Stable gzip header: the fingerprint identifies trace bytes, not wall time
    # or a random result directory. Compression runs in the standard C library.
    with path.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=1, mtime=0) as compressed:
            with io.TextIOWrapper(compressed, encoding="utf-8", newline="\n") as stream:
                yield stream


class Aggregates:
    def __init__(self):
        self.groups = defaultdict(lambda: defaultdict(lambda: [0.0, 0]))

    def add(self, key, metrics):
        for metric in METRICS:
            if metrics.get(metric) is not None:
                value = self.groups[key][metric]
                value[0] += metrics[metric]
                value[1] += 1

    def rows(self):
        for key, metrics in sorted(self.groups.items()):
            yield key, {metric: metrics[metric][0] / metrics[metric][1] if metrics[metric][1] else None
                        for metric in METRICS}


def _read_traces(path):
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8") as stream:
        for line in stream:
            yield Trace.from_record(json.loads(line))


def _selection(value, choices):
    selected = tuple(value.split(","))
    if not selected or len(set(selected)) != len(selected) or set(selected) - set(choices):
        raise argparse.ArgumentTypeError(f"choose unique values from {', '.join(map(str, choices))}")
    return selected


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline, event-driven file-quiescence research baseline (no Broker or file payload IO).")
    parser.add_argument("--seeds", type=int, default=16, help="Independent seed blocks PER split; not event count.")
    parser.add_argument("--splits", type=lambda s: _selection(s, SPLITS), default=tuple(SPLITS))
    parser.add_argument("--channels", type=lambda s: _selection(s, CHANNELS), default=CHANNELS)
    parser.add_argument("--widths", type=lambda s: tuple(map(int, _selection(s, tuple(map(str, WIDTHS))))), default=WIDTHS)
    parser.add_argument("--tie-orders", type=lambda s: _selection(s, ("observation_first", "timer_first")),
                        default=("observation_first", "timer_first"))
    parser.add_argument("--corpus", type=Path, help="Replay exported JSONL[.gz], with writer-labelled truth; do not infer EOF=complete.")
    parser.add_argument("--compare", type=Path, help="Previous report.json on byte-identical corpus and evaluation settings.")
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--pin-report", type=Path, help="Also save the compact report at a stable, reviewable path.")
    args = parser.parse_args(argv)
    if args.seeds < 2:
        parser.error("at least two independent seed blocks are required for uncertainty estimates")
    factories = estimators()
    baseline = json.loads(args.compare.read_text(encoding="utf-8")) if args.compare else None
    with BenchmarkWorkspace(SCENARIO, results_root=args.results_root) as workspace:
        trace_path = workspace.result_dir / "traces.jsonl.gz"
        if args.corpus:
            # Normalize imported records through the same canonical writer.
            source = _read_traces(args.corpus)
        else:
            source = generate(args.seeds, args.splits, args.channels, args.widths)
        source_path = Path(inspect.getsourcefile(quiet_policy))
        shutil.copy2(source_path, workspace.result_dir / "quiet_policy.py.txt")
        # Freeze the evaluator/generator too, including uncommitted experiments.
        for path in (REPO / "benchmarks/quiet_window").glob("*.py"):
            workspace.write_result_text(f"implementation/{path.name}", path.read_text(encoding="utf-8"))
        workspace.write_result_text("implementation/watch_quiet_window.py", Path(__file__).read_text(encoding="utf-8"))
        diff = subprocess.run(["git", "diff", "--binary", "HEAD"], cwd=REPO, capture_output=True, check=True)
        workspace.write_result_text("working-tree.patch", diff.stdout.decode("utf-8"))
        parameter_identity = {"contract": CONTRACT, "tie_orders": list(args.tie_orders),
                              "slo_resolution_nanoseconds": 1,
                              "proposal_semantics": "once-per-observed-content-generation",
                              "weighting": "equal-family-then-equal-channel-width-tie-within-seed",
                              "scope": "estimator-only-not-scheduler-or-extraction"}
        parameter_identity["evaluator_sources_xxh128"] = {
            name: fast_hash128((REPO / "benchmarks/quiet_window" / name).read_text(encoding="utf-8").encode("utf-8"))
            for name in ("replay.py", "statistics.py")
        }
        family_blocks, strata = Aggregates(), Aggregates()
        counts = Counter()
        resource = defaultdict(Counter)
        seen = set()
        started = time.perf_counter()
        with compressed_writer(trace_path) as traces, compressed_writer(workspace.result_dir / "outcomes.jsonl.gz") as outcomes:
            for trace in source:
                if trace.key in seen:
                    raise ValueError(f"duplicate trace identity: {trace.key}")
                seen.add(trace.key)
                traces.write(json.dumps(trace.record(), separators=(",", ":"), allow_nan=False) + "\n")
                counts["traces"] += 1
                counts["files"] += len(trace.files)
                counts["observations"] += len(trace.observations)
                order = list(factories)
                random.Random(trace.key).shuffle(order)
                for algorithm in order:
                    for tie_order in args.tie_orders:
                        result = replay(trace, factories[algorithm], tie_order=tie_order)
                        metrics = summarize_files(result["files"])
                        family_blocks.add((trace.split, trace.seed, algorithm, trace.family), metrics)
                        for axis, value in (("family", trace.family), ("channel", trace.channel), ("width", str(trace.width)), ("tie_order", tie_order)):
                            strata.add((trace.split, algorithm, axis, value), metrics)
                        resource[algorithm]["replay_cpu_ns"] += result["replay_cpu_ns"]
                        resource[algorithm]["observations"] += result["delivered_observations"]
                        resource[algorithm]["peak_live_estimators"] = max(resource[algorithm]["peak_live_estimators"], result["peak_live_estimators"])
                        outcomes.write(json.dumps({"trace": trace.key, "algorithm": algorithm, "tie_order": tie_order,
                                                   **result}, separators=(",", ":"), allow_nan=False) + "\n")
                if counts["traces"] % 200 == 0:
                    print(f"quiet-window: {counts['traces']} traces, {counts['files']} files", flush=True)
        corpus_hash = fast_hash128_file(str(trace_path))
        parameter_identity["corpus_xxh128"] = corpus_hash
        if baseline and baseline["parameters"]["evaluation"] != parameter_identity:
            raise ValueError("baseline corpus/evaluation differs; paired comparison would be invalid")
        seed_groups = defaultdict(list)
        for (split, seed, algorithm, _family), metrics in family_blocks.rows():
            seed_groups[(split, seed, algorithm)].append(metrics)
        samples = [{"split": split, "seed": seed, "algorithm": algorithm, **macro(rows)}
                   for (split, seed, algorithm), rows in sorted(seed_groups.items())]
        summaries = {}
        for split in sorted({row["split"] for row in samples}):
            summaries[split] = {
                algorithm: {metric: interval([row[metric] for row in samples
                                             if row["split"] == split and row["algorithm"] == algorithm and row[metric] is not None])
                            for metric in METRICS}
                for algorithm in factories
            }
        payload = {"parameters": {"evaluation": parameter_identity,
                                   "generator": {"seeds_per_split": args.seeds, "families": list(FAMILIES),
                                                 "channels": list(args.channels), "widths": list(args.widths)} if not args.corpus else None,
                                   "policy_source_xxh128": fast_hash128_file(str(source_path)),
                                   "source_corpus": str(args.corpus.resolve()) if args.corpus else "synthetic-generated"},
                   "samples": samples,
                   "summary": {"macro_by_split": summaries, "counts": dict(counts),
                               "strata": [{"split": split, "algorithm": algorithm, "axis": axis, "value": value, **metrics}
                                          for (split, algorithm, axis, value), metrics in strata.rows()],
                               "resources": {key: dict(value) for key, value in resource.items()},
                               "wall_seconds": time.perf_counter() - started,
                               "paired_difference_from_baseline": paired_comparison(samples, baseline) if baseline else None,
                               "artifacts": {"directory": str(workspace.result_dir), "traces": trace_path.name,
                                             "outcomes": "outcomes.jsonl.gz", "policy_source": "quiet_policy.py.txt"}}}
        report = render_report(report_from_payload(SCENARIO, payload))
        workspace.write_result_text("report.json", report)
        if args.pin_report:
            args.pin_report.parent.mkdir(parents=True, exist_ok=True)
            args.pin_report.write_text(report, encoding="utf-8")
        print(f"quiet-window baseline: {workspace.result_dir / 'report.json'}", flush=True)
        for split, summary in summaries.items():
            current = summary["adaptive"]
            print(f"{split}: false-ready={current['false_ready_file_rate']['mean']:.4f}, "
                  f"censored={current['censored_complete_rate']['mean']:.4f}, "
                  f"within-500ms={current['within_500ms']['mean']:.4f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
