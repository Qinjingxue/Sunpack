from __future__ import annotations

import argparse
import gzip
import inspect
import io
import json
import random
import shutil
import time
from collections import Counter, defaultdict
from contextlib import ExitStack, contextmanager
from pathlib import Path

from sunpack_native import fast_hash128, fast_hash128_file

from benchmarks.harness.reporting import report_from_payload, render_report
from benchmarks.harness.workspace import BenchmarkWorkspace
from benchmarks.quiet_window.corpus import CHANNELS, CONTRACT, FAMILIES, SPLITS, WIDTHS, Trace, generate
from benchmarks.quiet_window.replay import estimators, proposal_boundaries, replay
from benchmarks.quiet_window.statistics import BURST_WINDOWS, EVALUATION_CONTRACT, METRICS, interval, macro, paired_comparison, summarize_files
from sunpack.runtime.watch import quiet_policy
from sunpack.core.config.fields.watch import DEFAULT_WATCH_CONFIG


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


def main(argv=None, *, scheduler_mode=False):
    parser = argparse.ArgumentParser(description="Offline, event-driven file-quiescence research baseline (no Broker or file payload IO).")
    parser.add_argument("--seeds", type=int, default=16, help="Independent seed blocks PER split; not event count.")
    parser.add_argument("--splits", type=lambda s: _selection(s, SPLITS), default=tuple(SPLITS))
    parser.add_argument("--channels", type=lambda s: _selection(s, CHANNELS), default=CHANNELS)
    parser.add_argument("--families", type=lambda s: _selection(s, FAMILIES), default=FAMILIES)
    parser.add_argument("--widths", type=lambda s: tuple(map(int, _selection(s, tuple(map(str, WIDTHS))))), default=WIDTHS)
    parser.add_argument("--tie-orders", type=lambda s: _selection(s, ("observation_first", "timer_first")),
                        default=("observation_first", "timer_first"))
    parser.add_argument("--corpus", type=Path, help="Replay exported JSONL[.gz], with writer-labelled truth; do not infer EOF=complete.")
    parser.add_argument("--compare", type=Path, help="Previous report.json on byte-identical corpus and evaluation settings.")
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--pin-report", type=Path, help="Also save the compact report at a stable, reviewable path.")
    parser.add_argument("--algorithms", type=lambda s: _selection(s, estimators()),
                        default=("adaptive",) if scheduler_mode else tuple(estimators()))
    parser.add_argument("--policy-source", type=Path, help="Execute a frozen adaptive policy with the same current replay engine.")
    args = parser.parse_args(argv)
    if args.seeds < 2:
        parser.error("at least two independent seed blocks are required for uncertainty estimates")
    if args.policy_source:
        from benchmarks.quiet_window.cost import _load
        policy_module = _load(args.policy_source)
    else:
        policy_module = quiet_policy
    factories = {name: factory for name, factory in estimators(policy_module).items() if name in args.algorithms}
    proposal_semantics = ("production-enqueue-pop-ready-boundary-confirmation-instant-retirement"
                          if scheduler_mode else "once-per-observed-content-generation")
    if scheduler_mode:
        from benchmarks.quiet_window.scheduler_replay import prepare_metadata, replay_scheduler
    baseline = json.loads(args.compare.read_text(encoding="utf-8")) if args.compare else None
    source_path = args.policy_source or Path(inspect.getsourcefile(quiet_policy))
    scenario = "scheduling.watch-quiet-scheduler" if scheduler_mode else SCENARIO
    with BenchmarkWorkspace(scenario, results_root=args.results_root) as workspace:
        metadata_root = prepare_metadata(workspace.work / "metadata") if scheduler_mode else None
        trace_path = workspace.result_dir / "traces.jsonl.gz"
        if args.corpus:
            # Normalize imported records through the same canonical writer.
            source = _read_traces(args.corpus)
        else:
            source = generate(args.seeds, args.splits, args.channels, args.widths, args.families)
        shutil.copy2(source_path, workspace.result_dir / "quiet_policy.py.txt")
        evaluator_names = ("corpus.py", "writers.py", "replay.py", "statistics.py")
        if scheduler_mode:
            evaluator_names += ("scheduler_replay.py",)
        # Freeze only the executed generator/evaluator, including local edits.
        for name in evaluator_names:
            path = REPO / "benchmarks/quiet_window" / name
            workspace.write_result_text(f"implementation/{path.name}", path.read_text(encoding="utf-8"))
        workspace.write_result_text("implementation/watch_quiet_window.py", Path(__file__).read_text(encoding="utf-8"))
        parameter_identity = {"contract": EVALUATION_CONTRACT, "trace_contract": CONTRACT,
                              "algorithms": list(factories),
                              "channels": list(args.channels),
                              "families": list(args.families),
                              "runner_source_xxh128": fast_hash128(Path(__file__).read_text(encoding="utf-8").encode("utf-8")),
                              "tie_orders": list(args.tie_orders),
                              "slo_resolution_nanoseconds": 1,
                              "invalid_burst_windows_nanoseconds": dict(BURST_WINDOWS),
                              "invalid_burst_semantics": "max-sliding-half-open-window;per-logical-input-and-concurrent-trace;negative-writers-included",
                              "proposal_semantics": proposal_semantics,
                              "weighting": "equal-family-then-equal-channel-width-tie-within-seed",
                              "scope": "estimator-only-not-scheduler-or-extraction",
                              "valid_proposal_latency": "complete-visible-readable-and-split-ready-to-first-valid-proposal;incompatible-handle-wait-excluded"}
        if scheduler_mode:
            parameter_identity.update(
                contract="sunpack.quiet-scheduler/5", metric_contract=EVALUATION_CONTRACT,
                proposal_semantics="production-enqueue-pop-ready-boundary-confirmation-instant-retirement",
                scope="production-admission-with-virtual-metadata-readiness-clock-and-memory-only-wal;not-extraction",
                scoring_unit="single-file-or-complete-split-input;any-member-admission",
                busy_timer_coalescing="skip-state-invariant-busy-timers-preserving-cadence-until-same-path-change-delivery-or-unlock;probe-cpu-not-modelled",
                boundary_confirmation_seconds=DEFAULT_WATCH_CONFIG["boundary_confirmation_seconds"],
            )
        parameter_identity["evaluator_sources_xxh128"] = {
            name: fast_hash128((REPO / "benchmarks/quiet_window" / name).read_text(encoding="utf-8").encode("utf-8"))
            for name in evaluator_names
        }
        if scheduler_mode:
            from sunpack.runtime.watch import scheduler as runtime_scheduler, state as runtime_state
            parameter_identity["production_sources_xxh128"] = {}
            production_paths = [Path(inspect.getsourcefile(module)) for module in (runtime_scheduler, runtime_state)]
            production_paths += [REPO / "native/sunpack_native/src/scan" / name for name in ("catalog.rs", "directory.rs")]
            for path in production_paths:
                source_text = path.read_text(encoding="utf-8")
                parameter_identity["production_sources_xxh128"][path.name] = fast_hash128(source_text.encode("utf-8"))
                workspace.write_result_text(f"implementation/production-{path.name}", source_text)
        if baseline and {key: value for key, value in baseline["parameters"]["evaluation"].items() if key != "corpus_xxh128"} != parameter_identity:
            raise ValueError("baseline evaluation differs; replay both policies with the same corpus and evaluator")
        family_blocks, strata = Aggregates(), Aggregates()
        counts = Counter()
        resource = defaultdict(Counter)
        burst_worst = defaultdict(Counter)
        seen = set()
        started = time.perf_counter()
        with ExitStack() as stack:
            traces = stack.enter_context(compressed_writer(trace_path))
            outcomes = stack.enter_context(compressed_writer(workspace.result_dir / "outcomes.jsonl.gz"))
            for trace in source:
                if trace.key in seen:
                    raise ValueError(f"duplicate trace identity: {trace.key}")
                seen.add(trace.key)
                selected = (trace.split in args.splits and trace.seed < args.seeds
                            and trace.channel in args.channels and trace.width in args.widths
                            and trace.family in args.families)
                if not selected:
                    continue
                traces.write(json.dumps(trace.record(), separators=(",", ":"), allow_nan=False) + "\n")
                counts["traces"] += 1
                counts["files"] += len(trace.files)
                counts["observations"] += len(trace.observations)
                _, boundaries = proposal_boundaries(trace)
                arrived_count = sum(arrived is not None for arrived, _ in boundaries.values())
                counts["complete_arrival_files"] += arrived_count
                counts["ineligible_valid_proposal_files"] += len(trace.files) - arrived_count
                order = list(factories)
                random.Random(trace.key).shuffle(order)
                run = (lambda *a, **kw: replay_scheduler(*a, metadata_root=metadata_root, **kw)) if scheduler_mode else replay
                results = ((algorithm, tie_order, run(trace, factories[algorithm], tie_order=tie_order))
                           for algorithm in order for tie_order in args.tie_orders)
                for algorithm, tie_order, result in results:
                    scoring_files = result.get("inputs", result["files"])
                    metrics = summarize_files(scoring_files)
                    for label, _ in BURST_WINDOWS:
                        for suffix in ("input_max_per_trace", "all_inputs"):
                            name = f"invalid_burst_{label}_{suffix}"
                            for axis, value in (("all", "all"), ("family", trace.family), ("width", str(trace.width))):
                                key = (trace.split, algorithm, axis, value)
                                burst_worst[key][name] = max(burst_worst[key][name], metrics[name])
                    family_blocks.add((trace.split, trace.seed, algorithm, trace.family), metrics)
                    for axis, value in (("family", trace.family), ("channel", trace.channel), ("width", str(trace.width)), ("tie_order", tie_order)):
                        strata.add((trace.split, algorithm, axis, value), metrics)
                    resource[algorithm]["replay_cpu_ns"] += result["replay_cpu_ns"]
                    resource[algorithm]["observations"] += result["delivered_observations"]
                    resource[algorithm]["peak_live_estimators"] = max(resource[algorithm]["peak_live_estimators"], result["peak_live_estimators"])
                    for name in ("metadata_probes", "readiness_probes", "coalesced_busy_timer_runs"):
                        resource[algorithm][name] += result.get(name, 0)
                    resource[algorithm]["complete_arrival_inputs"] += metrics["complete_arrival_files"]
                    resource[algorithm]["missing_valid_proposal_inputs"] += metrics["complete_arrival_files"] - metrics["valid_proposal_files"]
                    for item in result.get("inputs", ()):
                        if item.get("missing_reason") not in (None, "no_processing_ready_input"):
                            resource[algorithm]["missing_reason:" + item["missing_reason"]] += 1
                    outcomes.write(json.dumps({"trace": trace.key, "algorithm": algorithm, "tie_order": tie_order,
                                               **result}, separators=(",", ":"), allow_nan=False) + "\n")
                if counts["traces"] % 200 == 0:
                    print(f"quiet-window: {counts['traces']} traces, {counts['files']} files", flush=True)
        if not counts["traces"]:
            raise ValueError("selected corpus contains no traces")
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
                                   "generator": {"seeds_per_split": args.seeds, "families": list(args.families),
                                                 "channels": list(args.channels), "widths": list(args.widths)} if not args.corpus else None,
                                   "policy_source_xxh128": fast_hash128_file(str(source_path)),
                                   "source_corpus": str(args.corpus.resolve()) if args.corpus else "synthetic-generated"},
                   "samples": samples,
                   "summary": {"macro_by_split": summaries, "counts": dict(counts),
                               "strata": [{"split": split, "algorithm": algorithm, "axis": axis, "value": value, **metrics}
                                          for (split, algorithm, axis, value), metrics in strata.rows()],
                               "resources": {key: dict(value) for key, value in resource.items()},
                               "burst_worst": [{"split": split, "algorithm": algorithm, "axis": axis, "value": value, **dict(values)}
                                               for (split, algorithm, axis, value), values in sorted(burst_worst.items())],
                               "wall_seconds": time.perf_counter() - started,
                               "paired_difference_from_baseline": paired_comparison(samples, baseline) if baseline else None,
                               "artifacts": {"directory": str(workspace.result_dir), "traces": trace_path.name,
                                             "outcomes": "outcomes.jsonl.gz", "policy_source": "quiet_policy.py.txt"}}}
        report = render_report(report_from_payload(scenario, payload))
        workspace.write_result_text("report.json", report)
        if args.pin_report:
            args.pin_report.parent.mkdir(parents=True, exist_ok=True)
            args.pin_report.write_text(report, encoding="utf-8")
        print(f"quiet-window baseline: {workspace.result_dir / 'report.json'}", flush=True)
        for split, summary in summaries.items():
            for algorithm, current in summary.items():
                print(f"{split}/{algorithm}: ready-to-valid-proposal="
                      f"{current['mean_ready_to_valid_proposal_seconds']['mean']}s, "
                      f"missing={current['censored_valid_proposal_rate']['mean']}, "
                      f"invalid/input={current['invalid_proposals_per_file']['mean']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
