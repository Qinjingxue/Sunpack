"""Replay the historical writer corpus through the production Rust Watch scheduler."""
from __future__ import annotations

import argparse
import filecmp
import gzip
import io
import json
import platform
import time
from collections import Counter, defaultdict
from contextlib import contextmanager
from pathlib import Path

from benchmarks.harness.workspace import BenchmarkWorkspace, REPO_ROOT
from benchmarks.quiet_window.corpus import CHANNELS, CONTRACT, FAMILIES, REPLAY_CHANNELS, SPLITS, WIDTHS, Trace, generate
from benchmarks.quiet_window.scheduler import scheduler_replay
from benchmarks.quiet_window.statistics import BURST_WINDOWS, EVALUATION_CONTRACT, METRICS, interval, macro, paired_comparison, summarize_files


@contextmanager
def canonical_gzip(path):
    with path.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=1, mtime=0) as stream:
            with io.TextIOWrapper(stream, encoding="utf-8", newline="\n") as text:
                yield text


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
            yield key, {
                metric: metrics[metric][0] / metrics[metric][1] if metrics[metric][1] else None
                for metric in METRICS
            }


def selection(value, choices):
    result = tuple(value.split(','))
    if not result or len(set(result)) != len(result) or set(result) - set(map(str, choices)):
        raise argparse.ArgumentTypeError(f'choose unique values from {", ".join(map(str, choices))}')
    return result


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--seeds', type=int, default=16)
    p.add_argument('--splits', type=lambda s: selection(s, SPLITS), default=tuple(SPLITS))
    p.add_argument('--families', type=lambda s: selection(s, FAMILIES), default=FAMILIES)
    p.add_argument('--channels', type=lambda s: selection(s, REPLAY_CHANNELS), default=CHANNELS)
    p.add_argument('--widths', type=lambda s: tuple(map(int, selection(s, WIDTHS))), default=WIDTHS)
    p.add_argument('--tie-orders', type=lambda s: selection(s, ('observation_first', 'timer_first')), default=('observation_first', 'timer_first'))
    p.add_argument('--corpus', type=Path, help='Replay previously exported JSONL or JSONL.gz traces.')
    p.add_argument('--compare', type=Path, help='Compare with a report from the same evaluator and corpus.')
    p.add_argument('--pin-report', type=Path, help='Write a second copy of the report at a stable path.')
    p.add_argument('--results-root', type=Path)
    args = p.parse_args(argv)
    if args.seeds < 1:
        p.error('seeds must be positive')
    scenario = 'quiet-corpus'
    runtime = REPO_ROOT / 'sunpack/sunpack_runtime'
    policy = runtime / 'src/runtime/watch/quiet.rs'
    names = ('adaptive',)
    with BenchmarkWorkspace(scenario, results_root=args.results_root) as ws, scheduler_replay(ws.work / "replay") as run:
        evaluation = {"mode": scenario, "metric_contract": EVALUATION_CONTRACT, "trace_contract": CONTRACT,
                      "algorithms": list(names), "tie_orders": list(args.tie_orders)}
        counts = Counter()
        family = Aggregates()
        strata = Aggregates()
        worst = defaultdict(Counter)
        resources = defaultdict(Counter)
        start = time.perf_counter()
        def selected_traces():
            if args.corpus:
                opener = gzip.open if args.corpus.suffix == '.gz' else open
                with opener(args.corpus, 'rt', encoding='utf-8') as stream:
                    for line in stream:
                        trace = Trace.from_record(json.loads(line))
                        if (trace.seed < args.seeds and trace.split in args.splits and trace.family in args.families
                                and trace.channel in args.channels and trace.width in args.widths):
                            yield trace
            else:
                yield from generate(args.seeds, args.splits, args.channels, args.widths, args.families)

        seen = set()
        corpus_path = ws.result_dir / 'traces.jsonl.gz'
        with canonical_gzip(corpus_path) as traces, canonical_gzip(ws.result_dir / 'outcomes.jsonl.gz') as outcomes:
            for trace in selected_traces():
                if trace.key in seen:
                    raise ValueError(f'duplicate trace identity: {trace.key}')
                seen.add(trace.key)
                traces.write(json.dumps(trace.record(), separators=(',', ':'), allow_nan=False) + '\n')
                counts.update(traces=1, files=len(trace.files), observations=len(trace.observations))
                for name in names:
                    for order in args.tie_orders:
                        result = run(trace, order)
                        metrics = summarize_files(result['inputs'])
                        family.add((trace.split, trace.seed, name, trace.family), metrics)
                        for axis, value in (('family', trace.family), ('channel', trace.channel), ('width', str(trace.width)), ('tie_order', order)):
                            strata.add((trace.split, name, axis, value), metrics)
                        for label, _ in BURST_WINDOWS:
                            for suffix in ('input_max_per_trace', 'all_inputs'):
                                metric = f'invalid_burst_{label}_{suffix}'
                                for axis, value in (('all', 'all'), ('family', trace.family), ('width', str(trace.width))):
                                    key = (trace.split, name, axis, value)
                                    worst[key][metric] = max(worst[key][metric], metrics[metric])
                        for field in ('replay_cpu_ns', 'replay_elapsed_ns', 'metadata_probes', 'readiness_probes',
                                      'scheduled_deadlines', 'coalesced_busy_timer_runs', 'delivered_observations'):
                            if field in result:
                                resources[name][field] += result[field]
                        resources[name]['peak_live_estimators'] = max(
                            resources[name]['peak_live_estimators'], result['peak_live_estimators'])
                        resources[name]['complete_arrival_inputs'] += metrics['complete_arrival_files']
                        resources[name]['missing_valid_proposal_inputs'] += (
                            metrics['complete_arrival_files'] - metrics['valid_proposal_files'])
                        for item in result['inputs']:
                            if item['missing_reason'] not in (None, 'no_processing_ready_input'):
                                resources[name]['missing_reason:' + item['missing_reason']] += 1
                        outcomes.write(json.dumps({'trace': trace.key, 'algorithm': name, 'tie_order': order, **result}, separators=(',', ':'), allow_nan=False) + '\n')
                if counts['traces'] % 200 == 0:
                    print(f"quiet corpus: {counts['traces']} traces", flush=True)
        if not counts['traces']:
            raise ValueError('selection contains no traces')
        blocks = defaultdict(list)
        for (split, seed, name, _), metrics in family.rows():
            blocks[(split, seed, name)].append(metrics)
        samples = [{'split': split, 'seed': seed, 'algorithm': name, **macro(rows)} for (split, seed, name), rows in sorted(blocks.items())]
        summary = {split: {name: {metric: interval([row[metric] for row in samples if row['split'] == split and row['algorithm'] == name and row[metric] is not None]) for metric in METRICS} for name in names} for split in args.splits}
        evaluator = [REPO_ROOT / 'benchmarks/quiet_window' / name for name in ('corpus.py', 'writers.py', 'replay.py', 'statistics.py')]
        evaluator.append(Path(__file__))
        evaluator.extend((REPO_ROOT / 'benchmarks/quiet_window/scheduler.py', runtime / 'tests/unit/runtime/watch/quiet_replay.rs'))
        evaluated_files = {'implementation/' + path.name: path for path in evaluator}
        for name, path in evaluated_files.items():
            ws.write_result_text(name, path.read_text(encoding='utf-8'))
        ws.write_result_text('implementation/production-quiet.rs', policy.read_text(encoding='utf-8'))
        for name in ('runtime/watch.rs', 'postprocess/mod.rs', 'scan/directory.rs'):
            ws.write_result_text('implementation/production/' + name,
                                 (runtime / 'src' / name).read_text(encoding='utf-8'))
        comparison = None
        if args.compare:
            baseline = json.loads(args.compare.read_text(encoding='utf-8'))
            artifacts = Path(baseline['artifacts'])
            if baseline['evaluation'] != evaluation or any(
                not filecmp.cmp(ws.result_dir / name, artifacts / name, shallow=False) for name in evaluated_files
            ) or not filecmp.cmp(corpus_path, artifacts / corpus_path.name, shallow=False):
                raise ValueError('baseline evaluator or corpus differs; paired comparison would be invalid')
            comparison = paired_comparison(samples, baseline)
        report = {'trace_contract': CONTRACT, 'evaluation': evaluation, 'artifacts': str(ws.result_dir),
                  'platform': platform.platform(), 'options': vars(args), 'counts': dict(counts), 'samples': samples,
                  'summary_by_split': summary, 'strata': [{'split': s, 'algorithm': n, 'axis': a, 'value': v, **metrics} for (s, n, a, v), metrics in strata.rows()],
                  'burst_worst': [{'split': s, 'algorithm': n, 'axis': a, 'value': v, **dict(row)} for (s, n, a, v), row in sorted(worst.items())],
                  'resources': dict(resources), 'wall_seconds': time.perf_counter() - start,
                  'paired_difference_from_baseline': comparison,
                  'limitations': 'Virtual filesystem and clock; immediate retirement at admission; no pipeline or OS timing.'}
        target = ws.write_result_json('report.json', report)
        if args.pin_report:
            args.pin_report.parent.mkdir(parents=True, exist_ok=True)
            args.pin_report.write_text(target.read_text(encoding='utf-8'), encoding='utf-8')
        print(f"Result: {target}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
