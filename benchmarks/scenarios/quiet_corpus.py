"""Replay the historical writer corpus against the current Rust quiet estimator."""
from __future__ import annotations

import argparse
import ctypes
import filecmp
import gzip
import io
import json
import platform
import subprocess
import time
from collections import Counter, defaultdict
from contextlib import ExitStack, contextmanager
from pathlib import Path

from benchmarks.harness.workspace import BenchmarkWorkspace, REPO_ROOT
from benchmarks.quiet_window.corpus import CHANNELS, CONTRACT, FAMILIES, SPLITS, WIDTHS, Trace, generate
from benchmarks.quiet_window.replay import estimators, replay
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


def compile_policy(work, path):
    source = path.read_text(encoding='utf-8')
    window = next(line for line in source.splitlines() if line.startswith('const WINDOW:'))
    policy = source[source.index('#[derive(Default)]\npub(super) struct Quiet'):source.index('pub(super) use crate::postprocess')]
    rust = '''use std::collections::VecDeque;
struct NativeWatchObservation { quiet_seconds:f64, cadence_seconds:f64, pending_interval_seconds:f64, last_content_event_at:Option<f64> }
mod policy {
use super::{NativeWatchObservation, VecDeque};
use std::time::Instant;
''' + window + '''
fn after(now:Instant, seconds:f64)->Instant { now.checked_add(std::time::Duration::try_from_secs_f64(seconds).unwrap_or_default()).unwrap_or(now) }
''' + policy + '''
#[no_mangle] pub extern "C" fn quiet_new()->*mut Quiet { Box::into_raw(Box::new(Quiet::default())) }
#[no_mangle] pub unsafe extern "C" fn quiet_free(p:*mut Quiet) { drop(Box::from_raw(p)); }
#[no_mangle] pub unsafe extern "C" fn quiet_observe(p:*mut Quiet, at:f64, boundary:bool, reset:bool, learn:bool, changed:bool)->f64 {
    let q=&mut *p;
    if changed { q.observe(at,boundary,reset,learn); } else if boundary { q.end_phase(); }
    q.seconds
}
}
'''
    probe = work / 'quiet_probe.rs'
    library = work / 'quiet_probe.dll'
    probe.write_text(rust, encoding='utf-8')
    subprocess.run(['rustc', '--edition=2021', '-O', '-A', 'dead_code', '--crate-type', 'cdylib', str(probe), '-o', str(library)], check=True)
    dll = ctypes.CDLL(str(library))
    dll.quiet_new.restype = ctypes.c_void_p
    dll.quiet_free.argtypes = [ctypes.c_void_p]
    dll.quiet_observe.argtypes = [ctypes.c_void_p, ctypes.c_double, ctypes.c_bool, ctypes.c_bool, ctypes.c_bool, ctypes.c_bool]
    dll.quiet_observe.restype = ctypes.c_double
    return dll


class Adaptive:
    def __init__(self, dll):
        self.dll = dll
        self.ptr = dll.quiet_new()
        self.size = None

    def observe(self, event):
        reset = self.size is not None and event.size < self.size
        self.size = event.size
        return self.dll.quiet_observe(self.ptr, event.at, event.phase_boundary, reset,
                                      event.learn_interval, event.content_changed)

    def __del__(self):
        if self.ptr:
            self.dll.quiet_free(self.ptr)
            self.ptr = None


def selection(value, choices):
    result = tuple(value.split(','))
    if not result or len(set(result)) != len(result) or set(result) - set(map(str, choices)):
        raise argparse.ArgumentTypeError(f'choose unique values from {", ".join(map(str, choices))}')
    return result


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--scheduler', action='store_true', help='Replay the production Rust Watch admission path.')
    p.add_argument('--seeds', type=int, default=16)
    p.add_argument('--splits', type=lambda s: selection(s, SPLITS), default=tuple(SPLITS))
    p.add_argument('--families', type=lambda s: selection(s, FAMILIES), default=FAMILIES)
    p.add_argument('--channels', type=lambda s: selection(s, CHANNELS), default=CHANNELS)
    p.add_argument('--widths', type=lambda s: tuple(map(int, selection(s, WIDTHS))), default=WIDTHS)
    p.add_argument('--tie-orders', type=lambda s: selection(s, ('observation_first', 'timer_first')), default=('observation_first', 'timer_first'))
    p.add_argument('--algorithms', help='Comma-separated estimators. Scheduler replay uses the production policy.')
    p.add_argument('--corpus', type=Path, help='Replay previously exported JSONL or JSONL.gz traces.')
    p.add_argument('--compare', type=Path, help='Compare with a report from the same evaluator and corpus.')
    p.add_argument('--pin-report', type=Path, help='Write a second copy of the report at a stable path.')
    p.add_argument('--policy-source', type=Path, help='Rust quiet.rs to use for the estimator-only comparison.')
    p.add_argument('--results-root', type=Path)
    args = p.parse_args(argv)
    if args.seeds < 1:
        p.error('seeds must be positive')
    if args.scheduler and args.algorithms not in (None, 'adaptive'):
        p.error('scheduler replay uses the production adaptive policy')
    if args.scheduler and args.policy_source:
        p.error('scheduler replay uses the checked-out Rust sources')
    scenario = 'quiet-scheduler' if args.scheduler else 'quiet-corpus'
    runtime = REPO_ROOT / 'sunpack/sunpack_runtime'
    policy = args.policy_source or runtime / 'src/runtime/watch/quiet.rs'
    with BenchmarkWorkspace(scenario, results_root=args.results_root) as ws, ExitStack() as stack:
        if args.scheduler:
            run = stack.enter_context(scheduler_replay(ws.work / "replay"))
            names = ('adaptive',)
        else:
            dll = compile_policy(ws.work, policy)
            stack.callback(ctypes.windll.kernel32.FreeLibrary, ctypes.c_void_p(dll._handle))
            factories = estimators(lambda: Adaptive(dll))
            names = selection(args.algorithms, factories) if args.algorithms else tuple(factories)
            run = lambda trace, order, name: replay(trace, factories[name], tie_order=order)
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
                        result = run(trace, order) if args.scheduler else run(trace, order, name)
                        metrics = summarize_files(result.get('inputs', result['files']))
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
                        for item in result.get('inputs', ()):
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
        if args.scheduler:
            evaluator.extend((REPO_ROOT / 'benchmarks/quiet_window/scheduler.py', runtime / 'tests/unit/runtime/watch/quiet_replay.rs'))
        evaluated_files = {'implementation/' + path.name: path for path in evaluator}
        for name, path in evaluated_files.items():
            ws.write_result_text(name, path.read_text(encoding='utf-8'))
        ws.write_result_text('implementation/production-quiet.rs', policy.read_text(encoding='utf-8'))
        if args.scheduler:
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
                  'limitations': ('Virtual filesystem and clock; immediate retirement at admission; no pipeline or OS timing.'
                                  if args.scheduler else 'Estimator-only lifecycle; one proposal per observed content generation.')}
        target = ws.write_result_json('report.json', report)
        if args.pin_report:
            args.pin_report.parent.mkdir(parents=True, exist_ok=True)
            args.pin_report.write_text(target.read_text(encoding='utf-8'), encoding='utf-8')
        print(f"Result: {target}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
