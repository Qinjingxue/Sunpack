"""Replay the historical writer corpus against the current Rust quiet estimator."""
from __future__ import annotations

import argparse
import ctypes
import gzip
import json
import platform
import subprocess
import time
from collections import Counter, defaultdict
from pathlib import Path

from benchmarks.harness.workspace import BenchmarkWorkspace, REPO_ROOT
from benchmarks.quiet_window.corpus import CHANNELS, CONTRACT, FAMILIES, SPLITS, WIDTHS, Trace, generate
from benchmarks.quiet_window.replay import estimators, replay
from benchmarks.quiet_window.statistics import BURST_WINDOWS, METRICS, interval, macro, summarize_files


def compile_policy(work):
    source = (REPO_ROOT / 'sunpack/sunpack_runtime/src/runtime/watch/quiet.rs').read_text(encoding='utf-8')
    policy = source[source.index('#[derive(Default)]\npub(super) struct Quiet'):source.index('pub(super) use crate::postprocess')]
    rust = '''use std::collections::VecDeque;
struct NativeWatchObservation { quiet_seconds:f64, cadence_seconds:f64, pending_interval_seconds:f64, last_content_event_at:Option<f64> }
mod policy {
use super::{NativeWatchObservation, VecDeque};
use std::time::Instant;
const WINDOW:usize=12;
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
    return dll, source


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
    p.add_argument('--seeds', type=int, default=16)
    p.add_argument('--splits', type=lambda s: selection(s, SPLITS), default=tuple(SPLITS))
    p.add_argument('--families', type=lambda s: selection(s, FAMILIES), default=FAMILIES)
    p.add_argument('--channels', type=lambda s: selection(s, CHANNELS), default=CHANNELS)
    p.add_argument('--widths', type=lambda s: tuple(map(int, selection(s, WIDTHS))), default=WIDTHS)
    p.add_argument('--tie-orders', type=lambda s: selection(s, ('observation_first', 'timer_first')), default=('observation_first', 'timer_first'))
    p.add_argument('--algorithms', default='adaptive,ewma,fixed-0s,fixed-0.05s,fixed-0.5s,fixed-2s,fixed-10s,fixed-180s')
    p.add_argument('--corpus', type=Path, help='Replay previously exported JSONL or JSONL.gz traces.')
    p.add_argument('--results-root', type=Path)
    args = p.parse_args(argv)
    if args.seeds < 1:
        p.error('seeds must be positive')
    with BenchmarkWorkspace('quiet-corpus', results_root=args.results_root) as ws:
        dll, source = compile_policy(ws.work)
        factories = estimators(lambda: Adaptive(dll))
        names = selection(args.algorithms, factories)
        counts = Counter()
        family = defaultdict(list)
        strata = defaultdict(list)
        worst = defaultdict(Counter)
        cpu = Counter()
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
        with gzip.open(ws.result_dir / 'traces.jsonl.gz', 'wt', encoding='utf-8') as traces, gzip.open(ws.result_dir / 'outcomes.jsonl.gz', 'wt', encoding='utf-8') as outcomes:
            for trace in selected_traces():
                if trace.key in seen:
                    raise ValueError(f'duplicate trace identity: {trace.key}')
                seen.add(trace.key)
                traces.write(json.dumps(trace.record(), separators=(',', ':'), allow_nan=False) + '\n')
                counts.update(traces=1, files=len(trace.files), observations=len(trace.observations))
                for name in names:
                    for order in args.tie_orders:
                        result = replay(trace, factories[name], tie_order=order)
                        metrics = summarize_files(result['files'])
                        family[(trace.split, trace.seed, name, trace.family)].append(metrics)
                        for axis, value in (('family', trace.family), ('channel', trace.channel), ('width', str(trace.width)), ('tie_order', order)):
                            strata[(trace.split, name, axis, value)].append(metrics)
                        for label, _ in BURST_WINDOWS:
                            for suffix in ('input_max_per_trace', 'all_inputs'):
                                metric = f'invalid_burst_{label}_{suffix}'
                                for axis, value in (('all', 'all'), ('family', trace.family), ('width', str(trace.width))):
                                    key = (trace.split, name, axis, value)
                                    worst[key][metric] = max(worst[key][metric], metrics[metric])
                        cpu[name] += result['replay_cpu_ns']
                        outcomes.write(json.dumps({'trace': trace.key, 'algorithm': name, 'tie_order': order, **result}, separators=(',', ':'), allow_nan=False) + '\n')
                if counts['traces'] % 200 == 0:
                    print(f"quiet corpus: {counts['traces']} traces", flush=True)
        if not counts['traces']:
            raise ValueError('selection contains no traces')
        blocks = defaultdict(list)
        for (split, seed, name, _), rows in family.items():
            blocks[(split, seed, name)].append(macro(rows))
        samples = [{'split': split, 'seed': seed, 'algorithm': name, **macro(rows)} for (split, seed, name), rows in sorted(blocks.items())]
        summary = {split: {name: {metric: interval([row[metric] for row in samples if row['split'] == split and row['algorithm'] == name and row[metric] is not None]) for metric in METRICS} for name in names} for split in args.splits}
        ws.write_result_text('quiet.rs.txt', source)
        for name in ('corpus.py', 'writers.py', 'replay.py', 'statistics.py'):
            ws.write_result_text('implementation/' + name, (REPO_ROOT / 'benchmarks/quiet_window' / name).read_text(encoding='utf-8'))
        ws.write_result_text('implementation/quiet_corpus.py', Path(__file__).read_text(encoding='utf-8'))
        report = {'trace_contract': CONTRACT, 'evaluation': 'historical estimator-only replay with Rust Quiet; not scheduler admission',
                  'platform': platform.platform(), 'options': vars(args), 'counts': dict(counts), 'samples': samples,
                  'summary_by_split': summary, 'strata': [{'split': s, 'algorithm': n, 'axis': a, 'value': v, **macro(rows)} for (s, n, a, v), rows in sorted(strata.items())],
                  'burst_worst': [{'split': s, 'algorithm': n, 'axis': a, 'value': v, **dict(row)} for (s, n, a, v), row in sorted(worst.items())],
                  'replay_cpu_ns': dict(cpu), 'wall_seconds': time.perf_counter() - start,
                  'limitations': 'Synthetic writer model; estimator-only lifecycle, not the Rust scheduler, filesystem, or extraction. Censored cases stay in the latency denominator.'}
        print(f"Result: {ws.write_result_json('report.json', report)}")
        ctypes.windll.kernel32.FreeLibrary(ctypes.c_void_p(dll._handle))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
