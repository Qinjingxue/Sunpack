"""Replay deterministic write intervals through the production Rust quiet policy."""
from __future__ import annotations

import argparse
import csv
import io
import platform
import subprocess
from pathlib import Path

from benchmarks.harness.workspace import BenchmarkWorkspace, REPO_ROOT


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--intervals', default='0.1,0.1,0.1,1,1,1,5,5,5',
                        help='Comma-separated seconds between content observations.')
    parser.add_argument('--repeats', type=int, default=10000, help='Policy replays for CPU timing.')
    parser.add_argument('--results-root', type=Path)
    parser.add_argument('--keep-workdir', action='store_true')
    args = parser.parse_args(argv)
    try:
        intervals = [float(x) for x in args.intervals.split(',')]
        if not intervals or any(not 0 < x < float('inf') for x in intervals) or args.repeats < 1:
            raise ValueError()
    except ValueError:
        parser.error('intervals and repeats must be positive finite values')
    source = (REPO_ROOT / 'sunpack/sunpack_runtime/src/runtime/watch/quiet.rs').read_text(encoding='utf-8')
    # Compile the actual policy and quantile function without exposing them in
    # the production binary. Fail explicitly if the source layout changes.
    policy = source[source.index('#[derive(Default)]\npub(super) struct Quiet'):source.index('pub(super) use crate::postprocess')]
    values = ','.join(repr(x) + '_f64' for x in intervals)
    rust = '''use std::collections::VecDeque;
struct NativeWatchObservation { quiet_seconds: f64, cadence_seconds: f64, pending_interval_seconds: f64, last_content_event_at: Option<f64> }
mod policy {
use super::{NativeWatchObservation, VecDeque};
use std::time::Instant;
const WINDOW: usize = 12;
fn after(now: Instant, seconds: f64) -> Instant {
    now.checked_add(std::time::Duration::try_from_secs_f64(seconds).unwrap_or_default()).unwrap_or(now)
}
''' + policy + '''
pub fn replay(intervals: &[f64], trace: bool) {
    let mut q = Quiet::default();
    let mut at = 0.0;
    q.observe(at, false, false, true);
    for (i, interval) in intervals.iter().enumerate() {
        at += interval;
        q.observe(at, false, false, true);
        if trace { println!("{},{},{},{},{},{}", i + 1, at, interval, q.seconds, q.cadence, q.tentative); }
    }
    std::hint::black_box(q);
}
}
fn main() {
    let values = [''' + values + '''];
    println!("step,at_seconds,interval_seconds,quiet_seconds,cadence_seconds,tentative_seconds");
    policy::replay(&values, true);
    let start = std::time::Instant::now();
    for _ in 0..''' + str(args.repeats) + ''' { policy::replay(&values, false); }
    eprintln!("{}", start.elapsed().as_nanos());
}
'''
    with BenchmarkWorkspace('quiet-trace', results_root=args.results_root, keep_workdir=args.keep_workdir) as ws:
        probe = ws.work / 'quiet.rs'
        executable = ws.work / 'quiet.exe'
        probe.write_text(rust, encoding='utf-8')
        subprocess.run(['rustc', '--edition=2021', '-O', '-A', 'dead_code', str(probe), '-o', str(executable)], check=True)
        result = subprocess.run([str(executable)], check=True, capture_output=True, text=True)
        rows = [{key: float(value) for key, value in row.items()} for row in csv.DictReader(io.StringIO(result.stdout))]
        report = {'boundary': 'in-process Rust policy replay; simulated timestamps, no filesystem or scheduler',
                  'platform': platform.platform(), 'options': vars(args), 'trace': rows,
                  'cpu_elapsed_ns': int(result.stderr.strip()),
                  'note': 'quiet_seconds is the predicted window, not measured Watch completion latency.'}
        print(f"Result: {ws.write_result_json('result.json', report)}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
