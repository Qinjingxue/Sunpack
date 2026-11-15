"""Measure recursive authorization and extraction on an archived game tree."""
from __future__ import annotations

import argparse
import platform
import shutil
import statistics
import subprocess
from pathlib import Path

from benchmarks.harness.corpus import SEVEN_ZIP
from benchmarks.harness.launcher import NativePackage
from benchmarks.harness.workspace import BenchmarkWorkspace
from benchmarks.scenarios.native_boundary import output_summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--game-tree', type=Path, help='Directory to package outside the measurement.')
    source.add_argument('--archive', type=Path, help='Existing game tree archive.')
    parser.add_argument('--runs', type=int, default=3)
    parser.add_argument('--launcher', type=Path)
    parser.add_argument('--profile', choices=('release', 'ci'), default='release')
    parser.add_argument('--arch', choices=('x64', 'arm64'), default='x64')
    parser.add_argument('--sample-ms', type=float, default=50)
    parser.add_argument('--results-root', type=Path)
    parser.add_argument('--keep-workdir', action='store_true')
    args = parser.parse_args(argv)
    if args.runs < 1 or args.sample_ms <= 0:
        parser.error('runs and sample-ms must be positive')
    with BenchmarkWorkspace('game-tree', results_root=args.results_root, keep_workdir=args.keep_workdir) as ws:
        if args.game_tree:
            root = args.game_tree.resolve()
            if not root.is_dir():
                parser.error('game-tree must be an existing directory')
            children = [str(p) for p in root.iterdir()]
            if not children:
                parser.error('game-tree must not be empty')
            archive = ws.corpus / 'game.7z'
            subprocess.run([str(SEVEN_ZIP), 'a', '-t7z', '-mx=0', str(archive), *children],
                           cwd=root, check=True, stdout=subprocess.DEVNULL)
        else:
            archive = args.archive.resolve()
            if not archive.is_file():
                parser.error('archive must be an existing file')
        with NativePackage(ws.work, launcher=args.launcher, profile=args.profile, arch=args.arch,
                           sample_ms=args.sample_ms) as app:
            rows = []
            for run in range(args.runs):
                output = ws.outputs / str(run)
                result = app.run('extract', '-r', '*', '-F', '-c', 'k', '-o', output, archive)
                if not result['response']['summary']['success_count']:
                    raise RuntimeError(f"Extraction failed: {result['response']}")
                rows.append({'run': run, 'output': output_summary(output), **result})
                shutil.rmtree(output)
            report = {'boundary': 'CLI extraction including recursive discovery and authorization',
                      'platform': platform.platform(), 'options': vars(args), 'archive_bytes': archive.stat().st_size,
                      'median_seconds': statistics.median(row['seconds'] for row in rows),
                      'max_sampled_rss_mib': max(row['peak_rss_mib'] for row in rows),
                      'sampling_note': 'Sampled peak is a lower bound.', 'rows': rows}
            print(f"Result: {ws.write_result_json('result.json', report)}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
