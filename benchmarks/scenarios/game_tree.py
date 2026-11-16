"""Measure recursive scan and authorization on a directory tree."""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import statistics
import subprocess
from pathlib import Path

from benchmarks.harness.launcher import NativePackage
from benchmarks.harness.memory import bytes_to_mib
from benchmarks.harness.native_probe import build_runtime_probe
from benchmarks.harness.workspace import REPO_ROOT, BenchmarkWorkspace
from benchmarks.scenarios.native_boundary import output_summary


def scan_directory(args, directory: Path, ws: BenchmarkWorkspace) -> None:
    roots = [directory] if args.single_root else sorted(path for path in directory.iterdir() if path.is_dir())
    if not roots:
        raise ValueError(f"No child directories in {directory}; use --single-root to scan it as one scope")
    executable = build_runtime_probe(args.profile, args.arch)
    command = [
        str(executable), "--ignored", "--exact", "--nocapture",
        "pipeline::discovery::game_tree_bench::scan",
    ]
    environment = os.environ.copy()
    environment.pop("SUNPACK_CONFIG_OVERRIDES", None)
    root_input = json.dumps([str(path) for path in roots])
    rows = []
    for run in range(1, args.runs + 1):
        proc = subprocess.run(command, cwd=REPO_ROOT, input=root_input, env=environment,
                              encoding="utf-8", capture_output=True)
        output = next((line.removeprefix("GAME_TREE_BENCH ")
                       for line in proc.stdout.splitlines() if line.startswith("GAME_TREE_BENCH ")), None)
        if proc.returncode or output is None:
            log = ws.write_result_text(f"scan-{run}.log", proc.stdout + proc.stderr)
            raise RuntimeError(f"Game-tree scan probe failed; see {log}")
        row = json.loads(output)
        row["run"] = run
        rows.append(row)
        print(f"Run {run}: {row['seconds']:.3f} s, "
              f"{bytes_to_mib(row['peak_working_set_bytes']):.2f} MiB peak working set, "
              f"{len(row['allowed_tasks'])} authorized", flush=True)

    report = {
        "boundary": "Direct recursive output-directory scan and authorization",
        "platform": platform.platform(),
        "options": vars(args),
        "directory": directory,
        "scan_roots": roots,
        "measurement": (
            "One fresh process per run. Build and process startup are outside the timer. "
            "The filesystem cache is retained. Memory uses Windows process high-water marks."
        ),
        "median_seconds": statistics.median(row["seconds"] for row in rows),
        "median_prepare_seconds": statistics.median(row["prepare_seconds"] for row in rows),
        "median_discover_authorize_seconds": statistics.median(row["discover_authorize_seconds"] for row in rows),
        "max_peak_working_set_mib": bytes_to_mib(max(row["peak_working_set_bytes"] for row in rows)),
        "max_peak_commit_mib": bytes_to_mib(max(row["peak_commit_bytes"] for row in rows)),
        "rows": rows,
    }
    result = ws.write_result_json("result.json", report)
    print(f"Result: {result}", flush=True)
    if any(row["directory_errors"] or row["discovery_errors"] for row in rows):
        raise RuntimeError(f"Game-tree scan reported errors; see {result}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--directory', '--game-tree', dest='directory', type=Path,
                        help='Scan immediate subdirectories as separate output scopes.')
    source.add_argument('--archive', type=Path, help='Measure CLI extraction of an existing game tree archive.')
    parser.add_argument('--single-root', action='store_true', help='Use --directory itself as one output scope.')
    parser.add_argument('--runs', type=int, default=3)
    parser.add_argument('--launcher', type=Path, help='Native CLI launcher for --archive.')
    parser.add_argument('--profile', choices=('release', 'ci'), default='release')
    parser.add_argument('--arch', choices=('x64', 'arm64'), default='x64')
    parser.add_argument('--sample-ms', type=float, default=50, help='Memory sampling interval for --archive.')
    parser.add_argument('--results-root', type=Path)
    parser.add_argument('--keep-workdir', action='store_true')
    args = parser.parse_args(argv)
    if args.runs < 1 or args.sample_ms <= 0:
        parser.error('runs and sample-ms must be positive')
    if args.single_root and not args.directory:
        parser.error('--single-root requires --directory')
    if args.launcher and not args.archive:
        parser.error('--launcher requires --archive')
    if args.directory and not args.directory.is_dir():
        parser.error('directory must be an existing directory')
    if args.archive and not args.archive.is_file():
        parser.error('archive must be an existing file')
    with BenchmarkWorkspace('game-tree', results_root=args.results_root, keep_workdir=args.keep_workdir) as ws:
        if args.directory:
            scan_directory(args, args.directory.resolve(), ws)
            return 0
        archive = args.archive.resolve()
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
