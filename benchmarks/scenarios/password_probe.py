"""Measure bounded password verification and complete CLI extraction."""
from __future__ import annotations

import argparse
import json
import platform
import statistics
from pathlib import Path

from benchmarks.harness.launcher import NativePackage
from benchmarks.harness.native_probe import build_runtime_probe, run_runtime_probe
from benchmarks.harness.password_corpus import build_cases
from benchmarks.harness.workspace import BenchmarkWorkspace


def measure_native(executable, case, candidates, correct, runs):
    data = run_runtime_probe(executable, 'benchmark_reader::password_phases', {
        'path': str(case.path), 'format': case.format, 'archive_input': case.archive_input(),
        'passwords': candidates, 'runs': runs, 'production_batches': True,
    })
    rows = data['rows']
    for row in rows:
        if row['methods'] != ([case.method] if case.method else []):
            raise RuntimeError(f'{case.path}: expected {case.method}, measured {row["methods"]}')
        matches = set()
        confirmed = set()
        fallback = False
        for batch in row['batches']:
            status = batch['status']
            if status not in {'match', 'no_match', 'unknown_needs_final_verifier'}:
                raise RuntimeError(f'{case.path}: unexpected verification result: {batch}')
            fallback |= status == 'unknown_needs_final_verifier'
            indices = batch['matched_indices'] or ([] if batch['matched_index'] is None else [batch['matched_index']])
            matches.update(batch['offset'] + index for index in indices)
            if batch['final_confirmation_required'] is False:
                confirmed.update(batch['offset'] + index for index in indices)
        if (correct is not None and correct not in matches and not fallback) or confirmed - {correct}:
            raise RuntimeError(f'{case.path}: verifier produced unexpected evidence: {row["batches"]}')
        # Both deliberately colliding header bytes enter the same batch. A
        # native rejection here confirms that the legacy codec prefix ran.
        collisions = len(case.prefix_collisions)
        wrong = len(candidates) if correct is None else correct
        if collisions and wrong >= collisions and matches.intersection(range(collisions)):
            raise RuntimeError(f'{case.path}: codec prefix failed to eliminate its known header collisions')
        row['surviving_candidates'] = sorted(matches)
        row['needs_worker_confirmation'] = fallback or bool(matches - confirmed)
    return {**data, 'method': case.method, 'candidate_count': len(candidates),
            'first_seconds': rows[0]['candidates_seconds'],
            'median_verification_seconds': statistics.median(row['candidates_seconds'] for row in rows),
            'median_prepare_seconds': statistics.median(row['prepare_seconds'] for row in rows),
            'peak_working_set_bytes': max(row['after_candidates']['peak_working_set_bytes'] for row in rows),
            'peak_commit_bytes': max(row['after_candidates']['peak_commit_bytes'] for row in rows)}


def measure_cli(app, case, candidates, correct, output):
    app.shutdown()
    (app.data / 'builtin_passwords.json').write_text(
        json.dumps({'passwords': [{'value': value} for value in candidates]}), encoding='utf-8')
    flags = ('-d',) if case.carrier_start is not None else ()
    row = app.run('extract', *flags, '-npa', '-nf', '-c', 'k', '-o', output,
                  case.path, accepted=(0, 1))
    row['process_high_water'] = app.memory_high_water()
    report = row['response']
    kinds = {failure['kind'] for task in report['tasks'] for failure in task['failures']}
    files = [path for path in output.rglob('*') if path.is_file()]
    if correct is None:
        ambiguous_method = case.may_report_unsupported_password and kinds == {'unsupported'}
        if row['returncode'] != 1 or (kinds != {'wrong_password'} and not ambiguous_method) or files:
            raise RuntimeError(f'{case.path}: all-wrong CLI returned {row["returncode"]}, failures={sorted(kinds)}, files={len(files)}')
        row['outcome'] = 'ambiguous_unsupported' if ambiguous_method else 'wrong_password'
    elif row['returncode'] != 0 or report['summary']['failed_count'] or not files:
        raise RuntimeError(f'{case.path}: correct-last CLI returned {row["returncode"]}, failures={sorted(kinds)}, files={len(files)}')
    else:
        row['outcome'] = 'extracted'
    row['output_files'] = len(files)
    row['output_bytes'] = sum(path.stat().st_size for path in files)
    return row


def candidate_list(case, wrong_count, position):
    count = wrong_count + (position == 'absent')
    values = [f'{case.candidate_prefix}{i:08d}' for i in range(count)]
    collisions = case.prefix_collisions[:count]
    values[:len(collisions)] = collisions
    correct = None if position == 'absent' else wrong_count
    if correct is not None:
        values.append(case.password)
    return values, correct


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--formats', default='7z,zip,rar,enc', help='Format families: 7z, zip, rar, enc')
    p.add_argument('--cases', default='*', help='Comma-separated fixture names or glob patterns')
    p.add_argument('--candidates', type=int, default=1000, help='Wrong candidates before the correct one. Both lists have one more candidate.')
    p.add_argument('--positions', default='absent,last', help='Comma-separated absent and/or last')
    p.add_argument('--runs', type=int, default=3)
    mode = p.add_mutually_exclusive_group()
    mode.add_argument('--skip-cli', action='store_true', help='Measure only the Rust password verifier')
    mode.add_argument('--skip-native', action='store_true', help='Measure only CLI extraction')
    p.add_argument('--launcher', type=Path)
    p.add_argument('--probe', type=Path, help='Use a saved matching runtime test executable')
    p.add_argument('--profile', choices=('release', 'ci'), default='release')
    p.add_argument('--arch', choices=('x64', 'arm64'), default='x64')
    p.add_argument('--sample-ms', type=float, default=10)
    p.add_argument('--results-root', type=Path)
    p.add_argument('--keep-workdir', action='store_true')
    args = p.parse_args(argv)
    formats = set(args.formats.split(','))
    positions = list(dict.fromkeys(args.positions.split(',')))
    if not formats <= {'7z', 'zip', 'rar', 'enc'}:
        p.error('--formats must select from 7z,zip,rar,enc')
    if not set(positions) <= {'absent', 'last'}:
        p.error('--positions must select from absent,last')
    if args.runs < 1 or args.candidates < 0 or args.sample_ms <= 0:
        p.error('runs and sample-ms must be positive; candidates must be nonnegative')
    executable = args.probe.resolve() if args.probe else build_runtime_probe(args.profile, args.arch)
    with BenchmarkWorkspace('password-probe', results_root=args.results_root,
                            keep_workdir=args.keep_workdir) as ws:
        cases, skipped = build_cases(ws.corpus, formats, args.cases.split(','), executable)
        if not cases:
            raise RuntimeError(f'No selected encrypted archive could be generated: {skipped}')
        report = {'platform': platform.platform(), 'options': vars(args), 'skipped': skipped,
                  'probe_executable': str(executable.resolve()),
                  'cli_launcher': str(args.launcher.resolve()) if args.launcher else f'development {args.arch} {args.profile}',
                  'fixtures': {name: dict(vars(case)) for name, case in cases.items()},
                  'native': {}, 'cli': {}, 'errors': {},
                  'memory_note': ('Rust measures process lifetime peaks and current memory at phase boundaries. '
                                  'CLI samples the process tree. Individual high-water marks include startup '
                                  'and omit processes already exited; they do not represent a tree total.')}
        if not args.skip_native:
            for position in positions:
                for name, case in cases.items():
                    candidates, correct = candidate_list(case, args.candidates, position)
                    key = f'{name}/{position}'
                    try:
                        data = measure_native(executable, case, candidates, correct, args.runs)
                    except RuntimeError as error:
                        report['errors'][f'native/{key}'] = str(error)
                        print(error, flush=True)
                    else:
                        report['native'][key] = data
                        print(f'{key} Rust {data["median_verification_seconds"]:.4f}s', flush=True)
                    ws.write_result_json('result.json', report)
        if not args.skip_cli:
            with NativePackage(ws.work, launcher=args.launcher, profile=args.profile,
                               arch=args.arch, sample_ms=args.sample_ms) as app:
                for position in positions:
                    for name, case in cases.items():
                        candidates, correct = candidate_list(case, args.candidates, position)
                        key = f'{name}/{position}'
                        rows = []
                        for run in range(args.runs):
                            output = ws.outputs / f'{name}-{position}-{run}'
                            try:
                                row = measure_cli(app, case, candidates, correct, output)
                            except RuntimeError as error:
                                report['errors'][f'cli/{key}'] = str(error)
                                print(error, flush=True)
                                break
                            rows.append(row)
                            print(f'{key} CLI {run + 1}: {row["seconds"]:.4f}s ({row["outcome"]})', flush=True)
                        if len(rows) == args.runs:
                            report['cli'][key] = {
                                'median_seconds': statistics.median(row['seconds'] for row in rows),
                                'max_sampled_rss_mib': max(row['peak_rss_mib'] for row in rows),
                                'max_sampled_private_mib': max(row['peak_private_mib'] for row in rows),
                                'rows': rows,
                            }
                        ws.write_result_json('result.json', report)
        print('Result:', ws.write_result_json('result.json', report))
        if report['errors']:
            raise RuntimeError(f'{len(report["errors"])} password benchmark workload(s) failed; see result.json')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
