"""Measure cold Rust password probing against generated encrypted formats."""
from __future__ import annotations
import argparse
import json
import platform
import statistics
import subprocess
from pathlib import Path

from benchmarks.harness.launcher import NativePackage
from benchmarks.harness.workspace import BenchmarkWorkspace
from benchmarks.harness.corpus import SEVEN_ZIP, RAR


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--formats', default='7z,zip,rar', help='Encrypted formats: 7z, zip, rar')
    p.add_argument('--candidates', type=int, default=1000, help='Wrong candidates before the matching password')
    p.add_argument('--runs', type=int, default=3)
    p.add_argument('--launcher', type=Path)
    p.add_argument('--profile', choices=('release', 'ci'), default='release')
    p.add_argument('--arch', choices=('x64', 'arm64'), default='x64')
    p.add_argument('--sample-ms', type=float, default=20)
    p.add_argument('--results-root', type=Path)
    p.add_argument('--keep-workdir', action='store_true')
    args = p.parse_args(argv)
    formats = args.formats.split(',')
    if not formats or any(f not in ('7z', 'zip', 'rar') for f in formats):
        p.error('formats must be selected from 7z,zip,rar')
    if args.runs < 1 or args.candidates < 0 or args.sample_ms <= 0:
        p.error('runs and sample-ms must be positive; candidates must be nonnegative')
    with BenchmarkWorkspace('password-probe', results_root=args.results_root, keep_workdir=args.keep_workdir) as ws:
        source = ws.corpus / 'source'
        source.mkdir()
        (source / 'payload.txt').write_bytes(b'password benchmark payload\n' * 128)
        cases = {}
        skipped = {}
        variants = {
            '7z': [('7z-header', SEVEN_ZIP, ['a', '-t7z', '-mhe=on', '-pbenchmark-final-key']),
                   ('7z-data', SEVEN_ZIP, ['a', '-t7z', '-mhe=off', '-pbenchmark-final-key'])],
            'zip': [('zip-aes', SEVEN_ZIP, ['a', '-tzip', '-mem=AES256', '-pbenchmark-final-key']),
                    ('zip-crypto', SEVEN_ZIP, ['a', '-tzip', '-mem=ZipCrypto', '-pbenchmark-final-key'])],
            'rar': [('rar5-header', RAR, ['a', '-ma5', '-hpbenchmark-final-key']),
                    ('rar5-data', RAR, ['a', '-ma5', '-pbenchmark-final-key']),
                    ('rar4-header', RAR, ['a', '-ma4', '-hpbenchmark-final-key']),
                    ('rar4-data', RAR, ['a', '-ma4', '-pbenchmark-final-key'])],
        }
        for fmt in formats:
            for name, tool, options in variants[fmt]:
                directory = ws.corpus / name
                directory.mkdir()
                archive = directory / ('archive.' + fmt)
                if not tool.is_file():
                    skipped[name] = f'Archive generator unavailable: {tool}'
                    continue
                result = subprocess.run([str(tool), *options, str(archive), str(source)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                if result.returncode or not archive.is_file():
                    skipped[name] = f'Generator failed ({result.returncode}): {result.stderr.decode("utf-8", "replace")}'
                else:
                    cases[name] = archive
        if not cases:
            raise RuntimeError(f'No encrypted archive could be generated: {skipped}')
        with NativePackage(ws.work, launcher=args.launcher, profile=args.profile, arch=args.arch, sample_ms=args.sample_ms) as app:
            values = [f'wrong-candidate-{i:08d}' for i in range(args.candidates)] + ['benchmark-final-key']
            (app.data / 'builtin_passwords.json').write_text(json.dumps({'passwords': [{'value': v} for v in values]}), encoding='utf-8')
            rows = []
            for fmt, archive in cases.items():
                for run in range(args.runs):
                    # Restart outside the measured request to avoid cached password/reader results.
                    app.shutdown()
                    measurement = app.run('scan', '-d', archive)
                    if not any(item.get('password_used') == 'benchmark-final-key' for item in measurement['response'].get('items', [])):
                        raise RuntimeError(f'{fmt}: scan did not report the matching password: {measurement["response"]}')
                    rows.append({'format': fmt, 'run': run, **measurement})
                    print(f'{fmt} round {run + 1}: {measurement["seconds"]:.3f}s', flush=True)
            report = {'boundary': 'cold native CLI scan; native process tree memory',
                      'platform': platform.platform(), 'options': vars(args), 'skipped': skipped,
                      'cases': {fmt: {'median_seconds': statistics.median(r['seconds'] for r in rows if r['format'] == fmt),
                                      'max_sampled_rss_mib': max(r['peak_rss_mib'] for r in rows if r['format'] == fmt)} for fmt in cases},
                      'sampling_note': 'Sampled peak is a lower bound.', 'rows': rows}
            print('Result:', ws.write_result_json('result.json', report))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
