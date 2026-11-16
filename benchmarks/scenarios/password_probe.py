"""Measure Rust password verification and CLI scan on generated encrypted formats."""
from __future__ import annotations
import argparse
import json
import platform
import statistics
import subprocess
from contextlib import nullcontext
from pathlib import Path

from benchmarks.harness.launcher import NativePackage
from benchmarks.harness.native_probe import build_runtime_probe, run_runtime_probe
from benchmarks.harness.workspace import BenchmarkWorkspace
from benchmarks.harness.corpus import SEVEN_ZIP, RAR
from tests.real.enc_support import ENC_PASSWORD, create_enc_case


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--formats', default='7z,zip,rar,enc', help='Encrypted formats: 7z, zip, rar, enc')
    p.add_argument('--candidates', type=int, default=1000, help='Wrong candidates before the matching password')
    p.add_argument('--runs', type=int, default=3)
    p.add_argument('--skip-cli', action='store_true', help='Measure only the Rust password verifier.')
    p.add_argument('--launcher', type=Path)
    p.add_argument('--profile', choices=('release', 'ci'), default='release')
    p.add_argument('--arch', choices=('x64', 'arm64'), default='x64')
    p.add_argument('--sample-ms', type=float, default=20)
    p.add_argument('--results-root', type=Path)
    p.add_argument('--keep-workdir', action='store_true')
    args = p.parse_args(argv)
    formats = args.formats.split(',')
    if not formats or any(f not in ('7z', 'zip', 'rar', 'enc') for f in formats):
        p.error('formats must be selected from 7z,zip,rar,enc')
    if args.runs < 1 or args.candidates < 0 or args.sample_ms <= 0:
        p.error('runs and sample-ms must be positive; candidates must be nonnegative')
    with BenchmarkWorkspace('password-probe', results_root=args.results_root, keep_workdir=args.keep_workdir) as ws:
        source = ws.corpus / 'source'
        source.mkdir()
        (source / 'payload.bin').write_bytes(bytes(range(256)) * 4096)
        cases = {}
        skipped = {}
        variants = {
            '7z': [('7z-header', SEVEN_ZIP, ['a', '-t7z', '-mhe=on', f'-p{ENC_PASSWORD}']),
                   ('7z-data', SEVEN_ZIP, ['a', '-t7z', '-mhe=off', f'-p{ENC_PASSWORD}'])],
            'zip': [('zip-aes', SEVEN_ZIP, ['a', '-tzip', '-mem=AES256', f'-p{ENC_PASSWORD}']),
                    ('zip-crypto', SEVEN_ZIP, ['a', '-tzip', '-mem=ZipCrypto', f'-p{ENC_PASSWORD}'])],
            'rar': [('rar5-header', RAR, ['a', '-ma5', f'-hp{ENC_PASSWORD}']),
                    ('rar5-data', RAR, ['a', '-ma5', f'-p{ENC_PASSWORD}']),
                    ('rar4-header', RAR, ['a', '-ma4', f'-hp{ENC_PASSWORD}']),
                    ('rar4-data', RAR, ['a', '-ma4', f'-p{ENC_PASSWORD}'])],
        }
        for fmt in formats:
            if fmt == 'enc':
                cases['enc-v4'] = (create_enc_case(ws.corpus, 'enc-v4').entry_path, fmt)
                continue
            for name, tool, options in variants[fmt]:
                directory = ws.corpus / name
                directory.mkdir()
                archive = directory / ('archive.' + fmt)
                if not tool.is_file():
                    skipped[name] = f'Archive generator unavailable: {tool}'
                    continue
                result = subprocess.run([str(tool), *options, '-mx=0' if fmt != 'rar' else '-m0',
                                         str(archive), str(source)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                if result.returncode or not archive.is_file():
                    skipped[name] = f'Generator failed ({result.returncode}): {result.stderr.decode("utf-8", "replace")}'
                else:
                    cases[name] = (archive, fmt)
        if not cases:
            raise RuntimeError(f'No encrypted archive could be generated: {skipped}')
        values = [f'wrong-candidate-{i:08d}' for i in range(args.candidates)] + [ENC_PASSWORD]
        executable = build_runtime_probe(args.profile, args.arch)
        native = {}
        required_matches = {'zip-aes', '7z-header', 'rar5-header', 'enc-v4'}
        for name, (archive, fmt) in cases.items():
            data = run_runtime_probe(executable, 'benchmark_reader::password',
                                     {'path': str(archive), 'format': fmt, 'passwords': values, 'runs': args.runs})
            result = data['result']
            matched = result['matched_index'] == args.candidates or args.candidates in result['matched_indices']
            if not matched and (name in required_matches or result['status'] != 'unknown_needs_final_verifier'):
                raise RuntimeError(f'{name}: native verifier did not find the expected candidate: {result}')
            data['requires_final_verifier'] = not matched
            seconds = [row['seconds'] for row in data['rows']]
            data['first_seconds'] = seconds[0]
            data['warm_median_seconds'] = statistics.median(seconds[1:] or seconds)
            native[name] = data
            label = 'requires final verification' if not matched else 'candidate found'
            print(f'{name} Rust verifier: {data["warm_median_seconds"]:.3f}s ({label})', flush=True)
        with (nullcontext() if args.skip_cli else
              NativePackage(ws.work, launcher=args.launcher, profile=args.profile, arch=args.arch, sample_ms=args.sample_ms)) as app:
            if app is not None:
                (app.data / 'builtin_passwords.json').write_text(json.dumps({'passwords': [{'value': v} for v in values]}), encoding='utf-8')
            rows = []
            for case, (archive, fmt) in (cases.items() if app is not None else ()):
                for run in range(args.runs):
                    # Restart outside the measured request to avoid cached password/reader results.
                    app.shutdown()
                    measurement = app.run('scan', *(('-d',) if fmt != 'enc' else ()), archive)
                    if not any(item.get('password_used') == ENC_PASSWORD for item in measurement['response'].get('items', [])):
                        raise RuntimeError(f'{case}: scan did not report the matching password: {measurement["response"]}')
                    rows.append({'format': case, 'run': run, **measurement})
                    print(f'{case} round {run + 1}: {measurement["seconds"]:.3f}s', flush=True)
            report = {'boundary': 'Rust password verification with a reused reader; CLI scan is reported separately',
                      'native': native,
                      'platform': platform.platform(), 'options': vars(args), 'skipped': skipped,
                      'cases': {fmt: {'median_seconds': statistics.median(r['seconds'] for r in rows if r['format'] == fmt),
                                      'max_sampled_rss_mib': max(r['peak_rss_mib'] for r in rows if r['format'] == fmt)} for fmt in cases} if rows else {},
                      'sampling_note': 'Native rows use Windows process high-water marks; CLI samples are lower bounds.', 'rows': rows}
            print('Result:', ws.write_result_json('result.json', report))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
