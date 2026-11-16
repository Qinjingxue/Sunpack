"""Measure large-file embedded scanning directly in Rust and through the CLI."""
from __future__ import annotations
import argparse
import io
import platform
import statistics
import zipfile
from collections import Counter
from pathlib import Path
from benchmarks.harness.embedded_corpus import _write_repeated, mixed_carrier
from benchmarks.harness.launcher import NativePackage
from benchmarks.harness.native_probe import build_runtime_probe, run_runtime_probe
from benchmarks.harness.workspace import BenchmarkWorkspace
from tests.real.enc_support import ENC_PASSWORD


def make_carrier(path: Path, size: int, segments: int):
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, 'w', compression=zipfile.ZIP_STORED) as archive:
        archive.writestr('payload.txt', b'embedded benchmark payload')
    entry = payload.getvalue()
    if size < segments * len(entry):
        raise ValueError('carrier is too small for embedded archives')
    padding, remainder = divmod(size - segments * len(entry), segments + 1)
    block = bytes(1024 * 1024)
    offsets = set()
    with path.open('wb') as out:
        for _ in range(segments):
            _write_repeated(out, padding, block)
            offsets.add(('zip', out.tell()))
            out.write(entry)
        _write_repeated(out, padding + remainder, block)
    return offsets


def stored_zip(path: Path, size: int):
    block = b'sunpack-embedded-scan' * 50_000
    with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_STORED) as archive:
        with archive.open('payload.bin', 'w', force_zip64=size > zipfile.ZIP64_LIMIT) as payload:
            _write_repeated(payload, size, block)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--size-mib', type=int, default=1024)
    parser.add_argument('--segments', type=int, default=128)
    inputs = parser.add_mutually_exclusive_group()
    inputs.add_argument('--file', type=Path, help='Scan an existing carrier instead of generating one.')
    inputs.add_argument('--mixed', action='store_true', help='Generate the historical Plan 5 mixed carrier.')
    inputs.add_argument('--stored-zip', action='store_true', help='Generate one large stored ZIP or ZIP64 archive.')
    parser.add_argument('--runs', type=int, default=3)
    parser.add_argument('--sample-ms', type=float, default=50)
    parser.add_argument('--profile', choices=('release', 'ci'), default='release')
    parser.add_argument('--arch', choices=('x64', 'arm64'), default='x64')
    parser.add_argument('--launcher', type=Path)
    parser.add_argument('--cold', action='store_true')
    parser.add_argument('--skip-cli', action='store_true', help='Measure only the direct Rust scanner.')
    parser.add_argument('--results-root', type=Path)
    parser.add_argument('--keep-workdir', action='store_true')
    args = parser.parse_args(argv)
    if min(args.size_mib, args.segments, args.runs, args.sample_ms) <= 0:
        parser.error('size, segments, runs and sample interval must be positive')
    if args.mixed and args.segments < 100:
        parser.error('--mixed requires at least 100 segments')
    with BenchmarkWorkspace('scan-embedded', results_root=args.results_root, keep_workdir=args.keep_workdir) as ws:
        expected = set()
        size = args.size_mib * 1024**2
        if args.file:
            path = args.file.resolve()
            if not path.is_file():
                raise FileNotFoundError(path)
        elif args.stored_zip:
            path = ws.corpus / 'stored.zip'
            stored_zip(path, size)
            expected = {('zip', 0)}
        elif args.mixed:
            path = ws.corpus / 'carrier.opaque'
            expected = mixed_carrier(ws.corpus, path, size, args.segments)
        else:
            path = ws.corpus / 'carrier.opaque'
            expected = make_carrier(path, size, args.segments)
        executable = build_runtime_probe(args.profile, args.arch)
        native = run_runtime_probe(executable, 'benchmark_reader::embedded',
                                   {'path': str(path), 'runs': args.runs})
        actual = {(fmt, offset) for fmt, offset, _ in native['result']['candidates']}
        missing = expected - actual
        if missing:
            raise RuntimeError(f'Rust scan missed embedded archives: {sorted(missing)[:8]}')
        native['median_seconds'] = statistics.median(row['seconds'] for row in native['rows'])
        rows = []
        if not args.skip_cli:
            passwords = ("-p", ENC_PASSWORD) if args.mixed else ()
            with NativePackage(ws.work, launcher=args.launcher, profile=args.profile, arch=args.arch,
                               sample_ms=args.sample_ms) as app:
                for run in range(args.runs):
                    if args.cold:
                        app.shutdown()
                    result = app.run('scan', *passwords, path)
                    summary = result['response']['summary']
                    if summary['scan_error_count'] or summary['input_error_count'] or summary['failed_count']:
                        raise RuntimeError(f"scan reported errors: {summary}")
                    if args.mixed:
                        actual_cli = {(item['format'], item['offset']) for item in result['response']['items']}
                        missing = expected - actual_cli
                        if missing:
                            raise RuntimeError(f'CLI scan missed embedded archives: {sorted(missing)[:8]}')
                    elif expected and summary['archive_count'] != len(expected):
                        raise RuntimeError(f"expected {len(expected)} embedded archives: {summary}")
                    rows.append({'run': run, **result})
        report = {'boundary': 'single-file Rust embedded scan; CLI discovery measured separately',
                  'input': str(path), 'size_bytes': path.stat().st_size,
                  'generated_segments': len(expected) if expected else None,
                  'generated_formats': dict(sorted(Counter(fmt for fmt, _ in expected).items())),
                  'machine': platform.platform(), 'options': vars(args), 'native': native,
                  'rows': rows, 'median_seconds': statistics.median(row['seconds'] for row in rows) if rows else None,
                  'memory_note': 'Native high-water marks and sampled CLI process-tree peaks; fixture generation is excluded.'}
        print(f"Result: {ws.write_result_json('result.json', report)}")
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
