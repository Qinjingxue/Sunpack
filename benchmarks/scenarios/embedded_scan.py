"""Measure a streamed large carrier through the native CLI scan boundary."""
from __future__ import annotations
import argparse
import io
import platform
import statistics
import zipfile
from pathlib import Path
from benchmarks.harness.launcher import NativePackage
from benchmarks.harness.workspace import BenchmarkWorkspace


def make_carrier(path: Path, size: int, segments: int):
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, 'w', compression=zipfile.ZIP_STORED) as archive:
        archive.writestr('payload.txt', b'embedded benchmark payload')
    entry = payload.getvalue()
    if size < segments * len(entry):
        raise ValueError('carrier is too small for embedded archives')
    padding, remainder = divmod(size - segments * len(entry), segments + 1)
    block = bytes(1024 * 1024)
    def zeros(out, count):
        while count:
            chunk = min(count, len(block))
            out.write(block[:chunk])
            count -= chunk
    with path.open('wb') as out:
        for _ in range(segments):
            zeros(out, padding)
            out.write(entry)
        zeros(out, padding + remainder)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--size-mib', type=int, default=1024)
    parser.add_argument('--segments', type=int, default=128)
    parser.add_argument('--file', type=Path, help='Scan an existing carrier instead of generating one')
    parser.add_argument('--runs', type=int, default=3)
    parser.add_argument('--sample-ms', type=float, default=50)
    parser.add_argument('--profile', choices=('release', 'ci'), default='release')
    parser.add_argument('--arch', choices=('x64', 'arm64'), default='x64')
    parser.add_argument('--launcher', type=Path)
    parser.add_argument('--cold', action='store_true')
    parser.add_argument('--results-root', type=Path)
    parser.add_argument('--keep-workdir', action='store_true')
    args = parser.parse_args(argv)
    if min(args.size_mib, args.segments, args.runs, args.sample_ms) <= 0:
        parser.error('size, segments, runs and sample interval must be positive')
    with BenchmarkWorkspace('scan-embedded', results_root=args.results_root, keep_workdir=args.keep_workdir) as ws:
        if args.file:
            path = args.file.resolve()
            if not path.is_file():
                raise FileNotFoundError(path)
        else:
            path = ws.corpus / 'carrier.opaque'
            make_carrier(path, args.size_mib * 1024**2, args.segments)
        with NativePackage(ws.work, launcher=args.launcher, profile=args.profile, arch=args.arch, sample_ms=args.sample_ms) as app:
            rows = []
            for run in range(args.runs):
                if args.cold:
                    app.shutdown()
                result = app.run('scan', path)
                summary = result['response']['summary']
                if summary['scan_error_count'] or summary['input_error_count'] or summary['failed_count']:
                    raise RuntimeError(f"scan reported errors: {summary}")
                if not args.file and summary['archive_count'] != args.segments:
                    raise RuntimeError(f"expected {args.segments} embedded archives: {summary}")
                rows.append({'run': run, **result})
        report = {'boundary': 'native CLI scan including resident runtime', 'input': str(path),
                  'size_bytes': path.stat().st_size, 'generated_segments': None if args.file else args.segments,
                  'machine': platform.platform(), 'options': vars(args), 'rows': rows,
                  'median_seconds': statistics.median(row['seconds'] for row in rows),
                  'memory_note': 'Sampled process-tree peaks are lower bounds. Fixture generation is excluded.'}
        print(f"Result: {ws.write_result_json('result.json', report)}")
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
