"""Compare two instrumented workers on identical real decompression inputs.

Run tests/memory/worker_format_probe.py --generate-only first. Both executables
use the same test telemetry and isolated Job, so CPU time is comparable despite
the CPU cap. This is a manual benchmark, not a correctness test of a benchmark.
"""
import argparse
import contextlib
import io
import json
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tests.memory import worker_reserve_probe as probe

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--before', type=Path, required=True)
    parser.add_argument('--after', type=Path, default=probe.WORKER)
    parser.add_argument('--cases', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--repetitions', type=int, default=3)
    args = parser.parse_args()
    probe.OUT = args.output.resolve()
    samples = []
    selected = {'zip-Deflate', 'zip-BZip2', 'zip-PPMd', '7z-LZMA2', 'lz4', 'zstd'}
    for case in json.loads(args.cases.read_text()):
        if case['name'] not in selected: continue
        for repeat in range(args.repetitions):
            # Alternate order to avoid always assigning the warm run to one side.
            versions = [('before', args.before), ('after', args.after)]
            if repeat % 2: versions.reverse()
            for version, worker in versions:
                probe.WORKER = worker.resolve()
                with contextlib.redirect_stdout(io.StringIO()):
                    report = probe.run(case['name'] + '-' + version, Path(case['archive']), case['format'], 8,
                        password=case['password'], expected_output=case['expected'])
                samples.append({'case': case['name'], 'version': version, **report})
        summary = {'case': case['name']}
        for version in ('before', 'after'):
            rows = [r for r in samples if r['case'] == case['name'] and r['version'] == version]
            summary[version] = {key: statistics.median(r[key] for r in rows)
                for key in ('cpu_seconds', 'worker_seconds')}
        print(json.dumps(summary), flush=True)
    (probe.OUT / 'comparison.json').write_text(json.dumps(samples, indent=2))
