"""Three-way public-set confirmation; all integer loading/timing stays native."""
from __future__ import annotations

import argparse
import json
import random
import shutil
from pathlib import Path

from benchmarks.hit_index.analysis import summarize
from benchmarks.hit_index.build import ROOT, CACHE, command, environment
from benchmarks.hit_index.corpus import invoke_json


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument('--corpus', type=Path, required=True)
    parser.add_argument('--original', type=Path, required=True)
    parser.add_argument('--inherited', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    from sunpack_native import fast_hash128_file

    saved = json.loads(args.corpus.read_text(encoding='utf-8'))
    development = {Path(c['arguments']['integer-set']).resolve() for c in saved['cases']
                   if c['family'].startswith('public-')}
    executable = CACHE / 'cpp/hit_index_benchmark.exe'
    binaries = {'original': args.original, 'inherited': args.inherited, 'candidate': args.candidate}
    identities = {}
    for name, source in [('runner', executable), *binaries.items()]:
        target = args.output / (name + source.suffix)
        shutil.copy2(source, target)
        identities[name] = {'origin': str(source.resolve()), 'xxh128': fast_hash128_file(target)}
        if name == 'runner':
            executable = target
        else:
            binaries[name] = target

    # The complete selection is saved before timing. No result-dependent picks.
    rng = random.Random(20261103)
    cases = []
    for family in ['census-income', 'weather_sept_85']:
        directory = CACHE / 'sources/croaring/benchmarks/realdata' / family
        inventory = invoke_json([executable, '--mode', 'inventory', '--directory', directory])
        if inventory['status'] != 'ok':
            raise RuntimeError(inventory)
        bins = {}
        for item in inventory['sets']:
            if Path(item['path']).resolve() not in development:
                bins.setdefault(item['n'].bit_length(), []).append(item)
        for _, items in sorted(bins.items()):
            for item in rng.sample(sorted(items, key=lambda x: x['path']), min(2, len(items))):
                cases.append({'case': family + '-' + Path(item['path']).stem,
                              'family': 'public-' + family, 'n': item['n'], 'span': item['span'],
                              'path': item['path'], 'xxh128': fast_hash128_file(Path(item['path']))})
    metadata = {'selection_seed': 20261103, 'per_log2_cardinality_bin': 2,
                'excluded_development_cases': sorted(str(p) for p in development),
                'process_blocks': 7, 'mode': 'verify', 'queries': 512,
                'scope': 'held-out files from the same two public families, not an external corpus',
                'revision': command(['git', 'rev-parse', 'HEAD']).strip(),
                'rustc': command(['rustc', '--version']).strip(),
                'capabilities': invoke_json([executable, '--mode', 'capabilities']),
                'source_xxh128': fast_hash128_file(ROOT / 'native/sunpack_native/src/scan/hit_storage.rs'),
                'binaries': identities, 'cases': cases}
    (args.output / 'selection.json').write_text(json.dumps(metadata, indent=2), encoding='utf-8')
    shutil.copy2(ROOT / 'native/sunpack_native/src/scan/hit_storage.rs', args.output / 'hit_storage.rs')
    (args.output / 'candidate.diff').write_text(command(['git', 'diff', '--', 'native/sunpack_native/src/scan/hit_storage.rs']), encoding='utf-8')
    rows = []
    with (args.output / 'raw.jsonl').open('w', encoding='utf-8') as journal:
        for block in range(7):
            ordered_cases = list(cases)
            rng.shuffle(ordered_cases)
            for index, case in enumerate(ordered_cases):
                names = list(binaries)
                rotation = (block + index) % len(names)
                names = names[rotation:] + names[:rotation]
                sizes = []
                for name in names:
                    row = invoke_json([executable, '--mode', 'verify', '--algorithm', 'sunpack',
                                       '--integer-set', case['path'], '--queries', 512,
                                       '--bridge', binaries[name]], env=environment())
                    row.update(case=case['case'], family=case['family'], configuration=name, block=block)
                    rows.append(row)
                    journal.write(json.dumps(row) + '\n')
                    journal.flush()
                    if row.get('status') != 'ok':
                        raise RuntimeError(row)
                    if name != 'original':
                        sizes.append(row['bytes'])
                if len(set(sizes)) != 1:
                    raise RuntimeError('Candidate changed inherited encoded size: ' + case['case'])
            print(f'confirmation block {block + 1}/7 complete ({len(cases)} inputs)', flush=True)
    result = {'metadata': metadata, 'samples': rows,
              'versus_original': summarize(rows, reference='original'),
              'versus_inherited': summarize(rows, reference='inherited')}
    (args.output / 'report.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(args.output / 'report.json')


if __name__ == '__main__':
    main()
