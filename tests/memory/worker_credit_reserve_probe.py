"""Manual CPU-credit/reserve scaling experiment, confined to a child Job.

The probe executable alone can simulate processor counts above this machine.
All output is independently CRC-checked by the shared memory probe. No workload
or CPU limit is applied to the installed worker or the parent process.
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tests.memory import worker_reserve_probe as probe


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cases', type=Path, default=ROOT / 'reports/worker-memory-optimization-20261027/cases.json')
    parser.add_argument('--report-dir', type=Path, default=ROOT / 'reports/worker-credit-reserve-20261027')
    parser.add_argument('--credits', type=int, nargs='+', default=[1, 2, 4, 8, 16, 32, 64, 128])
    parser.add_argument('--case', action='append', default=[])
    parser.add_argument('--reserve-mib', type=int, help='positive fixed override; omitted uses automatic reserve')
    parser.add_argument('--all-formats', action='store_true')
    parser.add_argument('--tasks-per-credit', type=int, default=2)
    parser.add_argument('--headroom-mib', type=int, help='test Job limit above the selected reserve')
    parser.add_argument('--cpu-rate', type=int, default=100)
    parser.add_argument('--independent-volumes', action='store_true')
    parser.add_argument('--dynamic', action='store_true')
    args = parser.parse_args()
    probe.OUT = args.report_dir.resolve()
    cases = json.loads(args.cases.read_text())
    selected = args.case or ([c['name'] for c in cases if c['name'] != 'corpus-test_read_format_rar_ppmd_lzss_conversion'] if args.all_formats else ['7z-BCJ2'])
    for credits in args.credits:
        for case in cases:
            if case['name'] not in selected: continue
            reserve = args.reserve_mib or (128 + 16 * credits)
            limit = reserve + args.headroom_mib if args.headroom_mib is not None else max(2048, reserve + 512)
            probe.run(case['name'] + '-credits' + str(credits), Path(case['archive']), case['format'], credits * args.tasks_per_credit,
                capacity=credits, reserve=args.reserve_mib, limit=limit,
                expected_output=case['expected'], password=case['password'], dynamic=args.dynamic,
                volumes=credits if args.independent_volumes else 1, cpu_rate=args.cpu_rate,
                extra_env={'SUNPACK_NATIVE_WORKER_THREAD_CAPACITY': '0', 'SUNPACK_TEST_LOGICAL_PROCESSORS': str(credits)})
