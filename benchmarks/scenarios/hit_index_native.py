"""Benchmark the production typed hit index using its independent native probe."""
from __future__ import annotations
import argparse
import ctypes
import platform
import statistics
import time
from pathlib import Path
import psutil
from benchmarks.harness.workspace import BenchmarkWorkspace
from benchmarks.hit_index.build import bridge


class Hit(ctypes.Structure):
    _fields_ = [('offset', ctypes.c_uint64), ('pattern', ctypes.c_uint8),
                ('padding', ctypes.c_uint8 * 3), ('owner', ctypes.c_uint32)]

class Stats(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in
                ('bytes', 'capacity', 'heap', 'mapped', 'prepare_ns', 'collect_ns', 'finish_ns')]


def probe(path):
    dll = ctypes.CDLL(str(path))
    dll.sp_build.argtypes = [ctypes.POINTER(Hit), ctypes.c_size_t, ctypes.c_uint32,
                             ctypes.c_uint64, ctypes.c_size_t, ctypes.c_size_t, ctypes.c_uint32]
    dll.sp_build.restype = ctypes.c_void_p
    dll.sp_stats.argtypes = [ctypes.c_void_p, ctypes.POINTER(Stats)]
    dll.sp_seq.argtypes = [ctypes.c_void_p, ctypes.c_uint16]
    dll.sp_seq.restype = ctypes.c_uint64
    dll.sp_free.argtypes = [ctypes.c_void_p]
    dll.sp_allocator.argtypes = [ctypes.c_bool]
    dll.sp_allocator.restype = ctypes.c_uint64
    return dll


def run(dll, hits, n, size, chunk, mode, rounds, meter):
    process = psutil.Process()
    rows = []
    for _ in range(rounds):
        baseline = dll.sp_allocator(True) if meter else None
        before = process.memory_info().private
        start = time.perf_counter_ns()
        handle = dll.sp_build(hits, n, mode, size, chunk, 6, 0)
        build_ns = time.perf_counter_ns() - start
        if not handle:
            raise RuntimeError('native hit-index probe could not build the index')
        try:
            stats = Stats()
            dll.sp_stats(handle, ctypes.byref(stats))
            built = process.memory_info().private
            start = time.perf_counter_ns()
            checksum = dll.sp_seq(handle, 0xffff)
            sequence_ns = time.perf_counter_ns() - start
            peak = dll.sp_allocator(False) if meter else None
        finally:
            start = time.perf_counter_ns()
            dll.sp_free(handle)
            free_ns = time.perf_counter_ns() - start
        rows.append({'build_ns': build_ns, 'sequence_ns': sequence_ns, 'free_ns': free_ns,
                     'sequence_guard': checksum, 'storage': {name: getattr(stats, name) for name, _ in Stats._fields_},
                     'private_before_bytes': before, 'private_built_bytes': built,
                     'allocator_peak_increase_bytes': max(0, peak - baseline) if meter else None})
    return rows


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hits', type=int, default=1000000)
    parser.add_argument('--gap', type=int, default=32)
    parser.add_argument('--runs', type=int, default=3)
    parser.add_argument('--chunk-kib', type=int, default=2048)
    parser.add_argument('--results-root', type=Path)
    parser.add_argument('--keep-workdir', action='store_true')
    args = parser.parse_args(argv)
    if min(args.hits, args.gap, args.runs, args.chunk_kib) < 1:
        parser.error('all workload dimensions must be positive')
    chunk = args.chunk_kib * 1024
    size = args.hits * args.gap + 1
    if (size // chunk) >= 2**32:
        parser.error('input exceeds the probe owner range')
    # Deterministic, sorted offsets and types exercise actual codec and builder.
    hits = (Hit * args.hits)()
    for i in range(args.hits):
        hits[i].offset = i * args.gap
        hits[i].pattern = i % 15
        hits[i].owner = hits[i].offset // chunk
    timing = probe(bridge())
    allocation = probe(bridge(meter=True))
    with BenchmarkWorkspace('scan-hit-index', results_root=args.results_root, keep_workdir=args.keep_workdir) as ws:
        measurements = {}
        expected = (17 * args.gap * args.hits * (args.hits - 1) // 2
                    + sum(i % 15 for i in range(args.hits))) & ((1 << 64) - 1)
        for name, mode in [('codec', 0), ('builder', 1)]:
            timed = run(timing, hits, args.hits, size, chunk, mode, args.runs, False)
            metered = run(allocation, hits, args.hits, size, chunk, mode, 1, True)
            if any(row['sequence_guard'] != expected for row in timed + metered):
                raise RuntimeError(f'{name} probe lost or changed hits')
            measurements[name] = {'timing': timed, 'allocation': metered,
                                  'median_build_ns': statistics.median(row['build_ns'] for row in timed),
                                  'median_sequence_ns': statistics.median(row['sequence_ns'] for row in timed)}
        report = {'boundary': 'production hit_storage copied into isolated native probe',
                  'distribution': 'deterministic equal gap, cycling 15 production hit types',
                  'options': vars(args), 'platform': platform.platform(), 'measurements': measurements,
                  'memory_note': 'Separate allocator-instrumented run; peak counts Rust allocator bytes, not mappings or whole-process peak. Private bytes are snapshots including Python and input.'}
        print(f"Result: {ws.write_result_json('result.json', report)}")
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
