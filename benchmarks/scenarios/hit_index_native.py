"""Benchmark the production typed hit index using its independent native probe."""
from __future__ import annotations
import argparse
import ctypes
import os
import platform
import statistics
import struct
import time
from pathlib import Path
import psutil
from benchmarks.harness.workspace import BenchmarkWorkspace
from benchmarks.harness.embedded_corpus import mixed_carrier
from benchmarks.harness.native_probe import build_runtime_probe, run_runtime_probe
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
    dll.sp_seek.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint64), ctypes.c_size_t, ctypes.c_uint16]
    dll.sp_seek.restype = ctypes.c_uint64
    dll.sp_free.argtypes = [ctypes.c_void_p]
    dll.sp_allocator.argtypes = [ctypes.c_bool]
    dll.sp_allocator.restype = ctypes.c_uint64
    return dll


def run(dll, hits, size, chunk, window, mode, rounds, meter):
    process = psutil.Process()
    targets = (ctypes.c_uint64 * 256)(*(size * i // 256 for i in range(256)))
    rows = []
    for _ in range(rounds):
        baseline = dll.sp_allocator(True) if meter else None
        before = process.memory_info().private
        start = time.perf_counter_ns()
        handle = dll.sp_build(hits, len(hits), mode, size, chunk, window, 0)
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
            start = time.perf_counter_ns()
            seek_guard = dll.sp_seek(handle, targets, len(targets), 0xffff)
            seek_ns = time.perf_counter_ns() - start
            peak = dll.sp_allocator(False) if meter else None
        finally:
            start = time.perf_counter_ns()
            dll.sp_free(handle)
            free_ns = time.perf_counter_ns() - start
        rows.append({'build_ns': build_ns, 'sequence_ns': sequence_ns, 'free_ns': free_ns,
                     'sequence_guard': checksum, 'seek_ns': seek_ns, 'seek_guard': seek_guard,
                     'storage': {name: getattr(stats, name) for name, _ in Stats._fields_},
                     'private_before_bytes': before, 'private_built_bytes': built,
                     'allocator_peak_increase_bytes': max(0, peak - baseline) if meter else None})
    return rows


def load_trace(path):
    header = struct.Struct('<8sQQQQ')
    with path.open('rb') as stream:
        magic, size, count, window, chunk = header.unpack(stream.read(header.size))
        if magic not in (b'SPHITS\0\x01', b'SPHITS\0\x02') or not chunk or path.stat().st_size != header.size + count * ctypes.sizeof(Hit):
            raise ValueError(f'Invalid or obsolete native hit trace: {path}; capture the source again')
        hits = (Hit * count)()
        if stream.readinto(hits) != ctypes.sizeof(hits):
            raise ValueError(f'Truncated native hit trace: {path}')
    if magic == b'SPHITS\0\x01':
        # v1 used tag 13 for the XZ footer. v2 assigns tag 13 to ENC.
        for hit in hits:
            if hit.pattern == 13:
                hit.pattern = 14
    # IOCP matcher workers may finish out of order. The Builder replays
    # complete owner batches, while the codec receives absolute offset order.
    ordered = sorted(hits, key=lambda hit: (hit.owner, hit.offset, hit.pattern))
    builder = (Hit * count)(*ordered)
    ordered.sort(key=lambda hit: (hit.offset, hit.pattern))
    return builder, (Hit * count)(*ordered), size, chunk, window or 6


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument('--hits', type=int, help='Generate this many equally spaced synthetic hits.')
    selection.add_argument('--file', type=Path, help='Capture actual matcher hits from this input instead of a generated mixed carrier.')
    selection.add_argument('--trace', type=Path, help='Replay a saved native hits.bin.')
    parser.add_argument('--gap', type=int, default=32)
    parser.add_argument('--runs', type=int, default=3)
    parser.add_argument('--chunk-kib', type=int, default=2048)
    parser.add_argument('--profile', choices=('release', 'ci'), default='release', help='Build profile for real trace capture.')
    parser.add_argument('--results-root', type=Path)
    parser.add_argument('--keep-workdir', action='store_true')
    args = parser.parse_args(argv)
    if min(args.hits if args.hits is not None else 1, args.gap, args.runs, args.chunk_kib) < 1:
        parser.error('all workload dimensions must be positive')
    with BenchmarkWorkspace('scan-hit-index', results_root=args.results_root, keep_workdir=args.keep_workdir) as ws:
        source = None
        if args.hits is not None:
            chunk = args.chunk_kib * 1024
            size = args.hits * args.gap + 1
            if size // chunk >= 2**32:
                parser.error('input exceeds the probe owner range')
            window = 6
            builder_hits = codec_hits = (Hit * args.hits)()
            for i, hit in enumerate(builder_hits):
                hit.offset = i * args.gap
                hit.pattern = i % 15
                hit.owner = hit.offset // chunk
            distribution = 'deterministic equal gap, cycling 15 production hit types'
        else:
            trace = args.trace or ws.result_dir / 'hits.bin'
            if not args.trace:
                source = args.file.resolve() if args.file else ws.corpus / 'mixed.opaque'
                if not args.file:
                    mixed_carrier(ws.corpus, source, 4 * 1024**2)
                executable = build_runtime_probe(args.profile, 'x64')
                run_runtime_probe(executable, 'benchmark_reader::embedded',
                                  {'path': str(source), 'runs': 1},
                                  env={**os.environ, 'SUNPACK_BENCH_HIT_TRACE': str(trace)})
            builder_hits, codec_hits, size, chunk, window = load_trace(trace)
            distribution = 'post-filter typed matcher hits from a real scan'
        timing = probe(bridge())
        allocation = probe(bridge(meter=True))
        measurements = {}
        expected = sum(17 * hit.offset + hit.pattern for hit in builder_hits) & ((1 << 64) - 1)
        for name, mode, hits in [('codec', 0, codec_hits), ('builder', 1, builder_hits)]:
            timed = run(timing, hits, size, chunk, window, mode, args.runs, False)
            metered = run(allocation, hits, size, chunk, window, mode, 1, True)
            if any(row['sequence_guard'] != expected for row in timed + metered):
                raise RuntimeError(f'{name} probe lost or changed hits')
            measurements[name] = {'timing': timed, 'allocation': metered,
                                  'median_build_ns': statistics.median(row['build_ns'] for row in timed),
                                  'median_sequence_ns': statistics.median(row['sequence_ns'] for row in timed),
                                  'median_seek_ns': statistics.median(row['seek_ns'] for row in timed)}
        report = {'boundary': 'production hit_storage copied into isolated native probe',
                  'distribution': distribution, 'source': source,
                  'trace': None if args.hits is not None else trace,
                  'hit_count': len(builder_hits), 'size_bytes': size, 'chunk_bytes': chunk, 'matching_window': window,
                  'options': vars(args), 'platform': platform.platform(), 'measurements': measurements,
                  'memory_note': 'Separate allocator-instrumented run; peak counts Rust allocator bytes, not mappings or whole-process peak. Private bytes are snapshots including Python and input.'}
        print(f"Result: {ws.write_result_json('result.json', report)}")
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
