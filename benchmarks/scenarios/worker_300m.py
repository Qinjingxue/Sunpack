"""Reproducible direct worker extraction of generated 300 MiB format corpus."""
from __future__ import annotations
import argparse
import json
import platform
import shutil
import statistics
import struct
import subprocess
import time
from pathlib import Path
import psutil
from benchmarks.harness.corpus import _cached_corpus, DEFAULT_CACHE_ROOT, GENERATED_FORMATS, SEVEN_ZIP
from benchmarks.harness.memory import ProcessSampler
from benchmarks.harness.workspace import BenchmarkWorkspace
from benchmarks.scenarios.native_boundary import output_summary
from benchmarks.scenarios.e2e_300m import _special_cases
from tests.helpers.native_build import native_build_dir


def encode(value):
    if value is None: return b'\x01'
    if isinstance(value, bool): return b'\x03' if value else b'\x02'
    if isinstance(value, int): return b'\x04' + struct.pack('<Q', value)
    if isinstance(value, str):
        data = value.encode('utf-8')
        return b'\x07' + struct.pack('<I', len(data)) + data
    if isinstance(value, list): return b'\x09' + b''.join(encode(v) for v in value) + b'\x00'
    if isinstance(value, dict): return b'\x0a' + b''.join(encode(k) + encode(v) for k, v in value.items()) + b'\x00'
    raise TypeError(type(value))


def read_frame(pipe):
    def exact(count):
        data = bytearray()
        while len(data) < count:
            part = pipe.read(count - len(data))
            if not part: raise EOFError('worker closed its output')
            data.extend(part)
        return bytes(data)
    header = exact(8)
    if header[:4] != b'SPBF': raise ValueError('invalid worker frame')
    payload = memoryview(exact(struct.unpack('<I', header[4:])[0]))
    offset = 0
    def read():
        nonlocal offset
        tag = payload[offset]; offset += 1
        if tag == 1: return None
        if tag in (2, 3): return tag == 3
        if tag in (4, 5, 6, 11, 12):
            fmt = {4:'<Q', 5:'<q', 6:'<d', 11:'<B', 12:'<I'}[tag]
            value = struct.unpack_from(fmt, payload, offset)[0]; offset += struct.calcsize(fmt)
            return value
        if tag in (7, 8):
            size = struct.unpack_from('<I', payload, offset)[0]; offset += 4
            value = bytes(payload[offset:offset+size]); offset += size
            return value.decode('utf-8') if tag == 7 else value.hex()
        if tag in (9, 10):
            values = []
            while payload[offset] != 0: values.append(read())
            offset += 1
            return values if tag == 9 else dict(zip(values[::2], values[1::2]))
        raise ValueError(f'unknown worker tag {tag}')
    return read()


def send(pipe, value):
    payload = encode(value)
    pipe.write(b'SPBF' + struct.pack('<I', len(payload)) + payload)
    pipe.flush()


def descriptor(item):
    path = Path(item['path'])
    fmt = item['format']
    hint = {'gz':'gzip', 'tgz':'gzip', 'bz2':'bzip2', 'tbz2':'bzip2', 'txz':'xz', 'tzst':'zstd', 'zst':'zstd', '7z-split':'7z', 'rar-split':'rar', 'rar4-split':'rar4'}.get(fmt, fmt)
    result = {'entry_path': str(path), 'open_mode': 'file', 'format_hint': hint}
    if fmt == '7z-split':
        parts = sorted(path.parent.glob(path.name.rsplit('.', 1)[0] + '.*'))
        result.update(open_mode='concat_ranges', ranges=[{'path':str(p), 'start':0} for p in parts])
    elif fmt in ('rar-split', 'rar4-split'):
        prefix = path.name.split('.part', 1)[0]
        parts = sorted(path.parent.glob(prefix + '.part*.rar'))
        result.update(open_mode='native_volumes', parts=[{'path':str(p), 'start':0, 'volume_number':i, 'canonical_name':p.name} for i,p in enumerate(parts, 1)])
    return result


def case_metadata(item):
    path = Path(item['path'])
    fmt = item['format']
    if fmt == '7z-split':
        volumes = sorted(path.parent.glob(path.name.rsplit('.', 1)[0] + '.*'))
    elif fmt in ('rar-split', 'rar4-split'):
        volumes = sorted(path.parent.glob(path.name.split('.part', 1)[0] + '.part*.rar'))
    else:
        volumes = [path]
    listing = subprocess.run([str(SEVEN_ZIP), 'l', '-slt', str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    wanted = {'Type', 'Method', 'Solid', 'Blocks', 'Volumes', 'Physical Size', 'Headers Size', 'Encrypted'}
    properties = {}
    for line in listing.stdout.decode('utf-8', 'replace').splitlines():
        if ' = ' in line:
            key, value = line.split(' = ', 1)
            if key in wanted and value not in properties.setdefault(key, []): properties[key].append(value)
    return {'format':fmt, 'volume_sizes': [p.stat().st_size for p in volumes],
            'payload_bytes':item.get('expected_payload_bytes'),
            'listing_returncode': listing.returncode, 'archive_properties': properties}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--formats', default=','.join((*GENERATED_FORMATS, 'zipx', 'lz4', 'enc', 'rar4', 'rar4-split')))
    p.add_argument('--runs', type=int, default=3)
    p.add_argument('--warmups', type=int, default=1)
    p.add_argument('--large-files', type=int, default=2)
    p.add_argument('--large-file-mib', type=int, default=150)
    p.add_argument('--worker', type=Path)
    p.add_argument('--profile', choices=('release','ci'), default='release')
    p.add_argument('--arch', choices=('x64','arm64'), default='x64')
    p.add_argument('--sample-ms', type=float, default=20)
    p.add_argument('--cache-root', type=Path, default=DEFAULT_CACHE_ROOT)
    p.add_argument('--rebuild-corpus', action='store_true')
    p.add_argument('--results-root', type=Path)
    p.add_argument('--keep-workdir', action='store_true')
    args = p.parse_args(argv)
    requested = set(args.formats.split(','))
    if not requested or not requested.issubset((*GENERATED_FORMATS, 'zipx', 'lz4', 'enc', 'rar4', 'rar4-split')): p.error('unknown format')
    if args.runs < 1 or args.warmups < 0 or args.large_files < 1 or args.large_file_mib < 1 or args.sample_ms <= 0: p.error('invalid run, fixture or sample settings')
    worker = args.worker or native_build_dir(Path(__file__).resolve().parents[2], args.arch, args.profile, 'sevenzip_bridge') / 'sunpack_sevenzip_worker.exe'
    with BenchmarkWorkspace('worker-300m', results_root=args.results_root, keep_workdir=args.keep_workdir) as ws:
        corpus, skipped, cache = _cached_corpus(ws.corpus, cache_root=args.cache_root, small_files=0, large_files=args.large_files, large_file_mib=args.large_file_mib, rebuild=args.rebuild_corpus)
        cases = {key:item for key,item in corpus.items() if item['workload'] == 'few_large' and item['format'] in requested}
        extras = _special_cases(ws.corpus, requested, args.large_file_mib, skipped)
        for item in extras.values():
            if item['format'] != 'enc':
                item['expected_payload_bytes'] = args.large_files * args.large_file_mib * 1024 * 1024
        cases.update(extras)
        if not cases: raise RuntimeError(f'No generated cases: {skipped}')
        catalog = {key: case_metadata(item) for key, item in cases.items()}
        proc = subprocess.Popen([str(worker)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            ready = read_frame(proc.stdout)
            if ready.get('type') != 'worker_ready': raise RuntimeError(f'Worker failed to start: {ready}')
            process = psutil.Process(proc.pid)
            sampler = ProcessSampler(args.sample_ms / 1000, processes=lambda: [process])
            rows = []
            with sampler:
                for key, item in sorted(cases.items()):
                    archive = descriptor(item)
                    for run in range(-args.warmups, args.runs):
                        output = ws.outputs / (key.replace(':', '-') + '-' + str(run))
                        output.mkdir()
                        start_sample = len(sampler.samples)
                        started = time.perf_counter()
                        request = {'job_id': 'benchmark', 'operation':'extract', 'origin':'foreground', 'output_dir':str(output), 'archive_input':archive, 'password_candidates':[], 'report_progress':False}
                        if item['format'] == 'enc':
                            request.update(password='sunpack-test', password_verified=True, encrypted=True)
                        send(proc.stdin, request)
                        while True:
                            event = read_frame(proc.stdout)
                            if event.get('type') == 'result' and event.get('job_id') == 'benchmark': break
                        elapsed = time.perf_counter() - started
                        sampler.take()
                        samples = sampler.samples[start_sample:]
                        if event.get('status') != 'ok': raise RuntimeError(f'{key}: {event}')
                        if run >= 0:
                            rows.append({'case':key, 'format':item['format'], 'run':run, 'seconds':elapsed, 'result':event,
                                         'output':output_summary(output), 'peak_rss_mib':max(s.rss_mib for s in samples), 'peak_private_mib':max(s.private_mib for s in samples)})
                            print(f'{key} round {run + 1}: {elapsed:.3f}s', flush=True)
                        shutil.rmtree(output)
        finally:
            if proc.poll() is None:
                send(proc.stdin, {'worker_command':'shutdown'})
                proc.stdin.close()
                proc.wait()
            proc.stdout.close()
        revision = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=Path(__file__).resolve().parents[2], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        stat = worker.stat()
        report = {'boundary':'persistent worker only, excludes fixture generation and process startup', 'platform':platform.platform(),
                  'environment': {'machine':platform.machine(), 'cpu':platform.processor(), 'logical_cpus':psutil.cpu_count(), 'physical_cpus':psutil.cpu_count(logical=False), 'ram_bytes':psutil.virtual_memory().total},
                  'revision':revision.stdout.decode('ascii', 'replace').strip() if revision.returncode == 0 else None,
                  'worker_binary':{'path':str(worker.resolve()), 'size':stat.st_size, 'modified_ns':stat.st_mtime_ns}, 'catalog':catalog,
                  'options':vars(args), 'corpus_cache':cache, 'skipped':skipped, 'rows':rows,
                  'fixture':'deterministic alternating compressible/random 150 MiB files by default; ENC uses its own deterministic fixture and a known password',
                  'worker_format_support': {'zipx':'supported as ZIP', 'lz4':'native LZ4 handler', 'enc':'native ENC handler; known password passed directly'},
                  'sampling_note':'sampled worker peaks are lower bounds; compressed TAR streams extract one TAR layer',
                  'cases':{key:{'median_seconds':statistics.median(r['seconds'] for r in rows if r['case']==key),
                                'max_sampled_rss_mib':max(r['peak_rss_mib'] for r in rows if r['case']==key)} for key in cases}}
        print('Result:', ws.write_result_json('result.json', report))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
