"""Reproducible direct worker extraction of generated 300 MiB format corpus."""
from __future__ import annotations
import argparse
import json
import platform
import re
import shutil
import statistics
import struct
import subprocess
import time
from pathlib import Path
import psutil
from benchmarks.harness.corpus import _cached_corpus, _run_7z, _run_rar, DEFAULT_CACHE_ROOT, SEVEN_ZIP
from benchmarks.harness.corpus_300m import FORMATS_300M, RAW_FORMATS, TAR_STREAMS, special_cases
from benchmarks.harness.memory import ProcessSampler
from benchmarks.harness.workspace import BenchmarkWorkspace
from benchmarks.scenarios.native_boundary import output_summary
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
    hint = {**RAW_FORMATS, 'gz':'gzip', 'tgz':'gzip', 'bz2':'bzip2', 'tbz2':'bzip2',
            'txz':'xz', 'tzst':'zstd', 'zst':'zstd', 'tar.lz4':'lz4', 'zip-split':'zip',
            'zipx-zstd':'zipx', '7z-zstd':'7z', '7z-lz4':'7z',
            '7z-split':'7z', 'rar-split':'rar', 'rar4-split':'rar4'}.get(fmt, fmt)
    result = {'entry_path': str(path), 'open_mode': 'file', 'format_hint': hint}
    if fmt in ('7z-split', 'zip-split'):
        parts = sorted(path.parent.glob(path.name.rsplit('.', 1)[0] + '.*'))
    elif fmt in ('rar-split', 'rar4-split'):
        prefix = path.name.split('.part', 1)[0]
        parts = sorted(path.parent.glob(prefix + '.part*.rar'))
    else:
        return result
    result.update(open_mode='native_volumes', parts=[
        {'path': str(part), 'start': 0, 'volume_number': index, 'canonical_name': part.name}
        for index, part in enumerate(parts, 1)
    ])
    return result


def case_metadata(item, stock_skip):
    path = Path(item['path'])
    fmt = item['format']
    if fmt in ('7z-split', 'zip-split'):
        volumes = sorted(path.parent.glob(path.name.rsplit('.', 1)[0] + '.*'))
    elif fmt in ('rar-split', 'rar4-split'):
        volumes = sorted(path.parent.glob(path.name.split('.part', 1)[0] + '.part*.rar'))
    else:
        volumes = [path]
    wanted = {'Type', 'Method', 'Solid', 'Blocks', 'Volumes', 'Physical Size', 'Headers Size', 'Encrypted'}
    properties = {}
    listing = None
    if stock_skip is None:
        listing = subprocess.run([str(SEVEN_ZIP), 'l', '-slt', str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for line in listing.stdout.decode('utf-8', 'replace').splitlines():
            if ' = ' in line:
                key, value = line.split(' = ', 1)
                if key in wanted and value not in properties.setdefault(key, []): properties[key].append(value)
    return {'format':fmt, 'volume_sizes': [p.stat().st_size for p in volumes],
            'variant': item.get('variant', 'standard'),
            'payload_bytes':item.get('expected_payload_bytes'),
            'stock_7z_skip': stock_skip,
            'listing_returncode': listing.returncode if listing else None, 'archive_properties': properties}


def stock_7z_skips():
    skips = {'enc': 'stock 7z.exe does not support ENC'}
    info = subprocess.check_output([str(SEVEN_ZIP), 'i']).decode('utf-8', errors='replace')
    formats, _, codecs = info.partition('Codecs:')
    if not re.search(r'^\s*\d+\s+\S+\s+lz4\s', formats, re.I | re.M):
        for name in ('lz4', 'tar.lz4'):
            skips[name] = 'stock 7z.exe does not advertise an LZ4 frame handler'
    for name, codec in (('7z-zstd', '4F71101'), ('7z-lz4', '4F71104')):
        if not re.search(rf'^\s*\d+\s+\w*D\w*\s+0*{codec}\s', codecs, re.I | re.M):
            skips[name] = f'stock 7z.exe does not advertise 7z codec {codec}'
    return skips


def solid_cases(root, formats, payload_bytes, skipped):
    source = root / 'payloads' / 'few-large'
    staging = root / 'solid-variants'
    staging.mkdir()
    cases = {}
    for fmt in sorted(formats & {'7z', 'rar', 'rar4'}):
        for variant, solid in [('solid', True), ('non-solid', False)]:
            key = f'few_large:{fmt}:{variant}'
            archive = staging / f'{fmt}-{variant}.{fmt if fmt == "7z" else "rar"}'
            if fmt == '7z':
                created = _run_7z(['a', '-y', '-t7z', '-ms=on' if solid else '-ms=off',
                                   str(archive), str(source)])
            else:
                created = _run_rar(['a', '-idq', '-r', '-ep1', '-y', '-ma4' if fmt == 'rar4' else '-ma5',
                                    '-s' if solid else '-s-', str(archive), str(source)])
            if created and archive.is_file():
                cases[key] = {'path': archive, 'format': fmt, 'variant': variant,
                              'expected_payload_bytes': payload_bytes}
            else:
                skipped[key] = 'Archive generator could not create this solid-mode variant'
    return cases


def stock_seven_zip(item, output, sample_ms):
    process = None
    sampler = ProcessSampler(sample_ms / 1000, processes=lambda: [process] if process else [])
    with sampler:
        started = time.perf_counter()
        with subprocess.Popen([str(SEVEN_ZIP), 'x', '-y', '-bd', '-bso0', f'-o{output}', str(item['path'])],
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.PIPE) as child:
            try:
                process = psutil.Process(child.pid)
            except psutil.NoSuchProcess:
                pass
            sampler.take()
            _, stderr = child.communicate()
            elapsed = time.perf_counter() - started
    return {'seconds': elapsed, 'exit_code': child.returncode, 'output': output_summary(output),
            'stderr': stderr.decode('utf-8', errors='replace'),
            'peak_rss_mib': max(sample.rss_mib for sample in sampler.samples),
            'peak_private_mib': max(sample.private_mib for sample in sampler.samples)}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--formats', default=','.join(FORMATS_300M))
    p.add_argument('--runs', type=int, default=3)
    p.add_argument('--warmups', type=int, default=1)
    p.add_argument('--compare-7z', action='store_true', help='Also measure stock 7z.exe on the same archives.')
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
    if not requested or not requested.issubset(FORMATS_300M): p.error('unknown format')
    if args.runs < 1 or args.warmups < 0 or args.large_files < 1 or args.large_file_mib < 1 or args.sample_ms <= 0: p.error('invalid run, fixture or sample settings')
    worker = args.worker or native_build_dir(Path(__file__).resolve().parents[2], args.arch, args.profile, 'sevenzip_bridge') / 'sunpack_sevenzip_worker.exe'
    with BenchmarkWorkspace('worker-300m', results_root=args.results_root, keep_workdir=args.keep_workdir) as ws:
        corpus, skipped, cache = _cached_corpus(ws.corpus, cache_root=args.cache_root, small_files=0, large_files=args.large_files, large_file_mib=args.large_file_mib, rebuild=args.rebuild_corpus)
        explicit_solid = {'7z', 'rar', 'rar4'}
        cases = {key:item for key,item in corpus.items()
                 if item['workload'] == 'few_large' and item['format'] in requested - explicit_solid}
        extras = special_cases(ws.corpus, corpus, requested - explicit_solid, skipped,
                               large_files=args.large_files, large_file_mib=args.large_file_mib)
        payload_bytes = args.large_files * args.large_file_mib * 1024**2
        cases.update(extras)
        cases.update(solid_cases(ws.corpus, requested, payload_bytes, skipped))
        if not cases: raise RuntimeError(f'No generated cases: {skipped}')
        stock_skips = stock_7z_skips()
        catalog = {key: case_metadata(item, stock_skips.get(item['format'])) for key, item in cases.items()}
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
                        if item.get('password'):
                            request.update(password=item['password'], password_verified=True, encrypted=True)
                        send(proc.stdin, request)
                        while True:
                            event = read_frame(proc.stdout)
                            if event.get('type') == 'result' and event.get('job_id') == 'benchmark': break
                        elapsed = time.perf_counter() - started
                        sampler.take()
                        samples = sampler.samples[start_sample:]
                        if event.get('status') != 'ok': raise RuntimeError(f'{key}: {event}')
                        output_info = output_summary(output)
                        expected = item['expected_payload_bytes']
                        if item['format'] in TAR_STREAMS:
                            expected = Path(corpus['few_large:tar']['path']).stat().st_size
                        if output_info['bytes'] != expected:
                            raise RuntimeError(f'{key}: wrote {output_info["bytes"]} bytes, expected {expected}')
                        if run >= 0:
                            rows.append({'case':key, 'format':item['format'], 'run':run, 'seconds':elapsed, 'result':event,
                                         'output':output_info, 'peak_rss_mib':max(s.rss_mib for s in samples), 'peak_private_mib':max(s.private_mib for s in samples)})
                            print(f'{key} round {run + 1}: {elapsed:.3f}s', flush=True)
                        shutil.rmtree(output)
        finally:
            if proc.poll() is None:
                send(proc.stdin, {'worker_command':'shutdown'})
                proc.stdin.close()
                proc.wait()
            proc.stdout.close()
        seven_zip_rows = []
        if args.compare_7z:
            for key, item in sorted(cases.items()):
                if reason := stock_skips.get(item['format']):
                    seven_zip_rows.append({'case': key, 'skipped': reason})
                    continue
                for run in range(-args.warmups, args.runs):
                    output = ws.outputs / f'stock-7z-{key.replace(":", "-")}-{run}'
                    baseline = stock_seven_zip(item, output, args.sample_ms)
                    if run >= 0:
                        worker_row = next(row for row in rows if row['case'] == key and row['run'] == run)
                        seven_zip_rows.append({'case': key, 'run': run, **baseline,
                                               'comparable': baseline['exit_code'] == 0
                                               and baseline['output']['bytes'] == worker_row['output']['bytes']})
                    shutil.rmtree(output, ignore_errors=True)
        revision = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=Path(__file__).resolve().parents[2], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        stat = worker.stat()
        report = {'boundary':'persistent worker only, excludes fixture generation and process startup', 'platform':platform.platform(),
                  'environment': {'machine':platform.machine(), 'cpu':platform.processor(), 'logical_cpus':psutil.cpu_count(), 'physical_cpus':psutil.cpu_count(logical=False), 'ram_bytes':psutil.virtual_memory().total},
                  'revision':revision.stdout.decode('ascii', 'replace').strip() if revision.returncode == 0 else None,
                  'worker_binary':{'path':str(worker.resolve()), 'size':stat.st_size, 'modified_ns':stat.st_mtime_ns}, 'catalog':catalog,
                  'options':vars(args), 'corpus_cache':cache, 'skipped':skipped, 'rows':rows,
                  'stock_7z_rows': seven_zip_rows,
                  'fixture':'deterministic alternating compressible/random 150 MiB files by default; ENC uses its own deterministic fixture and a known password',
                  'worker_format_support': {'zipx':'supported as ZIP', 'lz4':'native LZ4 handler', 'enc':'native ENC handler; known password passed directly'},
                  'sampling_note':'sampled worker peaks are lower bounds; compressed TAR streams extract one TAR layer',
                  'cases':{key:{'median_seconds':statistics.median(r['seconds'] for r in rows if r['case']==key),
                                'max_sampled_rss_mib':max(r['peak_rss_mib'] for r in rows if r['case']==key)} for key in cases}}
        print('Result:', ws.write_result_json('result.json', report))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
