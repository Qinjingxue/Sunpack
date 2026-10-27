"""Manual bounded measurement of unmanaged commit and recovery overhead.

Build sunpack_sevenzip_memory_probe first. Its telemetry exists only in that
executable. Windows Job caps, affinity and CPU rate apply only to the child.
The 60-second test deadline detects missing results without leaving load behind.
This complements unit tests: only a real worker exposes CRT stacks, codec heaps,
writer pools and the transient cost of restarting all extraction lanes together.
"""
import ctypes, json, os, queue, subprocess, sys, threading, time
from pathlib import Path
import psutil
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from sunpack.core.platform.windows.process_job import (
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION_STRUCT as Limits, _kernel32,
)
K = _kernel32()
K.QueryInformationJobObject.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p]
K.QueryInformationJobObject.restype = ctypes.c_int
K.GetTickCount64.restype = ctypes.c_ulonglong
K.GetProcessTimes.argtypes = [ctypes.c_void_p, *([ctypes.POINTER(ctypes.c_ulonglong)] * 4)]
K.GetProcessTimes.restype = ctypes.c_int
WORKER = ROOT / 'native/sevenzip_bridge/build-x64-ci/Release/sunpack_sevenzip_memory_probe.exe'
OUT = ROOT / 'reports/worker-reserve-20261027'

class Sandbox:
    def __init__(self, memory_mib, cpu_rate=100, affinity=3):
        self.handle = K.CreateJobObjectW(None, None)
        if not self.handle: raise ctypes.WinError(ctypes.get_last_error())
        self.limits = Limits()
        self.limits.BasicLimitInformation.LimitFlags = 0x2000 | 0x10 | 0x200
        self.limits.BasicLimitInformation.Affinity = affinity
        self.limits.JobMemoryLimit = memory_mib * 1024**2
        self.check(K.SetInformationJobObject(self.handle, 9, ctypes.byref(self.limits), ctypes.sizeof(self.limits)))
        class Cpu(ctypes.Structure):
            _fields_ = [('ControlFlags', ctypes.c_ulong), ('CpuRate', ctypes.c_ulong)]
        cpu = Cpu(1 | 4, cpu_rate)
        self.check(K.SetInformationJobObject(self.handle, 15, ctypes.byref(cpu), ctypes.sizeof(cpu)))
    def check(self, result):
        if not result: raise ctypes.WinError(ctypes.get_last_error())
    def assign(self, process):
        self.check(K.AssignProcessToJobObject(self.handle, int(process._handle)))
    def peak(self):
        info = Limits()
        self.check(K.QueryInformationJobObject(self.handle, 9, ctypes.byref(info), ctypes.sizeof(info), None))
        return info.PeakJobMemoryUsed / 1024**2
    def close(self): K.CloseHandle(self.handle)


def run(name, archive, hint, jobs, *, limit=768, dynamic=False, password=False, dry=False, capacity=None, extra_env=None, reserve=None, expected_output=None, workloads=None, volumes=1, cpu_rate=100, trace_memory=True):
    OUT.mkdir(parents=True, exist_ok=True)
    label = name + '-' + str(time.time_ns())
    trace = OUT / (label + '.csv')
    configured_reserve = 0 if reserve is None else reserve * 1024**2
    reserve = 128 + 16 * (capacity or jobs) if reserve is None else reserve
    initial_limit = reserve + 4 if dynamic else limit
    box = Sandbox(initial_limit, cpu_rate=cpu_rate, affinity=3)
    env = os.environ | {'SUNPACK_NATIVE_WORKER_THREAD_CAPACITY': str(capacity or jobs),
        'SUNPACK_TEST_MEMORY_TRACE': str(trace) if trace_memory else '', 'SUNPACK_NATIVE_MEMORY_RESERVE_BYTES':str(configured_reserve)} | (extra_env or {})
    error_file = (OUT / (label + '.stderr.txt')).open('w', encoding='utf-8')
    p = subprocess.Popen([str(WORKER)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=error_file,
        text=True, encoding='utf-8', creationflags=subprocess.CREATE_NO_WINDOW, env=env)
    box.assign(p)
    events, results, edits = [], [], []
    q = queue.Queue()
    started = time.monotonic()
    def reader():
        for line in p.stdout:
            event = json.loads(line)
            event['_tick'] = K.GetTickCount64()
            event['_t'] = round(time.monotonic() - started, 6)
            events.append(event)
            q.put(event)
    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    # Capture idle workers, including the cost of their full execution lanes.
    handshake = q.get(timeout=10)
    assert handshake['memory_reserve_bytes'] == reserve * 1024**2, handshake
    assert handshake['nominal_cpu_budget'] == (capacity or jobs), handshake
    time.sleep(.10)
    def set_limit(mib):
        box.limits.JobMemoryLimit = mib * 1024**2
        box.check(K.SetInformationJobObject(box.handle, 9, ctypes.byref(box.limits), ctypes.sizeof(box.limits)))
        edits.append({'tick':K.GetTickCount64(), 't': time.monotonic() - started, 'mib': mib})
    decode_started = time.monotonic()
    for i in range(jobs):
        item = workloads[i % len(workloads)] if workloads else {'archive': archive, 'format': hint, 'password': password}
        request = {'job_id': str(i), 'archive_path': str(item['archive']), 'format_hint': item['format'],
            'output_dir': str(OUT / 'outputs' / label / str(i)), 'origin': 'watch' if i%2 else 'foreground',
            'output_volume_key': 'reserve-probe-' + str(i % volumes), 'dry_run': dry}
        if item.get('password'): request['password_candidates'] = [item['password']]
        p.stdin.write(json.dumps(request) + '\n')
    p.stdin.flush()
    expanded = shrunk = restored = False
    shrink_time = 0
    host_min = psutil.virtual_memory().available
    try:
        while len(results) < jobs and time.monotonic() - started < 60:
            try: event = q.get(timeout=.02)
            except queue.Empty: event = {}
            host_min = min(host_min, psutil.virtual_memory().available)
            if p.poll() is not None: break
            if dynamic:
                if event.get('event') == 'memory_blocked' and not expanded:
                    set_limit(reserve+512); expanded=True
                if event.get('event') == 'decoder_started' and expanded and not shrunk:
                    set_limit(reserve+160); shrunk=True; shrink_time=time.monotonic()
                if shrunk and not restored and time.monotonic()-shrink_time>.5:
                    set_limit(reserve+512); restored=True
            if event.get('type') == 'result': results.append(event)
        if len(results) != jobs: raise RuntimeError((label, len(results), p.poll(), events[-6:]))
        if dynamic: assert expanded and shrunk and restored, ('pressure cycle not exercised', label, edits)
        worker_seconds = time.monotonic() - decode_started
        p.stdin.close(); p.wait(timeout=10); thread.join(timeout=5)
        assert p.returncode == 0 and all(e['status'] == 'ok' for e in results), (p.returncode,results)
        process_times = [ctypes.c_ulonglong() for _ in range(4)]
        box.check(K.GetProcessTimes(int(p._handle), *(ctypes.byref(value) for value in process_times)))
        rows=[]
        for line in (trace.read_text().splitlines() if trace_memory else ()):
            tick, phase, private, managed=line.split(',')
            private, managed = int(private), int(managed)
            rows.append({'tick':int(tick), 'phase':phase, 'private':private, 'managed':managed, 'unmanaged':private-managed})
        peak=max(rows,key=lambda r:r['unmanaged'],default={'unmanaged':0})
        output_checks = []
        if not dry:
            from sunpack_native import compute_directory_crc_manifest
            for index in range(jobs):
                result = next(e for e in results if e['job_id'] == str(index))
                manifest = compute_directory_crc_manifest(str(OUT / 'outputs' / label / str(index)), result['files_written'])
                assert manifest['status'] == 'ok' and not manifest['truncated'], manifest
                assert manifest['total_files'] == result['files_written'], manifest
                expected = sorted((r[3], r[6]) for e in events if e.get('type') == 'manifest_chunk'
                    and e.get('job_id') == str(index) for r in e['rows'] if r[5])
                actual = sorted((r['size'], r['crc32']) for r in manifest['files'])
                if len(expected) == len(actual): assert expected == actual, (expected, actual)
                reference = workloads[index % len(workloads)].get('expected') if workloads else expected_output
                if reference is not None: assert sorted(map(tuple, reference)) == actual, (reference, actual)
                output_checks.append({'files':manifest['total_files'], 'crc_checked': reference is not None or len(expected) == len(actual)})
        recovery_tick = next((e['_tick'] for e in events if e.get('event') == 'memory_reclaimed'), None)
        recovery = [r for r in rows if recovery_tick is not None and r['tick'] >= recovery_tick]
        recovery_baseline = next((r['unmanaged'] for r in reversed(rows)
            if recovery_tick is not None and r['tick'] < recovery_tick), rows[0]['unmanaged'] if rows else 0)
        report={'label':label,'jobs':jobs,'capacity':capacity or jobs,'limit_mib':limit,'initial_limit_mib':initial_limit,'dynamic':dynamic,'dry':dry,'volumes':volumes,'cpu_rate':cpu_rate,
            'output_checks':output_checks, 'returncode':p.returncode,'elapsed':round(time.monotonic()-started,3), 'worker_seconds':worker_seconds,
            'cpu_seconds':(process_times[2].value + process_times[3].value) / 10_000_000, 'job_peak_mib':box.peak(),
            'unmanaged_peak_mib':peak['unmanaged']/1024**2,'unmanaged_peak_row':peak,
            'private_peak_mib':max((r['private'] for r in rows),default=0)/1024**2,
            'managed_peak_mib':max((r['managed'] for r in rows),default=0)/1024**2,
            'idle_unmanaged_mib':rows[0]['unmanaged']/1024**2 if rows else 0,
            'reserve_mib':reserve, 'automatic_reserve':configured_reserve == 0,
            'recovery_unmanaged_peak_mib':max((r['unmanaged'] for r in recovery),default=0)/1024**2,
            'recovery_unmanaged_growth_mib':max((r['unmanaged']-recovery_baseline for r in recovery),default=0)/1024**2,
            'thread_resource_retries':sum(e.get('event')=='memory_thread_resource_retry' for e in events),'memory_reclaims':sum(e.get('event')=='memory_reclaimed' for e in events),
            'max_admitted':max((e.get('active_jobs',0) for e in events),default=0),
            'host_min_available_mib':host_min/1024**2,'edits':edits,'samples':len(rows),'memory_measured':trace_memory}
        if not trace_memory:
            for key in ('unmanaged_peak_mib', 'unmanaged_peak_row', 'private_peak_mib', 'managed_peak_mib',
                        'idle_unmanaged_mib', 'recovery_unmanaged_peak_mib', 'recovery_unmanaged_growth_mib'):
                report[key] = None
        (OUT/(label+'.summary.json')).write_text(json.dumps(report,indent=2))
        print(json.dumps(report),flush=True)
        return report
    finally:
        if p.poll() is None: p.terminate(); p.wait(timeout=10)
        (OUT/(label+'.events.jsonl')).write_text('\n'.join(json.dumps(e) for e in events))
        error_file.close()
        box.close()

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('--format', required=True)
    parser.add_argument('--worker', type=Path, default=WORKER)
    parser.add_argument('--report-dir', type=Path, default=OUT)
    parser.add_argument('--jobs', type=int, default=8)
    parser.add_argument('--capacity', type=int)
    parser.add_argument('--volumes', type=int, default=1, help='independent writer facilities on the test drive')
    parser.add_argument('--cpu-rate', type=int, default=100, help='child Job CPU rate in units of 1/100 percent')
    parser.add_argument('--limit-mib', type=int, default=768)
    parser.add_argument('--reserve-mib', type=int, help='positive fixed override; omitted uses worker automatic reserve')
    parser.add_argument('--dynamic', action='store_true')
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--password')
    args = parser.parse_args()
    WORKER = args.worker.resolve()
    OUT = args.report_dir.resolve()
    assert WORKER.name == 'sunpack_sevenzip_memory_probe.exe', 'use the test probe target, never a distributed worker'
    run(args.format, args.archive.resolve(), args.format, args.jobs, limit=args.limit_mib,
        reserve=args.reserve_mib, capacity=args.capacity, dynamic=args.dynamic,
        password=args.password, dry=args.dry_run, volumes=args.volumes, cpu_rate=args.cpu_rate)
