"""Real Windows access/share, CLOSE-journal and directory-notification anchors."""
from __future__ import annotations

import argparse
import ctypes
import json
import threading
import time
from contextlib import ExitStack
from ctypes import wintypes
from pathlib import Path

from sunpack_native import watch_candidate_for_path, watch_file_is_ready
from watchdog.events import FileSystemEventHandler
from sunpack.runtime.watch.observer import Observer
from benchmarks.harness.workspace import BenchmarkWorkspace
from benchmarks.watch_broker import watch_broker_lease


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repeats',type=int,default=3)
    args=parser.parse_args(argv)
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.CreateFileW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE]
    kernel.CreateFileW.restype=wintypes.HANDLE
    kernel.WriteFile.argtypes=[wintypes.HANDLE,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD),ctypes.c_void_p]
    kernel.WriteFile.restype=wintypes.BOOL
    kernel.FlushFileBuffers.argtypes=[wintypes.HANDLE]
    kernel.CloseHandle.argtypes=[wintypes.HANDLE]
    handles=set()

    def close(handle):
        if handle in handles:
            handles.remove(handle)
            kernel.CloseHandle(handle)

    def opened(path, access, share=7):
        desired=(0x80000000 if access&1 else 0)|(0x40000000 if access&2 else 0)|(0x10000 if access&4 else 0)
        handle=kernel.CreateFileW(str(path),desired,share,None,3,0x80,None)
        if handle==ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        handles.add(handle)
        return handle

    def write(handle):
        payload=ctypes.create_string_buffer(b'calibration-range')
        count=wintypes.DWORD()
        if not kernel.WriteFile(handle,payload,17,ctypes.byref(count),None):
            raise ctypes.WinError(ctypes.get_last_error())

    with BenchmarkWorkspace('watch.quiet-calibrate') as workspace, ExitStack() as cleanup, watch_broker_lease() as broker:
        cleanup.callback(lambda: [close(handle) for handle in tuple(handles)])
        root=workspace.corpus
        sharing=[]
        path=root/'sharing.opaque'
        path.touch()
        for access in range(1,8):
            for share in range(8):
                handle=opened(path,access,share)
                try:
                    actual=bool(watch_file_is_ready(str(path)))
                finally:
                    close(handle)
                predicted=not ((access&~1) or not (share&1))
                sharing.append(dict(access=access,share=share,native_ready=actual,predicted=predicted))
                if actual!=predicted:
                    raise RuntimeError(f'handle compatibility model mismatch: {sharing[-1]}')
        events=[]
        gate=threading.Lock()

        class Handler(FileSystemEventHandler):
            def on_any_event(self,event):
                if not event.is_directory:
                    with gate:
                        events.append(dict(file=Path(event.src_path).name,kind=event.event_type,at=time.perf_counter()))

        observer=Observer()
        observer.schedule(Handler(),str(root),recursive=False)
        observer.start()
        records=[]
        try:
            for mode in ('buffered','flushed','readonly_tail','two_writers'):
                for repeat in range(args.repeats):
                    path=root/f'{mode}-{repeat}.opaque'
                    path.touch()
                    writer=opened(path,2)
                    tail=None
                    try:
                        write(writer)
                        if mode!='buffered':
                            if not kernel.FlushFileBuffers(writer):
                                raise ctypes.WinError(ctypes.get_last_error())
                        if mode in ('readonly_tail','two_writers'):
                            tail=opened(path,1 if mode=='readonly_tail' else 2)
                        before=watch_candidate_for_path(str(path),None)
                        ready_before=bool(watch_file_is_ready(str(path)))
                        # Controlled separation of write/flush and close, not
                        # a production polling interval or a scoring timeout.
                        threading.Event().wait(.05)
                    finally:
                        close(writer)
                    closed=time.perf_counter()
                    after=watch_candidate_for_path(str(path),int(before['change_usn']))
                    record=dict(mode=mode,repeat=repeat,file=path.name,closed_at=closed,
                                ready_before=ready_before,ready_after_first_close=bool(watch_file_is_ready(str(path))),
                                close_seen_after_first_close=bool(after['change_reasons']&0x80000000),
                                reasons_known=bool(after['change_reasons_known']),reason_error=after['change_reason_error'])
                    try:
                        threading.Event().wait(.15)
                        if tail is not None:
                            close(tail)
                            tail=None
                            last=watch_candidate_for_path(str(path),int(after['change_usn']))
                            record['last_close_seen']=bool(last['change_reasons']&0x80000000)
                            record['ready_after_last_close']=bool(watch_file_is_ready(str(path)))
                    finally:
                        if tail is not None:
                            close(tail)
                    with gate:
                        record['directory_events']=[dict(kind=e['kind'],relative_to_first_close_seconds=e['at']-closed)
                                                    for e in events if e['file']==path.name]
                    records.append(record)
                    print(mode,repeat,'ready',ready_before,record['ready_after_first_close'],
                          'CLOSE',record['close_seen_after_first_close'],'known',record['reasons_known'],flush=True)
        finally:
            observer.stop()
            observer.join()
        report=dict(broker=broker,sharing=sharing,lifecycles=records,
                    note='Controlled native anchors, not a guarantee of notification latency under arbitrary system load.')
        output=workspace.result_dir/'report.json'
        output.write_text(json.dumps(report,indent=2),encoding='utf8')
        print('report:',output,flush=True)
    return 0


if __name__=='__main__':
    raise SystemExit(main())
