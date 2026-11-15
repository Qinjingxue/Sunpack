"""Start real Windows process trees under a test-owned commit limit."""

import _winapi
import ctypes
import msvcrt
import os
import subprocess
import tempfile
from ctypes import wintypes


class _BasicLimits(ctypes.Structure):
    _fields_ = [
        ("process_time", ctypes.c_int64),
        ("job_time", ctypes.c_int64),
        ("flags", wintypes.DWORD),
        ("min_working_set", ctypes.c_size_t),
        ("max_working_set", ctypes.c_size_t),
        ("active_process_limit", wintypes.DWORD),
        ("affinity", ctypes.c_size_t),
        ("priority_class", wintypes.DWORD),
        ("scheduling_class", wintypes.DWORD),
    ]


class _ExtendedLimits(ctypes.Structure):
    _fields_ = [
        ("basic", _BasicLimits),
        ("io_counters", ctypes.c_uint64 * 6),
        ("process_memory_limit", ctypes.c_size_t),
        ("job_memory_limit", ctypes.c_size_t),
        ("peak_process_memory", ctypes.c_size_t),
        ("peak_job_memory", ctypes.c_size_t),
    ]


_CREATE_SUSPENDED = 0x00000004
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_KERNEL = ctypes.WinDLL("kernel32", use_last_error=True)


def _kernel_function(name, restype, *argtypes):
    function = getattr(_KERNEL, name)
    function.restype = restype
    function.argtypes = argtypes
    return function


_create_job = _kernel_function("CreateJobObjectW", wintypes.HANDLE, ctypes.c_void_p, wintypes.LPCWSTR)
_set_job = _kernel_function(
    "SetInformationJobObject", wintypes.BOOL, wintypes.HANDLE, ctypes.c_int,
    ctypes.c_void_p, wintypes.DWORD,
)
_query_job = _kernel_function(
    "QueryInformationJobObject", wintypes.BOOL, wintypes.HANDLE, ctypes.c_int,
    ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p,
)
_assign_process = _kernel_function("AssignProcessToJobObject", wintypes.BOOL,
                                   wintypes.HANDLE, wintypes.HANDLE)
_in_job = _kernel_function("IsProcessInJob", wintypes.BOOL, wintypes.HANDLE,
                           wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL))
_resume_thread = _kernel_function("ResumeThread", wintypes.DWORD, wintypes.HANDLE)


def _check(result):
    if not result:
        raise ctypes.WinError(ctypes.get_last_error())


class WindowsJob:
    def __init__(self, memory_limit):
        self.memory_limit = memory_limit

    def __enter__(self):
        self.handle = _create_job(None, None)
        _check(self.handle)
        limits = _ExtendedLimits()
        limits.basic.flags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | _JOB_OBJECT_LIMIT_JOB_MEMORY
        limits.job_memory_limit = self.memory_limit
        try:
            _check(_set_job(self.handle, _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                            ctypes.byref(limits), ctypes.sizeof(limits)))
            configured = _ExtendedLimits()
            _check(_query_job(self.handle, _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                              ctypes.byref(configured), ctypes.sizeof(configured), None))
            assert configured.basic.flags & limits.basic.flags == limits.basic.flags
            assert configured.job_memory_limit == self.memory_limit
        except BaseException:
            _winapi.CloseHandle(self.handle)
            raise
        return self

    def __exit__(self, *exc):
        _winapi.CloseHandle(self.handle)

    def contains(self, pid):
        process = _winapi.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        try:
            in_job = wintypes.BOOL()
            _check(_in_job(process, self.handle, ctypes.byref(in_job)))
            return bool(in_job.value)
        finally:
            _winapi.CloseHandle(process)

    def run(self, arguments, *, cwd, env, timeout):
        args = list(map(str, arguments))
        with (
            open(os.devnull, "rb") as stdin,
            tempfile.TemporaryFile() as stdout,
            tempfile.TemporaryFile() as stderr,
        ):
            startup = subprocess.STARTUPINFO()
            startup.dwFlags = subprocess.STARTF_USESTDHANDLES
            startup.hStdInput = msvcrt.get_osfhandle(stdin.fileno())
            startup.hStdOutput = msvcrt.get_osfhandle(stdout.fileno())
            startup.hStdError = msvcrt.get_osfhandle(stderr.fileno())
            handles = [startup.hStdInput, startup.hStdOutput, startup.hStdError]
            startup.lpAttributeList = {"handle_list": handles}
            for handle in handles:
                os.set_handle_inheritable(handle, True)
            process, thread, _, _ = _winapi.CreateProcess(
                args[0], subprocess.list2cmdline(args), None, None, True,
                _CREATE_SUSPENDED | subprocess.CREATE_NO_WINDOW,
                env, str(cwd), startup,
            )
            try:
                # No launcher code can run or create an unconstrained owner before assignment.
                _check(_assign_process(self.handle, process))
                if _resume_thread(thread) == 0xFFFFFFFF:
                    raise ctypes.WinError(ctypes.get_last_error())
                if _winapi.WaitForSingleObject(process, int(timeout * 1000)) == _winapi.WAIT_TIMEOUT:
                    raise subprocess.TimeoutExpired(args, timeout)
                code = _winapi.GetExitCodeProcess(process)
            except BaseException:
                if _winapi.WaitForSingleObject(process, 0) == _winapi.WAIT_TIMEOUT:
                    _winapi.TerminateProcess(process, 1)
                    _winapi.WaitForSingleObject(process, _winapi.INFINITE)
                raise
            finally:
                _winapi.CloseHandle(thread)
                _winapi.CloseHandle(process)
            stdout.seek(0)
            stderr.seek(0)
            return subprocess.CompletedProcess(args, code, stdout.read().decode("utf-8"),
                                               stderr.read().decode("utf-8"))
