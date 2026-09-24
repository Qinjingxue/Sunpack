from __future__ import annotations

import asyncio
import os
import struct
import sys
import time
from typing import Any, Callable

from sunpack.core.config.cli_settings import load_cli_language_from_config
from sunpack.core.i18n import I18nContext
from sunpack.core.support.process_executable import current_process_executable, is_packaged_process
from sunpack.core.support.resources import writable_data_dir
from sunpack.core.support.runtime_cwd import runtime_working_directory
from sunpack.core.support.resource_lifecycle import open_service_file
from sunpack.core.support.runtime_identity import (
    require_runtime_id,
    runtime_id,
    runtime_id_argument,
    runtime_id_available,
)


SERVER_ARG = "--persistent-server"
SHUTDOWN_ARG = "--persistent-shutdown"
_REQUEST_MAGIC = b"SPK2"
_STREAM_MAGIC = b"SPS2"


def _runtime_binary_build_id() -> bytes:
    value = 0xCBF29CE484222325
    try:
        with open_service_file(current_process_executable(), "rb") as stream:
            while chunk := stream.read(1024 * 1024):
                for byte in chunk:
                    value ^= byte
                    value = (value * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    except OSError:
        return b"0000000000000000"
    return f"{value:016x}".encode("ascii")


_RUNTIME_BUILD_ID = _runtime_binary_build_id()


def _runtime_binary_stamp() -> str:
    try:
        metadata = current_process_executable().stat()
    except OSError:
        return "unavailable"
    return f"{int(metadata.st_size):x}-{int(metadata.st_mtime_ns):x}"


_RUNTIME_BINARY_STAMP = _runtime_binary_stamp()
_MAX_FIELD_BYTES = 16 * 1024 * 1024
_MAX_REQUEST_BYTES = 64 * 1024 * 1024
_MAX_ARGC = 4096
_TERMINAL_COLUMNS_ARG = "--_sunpack-terminal-columns="
_PIPE_PREFIX = r"\\.\pipe\SunPack-"
_SERVER_STARTUP_TIMEOUT_SECONDS = 10.0


def handle_early_argv(argv: list[str]) -> int | None:
    if not argv:
        return None
    if argv[0] == SERVER_ARG:
        return asyncio.run(run_server())
    if argv[0] == SHUTDOWN_ARG:
        return submit_request([], shutdown=True)
    return None


def state_path() -> str:
    identity = runtime_id() or "direct"
    return str(writable_data_dir() / f"runtime-{identity}.state")


def pipe_name() -> str:
    identity = require_runtime_id()
    return f"{_PIPE_PREFIX}{identity}"


def server_command() -> list[str]:
    if is_packaged_process():
        command = [str(current_process_executable()), SERVER_ARG]
    else:
        entry = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "sunpack.py"))
        if os.path.isfile(entry):
            command = [str(current_process_executable()), entry, SERVER_ARG]
        else:
            command = [str(current_process_executable()), "-m", "sunpack", SERVER_ARG]
    if runtime_id_available():
        command.append(runtime_id_argument())
    return command


def submit_request(argv: list[str], *, shutdown: bool = False) -> int:
    request_cwd = os.getcwd()
    i18n = I18nContext(load_cli_language_from_config(request_cwd))
    request_argv = list(argv)
    pause = "--pause" in request_argv
    if pause:
        request_argv = [item for item in request_argv if item != "--pause"]
        if "--no-pause" not in request_argv:
            request_argv.append("--no-pause")
    supports_terminal_updates = _client_supports_terminal_updates(sys.stdout)
    payload = {
        "argv": request_argv,
        "cwd": request_cwd,
        "shutdown": bool(shutdown),
        "stdout_tty": supports_terminal_updates,
        "stdout_columns": _client_terminal_columns(sys.stdout) if supports_terminal_updates else 0,
        "stdin_tty": bool(sys.stdin is not None and sys.stdin.isatty()),
    }
    response = _send_or_start(payload)
    stdout = str(response.get("stdout") or "")
    stderr = str(response.get("stderr") or "")
    if stdout:
        print(stdout, end="", file=sys.stdout)
    if stderr:
        print(stderr, end="", file=sys.stderr)
    if pause and sys.stdin is not None and sys.stdin.isatty():
        try:
            input(i18n.t("cli.press_enter"))
        except (EOFError, KeyboardInterrupt):
            pass
    return int(response.get("exit_code", 1))


def _client_supports_terminal_updates(stream) -> bool:
    if stream is None:
        return False
    from sunpack.pipeline.coordinator.reporting import _terminal_supports_updates

    return _terminal_supports_updates(stream)


def _client_terminal_columns(stream) -> int:
    try:
        columns = int(os.get_terminal_size(stream.fileno()).columns)
    except (AttributeError, OSError, TypeError, ValueError):
        return 80
    return max(20, min(1000, columns))


def _send_or_start(payload: dict[str, Any]) -> dict[str, Any]:
    request_cwd = str(payload.get("cwd") or os.getcwd())
    i18n = I18nContext(load_cli_language_from_config(request_cwd))
    if not runtime_id_available():
        if payload.get("shutdown"):
            return {"exit_code": 0, "stdout": "", "stderr": ""}
        return {
            "exit_code": 2,
            "stdout": "",
            "stderr": i18n.t("cli.persistent_identity_required") + "\n",
        }
    response = _try_send(payload)
    if response is not None:
        return response
    if payload.get("shutdown"):
        return {"exit_code": 0, "stdout": "", "stderr": ""}
    import subprocess

    creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    try:
        process = subprocess.Popen(
            server_command(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            creationflags=creationflags,
            cwd=runtime_working_directory(),
        )
    except OSError as exc:
        return {
            "exit_code": 1,
            "stdout": "",
            "stderr": i18n.t("cli.persistent_launch_failed", error=exc) + "\n",
        }

    deadline = time.monotonic() + _SERVER_STARTUP_TIMEOUT_SECONDS
    runtime_exit_code: int | None = None
    while time.monotonic() < deadline:
        response = _try_send(payload)
        if response is not None:
            return response
        poll = getattr(process, "poll", None)
        if poll is not None:
            runtime_exit_code = poll()
            if runtime_exit_code not in (None, 0):
                break
        time.sleep(0.025)
    error = i18n.t("cli.persistent_start_timeout")
    if runtime_exit_code not in (None, 0):
        error += "\n" + i18n.t("cli.persistent_runtime_exited", code=runtime_exit_code)
    return {
        "exit_code": 1,
        "stdout": "",
        "stderr": error + "\n",
    }


class _PipeConnection:
    """Small synchronous byte-stream adapter around a Windows named-pipe HANDLE."""

    def __init__(self, handle) -> None:
        self._handle = handle

    def sendall(self, data: bytes) -> None:
        import ctypes
        from ctypes import wintypes

        if not data:
            return
        kernel32 = _kernel32()
        buffer = ctypes.create_string_buffer(data)
        offset = 0
        while offset < len(data):
            written = wintypes.DWORD()
            size = min(len(data) - offset, 0x7FFFFFFF)
            if not kernel32.WriteFile(self._handle, ctypes.byref(buffer, offset), size, ctypes.byref(written), None):
                raise OSError(ctypes.get_last_error(), "WriteFile failed")
            if written.value == 0:
                raise OSError("named pipe closed while writing")
            offset += int(written.value)

    def recv(self, size: int) -> bytes:
        import ctypes
        from ctypes import wintypes

        if size <= 0:
            return b""
        kernel32 = _kernel32()
        buffer = ctypes.create_string_buffer(size)
        read = wintypes.DWORD()
        if not kernel32.ReadFile(self._handle, buffer, size, ctypes.byref(read), None):
            error = ctypes.get_last_error()
            if error in {109, 232, 233}:
                return b""
            raise OSError(error, "ReadFile failed")
        return buffer.raw[: read.value]

    def close(self) -> None:
        import ctypes

        if self._handle is not None:
            _kernel32().CloseHandle(self._handle)
            self._handle = None


def _kernel32():
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.WaitNamedPipeW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD)
    kernel32.WaitNamedPipeW.restype = wintypes.BOOL
    kernel32.CreateFileW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.SetNamedPipeHandleState.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
        wintypes.LPVOID,
    )
    kernel32.SetNamedPipeHandleState.restype = wintypes.BOOL
    kernel32.ReadFile.argtypes = (
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    )
    kernel32.ReadFile.restype = wintypes.BOOL
    kernel32.WriteFile.argtypes = kernel32.ReadFile.argtypes
    kernel32.WriteFile.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    return kernel32


def _open_pipe(name: str) -> _PipeConnection | None:
    if os.name != "nt" or not name.startswith(_PIPE_PREFIX):
        return None
    import ctypes
    from ctypes import wintypes

    kernel32 = _kernel32()
    deadline = time.monotonic() + 2.0
    invalid_handle = ctypes.c_void_p(-1).value
    while True:
        handle = kernel32.CreateFileW(name, 0xC0000000, 0, None, 3, 0, None)
        if handle != invalid_handle:
            mode = wintypes.DWORD(0)
            if not kernel32.SetNamedPipeHandleState(handle, ctypes.byref(mode), None, None):
                kernel32.CloseHandle(handle)
                return None
            return _PipeConnection(handle)
        error = ctypes.get_last_error()
        if error != 231:
            return None
        remaining = int(max(0.0, deadline - time.monotonic()) * 1000)
        if remaining <= 0 or not kernel32.WaitNamedPipeW(name, remaining):
            return None


def _read_state() -> tuple[str, bytes] | None:
    try:
        with open_service_file(state_path(), "r", encoding="ascii") as stream:
            pipe, token_hex, build_id, _pid, binary_stamp = stream.read().splitlines()[:5]
        token = bytes.fromhex(token_hex)
    except (FileNotFoundError, OSError, ValueError):
        return None
    if (
        len(token) != 32
        or not pipe.startswith(_PIPE_PREFIX)
        or build_id != _RUNTIME_BUILD_ID.decode("ascii")
        or binary_stamp != _RUNTIME_BINARY_STAMP
    ):
        return None
    return pipe, token


def _try_send(payload: dict[str, Any]) -> dict[str, Any] | None:
    state = _read_state()
    if state is None:
        return None
    pipe, token = state
    connection = _open_pipe(pipe)
    if connection is None:
        return None
    try:
        cwd = str(payload.get("cwd") or "").encode("utf-8", "surrogatepass")
        argv_values = [str(item) for item in payload.get("argv") or []]
        try:
            stdout_columns = int(payload.get("stdout_columns") or 0)
        except (TypeError, ValueError):
            stdout_columns = 0
        if stdout_columns > 0:
            argv_values.append(f"{_TERMINAL_COLUMNS_ARG}{max(20, min(1000, stdout_columns))}")
        argv = [item.encode("utf-8", "surrogatepass") for item in argv_values]
        if len(cwd) > _MAX_FIELD_BYTES or len(argv) > _MAX_ARGC or any(len(item) > _MAX_FIELD_BYTES for item in argv):
            return None
        flags = ((1 if payload.get("shutdown") else 0)
                 | (2 if payload.get("stdout_tty") else 0)
                 | (4 if payload.get("stdin_tty") else 0))
        body = [_RUNTIME_BUILD_ID, token, struct.pack("!III", flags, len(cwd), len(argv)), cwd]
        for item in argv:
            body.extend((struct.pack("!I", len(item)), item))
        connection.sendall(_REQUEST_MAGIC + b"".join(body))
        if _recv_exact(connection, 4) != _STREAM_MAGIC or _recv_exact(connection, len(_RUNTIME_BUILD_ID)) != _RUNTIME_BUILD_ID:
            return None
        return _recv_stream(connection)
    except (EOFError, OSError, ValueError):
        return None
    finally:
        connection.close()


class _PipeRequestProtocol(asyncio.Protocol):
    """One-request named-pipe protocol with incremental request and input parsing."""

    def __init__(
        self,
        token: bytes,
        *,
        on_connected: Callable[[], None],
        on_closed: Callable[[], None],
        on_completed: Callable[[], None],
        on_shutdown: Callable[[], None],
    ) -> None:
        self._token = token
        self._on_connected = on_connected
        self._on_closed = on_closed
        self._on_completed = on_completed
        self._on_shutdown = on_shutdown
        self._transport: asyncio.Transport | None = None
        self._buffer = bytearray()
        self._stage = "header"
        self._payload: dict[str, Any] | None = None
        self._argv_remaining = 0
        self._next_arg_size: int | None = None
        self._request_bytes = 0
        self._input_size: int | None = None
        self._input_waiter: asyncio.Future[str] | None = None
        self._request_task: asyncio.Task[None] | None = None
        self._output_queue: asyncio.Queue[bytes | None] = asyncio.Queue()
        self._output_task: asyncio.Task[None] | None = None
        self._write_ready = asyncio.Event()
        self._write_ready.set()
        self._closed = False
        self._counted_active = False
        self._connected_at = time.monotonic()

    @property
    def output_queue(self) -> asyncio.Queue[bytes | None]:
        return self._output_queue

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = transport  # type: ignore[assignment]
        self._counted_active = True
        self._on_connected()
        self._output_task = asyncio.create_task(self._pump_output(), name="persistent-pipe-output")

    def data_received(self, data: bytes) -> None:
        if self._closed:
            return
        self._buffer.extend(data)
        if len(self._buffer) > _MAX_REQUEST_BYTES:
            self._abort()
            return
        try:
            if self._request_task is None:
                payload = self._parse_request()
                if payload is not None:
                    self._request_task = asyncio.create_task(self._run_request(payload), name="persistent-pipe-request")
            if self._request_task is not None:
                self._parse_input()
        except (UnicodeDecodeError, ValueError):
            self._abort()

    def connection_lost(self, exc: Exception | None) -> None:
        self._closed = True
        if self._input_waiter is not None and not self._input_waiter.done():
            self._input_waiter.set_exception(ConnectionError("persistent pipe client disconnected"))
        if self._request_task is not None and not self._request_task.done():
            self._request_task.cancel()
        if self._output_task is not None and not self._output_task.done():
            self._output_task.cancel()
        if self._counted_active:
            self._counted_active = False
            self._on_closed()

    def pause_writing(self) -> None:
        self._write_ready.clear()

    def resume_writing(self) -> None:
        self._write_ready.set()

    def _parse_request(self) -> dict[str, Any] | None:
        if self._stage == "header":
            header_size = 4 + len(_RUNTIME_BUILD_ID) + len(self._token) + 12
            if len(self._buffer) < header_size:
                return None
            if bytes(self._buffer[:4]) != _REQUEST_MAGIC:
                raise ValueError("invalid persistent request magic")
            build_start = 4
            build_end = build_start + len(_RUNTIME_BUILD_ID)
            if bytes(self._buffer[build_start:build_end]) != _RUNTIME_BUILD_ID:
                raise ValueError("invalid persistent runtime build id")
            token_start = build_end
            token_end = token_start + len(self._token)
            if bytes(self._buffer[token_start:token_end]) != self._token:
                raise ValueError("invalid persistent request token")
            flags, cwd_size, argc = struct.unpack("!III", self._buffer[token_end:header_size])
            del self._buffer[:header_size]
            if cwd_size > _MAX_FIELD_BYTES or argc > _MAX_ARGC:
                raise ValueError("persistent request header exceeds limits")
            self._payload = {
                "argv": [],
                "shutdown": bool(flags & 1),
                "stdout_tty": bool(flags & 2),
                "stdin_tty": bool(flags & 4),
            }
            self._request_bytes = int(cwd_size)
            self._argv_remaining = int(argc)
            self._next_arg_size = int(cwd_size)
            self._stage = "cwd"

        if self._stage == "cwd":
            assert self._payload is not None and self._next_arg_size is not None
            if len(self._buffer) < self._next_arg_size:
                return None
            self._payload["cwd"] = bytes(self._buffer[:self._next_arg_size]).decode("utf-8", "surrogatepass")
            del self._buffer[:self._next_arg_size]
            self._next_arg_size = None
            self._stage = "argv"

        while self._argv_remaining:
            assert self._payload is not None
            if self._next_arg_size is None:
                if len(self._buffer) < 4:
                    return None
                self._next_arg_size = struct.unpack("!I", self._buffer[:4])[0]
                del self._buffer[:4]
                if self._next_arg_size > _MAX_FIELD_BYTES:
                    raise ValueError("persistent argument exceeds limit")
                self._request_bytes += self._next_arg_size
                if self._request_bytes > _MAX_REQUEST_BYTES:
                    raise ValueError("persistent request exceeds total limit")
            if len(self._buffer) < self._next_arg_size:
                return None
            self._payload["argv"].append(
                bytes(self._buffer[:self._next_arg_size]).decode("utf-8", "surrogatepass")
            )
            del self._buffer[:self._next_arg_size]
            self._next_arg_size = None
            self._argv_remaining -= 1

        payload = self._payload
        self._stage = "complete"
        return payload

    def _parse_input(self) -> None:
        waiter = self._input_waiter
        if waiter is None or waiter.done():
            if self._buffer:
                raise ValueError("unexpected persistent input data")
            return
        if self._input_size is None:
            if len(self._buffer) < 4:
                return
            self._input_size = struct.unpack("!I", self._buffer[:4])[0]
            del self._buffer[:4]
            if self._input_size > _MAX_FIELD_BYTES:
                raise ValueError("persistent input exceeds limit")
        if len(self._buffer) < self._input_size:
            return
        text = bytes(self._buffer[:self._input_size]).decode("utf-8", "replace")
        del self._buffer[:self._input_size]
        self._input_size = None
        self._input_waiter = None
        waiter.set_result(text)

    async def _run_request(self, payload: dict[str, Any]) -> None:
        from sunpack.runtime.cli.runtime_state import runtime_host

        host = runtime_host()
        foreground_active = False
        exit_code: int | None = None
        started_at = time.monotonic()
        try:
            if host is not None and not payload.get("shutdown"):
                await host.foreground_started()
                foreground_active = True
                argv = list(payload.get("argv") or [])
                host.log_event(
                    "foreground_request_started",
                    origin="foreground",
                    command=str(argv[0] if argv else ""),
                    queue_ms=max(0.0, (started_at - self._connected_at) * 1000.0),
                )
            await self.send_frame(_STREAM_MAGIC + _RUNTIME_BUILD_ID)
            if payload.get("shutdown"):
                await self.send_frame(struct.pack("!BIi", 0, 4, 0))
                await self.flush_output()
                self._on_shutdown()
            else:
                exit_code = await _execute_streaming_request_async(payload, self)
                await self.send_frame(struct.pack("!BIi", 0, 4, exit_code))
                await self.flush_output()
                self._on_completed()
        except (asyncio.CancelledError, ConnectionError, OSError):
            raise
        except Exception:
            pass
        finally:
            if foreground_active:
                host.log_event(
                    "foreground_request_finished",
                    origin="foreground",
                    exit_code=exit_code,
                    duration_ms=max(0.0, (time.monotonic() - started_at) * 1000.0),
                )
                await host.foreground_finished()
            await self._finish_after_output()

    async def _pump_output(self) -> None:
        try:
            while True:
                frame = await self._output_queue.get()
                try:
                    if frame is None:
                        return
                    transport = self._transport
                    if transport is None or self._closed:
                        raise ConnectionError("persistent pipe transport is closed")
                    transport.write(frame)
                    if transport.get_write_buffer_size() > 256 * 1024:
                        await self._write_ready.wait()
                finally:
                    self._output_queue.task_done()
        except asyncio.CancelledError:
            raise

    async def send_frame(self, frame: bytes) -> None:
        if self._closed:
            raise ConnectionError("persistent pipe transport is closed")
        await self._output_queue.put(frame)

    async def flush_output(self) -> None:
        await self._output_queue.join()

    async def read_input(self, prompt: str, stdout: "_AsyncConnectionTextStream") -> str:
        if prompt:
            stdout.write(prompt)
        await self.flush_output()
        loop = asyncio.get_running_loop()
        waiter: asyncio.Future[str] = loop.create_future()
        self._input_waiter = waiter
        await self.send_frame(struct.pack("!BI", 3, 0))
        await self.flush_output()
        self._parse_input()
        return await waiter

    async def _finish_after_output(self) -> None:
        if self._output_task is not None and not self._output_task.done():
            await self._output_queue.put(None)
            await self._output_task
        if self._transport is not None and not self._closed:
            self._transport.close()

    def _abort(self) -> None:
        self._closed = True
        if self._transport is not None:
            self._transport.close()


async def run_server() -> int:
    if os.name != "nt":
        return 1
    try:
        require_runtime_id()
    except RuntimeError:
        i18n = I18nContext(load_cli_language_from_config())
        print(i18n.t("cli.persistent_identity_required"), file=sys.stderr, flush=True)
        return 2
    import secrets

    lock_stream = _acquire_server_lock()
    if lock_stream is None:
        return 0
    token = secrets.token_bytes(32)
    from sunpack.runtime.cli.persistent_runtime import (
        close_persistent_runtime,
        enable_persistent_runtime,
        persistent_runtime_is_idle,
        persistent_server_idle_seconds,
    )
    from sunpack.runtime.cli.runtime_host import RuntimeHost
    from sunpack.runtime.cli.runtime_state import set_runtime_host

    shutdown = asyncio.Event()
    state_changed = asyncio.Event()
    state = {
        "served": False,
        "last_completed": time.monotonic(),
        "active": 0,
        "exit_reason": "shutdown",
    }

    def notify_state_changed() -> None:
        state_changed.set()

    enable_persistent_runtime(state_changed=notify_state_changed)
    runtime_host = RuntimeHost(
        log_path=state_path() + ".events.jsonl",
        state_changed=notify_state_changed,
    )
    set_runtime_host(runtime_host)

    def connected() -> None:
        state["active"] += 1
        notify_state_changed()

    def closed() -> None:
        state["active"] = max(0, state["active"] - 1)
        notify_state_changed()

    def completed() -> None:
        state["served"] = True
        state["last_completed"] = time.monotonic()
        notify_state_changed()

    def requested_shutdown() -> None:
        state["exit_reason"] = "cli_shutdown"
        shutdown.set()
        notify_state_changed()

    loop = asyncio.get_running_loop()
    start_serving_pipe = getattr(loop, "start_serving_pipe", None)
    if start_serving_pipe is None:
        try:
            await runtime_host.close(exit_reason="pipe_transport_unavailable")
        finally:
            set_runtime_host(None)
            await close_persistent_runtime()
            lock_stream.close()
        return 1

    name = pipe_name()

    def protocol_factory() -> _PipeRequestProtocol:
        return _PipeRequestProtocol(
            token,
            on_connected=connected,
            on_closed=closed,
            on_completed=completed,
            on_shutdown=requested_shutdown,
        )

    from sunpack.core.platform.windows.secure_pipe import start_serving_current_user_pipe

    try:
        servers = await start_serving_current_user_pipe(loop, protocol_factory, name)
    except Exception:
        try:
            await runtime_host.close(exit_reason="pipe_create_failed")
        finally:
            set_runtime_host(None)
            await close_persistent_runtime()
            lock_stream.close()
        return 1
    _write_state(name, token)

    async def monitor_idle() -> None:
        await _monitor_idle_shutdown(
            shutdown=shutdown,
            state_changed=state_changed,
            state=state,
            watch_active=lambda: runtime_host.watch_enabled,
            idle_seconds=persistent_server_idle_seconds,
            runtime_idle=persistent_runtime_is_idle,
        )

    monitor = asyncio.create_task(monitor_idle(), name="persistent-idle-monitor")
    try:
        await shutdown.wait()
        return 0
    finally:
        monitor.cancel()
        await asyncio.gather(monitor, return_exceptions=True)
        _close_pipe_servers(servers)
        _remove_state_if_owned(name, token)
        try:
            await runtime_host.close(exit_reason=str(state["exit_reason"]))
        finally:
            set_runtime_host(None)
            try:
                await close_persistent_runtime()
            finally:
                from sunpack.core.platform.windows.process_job import close_child_job

                close_child_job()
                lock_stream.close()


def _close_pipe_servers(servers: list[Any]) -> None:
    for server in servers:
        server.close()


def _idle_shutdown_due(
    *,
    served_request: bool,
    last_completed_at: float,
    idle_seconds: float,
    runtime_idle: bool,
    now: float | None = None,
) -> bool:
    if not served_request or not runtime_idle:
        return False
    if now is None:
        now = time.monotonic()
    return now - last_completed_at >= max(0.0, float(idle_seconds))


async def _monitor_idle_shutdown(
    *,
    shutdown: asyncio.Event,
    state_changed: asyncio.Event,
    state: dict[str, Any],
    watch_active: Callable[[], bool],
    idle_seconds: Callable[[], float],
    runtime_idle: Callable[[], bool],
) -> None:
    """Wait for lifecycle changes and one idle deadline without fixed polling."""

    while not shutdown.is_set():
        state_changed.clear()
        if (
            not state.get("served")
            or int(state.get("active") or 0) > 0
            or watch_active()
            or not runtime_idle()
        ):
            await state_changed.wait()
            continue

        timeout = max(
            0.0,
            float(state.get("last_completed") or 0.0)
            + max(0.0, float(idle_seconds()))
            - time.monotonic(),
        )
        if timeout > 0.0:
            try:
                await asyncio.wait_for(state_changed.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                pass
            else:
                continue

        if (
            not state.get("active")
            and not watch_active()
            and _idle_shutdown_due(
                served_request=bool(state.get("served")),
                last_completed_at=float(state.get("last_completed") or 0.0),
                idle_seconds=idle_seconds(),
                runtime_idle=runtime_idle(),
            )
        ):
            state["exit_reason"] = "idle_timeout"
            shutdown.set()


def _recv_exact(connection, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = connection.recv(size - len(chunks))
        if not chunk:
            raise EOFError("persistent connection closed")
        chunks.extend(chunk)
    return bytes(chunks)


def _recv_request(connection, token: bytes) -> dict[str, Any] | None:
    if (
        _recv_exact(connection, 4) != _REQUEST_MAGIC
        or _recv_exact(connection, len(_RUNTIME_BUILD_ID)) != _RUNTIME_BUILD_ID
        or _recv_exact(connection, len(token)) != token
    ):
        return None
    flags, cwd_size, argc = struct.unpack("!III", _recv_exact(connection, 12))
    if cwd_size > _MAX_FIELD_BYTES or argc > _MAX_ARGC:
        return None
    cwd = _recv_exact(connection, cwd_size).decode("utf-8", "surrogatepass")
    argv = []
    for _ in range(argc):
        size = struct.unpack("!I", _recv_exact(connection, 4))[0]
        if size > _MAX_FIELD_BYTES:
            return None
        argv.append(_recv_exact(connection, size).decode("utf-8", "surrogatepass"))
    return {
        "cwd": cwd,
        "argv": argv,
        "shutdown": bool(flags & 1),
        "stdout_tty": bool(flags & 2),
        "stdin_tty": bool(flags & 4),
    }


def _recv_stream(connection, input_stream=None) -> dict[str, Any]:
    input_stream = sys.stdin if input_stream is None else input_stream
    while True:
        kind, size = struct.unpack("!BI", _recv_exact(connection, 5))
        if size > _MAX_FIELD_BYTES:
            raise ValueError("persistent stream frame is too large")
        payload = _recv_exact(connection, size)
        if kind == 0:
            if size != 4:
                raise ValueError("invalid persistent final frame")
            return {"exit_code": struct.unpack("!i", payload)[0], "stdout": "", "stderr": ""}
        if kind == 3:
            line = input_stream.readline() if input_stream is not None else ""
            encoded = line.encode("utf-8", "surrogatepass")
            connection.sendall(struct.pack("!I", len(encoded)) + encoded)
        else:
            stream = sys.stdout if kind == 1 else sys.stderr
            stream.write(payload.decode("utf-8", "replace"))
            stream.flush()


class _AsyncConnectionTextStream:
    encoding = "utf-8"
    errors = "replace"

    def __init__(
        self,
        loop: asyncio.AbstractEventLoop,
        queue: asyncio.Queue[bytes | None],
        kind: int,
        *,
        is_tty: bool = False,
        terminal_columns: int | None = None,
    ):
        self.loop = loop
        self.queue = queue
        self.kind = kind
        self._is_tty = is_tty
        self.supports_terminal_updates = is_tty
        self.terminal_columns = terminal_columns

    def write(self, text: str) -> int:
        value = str(text)
        data = value.encode("utf-8", "surrogatepass")
        if data:
            frame = struct.pack("!BI", self.kind, len(data)) + data
            self.loop.call_soon_threadsafe(self.queue.put_nowait, frame)
        return len(value)

    def flush(self) -> None:
        return None

    def isatty(self) -> bool:
        return self._is_tty


class _StreamRequestConnection:
    """Stream adapter kept for direct unit tests of command streaming behavior."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader = reader
        self.writer = writer
        self.output_queue: asyncio.Queue[bytes | None] = asyncio.Queue()
        self._output_task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        self._output_task = asyncio.create_task(self._pump_output(), name="persistent-stream-output")

    async def close(self) -> None:
        if self._output_task is not None:
            await self.output_queue.put(None)
            await self._output_task

    async def _pump_output(self) -> None:
        while True:
            frame = await self.output_queue.get()
            try:
                if frame is None:
                    return
                self.writer.write(frame)
                await self.writer.drain()
            finally:
                self.output_queue.task_done()

    async def send_frame(self, frame: bytes) -> None:
        await self.output_queue.put(frame)

    async def flush_output(self) -> None:
        await self.output_queue.join()

    async def read_input(self, prompt: str, stdout: _AsyncConnectionTextStream) -> str:
        if prompt:
            stdout.write(prompt)
        await self.flush_output()
        await self.send_frame(struct.pack("!BI", 3, 0))
        await self.flush_output()
        size = struct.unpack("!I", await self.reader.readexactly(4))[0]
        if size > _MAX_FIELD_BYTES:
            raise ValueError("persistent input frame is too large")
        return (await self.reader.readexactly(size)).decode("utf-8", "replace")


async def _execute_streaming_request_async(
    payload: dict[str, Any],
    connection_or_reader,
    writer=None,
) -> int:
    from sunpack.runtime.cli.cli import async_main

    owns_connection = writer is not None
    connection = _StreamRequestConnection(connection_or_reader, writer) if owns_connection else connection_or_reader
    if owns_connection:
        await connection.start()
    loop = asyncio.get_running_loop()

    argv = []
    terminal_columns = None
    for item in payload.get("argv") or []:
        value = str(item)
        if value.startswith(_TERMINAL_COLUMNS_ARG):
            try:
                terminal_columns = max(20, min(1000, int(value[len(_TERMINAL_COLUMNS_ARG):])))
            except ValueError:
                terminal_columns = None
            continue
        argv.append(value)

    stdout = _AsyncConnectionTextStream(
        loop,
        connection.output_queue,
        1,
        is_tty=bool(payload.get("stdout_tty")),
        terminal_columns=terminal_columns,
    )
    stderr = _AsyncConnectionTextStream(loop, connection.output_queue, 2, is_tty=False)
    try:
        return int(
            await async_main(
                argv,
                cwd=str(payload.get("cwd") or runtime_working_directory()),
                stdout=stdout,
                stderr=stderr,
                input_reader=lambda prompt="": connection.read_input(prompt, stdout),
            )
            or 0
        )
    except asyncio.CancelledError:
        raise
    except BaseException as exc:
        request_cwd = str(payload.get("cwd") or runtime_working_directory())
        print(I18nContext(load_cli_language_from_config(request_cwd)).t("cli.persistent_request_failed", error=exc), file=stderr)
        return 1
    finally:
        await asyncio.sleep(0)
        await connection.flush_output()
        if owns_connection:
            await connection.close()


def _write_state(name: str, token: bytes) -> None:
    path = state_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temporary = f"{path}.{os.getpid()}.tmp"
    with open_service_file(temporary, "w", encoding="ascii", newline="\n") as stream:
        stream.write(
            f"{name}\n{token.hex()}\n{_RUNTIME_BUILD_ID.decode('ascii')}\n"
            f"{os.getpid()}\n{_RUNTIME_BINARY_STAMP}\n"
        )
    os.replace(temporary, path)


def _remove_state_if_owned(name: str, token: bytes) -> bool:
    path = state_path()
    try:
        with open_service_file(path, "r", encoding="ascii") as stream:
            state_name, token_hex, build_id, pid_text, binary_stamp = stream.read().splitlines()[:5]
        if (
            state_name != name
            or bytes.fromhex(token_hex) != token
            or build_id != _RUNTIME_BUILD_ID.decode("ascii")
            or int(pid_text) != os.getpid()
            or binary_stamp != _RUNTIME_BINARY_STAMP
        ):
            return False
        os.remove(path)
        return True
    except (FileNotFoundError, OSError, ValueError):
        return False


def _acquire_server_lock():
    import msvcrt

    path = state_path() + ".lock"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    stream = open_service_file(path, "a+b")
    if stream.tell() == 0:
        stream.write(b"0")
        stream.flush()
    stream.seek(0)
    try:
        msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
    except OSError:
        stream.close()
        return None
    return stream
