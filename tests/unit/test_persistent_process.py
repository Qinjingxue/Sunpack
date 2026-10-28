import asyncio
import io
import os
import secrets
import socket
import struct
import threading
import time

import pytest

from sunpack.core.support import runtime_identity
from sunpack.runtime.cli import persistent_process


def _enable_test_runtime_identity(monkeypatch):
    monkeypatch.setattr(runtime_identity, "_runtime_id", "v2-0123456789abcdef")


def test_stop_frame_is_fragment_safe_idempotent_and_separate_from_password(tmp_path):
    # Request framing tests do not cover controls arriving between prompt
    # bytes. This catches stream corruption without starting another process.
    async def scenario():
        protocol = persistent_process._PipeRequestProtocol(
            b"t" * 32, on_connected=lambda: None, on_closed=lambda: None,
            on_completed=lambda: None, on_shutdown=lambda: None,
        )
        protocol._payload = {"cwd": str(tmp_path)}
        for chunk in (b"\xff", b"\xff\xff", b"\xff", b"\xff" * 8):
            protocol._buffer.extend(chunk)
            protocol._parse_input()
        assert protocol._cancellation.cancelled
        assert protocol.output_queue.qsize() == 1
        waiter = asyncio.get_running_loop().create_future()
        protocol._input_waiter = waiter
        password = b"quietQpassword\n"
        protocol._buffer.extend(struct.pack("!I", len(password)) + password)
        protocol._parse_input()
        assert await waiter == password.decode()
        assert not protocol._buffer
    asyncio.run(scenario())


@pytest.mark.parametrize("mode", ["q", "password", "ctrl_prompt"])
def test_console_controls_are_duplex_and_yield_stdin_to_prompts(tmp_path, mode):
    # Mock transports cannot catch synchronous Windows pipe IO serializing a
    # concurrent control write. A hidden real console also verifies the input
    # listener wakes on Q and joins without an input event at shutdown.
    import subprocess
    import sys
    from sunpack.core.platform.windows.secure_pipe import start_serving_current_user_pipe

    script = tmp_path / "console_client.py"
    script.write_text(r'''
import ctypes, sys, threading
from contextlib import contextmanager
from ctypes import wintypes as w
from sunpack.runtime.cli.persistent_process import _open_pipe, _recv_stream
from sunpack.core.platform.windows.console_cancel import ConsoleCancellation
k = ctypes.WinDLL("kernel32", use_last_error=True)
k.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, ctypes.c_void_p, w.DWORD, w.DWORD, w.HANDLE]
k.CreateFileW.restype = w.HANDLE
k.SetStdHandle.argtypes = [w.DWORD, w.HANDLE]
handle = k.CreateFileW("CONIN$", 0xC0000000, 3, None, 3, 0, None)
assert handle not in (None, -1)
k.SetStdHandle(-10 & 0xffffffff, handle)
class Key(ctypes.Structure):
    _fields_ = [("down", w.BOOL), ("repeat", w.WORD), ("virtual", w.WORD), ("scan", w.WORD), ("char", w.WCHAR), ("modifiers", w.DWORD)]
class Event(ctypes.Union):
    _fields_ = [("key", Key), ("padding", w.DWORD * 4)]
class Record(ctypes.Structure):
    _fields_ = [("kind", w.WORD), ("event", Event)]
k.WriteConsoleInputW.argtypes = [w.HANDLE, ctypes.c_void_p, w.DWORD, ctypes.POINTER(w.DWORD)]
def inject():
    assert sys.stdin.readline().strip() == "inject"
    if sys.argv[2] == "ctrl_prompt":
        assert k.GenerateConsoleCtrlEvent(1, 0)
        return
    text = "q" if sys.argv[2] == "q" else "quietQpassword\r"
    record, count = Record(), w.DWORD()
    record.kind = 1
    for char in text:
        record.event.key = Key(True, 1, ord(char.upper()), 0, char, 0)
        assert k.WriteConsoleInputW(handle, ctypes.byref(record), 1, ctypes.byref(count))
base_prompt = ConsoleCancellation.prompt
@contextmanager
def prompt(self):
    with base_prompt(self):
        print("prompt_ready", flush=True)
        yield
ConsoleCancellation.prompt = prompt
connection = _open_pipe(sys.argv[1])
assert connection is not None
thread = threading.Thread(target=inject)
thread.start()
print("ready", flush=True)
console = open("CONIN$", encoding="utf-8") if sys.argv[2] != "q" else None
response = _recv_stream(connection, input_stream=console)
thread.join()
connection.close()
print("exit", response["exit_code"], flush=True)
''', encoding="utf-8")

    async def scenario():
        name = persistent_process._PIPE_PREFIX + "cancel-test-" + secrets.token_hex(8)
        stop_received = asyncio.Event()
        class Protocol(asyncio.Protocol):
            def connection_made(self, transport):
                self.transport, self.data = transport, bytearray()
                if mode != "q":
                    self.transport.write(struct.pack("!BI", 3, 0))
            def data_received(self, data):
                self.data.extend(data)
                if mode == "q" and len(self.data) == 4:
                    assert self.data == b"\xff" * 4
                elif mode == "password" and len(self.data) >= 4 + len(b"quietQpassword\n"):
                    assert self.data[4:] == b"quietQpassword\n"
                elif mode == "ctrl_prompt" and len(self.data) == 8:
                    assert self.data == b"\xff" * 4 + b"\0" * 4
                else:
                    return
                if not stop_received.is_set():
                    stop_received.set()
                    self.transport.write(struct.pack("!BIi", 0, 4, 0 if mode == "password" else 130))
                    self.transport.close()
        servers = await start_serving_current_user_pipe(asyncio.get_running_loop(), Protocol, name)
        startup = subprocess.STARTUPINFO()
        startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startup.wShowWindow = 0
        env = dict(os.environ, PYTHONPATH=os.getcwd())
        process = await asyncio.create_subprocess_exec(
            sys.executable, str(script), name, mode, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NEW_CONSOLE,
            startupinfo=startup, env=env,
        )
        try:
            ready = await asyncio.wait_for(process.stdout.readline(), 5)
            assert ready.strip() == b"ready", (await process.stderr.read()).decode(errors="replace") if not ready else ready
            if mode != "q":
                assert (await asyncio.wait_for(process.stdout.readline(), 5)).strip() == b"prompt_ready"
            process.stdin.write(b"inject\n")
            await process.stdin.drain()
            await asyncio.wait_for(stop_received.wait(), 5)
            stdout, stderr = await asyncio.wait_for(process.communicate(), 5)
            assert process.returncode == 0, stderr.decode(errors="replace")
            assert (b"exit 0" if mode == "password" else b"exit 130") in stdout
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()
            for server in servers:
                server.close()
    asyncio.run(scenario())


class _AsyncWriter:
    def __init__(self, reader=None, input_line: bytes = b""):
        self.wire = bytearray()
        self.reader = reader
        self.input_line = input_line

    def write(self, data):
        self.wire.extend(data)
        if self.reader is not None and data[:1] == b"\x03":
            self.reader.feed_data(struct.pack("!I", len(self.input_line)) + self.input_line)

    async def drain(self):
        pass


def test_streaming_execute_uses_request_local_cwd_and_streams(tmp_path, monkeypatch):
    from sunpack.runtime.cli import cli

    async def fake_main(argv, **context):
        assert argv == ["config", "validate"]
        assert context["cwd"] == str(tmp_path)
        print(f"cwd={context['cwd']}", file=context["stdout"])
        print("warning", file=context["stderr"])
        return 7

    monkeypatch.setattr(cli, "async_main", fake_main)

    async def scenario():
        writer = _AsyncWriter()
        code = await persistent_process._execute_streaming_request_async(
            {"cwd": str(tmp_path), "argv": ["config", "validate"]},
            asyncio.StreamReader(),
            writer,
        )
        return code, bytes(writer.wire)

    exit_code, wire = asyncio.run(scenario())
    assert exit_code == 7
    assert f"cwd={tmp_path}".encode() in wire
    assert b"warning" in wire


def test_watch_stop_control_acknowledges_active_and_finished_batches(tmp_path, monkeypatch):
    # Transport framing tests do not exercise real host/coordinator rejection.
    # One in-process round trip covers absent/reloading Watch, expired batches,
    # repeated delivery and cleanup without launching an engine or another host.
    from types import SimpleNamespace
    from sunpack.runtime.cli import runtime_state
    from sunpack.runtime.cli.runtime_host import RuntimeHost
    from sunpack.runtime.watch.toast import WatchToastCoordinator
    from tests.helpers.config_factory import make_config

    snapshots, cancelled = [], []
    coordinator = WatchToastCoordinator(
        SimpleNamespace(publish=snapshots.append, clear=lambda: None),
        make_config(), str(tmp_path / 'state'),
    )
    host = RuntimeHost()
    current = None
    monkeypatch.setattr(runtime_state, 'runtime_host', lambda: current)

    async def send(argv):
        return await persistent_process._execute_streaming_request_async({'argv': argv}, None)

    async def scenario():
        nonlocal current
        assert await send(['--cancel-watch-batch']) == 2
        assert await send(['--cancel-watch-batch', 'obsolete']) == 1
        current = host
        assert await send(['--cancel-watch-batch', 'obsolete']) == 1
        service = SimpleNamespace(scheduler=None, toast_coordinator=coordinator)
        host._watch_service = service
        assert await send(['--cancel-watch-batch', 'obsolete']) == 1
        service.scheduler = SimpleNamespace(cancel_requests=cancelled.append)
        service.toast_coordinator = None
        assert await send(['--cancel-watch-batch', 'obsolete']) == 1
        service.toast_coordinator = coordinator
        coordinator.submitted('active', str(tmp_path / 'active.zip'))
        coordinator.submitted('scanning', str(tmp_path / 'scanning.zip'))
        coordinator.progress('active', SimpleNamespace(main_path='active.zip'), {
            'type': 'progress', 'event': 'extract_started',
        })
        batch_id = snapshots[-1].batch_id
        assert await send(['--cancel-watch-batch', 'obsolete']) == 0
        assert not cancelled and snapshots[-1].actions
        for _ in range(2):
            assert await send(['--cancel-watch-batch', batch_id]) == 0
            assert cancelled[-1] == ('active', 'scanning')
        assert not snapshots[-1].actions
        coordinator.interrupted('active', [])
        coordinator.interrupted('scanning', [])
        assert not snapshots[-1].actions
        assert await send(['--cancel-watch-batch', batch_id]) == 0
        coordinator._finalize(coordinator._finalize_generation)
        assert await send(['--cancel-watch-batch', batch_id]) == 0
        assert len(cancelled) == 2
        coordinator.submitted('next', str(tmp_path / 'next.zip'))
        coordinator.progress('next', SimpleNamespace(main_path='next.zip'), {
            'type': 'progress', 'event': 'extract_started',
        })
        assert await send(['--cancel-watch-batch', batch_id]) == 0
        assert snapshots[-1].actions and len(cancelled) == 2
        coordinator.stop()
        assert await send(['--cancel-watch-batch', batch_id]) == 1

    try:
        asyncio.run(scenario())
    finally:
        coordinator.stop()


def test_submit_request_strips_server_side_pause(tmp_path, monkeypatch):
    captured = {}
    request_cwd = os.getcwd()

    def fake_send(payload):
        captured.update(payload)
        captured["client_cwd"] = os.getcwd()
        return {"exit_code": 0, "stdout": "done\n", "stderr": ""}

    monkeypatch.setattr(persistent_process, "_send_or_start", fake_send)
    monkeypatch.setattr(persistent_process, "runtime_working_directory", lambda: str(tmp_path))
    monkeypatch.setattr(persistent_process.sys, "stdout", io.StringIO())
    monkeypatch.setattr(persistent_process.sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(persistent_process, "_client_supports_terminal_updates", lambda _stream: True)
    monkeypatch.setattr(persistent_process, "_client_terminal_columns", lambda _stream: 93)

    assert persistent_process.submit_request(["extract", "sample.zip", "--pause"]) == 0
    assert "--pause" not in captured["argv"]
    assert "--no-pause" in captured["argv"]
    assert captured["cwd"] == request_cwd
    assert captured["client_cwd"] == request_cwd
    assert captured["stdout_tty"] is True
    assert captured["stdout_columns"] == 93
    assert os.getcwd() == request_cwd
    assert persistent_process.sys.stdout.getvalue() == "done\n"


def test_submit_request_does_not_claim_unverified_terminal_updates(tmp_path, monkeypatch):
    captured = {}

    def fake_send(payload):
        captured.update(payload)
        return {"exit_code": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(persistent_process, "_send_or_start", fake_send)
    monkeypatch.setattr(persistent_process, "_client_supports_terminal_updates", lambda _stream: False)
    monkeypatch.setattr(persistent_process.sys.stdin, "isatty", lambda: False)

    assert persistent_process.submit_request(["extract", str(tmp_path / "sample.zip")]) == 0
    assert captured["stdout_tty"] is False


def test_extract_is_submitted_to_persistent_server_by_default(monkeypatch):
    from sunpack.runtime.cli import cli, runtime_state

    _enable_test_runtime_identity(monkeypatch)
    submitted = []
    monkeypatch.setattr(runtime_state, "server_runtime_active", lambda: False)
    monkeypatch.setattr(persistent_process, "submit_request", lambda argv: submitted.append(argv) or 6)

    assert cli.main(["extract", "sample.zip"]) == 6
    assert submitted == [["extract", "sample.zip"]]


def test_all_short_commands_are_submitted_to_persistent_server(monkeypatch):
    from sunpack.runtime.cli import cli, runtime_state

    _enable_test_runtime_identity(monkeypatch)
    submitted = []
    monkeypatch.setattr(runtime_state, "server_runtime_active", lambda: False)
    monkeypatch.setattr(persistent_process, "submit_request", lambda argv: submitted.append(argv) or 0)

    assert cli.main(["scan", "sample.zip"]) == 0
    assert cli.main(["watch", "status"]) == 0
    assert cli.main(["config", "validate"]) == 0
    assert submitted == [
        ["scan", "sample.zip"],
        ["watch", "status"],
        ["config", "validate"],
    ]


def test_extract_help_stays_local_and_does_not_start_server(monkeypatch):
    from sunpack.runtime.cli import cli

    monkeypatch.setattr(persistent_process, "submit_request", lambda _argv: (_ for _ in ()).throw(AssertionError()))

    assert cli.main(["extract", "--help"]) == 0


def test_streaming_request_forwards_output_before_final_result(monkeypatch):
    server, client = socket.socketpair()
    output = io.StringIO()
    error = io.StringIO()
    monkeypatch.setattr(persistent_process.sys, "stdout", output)
    monkeypatch.setattr(persistent_process.sys, "stderr", error)

    def send_frames():
        import struct

        server.sendall(struct.pack("!BI", 1, 4) + b"25%\n")
        server.sendall(struct.pack("!BI", 2, 5) + b"warn\n")
        server.sendall(struct.pack("!BIi", 0, 4, 7))
        server.close()

    thread = threading.Thread(target=send_frames)
    thread.start()
    try:
        response = persistent_process._recv_stream(client)
    finally:
        client.close()
        thread.join()

    assert response["exit_code"] == 7
    assert output.getvalue() == "25%\n"
    assert error.getvalue() == "warn\n"


def test_connection_stream_preserves_client_tty_capability():
    async def scenario():
        queue = persistent_process._ConnectionOutputQueue()
        stream = persistent_process._AsyncConnectionTextStream(
            asyncio.get_running_loop(), queue, 1, is_tty=True, terminal_columns=93
        )
        assert stream.isatty()
        assert stream.supports_terminal_updates
        assert stream.terminal_columns == 93
        assert stream.write("progress") == 8
        await asyncio.sleep(0)
        frame = await queue.get()
        kind, size = struct.unpack("!BI", frame[:5])
        assert (kind, size) == (1, 8)
        assert frame[5:] == b"progress"
    asyncio.run(scenario())


@pytest.mark.parametrize("disconnect", [False, True])
def test_large_unicode_stream_backpressure_and_disconnect(monkeypatch, disconnect):
    # Small frame tests miss oversized writes, split UTF-8 and producers parked
    # behind a slow/disconnected client. One real stream covers all three;
    # disconnect must release its producer without polling or leaked callbacks.
    from sunpack.pipeline.coordinator.async_work import AsyncWorkBroker

    text = "压缩😀" * 1_800_000  # One legal write exceeds the 16 MiB frame limit.

    async def scenario():
        entered = asyncio.Event()
        release = asyncio.Event()

        class SlowWriter(_AsyncWriter):
            async def drain(self):
                entered.set()
                await release.wait()

        writer = SlowWriter()
        connection = persistent_process._StreamRequestConnection(asyncio.StreamReader(), writer)
        await connection.start()
        queue = connection.output_queue
        stream = persistent_process._AsyncConnectionTextStream(asyncio.get_running_loop(), queue, 1)
        broker = AsyncWorkBroker()
        producer = asyncio.create_task(broker.run("cli_output", "", stream.write, text))
        try:
            await asyncio.wait_for(entered.wait(), 2)
            assert not producer.done()
            assert queue.buffered_bytes <= queue.max_bytes
            if disconnect:
                queue.close()
                connection._output_task.cancel()
                await asyncio.gather(connection._output_task, return_exceptions=True)
            else:
                release.set()
            assert await asyncio.wait_for(producer, 4) == len(text)
            if not disconnect:
                await connection.flush_output()
                await connection.send_frame(struct.pack("!BIi", 0, 4, 0))
                await connection.close()
            assert queue.empty()
            assert queue.buffered_bytes == 0
            return bytes(writer.wire)
        finally:
            release.set()
            queue.close()
            await broker.close()

    wire = asyncio.run(scenario())
    if not disconnect:
        class Connection:
            def __init__(self):
                self.data = io.BytesIO(wire)

            def recv(self, size):
                return self.data.read(size)

        output = io.StringIO()
        monkeypatch.setattr(persistent_process.sys, "stdout", output)
        assert persistent_process._recv_stream(Connection())["exit_code"] == 0
        assert output.getvalue() == text


def test_progress_never_waits_for_a_reporter_parked_on_output():
    # A bounded queue alone deadlocks if native progress on the loop acquires a
    # lock held by a blocked report writer. Ordinary stream tests use no shared
    # reporter, so this is independent lifecycle coverage at negligible cost.
    from types import SimpleNamespace
    from sunpack.pipeline.coordinator.reporting import RunReporter

    async def scenario():
        held = asyncio.Event()
        release = threading.Event()
        reporter = RunReporter(stdout=io.StringIO())
        task = SimpleNamespace(main_path="archive.bin", logical_name="archive.bin")
        reporter.tasks_discovered(1, [task])
        loop = asyncio.get_running_loop()

        def report_thread():
            with reporter._lock:
                loop.call_soon_threadsafe(held.set)
                assert release.wait(2), "progress blocked the loop behind the report lock"

        writer = asyncio.create_task(asyncio.to_thread(report_thread))
        try:
            await held.wait()
            reporter.task_progress(task, {"type": "progress", "completed_bytes": 1, "total_bytes": 2})
        finally:
            release.set()
            await writer

    asyncio.run(scenario())


def test_streaming_request_strips_terminal_columns_metadata(monkeypatch):
    from sunpack.runtime.cli import cli

    async def fake_main(argv, **context):
        assert argv == ["extract", "sample.zip"]
        assert context["stdout"].terminal_columns == 79
        return 0

    monkeypatch.setattr(cli, "async_main", fake_main)

    async def scenario():
        return await persistent_process._execute_streaming_request_async(
            {
                "argv": ["extract", "sample.zip", "--_sunpack-terminal-columns=79"],
                "stdout_tty": True,
            },
            asyncio.StreamReader(),
            _AsyncWriter(),
        )

    assert asyncio.run(scenario()) == 0


def test_streaming_request_returns_help_through_the_request_stream():
    async def scenario():
        writer = _AsyncWriter()
        code = await persistent_process._execute_streaming_request_async(
            {"argv": ["--help"]},
            asyncio.StreamReader(),
            writer,
        )
        return code, bytes(writer.wire)

    code, wire = asyncio.run(scenario())
    assert code == 0
    assert b"extract" in wire


def test_streaming_request_round_trips_interactive_input(monkeypatch):
    from sunpack.runtime.cli import cli

    async def fake_main(_argv, **context):
        return 0 if (await context["input_reader"]("password: ")).strip() == "secret" else 1

    monkeypatch.setattr(cli, "async_main", fake_main)

    async def scenario():
        reader = asyncio.StreamReader()
        writer = _AsyncWriter(reader, b"secret\n")
        code = await persistent_process._execute_streaming_request_async(
            {"argv": ["extract"], "stdin_tty": True}, reader, writer
        )
        return code, bytes(writer.wire)

    code, wire = asyncio.run(scenario())
    assert code == 0
    # A client blocks on the input request, so it must receive the prompt first.
    prompt = b"password: "
    assert wire == struct.pack("!BI", 1, len(prompt)) + prompt + struct.pack("!BI", 3, 0)


def test_try_send_does_not_request_replay_after_submission_disconnect(tmp_path, monkeypatch):
    token = b"t" * 32

    class DroppedConnection:
        def __init__(self):
            self.sent = []
            self.closed = False

        def sendall(self, data):
            self.sent.append(bytes(data))

        def recv(self, _size):
            return b""

        def close(self):
            self.closed = True

    connection = DroppedConnection()
    monkeypatch.setattr(
        persistent_process,
        "_read_state",
        lambda: (r"\\.\pipe\SunPack-test", token),
    )
    monkeypatch.setattr(persistent_process, "_open_pipe", lambda _name: connection)
    monkeypatch.setattr(persistent_process, "_runtime_binary_build_id", lambda: b"build-id")

    response = persistent_process._try_send({
        "cwd": str(tmp_path),
        "argv": ["extract", "sample.zip"],
    })

    assert response is not None
    assert response["exit_code"] == 1
    assert connection.sent
    assert connection.sent[0].startswith(persistent_process._REQUEST_MAGIC)
    assert connection.closed is True


def test_shutdown_does_not_start_a_missing_server(monkeypatch):
    monkeypatch.setattr(persistent_process, "_try_send", lambda payload: None)

    response = persistent_process._send_or_start({"shutdown": True})

    assert response["exit_code"] == 0


def test_server_idle_shutdown_requires_completed_request_and_idle_runtime():
    assert not persistent_process._idle_shutdown_due(
        served_request=False,
        last_completed_at=10.0,
        idle_seconds=5.0,
        runtime_idle=True,
        now=20.0,
    )
    assert not persistent_process._idle_shutdown_due(
        served_request=True,
        last_completed_at=10.0,
        idle_seconds=5.0,
        runtime_idle=False,
        now=20.0,
    )
    assert not persistent_process._idle_shutdown_due(
        served_request=True,
        last_completed_at=10.0,
        idle_seconds=5.0,
        runtime_idle=True,
        now=14.9,
    )
    assert persistent_process._idle_shutdown_due(
        served_request=True,
        last_completed_at=10.0,
        idle_seconds=5.0,
        runtime_idle=True,
        now=15.0,
    )


def test_idle_shutdown_monitor_waits_for_events_and_one_deadline():
    async def scenario():
        shutdown = asyncio.Event()
        state_changed = asyncio.Event()
        state = {
            "served": False,
            "last_completed": time.monotonic(),
            "active": 0,
            "exit_reason": "shutdown",
        }
        task = asyncio.create_task(
            persistent_process._monitor_idle_shutdown(
                shutdown=shutdown,
                state_changed=state_changed,
                state=state,
                watch_active=lambda: False,
                idle_seconds=lambda: 0.02,
                runtime_idle=lambda: True,
            )
        )
        await asyncio.sleep(0.03)
        assert not shutdown.is_set()

        state["served"] = True
        state["last_completed"] = time.monotonic()
        state_changed.set()
        await asyncio.wait_for(shutdown.wait(), timeout=0.5)
        await task

        assert state["exit_reason"] == "idle_timeout"

    asyncio.run(scenario())


def test_idle_shutdown_monitor_cancels_deadline_when_runtime_becomes_busy():
    async def scenario():
        shutdown = asyncio.Event()
        state_changed = asyncio.Event()
        state = {
            "served": True,
            "last_completed": time.monotonic(),
            "active": 0,
            "exit_reason": "shutdown",
        }
        task = asyncio.create_task(
            persistent_process._monitor_idle_shutdown(
                shutdown=shutdown,
                state_changed=state_changed,
                state=state,
                watch_active=lambda: False,
                idle_seconds=lambda: 0.04,
                runtime_idle=lambda: True,
            )
        )
        await asyncio.sleep(0.01)
        state["active"] = 1
        state_changed.set()
        await asyncio.sleep(0.05)
        assert not shutdown.is_set()

        state["active"] = 0
        state["last_completed"] = time.monotonic()
        state_changed.set()
        await asyncio.wait_for(shutdown.wait(), timeout=0.5)
        await task

    asyncio.run(scenario())


def test_pipe_server_cleanup_only_requires_close():
    closed = []

    class FakePipeServer:
        def close(self):
            closed.append(True)

    persistent_process._close_pipe_servers([FakePipeServer()])

    assert closed == [True]


def test_state_cleanup_only_removes_owned_server_state(tmp_path, monkeypatch):
    state = tmp_path / "runtime.state"
    token = b"a" * 32
    name = r"\\.\pipe\SunPack-test"
    monkeypatch.setattr(persistent_process, "state_path", lambda: str(state))

    persistent_process._write_state(name, token)
    assert not persistent_process._remove_state_if_owned(r"\\.\pipe\SunPack-other", token)
    assert state.exists()
    assert not persistent_process._remove_state_if_owned(name, b"b" * 32)
    assert state.exists()
    assert persistent_process._remove_state_if_owned(name, token)
    assert not state.exists()


def _prepare_server_publication_test(tmp_path, monkeypatch):
    from sunpack.core.platform.windows import process_job
    from sunpack.runtime.cli import persistent_runtime, runtime_host, runtime_state

    _enable_test_runtime_identity(monkeypatch)
    state = tmp_path / "runtime.state"
    old_name = r"\\.\pipe\SunPack-v2-0123456789abcdef-old"
    old_token = b"a" * 32
    new_token = b"b" * 32
    closed = []

    monkeypatch.setattr(persistent_process, "state_path", lambda: str(state))
    monkeypatch.setattr(persistent_process, "_runtime_binary_build_id", lambda: b"0123456789abcdef")
    monkeypatch.setattr(persistent_process, "_acquire_server_lock", lambda: io.BytesIO())
    monkeypatch.setattr(secrets, "token_bytes", lambda _size: new_token)
    monkeypatch.setattr(secrets, "token_hex", lambda _size: "c" * 32)
    monkeypatch.setattr(persistent_runtime, "enable_persistent_runtime", lambda **_kwargs: None)
    monkeypatch.setattr(persistent_runtime, "persistent_runtime_is_idle", lambda: True)
    monkeypatch.setattr(persistent_runtime, "persistent_server_idle_seconds", lambda: 15.0)
    monkeypatch.setattr(runtime_state, "set_runtime_host", lambda _host: None)
    monkeypatch.setattr(process_job, "close_child_job", lambda: None)

    async def close_runtime():
        closed.append("runtime")

    class FakeHost:
        watch_enabled = False

        def __init__(self, **_kwargs):
            pass

        async def close(self, **_kwargs):
            closed.append("host")

    monkeypatch.setattr(persistent_runtime, "close_persistent_runtime", close_runtime)
    monkeypatch.setattr(runtime_host, "RuntimeHost", FakeHost)
    persistent_process._write_state(old_name, old_token)
    return state, old_name, new_token, closed


def test_server_publishes_fresh_endpoint_before_it_can_accept_clients(tmp_path, monkeypatch):
    from sunpack.core.platform.windows import secure_pipe

    state, old_name, new_token, closed = _prepare_server_publication_test(tmp_path, monkeypatch)
    published = []

    class FakePipeServer:
        def close(self):
            published.append("closed")

    async def expose_pipe(_loop, protocol_factory, name):
        assert name != old_name
        assert name.endswith("-" + "c" * 32)
        assert persistent_process._read_state() == (name, new_token)
        protocol = protocol_factory()
        assert protocol._token == new_token
        published.append(name)
        protocol._on_shutdown()
        return [FakePipeServer()]

    monkeypatch.setattr(secure_pipe, "start_serving_current_user_pipe", expose_pipe)

    assert asyncio.run(persistent_process.run_server()) == 0
    assert published == [persistent_process.pipe_name() + "-" + "c" * 32, "closed"]
    assert not state.exists()
    assert closed == ["host", "runtime"]


def test_server_removes_published_state_if_pipe_creation_fails(tmp_path, monkeypatch):
    from sunpack.core.platform.windows import secure_pipe

    state, old_name, new_token, closed = _prepare_server_publication_test(tmp_path, monkeypatch)

    async def fail_to_expose_pipe(_loop, _protocol_factory, name):
        assert name != old_name
        assert persistent_process._read_state() == (name, new_token)
        raise OSError("pipe creation failed")

    monkeypatch.setattr(secure_pipe, "start_serving_current_user_pipe", fail_to_expose_pipe)

    assert asyncio.run(persistent_process.run_server()) == 1
    assert not state.exists()
    assert closed == ["host", "runtime"]


def test_competing_server_waits_for_owner_endpoint_before_exiting(tmp_path):
    """Single-process publication tests miss a losing server exiting too early.

    Two real processes and pipe gates cover that handoff without a speed
    threshold; the queue/exit timeouts only guard a broken handshake.
    """
    import queue
    import subprocess
    import sys
    from pathlib import Path

    script = r'''
import asyncio, contextlib, sys
from sunpack.core.support.runtime_identity import set_runtime_id
from sunpack.runtime.cli import persistent_process as runtime
from sunpack.core.platform.windows import file_mutex, secure_pipe
role, path, identity = sys.argv[1:]
set_runtime_id(identity)
runtime.state_path = lambda: path
acquire = runtime._acquire_server_lock
def observed_acquire():
    owner = acquire()
    if role == "owner":
        assert owner is not None
        print("OWNED", flush=True)
        assert sys.stdin.readline().strip() == "publish"
    elif owner is None:
        endpoint = runtime._read_state()
        connection = runtime._open_pipe(endpoint[0]) if endpoint else None
        print("OWNER_READY=" + str(connection is not None), flush=True)
        if connection is not None:
            connection.close()
    return owner
runtime._acquire_server_lock = observed_acquire
if role == "contender":
    gate = file_mutex.file_mutex
    @contextlib.contextmanager
    def observed_gate(*args, **kwargs):
        print("ENTERING", flush=True)
        with gate(*args, **kwargs):
            yield
    file_mutex.file_mutex = observed_gate
else:
    expose = secure_pipe.start_serving_current_user_pipe
    async def ready(loop, factory, name):
        servers = await expose(loop, factory, name)
        async def stop():
            assert (await asyncio.to_thread(sys.stdin.readline)).strip() == "stop"
            factory()._on_shutdown()
        asyncio.create_task(stop())
        print("READY", flush=True)
        return servers
    secure_pipe.start_serving_current_user_pipe = ready
raise SystemExit(asyncio.run(runtime.run_server()))
'''
    identity = "v2-" + secrets.token_hex(8)
    children = []
    readers = []

    def start(role):
        process = subprocess.Popen(
            [sys.executable, "-c", script, role, str(tmp_path / "runtime.state"), identity],
            cwd=Path(__file__).resolve().parents[2], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8",
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        children.append(process)
        messages = queue.Queue()
        def read():
            for line in process.stdout:
                messages.put(line.strip())
            messages.put(None)
        reader = threading.Thread(target=read, daemon=True)
        reader.start()
        readers.append(reader)
        return process, messages

    try:
        owner, owner_messages = start("owner")
        assert owner_messages.get(timeout=10) == "OWNED"
        contender, contender_messages = start("contender")
        # The old implementation first reports OWNER_READY=False. Release the
        # owner on either event, so both versions finish and yield real evidence.
        first = contender_messages.get(timeout=10)
        owner.stdin.write("publish\n")
        owner.stdin.flush()
        assert owner_messages.get(timeout=10) == "READY"
        evidence = contender_messages.get(timeout=10) if first == "ENTERING" else first
        assert contender.wait(timeout=10) == 0
        assert evidence == "OWNER_READY=True"
        owner.stdin.write("stop\n")
        owner.stdin.flush()
        assert owner.wait(timeout=10) == 0
    finally:
        for process in children:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)
            process.stdin.close()
        for reader in readers:
            reader.join(timeout=10)
        for process in children:
            process.stdout.close()
            process.stderr.close()


def test_protocol_incrementally_parses_a_fragmented_request(monkeypatch):
    captured = {}
    completed = []

    class Transport:
        def __init__(self):
            self.wire = bytearray()
            self.closed = False

        def write(self, data):
            self.wire.extend(data)

        def get_write_buffer_size(self):
            return 0

        def close(self):
            self.closed = True

    async def fake_execute(payload, _connection):
        captured.update(payload)
        return 9

    monkeypatch.setattr(persistent_process, "_execute_streaming_request_async", fake_execute)
    token = b"t" * 32

    async def scenario():
        protocol = persistent_process._PipeRequestProtocol(
            token,
            on_connected=lambda: None,
            on_closed=lambda: None,
            on_completed=lambda: completed.append(True),
            on_shutdown=lambda: None,
        )
        transport = Transport()
        protocol.connection_made(transport)
        cwd = b"C:\\work"
        argv = [b"scan", b"archive.zip"]
        wire = bytearray(persistent_process._REQUEST_MAGIC)
        wire.extend(persistent_process._runtime_binary_build_id())
        wire.extend(token)
        wire.extend(struct.pack("!III", 6, len(cwd), len(argv)))
        wire.extend(cwd)
        for item in argv:
            wire.extend(struct.pack("!I", len(item)))
            wire.extend(item)
        for index in range(0, len(wire), 3):
            protocol.data_received(bytes(wire[index:index + 3]))
        assert protocol._request_task is not None
        await protocol._request_task
        return bytes(transport.wire), transport.closed

    wire, closed = asyncio.run(scenario())
    assert captured == {
        "argv": ["scan", "archive.zip"],
        "cwd": "C:\\work",
        "shutdown": False,
        "stdout_tty": True,
        "stdin_tty": True,
    }
    assert wire == (
        persistent_process._STREAM_MAGIC
        + persistent_process._runtime_binary_build_id()
        + struct.pack("!BIi", 0, 4, 9)
    )
    assert completed == [True]
    assert closed


@pytest.mark.parametrize("disconnect_phase", ["queued", "flushing", "write_error", "finishing"])
def test_protocol_disconnect_releases_request_and_discards_late_output(monkeypatch, disconnect_phase):
    from sunpack.runtime.cli import cli
    from sunpack.runtime.cli.runtime_host import RuntimeHost
    from sunpack.runtime.cli.runtime_state import set_runtime_host

    async def scenario():
        host = RuntimeHost()
        set_runtime_host(host)
        entered = asyncio.Event()
        parked = asyncio.Event()
        streams = []
        completed = []
        closed = []
        disconnected = asyncio.Event()
        finishing = asyncio.Event()
        finish_foreground = host.foreground_finished

        async def foreground_finished():
            finishing.set()
            await finish_foreground()

        monkeypatch.setattr(host, "foreground_finished", foreground_finished)

        def on_closed():
            closed.append(True)
            disconnected.set()

        protocol = persistent_process._PipeRequestProtocol(
            b"t" * 32,
            on_connected=lambda: None,
            on_closed=on_closed,
            on_completed=lambda: completed.append(True),
            on_shutdown=lambda: None,
        )

        class Transport:
            def write(self, _data):
                if disconnect_phase == "write_error":
                    raise BrokenPipeError("client disconnected")

            def get_write_buffer_size(self):
                return 300000 if disconnect_phase == "flushing" else 0

            def close(self):
                if disconnect_phase == "write_error":
                    asyncio.get_running_loop().call_soon(protocol.connection_lost, None)

        async def command(*_args, stdout, **_kwargs):
            streams.append(stdout)
            stdout.write("progress 1\n")
            stdout.write("progress 2\n")
            entered.set()
            if disconnect_phase == "finishing":
                await host._foreground_state_lock.acquire()
                return 0
            if disconnect_phase == "flushing":
                await protocol.flush_output()
            await parked.wait()

        monkeypatch.setattr(cli, "async_main", command)
        protocol.connection_made(Transport())
        if disconnect_phase == "flushing":
            protocol.pause_writing()
        request = protocol._request_task = asyncio.create_task(protocol._run_request({
            "cwd": os.getcwd(), "argv": ["extract"],
        }))
        try:
            await asyncio.wait_for(entered.wait(), 1)
            # queued covers writes already scheduled on the loop; flushing
            # covers a frame held by transport backpressure plus queued frames.
            if disconnect_phase == "write_error":
                await asyncio.wait_for(disconnected.wait(), 1)
            else:
                if disconnect_phase == "finishing":
                    await asyncio.wait_for(finishing.wait(), 1)
                protocol.connection_lost(None)
                if disconnect_phase == "finishing":
                    host._foreground_state_lock.release()
            streams[0].write("late loop output\n")
            await asyncio.to_thread(streams[0].write, "late worker output\n")
            result = await asyncio.wait_for(asyncio.gather(request, return_exceptions=True), 1)
            if disconnect_phase == "finishing":
                assert result[0] is None
            else:
                assert isinstance(result[0], asyncio.CancelledError)
            await asyncio.gather(protocol._output_task, return_exceptions=True)
            await asyncio.sleep(0)
            await asyncio.wait_for(protocol.flush_output(), 1)
            assert protocol.output_queue.empty()
            assert host._foreground_requests == 0
            assert not host._foreground_gate_requested
            assert closed == [True]
            assert completed == ([True] if disconnect_phase == "finishing" else [])
            # The shared host must still admit and release the next request.
            await host.foreground_started()
            await host.foreground_finished()
            assert host._foreground_requests == 0
            assert not host._foreground_gate_requested
        finally:
            if host._foreground_state_lock.locked():
                host._foreground_state_lock.release()
            request.cancel()
            protocol._output_task.cancel()
            await asyncio.gather(request, protocol._output_task, return_exceptions=True)
            set_runtime_host(None)

    asyncio.run(scenario())


def test_protocol_rejects_a_different_runtime_build_id():
    token = b"t" * 32

    async def scenario():
        protocol = persistent_process._PipeRequestProtocol(
            token,
            on_connected=lambda: None,
            on_closed=lambda: None,
            on_completed=lambda: None,
            on_shutdown=lambda: None,
        )

        class Transport:
            def __init__(self):
                self.closed = False

            def write(self, _data):
                pass

            def get_write_buffer_size(self):
                return 0

            def close(self):
                self.closed = True

        transport = Transport()
        protocol.connection_made(transport)
        build = b"X" * len(persistent_process._runtime_binary_build_id())
        protocol.data_received(
            persistent_process._REQUEST_MAGIC + build + token + struct.pack("!III", 0, 0, 0)
        )
        await asyncio.sleep(0)
        return transport.closed, protocol._request_task

    closed, task = asyncio.run(scenario())
    assert closed is True
    assert task is None


def test_persistent_config_snapshot_reuses_a_source_without_mtime_checks(tmp_path, monkeypatch):
    from sunpack.runtime.cli import persistent_runtime

    calls = []
    sources = {
        "first": (str(tmp_path / "first.json"), None, None),
        "second": (str(tmp_path / "second.json"), None, None),
    }

    monkeypatch.setattr(persistent_runtime, "config_source_key", lambda cwd=None: sources[str(cwd)])
    monkeypatch.setattr(
        persistent_runtime,
        "load_raw_config_payload",
        lambda cwd=None: (tmp_path / f"{cwd}.json", {"cli": {"language": str(cwd)}}),
    )

    def load_config(cwd=None):
        calls.append(str(cwd))
        return {"cli": {"language": str(cwd)}, "output": {"root": str(cwd)}}

    monkeypatch.setattr(persistent_runtime, "load_config", load_config)

    async def scenario():
        await persistent_runtime.close_persistent_runtime()
        persistent_runtime.enable_persistent_runtime()
        first = persistent_runtime.load_request_config("first")
        first["cli"]["language"] = "mutated"
        assert persistent_runtime.load_request_config("first")["cli"]["language"] == "first"
        assert persistent_runtime.load_request_config("second")["cli"]["language"] == "second"
        await persistent_runtime.close_persistent_runtime()

    asyncio.run(scenario())
    assert calls == ["first", "second"]


def test_external_config_sources_reload_between_requests_and_evict_watches(tmp_path, monkeypatch):
    """Cover real request-source events and bounded watch lifetime together.

    Fixed-directory/fake-snapshot tests miss external override updates. This
    single event-driven case also catches observer retention after LRU eviction.
    """
    import json
    from sunpack.runtime.cli import persistent_runtime as runtime

    async def scenario():
        await runtime.close_persistent_runtime()
        reloaded = asyncio.Event()
        changed = runtime._configuration_files_changed
        monkeypatch.setattr(runtime, "_configuration_files_changed", lambda: (changed(), reloaded.set()))
        monkeypatch.setattr(runtime, "_CONFIG_SNAPSHOT_LIMIT", 1)
        first_dir, second_dir = tmp_path / "external-one", tmp_path / "external-two"
        first_dir.mkdir(); second_dir.mkdir()
        first, second = first_dir / "override.json", second_dir / "override.json"
        first.write_text(json.dumps({"post_extract": {"archive_cleanup_mode": "k"}}), encoding="utf-8")
        second.write_text(json.dumps({"post_extract": {"archive_cleanup_mode": "r"}}), encoding="utf-8")
        monkeypatch.setenv("SUNPACK_CONFIG_OVERRIDES", str(first))
        runtime.enable_persistent_runtime()
        runtime._CONFIG_OBSERVER.debounce_seconds = 0
        try:
            assert runtime.load_request_config()["post_extract"]["archive_cleanup_mode"] == "keep"
            replacement = first_dir / "replacement.json"
            replacement.write_text(json.dumps({"post_extract": {"archive_cleanup_mode": "d"}}), encoding="utf-8")
            replacement.replace(first)
            await asyncio.wait_for(reloaded.wait(), 3)
            assert runtime.load_request_config()["post_extract"]["archive_cleanup_mode"] == "delete"
            monkeypatch.setenv("SUNPACK_CONFIG_OVERRIDES", str(second))
            assert runtime.load_request_config()["post_extract"]["archive_cleanup_mode"] == "recycle"
            assert first_dir.resolve() not in runtime._CONFIG_OBSERVER._directories
        finally:
            await runtime.close_persistent_runtime()
    asyncio.run(scenario())


def test_server_process_starts_in_neutral_working_directory(tmp_path, monkeypatch):
    _enable_test_runtime_identity(monkeypatch)
    captured = {}
    attempts = iter([None, {"exit_code": 0, "stdout": "", "stderr": ""}])

    monkeypatch.setattr(persistent_process, "_try_send", lambda _payload: next(attempts))
    monkeypatch.setattr(persistent_process, "runtime_working_directory", lambda: str(tmp_path))
    monkeypatch.setattr("subprocess.Popen", lambda *args, **kwargs: captured.update(kwargs))

    response = persistent_process._send_or_start({"argv": ["extract", "sample.zip"]})

    assert response["exit_code"] == 0
    assert captured["cwd"] == str(tmp_path)


def test_persistent_runtime_reuses_engine_for_request_only_config(monkeypatch):
    from sunpack.runtime.cli import persistent_runtime

    events = []
    callbacks = []

    class FakeEngine:
        work_broker = None
        def __init__(self, config):
            self.config = config
            events.append(("init", config["output"]["root"]))

        async def __aenter__(self):
            events.append(("start",))
            return self

        def is_idle(self):
            return True

        def reconfigure_request(self, config):
            self.config = config
            events.append(("reconfigure", config["output"]["root"]))

        def set_state_changed_callback(self, callback):
            callbacks.append(callback)

        async def aclose(self, *, graceful=True):
            events.append(("close", graceful))

    monkeypatch.setattr(persistent_runtime, "PipelineEngine", FakeEngine)
    monkeypatch.setattr(persistent_runtime, "config_source_key", lambda: ("same", None, None))
    first = {
        "output": {"root": "one", "common_root": "a"},
        "cli": {"quiet": True},
        "performance": {"persistent_server_idle_seconds": 3},
    }
    second = {
        "output": {"root": "two", "common_root": "b"},
        "cli": {"quiet": False},
        "performance": {"persistent_server_idle_seconds": 9},
    }
    async def scenario():
        await persistent_runtime.close_persistent_runtime()

        def state_changed():
            pass

        persistent_runtime.enable_persistent_runtime(state_changed=state_changed)
        async with persistent_runtime.pipeline_engine(first) as first_engine:
            pass
        async with persistent_runtime.pipeline_engine(second) as second_engine:
            pass
        assert first_engine is second_engine
        assert events[:2] == [("init", "one"), ("start",)]
        assert ("reconfigure", "two") in events
        assert persistent_runtime.persistent_runtime_is_idle()
        assert persistent_runtime.persistent_server_idle_seconds() == 9
        assert callbacks == [state_changed]
        await persistent_runtime.close_persistent_runtime()
        assert callbacks[-1] is None

    asyncio.run(scenario())


def test_persistent_runtime_concurrent_first_requests_share_worker_and_outputs(tmp_path):
    from sunpack.runtime.cli import persistent_runtime
    from tests.helpers.config_factory import make_config

    async def scenario():
        await persistent_runtime.close_persistent_runtime()
        persistent_runtime.enable_persistent_runtime()
        engines = []
        try:
            config = make_config()
            engines = await asyncio.gather(
                persistent_runtime.shared_pipeline_engine(config),
                persistent_runtime.shared_pipeline_engine(config),
            )
            assert engines[0] is engines[1]
            worker = engines[0]._services.sevenzip_runner._async_worker_holder._worker
            assert worker.is_alive()
            output = str(tmp_path / "shared")
            reserved = [
                engine._services.output_reservations.reserve(output, str(index), set())
                for index, engine in enumerate(engines)
            ]
            assert reserved == [output, str(tmp_path / "shared(1)")]
            await persistent_runtime.close_persistent_runtime()
            assert not worker.is_alive()
        finally:
            await persistent_runtime.close_persistent_runtime()
            # Also clean up orphaned engines when this regression fails.
            for engine in engines:
                await engine.aclose(graceful=True)

    asyncio.run(scenario())


@pytest.mark.parametrize("interruption", ["error", "cancel", "shutdown"])
def test_persistent_runtime_interrupted_initialization_releases_owner(monkeypatch, interruption):
    from sunpack.runtime.cli import persistent_runtime

    async def scenario():
        await persistent_runtime.close_persistent_runtime()
        entered = asyncio.Event()
        release = asyncio.Event()
        created = []

        class FakeEngine:
            work_broker = None
            def __init__(self, config):
                self.closed = False
                self.callback = None
                created.append(self)

            async def __aenter__(self):
                if self is created[0]:
                    entered.set()
                    await release.wait()
                    if interruption == "error":
                        raise RuntimeError("startup failed")
                return self

            def set_state_changed_callback(self, callback):
                self.callback = callback

            def reconfigure_request(self, config):
                pass

            async def aclose(self, *, graceful=True):
                self.closed = True

        monkeypatch.setattr(persistent_runtime, "PipelineEngine", FakeEngine)
        persistent_runtime.enable_persistent_runtime(state_changed=lambda: None)
        requests = []
        closing = None
        try:
            first = asyncio.create_task(persistent_runtime.shared_pipeline_engine({}))
            requests.append(first)
            await entered.wait()
            waiting = asyncio.create_task(persistent_runtime.shared_pipeline_engine({}))
            requests.append(waiting)
            await asyncio.sleep(0)
            assert len(created) == 1
            if interruption == "shutdown":
                closing = asyncio.create_task(persistent_runtime.close_persistent_runtime())
                await asyncio.sleep(0)
            elif interruption == "cancel":
                first.cancel()
            release.set()
            outcomes = await asyncio.wait_for(
                asyncio.gather(*requests, return_exceptions=True), timeout=2,
            )
            assert created[0].closed and created[0].callback is None
            if closing is not None:
                await closing
                assert all(isinstance(outcome, RuntimeError) for outcome in outcomes)
                assert persistent_runtime.current_pipeline_engine() is None
                assert len(created) == 1
            else:
                expected = asyncio.CancelledError if interruption == "cancel" else RuntimeError
                assert isinstance(outcomes[0], expected)
                assert outcomes[1] is persistent_runtime.current_pipeline_engine()
                assert len(created) == 2 and not created[1].closed
            await persistent_runtime.close_persistent_runtime()
            assert all(engine.closed and engine.callback is None for engine in created)
        finally:
            release.set()
            await asyncio.gather(*requests, return_exceptions=True)
            if closing is not None:
                await closing
            await persistent_runtime.close_persistent_runtime()

    asyncio.run(scenario())


def test_cli_password_snapshot_hot_updates_without_watch_or_request_io(tmp_path, monkeypatch):
    # Unique coverage: the CLI-only server observes JSON events, pins requests and releases its observer.
    import sunpack.core.passwords.internal.builtin as builtin
    from sunpack.runtime.cli import persistent_runtime
    from tests.helpers.passwords import write_password_json
    path = tmp_path / "builtin_passwords.json"
    write_password_json(path, ["before"])
    monkeypatch.setattr(builtin, "builtin_password_path", lambda: path)
    async def scenario():
        await persistent_runtime.close_persistent_runtime()
        persistent_runtime.enable_persistent_runtime()
        source = builtin.password_file_source()
        changed = asyncio.Event()
        loop = asyncio.get_running_loop()
        reload = source.reload
        def observed_reload():
            previous = source.snapshot
            updated = reload()
            if updated is not previous:
                loop.call_soon_threadsafe(changed.set)
            return updated
        monkeypatch.setattr(source, "reload", observed_reload)
        reads = []
        read = builtin.read_shared_utf8_text
        def record(*args, **kwargs):
            reads.append(args[0])
            return read(*args, **kwargs)
        monkeypatch.setattr(builtin, "read_shared_utf8_text", record)
        try:
            pinned = persistent_runtime.load_request_config()["password_snapshot"]
            persistent_runtime.load_request_config()
            assert reads == []
            temp = path.with_suffix(".tmp")
            write_password_json(temp, ["after"])
            temp.replace(path)
            await asyncio.wait_for(changed.wait(), 5)
            assert pinned.global_passwords == ("before",)
            assert persistent_runtime.load_request_config()["password_snapshot"].global_passwords == ("after",)
            changed.clear()
            path.unlink()
            await asyncio.wait_for(changed.wait(), 5)
            assert not persistent_runtime.load_request_config()["password_snapshot"].global_passwords
            assert not path.exists()
        finally:
            await persistent_runtime.close_persistent_runtime()
        assert persistent_runtime._CONFIG_OBSERVER is None
        assert persistent_runtime._PASSWORD_RELOAD_TASK is None
    asyncio.run(scenario())





def test_runtime_startup_does_not_fail_because_elapsed_time_passes(monkeypatch, tmp_path):
    """Only process exit or transport failure, not an old 10s clock, decides startup."""
    _enable_test_runtime_identity(monkeypatch)

    class FakeProcess:
        def poll(self):
            return None

    replies = iter([None, None, None, {"exit_code": 0, "stdout": "", "stderr": ""}])
    ticks = iter([0.0, 1000.0, 2000.0, 3000.0])
    monkeypatch.setattr(persistent_process, "_try_send", lambda _payload: next(replies))
    monkeypatch.setattr(persistent_process, "server_command", lambda: ["unused"])
    monkeypatch.setattr(persistent_process, "runtime_working_directory", lambda: str(tmp_path))
    monkeypatch.setattr("subprocess.Popen", lambda *args, **kwargs: FakeProcess())
    # Simulate a clock advancing well beyond the removed 10s deadline.
    monkeypatch.setattr(persistent_process, "time", type("Clock", (), {
        "monotonic": staticmethod(lambda: next(ticks)),
        "sleep": staticmethod(lambda _seconds: None),
    })())
    assert persistent_process._send_or_start({"argv": ["extract", "test.zip"]})["exit_code"] == 0
