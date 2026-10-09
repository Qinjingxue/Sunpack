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
        return await persistent_process._execute_streaming_request_async(
            {"argv": ["extract"], "stdin_tty": True}, reader, writer
        )

    assert asyncio.run(scenario()) == 0


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
    persistent_runtime.enable_persistent_runtime()
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
