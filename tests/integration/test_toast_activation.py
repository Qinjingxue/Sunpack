from __future__ import annotations

import asyncio
import secrets
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

from sunpack.core.platform.windows import toast_host
from sunpack.core.platform.windows.secure_pipe import start_serving_current_user_pipe
from sunpack.core.support import runtime_identity
from sunpack.pipeline.coordinator.async_work import CancellationToken
from sunpack.runtime.cli import persistent_process, runtime_state
from sunpack.runtime.cli.runtime_host import RuntimeHost
from sunpack.runtime.watch.toast import WatchToastCoordinator
from tests.helpers.config_factory import make_config


def test_activation_helper_routes_registered_identity_and_acknowledges_completion(tmp_path, monkeypatch):
    """Mocked send tests cannot catch a helper reading the wrong state namespace.

    One real child/pipe lifecycle covers identity forwarding, authenticated
    dispatch, debounce/finalization races and a stale click during a new batch.
    Native action delivery and the scheduler endpoint are substituted; state
    lookup and transport are real. Pipeline interruption has a separate test.
    """
    identity = "v2-0123456789abcdef"
    monkeypatch.setattr(runtime_identity, "_runtime_id", identity)
    monkeypatch.setattr(persistent_process, "writable_data_dir", lambda: tmp_path)
    monkeypatch.setattr(toast_host, "__compiled__", object(), raising=False)
    monkeypatch.setattr(toast_host, "current_process_executable", lambda: Path(sys.executable))
    executable, arguments = toast_host._activation_command()
    # The compiled helper command consists only of these whitespace-free flags.
    assert arguments == "--toast-activated " + runtime_identity.runtime_id_argument(identity)
    child_source = r'''
import sys
from pathlib import Path
from types import SimpleNamespace
from sunpack.core.platform.windows import toast_host
from sunpack.runtime.cli import persistent_process
from sunpack.runtime.entrypoint import main
state_dir, batch = Path(sys.argv.pop(1)), sys.argv.pop(1)
persistent_process.writable_data_dir = lambda: state_dir
def activated_batch(buffer, capacity):
    buffer.value = batch
    return 0
toast_host._load_library = lambda: SimpleNamespace(
    sunpack_toast_activate=lambda: 0, sunpack_toast_cancel_batch=activated_batch)
def unexpected_presenter(**kwargs):
    raise AssertionError('helper falsely reported failure')
toast_host._NativeToastPresenter = unexpected_presenter
raise SystemExit(main())
'''

    snapshots, cancelled = [], []
    token = CancellationToken()

    def cancel(requests):
        cancelled.append(requests)
        token.cancel()

    coordinator = WatchToastCoordinator(
        SimpleNamespace(publish=snapshots.append, clear=lambda: None),
        make_config({"watch": {"toast_completion_debounce_ms": 60_000}}),
        str(tmp_path / "reports"),
    )
    runtime = RuntimeHost()
    runtime._watch_service = SimpleNamespace(
        scheduler=SimpleNamespace(cancel_requests=cancel), toast_coordinator=coordinator,
    )
    monkeypatch.setattr(runtime_state, "runtime_host", lambda: runtime)

    async def scenario():
        protocols = []
        name = persistent_process.pipe_name() + "-toast-test-" + secrets.token_hex(8)
        secret = secrets.token_bytes(32)

        def factory():
            protocol = persistent_process._PipeRequestProtocol(
                secret, on_connected=lambda: None, on_closed=lambda: None,
                on_completed=lambda: None, on_shutdown=lambda: None,
            )
            protocols.append(protocol)
            return protocol

        servers = await start_serving_current_user_pipe(asyncio.get_running_loop(), factory, name)
        persistent_process._write_state(name, secret)

        async def click(batch):
            child = await asyncio.create_subprocess_exec(
                executable, "-c", child_source, str(tmp_path), batch,
                *arguments.split(), "-Embedding",
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            try:
                stdout, stderr = await asyncio.wait_for(child.communicate(), 10)
                assert child.returncode == 0, (stdout, stderr)
            finally:
                if child.returncode is None:
                    child.kill()
                    await child.wait()

        def submit(request):
            path = str(tmp_path / (request + ".blob"))
            coordinator.submitted(request, path)
            coordinator.progress(request, SimpleNamespace(main_path=path), {
                "type": "progress", "event": "extract_started",
            })

        try:
            submit("active")
            coordinator.submitted("scanning", str(tmp_path / "scanning.blob"))
            batch = snapshots[-1].batch_id
            actions = snapshots[-1].actions
            await click(batch)
            assert token.cancelled and cancelled == [("active", "scanning")]
            coordinator.interrupted("active", [])
            coordinator.interrupted("scanning", [])
            assert snapshots[-1].actions == actions
            await click(batch)  # Completion debounce has not fired.
            coordinator._finalize(coordinator._finalize_generation)
            submit("next")
            await click(batch)  # The old notification must not stop the new batch.
            assert len(cancelled) == 1 and snapshots[-1].actions
            assert len(protocols) == 3
        finally:
            coordinator.stop()
            persistent_process._close_pipe_servers(servers)
            for protocol in protocols:
                if protocol._transport is not None:
                    protocol._transport.close()
            tasks = [task for protocol in protocols
                     for task in (protocol._request_task, protocol._output_task) if task is not None]
            await asyncio.gather(*tasks, return_exceptions=True)

    asyncio.run(scenario())
