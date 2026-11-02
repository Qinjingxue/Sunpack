"""The lease test must report protocol failures and reap both subprocesses."""
import asyncio
import pytest

from tests.integration.test_watch_broker_service import _exercise_process_leases


@pytest.mark.parametrize("stage", ["first_ready", "second_ready", "pong", "bad_ready"])
def test_lease_test_cleans_up_when_a_child_does_not_complete_protocol(tmp_path, monkeypatch, stage):
    # Normal Broker roundtrips cannot detect a stuck handshake or an orphaned
    # first client when the second fails. Tiny disposable children cover both.
    marker = tmp_path / "started"
    helper = f'''
import pathlib, sys
marker = pathlib.Path({str(marker)!r})
second = marker.exists()
marker.touch()
stage = {stage!r}
if stage == "bad_ready":
    print("diagnostic", file=sys.stderr, flush=True)
    print("BAD", flush=True)
elif stage == "first_ready" or (stage == "second_ready" and second):
    sys.stdin.read()
else:
    print("READY", flush=True)
    for line in sys.stdin:
        if line.strip() == "exit":
            break
        if line.strip() == "ping" and stage != "pong":
            print("PONG", flush=True)
'''
    processes = []
    original = asyncio.create_subprocess_exec

    async def start(*args, **kwargs):
        process = await original(*args, **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", start)
    with pytest.raises(AssertionError):
        asyncio.run(_exercise_process_leases(helper, reply_timeout=1.0))
    assert len(processes) == (2 if stage in {"second_ready", "pong"} else 1)
    assert all(process.returncode is not None for process in processes)
