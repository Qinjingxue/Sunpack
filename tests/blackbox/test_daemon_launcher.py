import subprocess

import pytest

import json

import psutil

from tests.helpers.package import package


def test_daemon_stop_waits_and_absent_controls_do_not_start(package):
    # These controls must be safe without a daemon, unlike ordinary CLI commands.
    result = package.json('daemon', 'stop')
    assert result['summary'] == {'running': False}
    follow = package.run('--watch-status-follow')
    assert follow.returncode == 0 and not follow.stderr
    assert json.loads(follow.stdout) == {"running": False, "enabled": False, "phase": "stopped"}
    assert not list(package.data.glob('runtime-*.state'))

    assert package.json('config', 'show')['items']
    state, = package.data.glob('runtime-*.state')
    owner = psutil.Process(int(state.read_text(encoding='utf-8').splitlines()[3]))
    stopped = package.run('d', '-j', 'stop')
    assert stopped.returncode == 0, stopped.stderr
    assert json.loads(stopped.stdout)['summary'] == {'running': False}
    assert not owner.is_running(), 'daemon stop returned before runtime exited'
    assert not list(package.data.glob('runtime-*.state'))


def test_daemon_stop_waits_for_retiring_owner_lock(package):
    # The listener can disappear before the runtime releases its persistent
    # state lock. Holding that exact range makes the teardown boundary explicit.
    import msvcrt

    assert package.json("config", "show")["items"]
    state, = package.data.glob("runtime-*.state")
    assert package.run("daemon", "stop").returncode == 0
    with open(str(state) + ".lock", "r+b") as lock:
        lock.seek(1)
        msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        stopping = subprocess.Popen([str(package.launcher), "daemon", "stop", "--json"],
                                    cwd=package.data, env=package.env,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            with pytest.raises(subprocess.TimeoutExpired):
                stopping.wait(timeout=0.3)
        finally:
            lock.seek(1)
            msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
            output, error = stopping.communicate(timeout=15)
    assert stopping.returncode == 0, error
    assert json.loads(output)["summary"] == {"running": False}


def test_status_follow_does_not_report_unreachable_owner_as_stopped(package):
    import msvcrt

    assert package.json("config", "show")["items"]
    state, = package.data.glob("runtime-*.state")
    assert package.run("daemon", "stop").returncode == 0
    with open(str(state) + ".lock", "r+b") as lock:
        # Both a live listener and a retiring owner prevent a stopped verdict.
        for offset in (0, 1):
            lock.seek(offset)
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
            try:
                follow = package.run("--watch-status-follow", timeout=5)
                assert follow.returncode != 0
                assert not follow.stdout
            finally:
                lock.seek(offset)
                msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
    assert not list(package.data.glob("runtime-*.state"))
