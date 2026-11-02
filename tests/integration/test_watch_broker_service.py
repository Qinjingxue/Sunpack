from __future__ import annotations

import os
import asyncio
import re
import statistics
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

import pytest


pytestmark = [
    pytest.mark.skipif(__import__("sys").platform != "win32", reason="Windows-only service test"),
    pytest.mark.requires_watch_broker,
]


def test_installed_broker_lifecycle_usn_roundtrip_and_hot_ipc(tmp_path):
    # A pytest worker can retain leases from other Watch tests. This contract
    # needs a process that owns exactly the acquire/release pair below.
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; from pathlib import Path; "
            "from tests.integration.test_watch_broker_service import _broker_lifecycle_roundtrip; "
            "_broker_lifecycle_roundtrip(Path(sys.argv[1]))",
            str(tmp_path),
        ],
        capture_output=True,
        cwd=Path(__file__).resolve().parents[2],
        text=True,
        check=False,
        timeout=30.0,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def _broker_lifecycle_roundtrip(tmp_path):
    import sunpack_native
    from sunpack.core.platform.windows.elevation import is_process_elevated

    is_elevated = is_process_elevated()

    archive = tmp_path / "broker-roundtrip.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as target:
        target.writestr("payload.bin", b"a" * 4096)

    cold_started = time.perf_counter()
    sunpack_native.watch_broker_acquire()
    cold_start_seconds = time.perf_counter() - cold_started
    try:
        assert cold_start_seconds < 2.0
        assert sunpack_native.watch_broker_is_connected()
        service_name = os.environ["SUNPACK_WATCH_BROKER_SERVICE_NAME"]
        assert service_name.startswith("SunPackWatchBrokerTest_")
        assert service_name != "SunPackWatchBroker"
        if not is_elevated:
            denied_stop = subprocess.run(
                ["sc.exe", "stop", service_name],
                capture_output=True,
                text=True,
                check=False,
            )
            assert denied_stop.returncode != 0
        sunpack_native.validate_ntfs_watch_root(str(tmp_path))
        # Ping reconnects automatically and previously hid lease loss on a
        # complete journal rejection. Check the connection and SCM identity
        # before issuing any request that could repair it.
        def broker_pid():
            result = subprocess.run(["sc.exe", "queryex", service_name],
                                    capture_output=True, text=True, check=True)
            return int(re.search(r"\bPID\s*:\s*(\d+)", result.stdout)[1])

        pid = broker_pid()
        volume, journal, start = sunpack_native.watch_volume_cursor(str(tmp_path))
        archive.touch()
        _, _, end = sunpack_native.watch_volume_cursor(str(tmp_path))
        assert end > start
        for expected_journal, previous in ((journal ^ 1, start), (journal, 1)):
            with pytest.raises(OSError):
                sunpack_native.watch_directories_changes([str(tmp_path)], volume, expected_journal, previous, end)
            assert sunpack_native.watch_broker_is_connected()
            assert broker_pid() == pid != 0
        sunpack_native.watch_directories_changes([str(tmp_path)], volume, journal, start, end)
        assert broker_pid() == pid
        baseline = sunpack_native.watch_candidate_for_path(str(archive), None)
        assert baseline is not None
        previous_usn = int(baseline["change_usn"])

        with archive.open("ab", buffering=0) as stream:
            stream.write(b"broker-usn-change")
        observed = sunpack_native.watch_candidate_for_path(str(archive), previous_usn)
        assert observed is not None
        assert int(observed["change_usn"]) > previous_usn
        assert observed["change_reasons_known"] is True
        assert int(observed["change_reasons"]) & 0x0000_0003

        samples = [float(sunpack_native.watch_broker_ping_seconds()) for _ in range(500)]
        ordered = sorted(samples)
        p95 = ordered[int((len(ordered) - 1) * 0.95)]
        assert statistics.median(samples) < 0.0005
        assert p95 < 0.001
    finally:
        sunpack_native.watch_broker_release()

    assert not sunpack_native.watch_broker_is_connected()
    # Unlike overlapping leases, short consecutive uses race service teardown
    # against the next SCM start/pipe connect. Keep this in the isolated process.
    for _ in range(16):
        sunpack_native.watch_broker_acquire()
        try:
            sunpack_native.watch_broker_ping_seconds()
        finally:
            sunpack_native.watch_broker_release()


_LEASE_HELPER = """
import sys
import sunpack_native
sunpack_native.watch_broker_acquire()
print('READY', flush=True)
try:
    for line in sys.stdin:
        command = line.strip()
        if command == 'ping':
            sunpack_native.watch_broker_ping_seconds()
            print('PONG', flush=True)
        elif command == 'exit':
            break
finally:
    sunpack_native.watch_broker_release()
"""

async def _exercise_process_leases(helper: str, *, reply_timeout: float = 30.0):
    processes = []
    errors = []
    failed = False

    async def start_client():
        error_file = tempfile.TemporaryFile()
        errors.append(error_file)
        process = await asyncio.create_subprocess_exec(
            sys.executable, "-c", helper, stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=error_file,
        )
        processes.append(process)
        await expect(process, b"READY")
        return process

    async def expect(process, expected):
        try:
            line = await asyncio.wait_for(process.stdout.readline(), reply_timeout)
        except asyncio.TimeoutError as error:
            raise AssertionError(f"broker lease subprocess {process.pid} did not send {expected.decode()}") from error
        assert line.strip() == expected, f"broker lease subprocess {process.pid}: expected {expected!r}, got {line!r}"

    try:
        first = await start_client()
        second = await start_client()
        first.stdin.write(b"exit\n")
        await first.stdin.drain()
        assert await asyncio.wait_for(first.wait(), 5.0) == 0
        second.stdin.write(b"ping\n")
        await second.stdin.drain()
        await expect(second, b"PONG")
    except BaseException:
        failed = True
        raise
    finally:
        cleanup_failures = []
        for process in processes:
            if process.stdin is not None:
                process.stdin.close()
        for process in processes:
            if process.returncode is None:
                try:
                    await asyncio.wait_for(process.wait(), 5.0)
                except asyncio.TimeoutError:
                    cleanup_failures.append(f"broker lease subprocess {process.pid} did not exit")
                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass
                    await process.wait()
            if not failed and process.returncode != 0:
                cleanup_failures.append(f"broker lease subprocess {process.pid} exited {process.returncode}")
        for error_file in errors:
            if failed or cleanup_failures:
                error_file.seek(0)
                diagnostic = error_file.read(65536).decode("utf-8", errors="replace")
                if diagnostic:
                    print(f"broker lease subprocess stderr:\n{diagnostic}", file=sys.stderr)
            error_file.close()
        if cleanup_failures and not failed:
            raise AssertionError("; ".join(cleanup_failures))


def test_service_stays_alive_until_the_last_process_lease_is_released():
    asyncio.run(_exercise_process_leases(_LEASE_HELPER))
