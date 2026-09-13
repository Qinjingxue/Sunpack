from __future__ import annotations

import os
import statistics
import subprocess
import sys
import time
import zipfile

import pytest


pytestmark = [
    pytest.mark.skipif(__import__("sys").platform != "win32", reason="Windows-only service test"),
    pytest.mark.requires_watch_broker,
]


def test_installed_broker_lifecycle_usn_roundtrip_and_hot_ipc(tmp_path):
    import sunpack_native
    from sunpack.platform.windows.elevation import is_process_elevated

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
    time.sleep(1.2)


def test_service_stays_alive_until_the_last_process_lease_is_released():
    helper = """
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

    def start_client() -> subprocess.Popen[str]:
        process = subprocess.Popen(
            [sys.executable, "-c", helper],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert process.stdout is not None
        ready = process.stdout.readline().strip()
        if ready != "READY":
            stderr = process.stderr.read() if process.stderr is not None else ""
            process.kill()
            pytest.fail(f"broker lease subprocess failed: {ready!r} {stderr}")
        return process

    first = start_client()
    second = start_client()
    try:
        assert first.stdin is not None
        first.stdin.write("exit\n")
        first.stdin.flush()
        assert first.wait(timeout=5.0) == 0

        assert second.stdin is not None and second.stdout is not None
        second.stdin.write("ping\n")
        second.stdin.flush()
        assert second.stdout.readline().strip() == "PONG"
    finally:
        for process in (first, second):
            if process.poll() is None:
                if process.stdin is not None:
                    process.stdin.write("exit\n")
                    process.stdin.flush()
                try:
                    process.wait(timeout=5.0)
                except subprocess.TimeoutExpired:
                    process.kill()
