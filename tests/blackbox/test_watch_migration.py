import json
import random
import subprocess
import time
import zipfile
from pathlib import Path

import psutil
import pytest

from tests.helpers.native_fixture import native_fixture


pytestmark = pytest.mark.requires_watch_broker


def _wait_for(predicate, message):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    pytest.fail(message)


def _zip(path, name, payload):
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(name, payload)


def _staged_worker(package, tmp_path):
    warmup = tmp_path / "warmup.zip"
    _zip(warmup, "warmup.txt", b"warmup")
    package.json("extract", "-o", tmp_path / "warmup-out", warmup)
    worker_path = package.launcher.parent.parent / "tools" / "sunpack_sevenzip_worker.exe"
    return next(
        process for process in psutil.process_iter(["exe"])
        if process.info["exe"] and Path(process.info["exe"]) == worker_path
    )


def test_watch_resumes_missing_volumes_with_a_rebuilt_catalog(package, tmp_path):
    watched = tmp_path / "watched"
    watched.mkdir()
    output = tmp_path / "out"
    content = random.Random(35).randbytes(4500)
    payload = tmp_path / "payload.txt"
    payload.write_bytes(content)
    subprocess.run(
        [str(package.tools / "7z.exe"), "a", "-t7z", "-mx=0", "-v1k",
         str(watched / "series.7z"), str(payload)],
        check=True, capture_output=True,
    )
    parts = sorted(watched.glob("series.7z.*"))
    assert len(parts) >= 3
    missing = tmp_path / parts[1].name
    parts[1].replace(missing)

    package.json("watch", "add", watched, "-o", output)
    blocked = package.run("watch", "start", "--once", "--no-tray", "--json")
    assert blocked.returncode == 1, (blocked.stdout, blocked.stderr)
    assert not list(output.rglob(payload.name))

    # Only the disposable catalog is lost. The durable missing-volume blocker
    # must retry even when startup has no catalog delta for the arriving peer.
    state = package.data / ".sunpack_watch"
    roots = package.data / "sunpack_watch_roots.txt"
    assert roots.read_text(encoding="utf-8").split("|")[3].strip() == "true"
    catalog = list(state.glob("catalog.*.bin"))
    assert catalog
    for path in catalog:
        path.unlink()
    missing.replace(parts[1])
    package.json("watch", "start", "--once", "--no-tray")
    assert [path.read_bytes() for path in output.rglob(payload.name)] == [content]


def test_watch_replays_changed_source_without_cancelling_its_batch_siblings(package, tmp_path):
    watched = tmp_path / "watched"
    staging = tmp_path / "staging"
    staging.mkdir()
    _zip(staging / "source.zip", "source.txt", b"first generation")
    _zip(staging / "other.zip", "other.txt", b"unrelated batch member")
    replacement = tmp_path / "replacement.zip"
    _zip(replacement, "source.txt", b"fresh generation")
    output = tmp_path / "out"

    # Start the root observer on the existing parent. Moving the prepared
    # directory into place admits both inputs in the same checkpoint.
    package.json("watch", "add", watched, "-o", output)
    package.json("watch", "start", "--no-tray")
    worker = _staged_worker(package, tmp_path)
    owner = worker.parent()
    worker.suspend()
    try:
        staging.replace(watched)
        _wait_for(
            lambda: (output / "other").is_dir() and (output / "source").is_dir(),
            "Watch did not admit both sources to the worker",
        )
        # Keep the mapped file's size and identity. A downloader can overwrite
        # an open archive even when its current mapping prevents replacement.
        with (watched / "source.zip").open("r+b") as source:
            updated = replacement.read_bytes()
            assert len(updated) == (watched / "source.zip").stat().st_size
            assert source.write(updated) == len(updated)
        _wait_for(
            lambda: package.json("watch", "status")["summary"]["pending"] > 0,
            "Watch did not queue the replacement while the batch was in flight",
        )
    finally:
        worker.resume()

    # Stop drains the admitted batch. Keep the root absent during restart so
    # the durable deferred source can only be resumed when the root returns.
    assert package.json("watch", "stop")["summary"]["stopped"]
    assert package.run("--persistent-shutdown").returncode == 0
    owner.wait(timeout=30)
    worker.wait(timeout=30)
    watched.replace(staging)
    package.json("watch", "start", "--no-tray")
    staging.replace(watched)
    _wait_for(
        lambda: b"fresh generation" in [path.read_bytes() for path in output.rglob("source.txt")],
        "Watch did not recover the durable source when the root returned",
    )
    assert package.json("watch", "stop")["summary"]["stopped"]
    assert [path.read_bytes() for path in output.rglob("other.txt")] == [b"unrelated batch member"]
    assert b"fresh generation" in [path.read_bytes() for path in output.rglob("source.txt")]


def test_cancelled_watch_generation_is_durable_before_worker_stops(package, tmp_path):
    watched = tmp_path / "watched"
    watched.mkdir()
    output = tmp_path / "out"
    incoming = tmp_path / "incoming.zip"
    source = watched / incoming.name
    _zip(incoming, "payload.txt", b"cancelled generation")
    package.json("watch", "add", watched, "-o", output)
    package.json("watch", "start", "--no-tray")
    worker = _staged_worker(package, tmp_path)
    owner = worker.parent()
    events = package.data / ".sunpack_watch" / "events.json"
    batch = None

    def admitted():
        nonlocal batch
        if not (output / "incoming").is_dir():
            return False
        try:
            history = native_fixture("display_events", path=str(events))["history"]
        except subprocess.CalledProcessError:
            return False
        batch = next((row["owner"] for row in history
                      if row["event"] == "pipeline_request_started"), None)
        return batch is not None

    # Hold the worker so a crash immediately after cancellation cannot be
    # mistaken for a normally completed cleanup or ordinary Watch shutdown.
    worker.suspend()
    owner_stopped = False
    try:
        incoming.replace(source)
        _wait_for(admitted, "Watch did not admit the archive before cancellation")
        cancel = package.run("--cancel-watch-batch", batch)
        assert cancel.returncode == 0, (cancel.stdout, cancel.stderr)
        owner.kill()
        owner.wait(timeout=30)
        owner_stopped = True
    finally:
        if owner_stopped:
            # Its job object has already begun terminating the child. Windows
            # can still return its PID while rejecting NtResumeProcess.
            worker.wait(timeout=30)
        else:
            try:
                worker.resume()
            except psutil.NoSuchProcess:
                pass

    package.json("watch", "start", "--once", "--no-tray")
    assert source.is_file()
    assert not list(output.rglob("payload.txt"))
    _zip(incoming, "payload.txt", b"replacement generation")
    incoming.replace(source)
    package.json("watch", "start", "--once", "--no-tray")
    assert [path.read_bytes() for path in output.rglob("payload.txt")] == [b"replacement generation"]


def test_invalid_password_edit_keeps_watch_running_with_last_valid_passwords(package, tmp_path):
    watched = tmp_path / "watched"
    watched.mkdir()
    output = tmp_path / "out"
    payload = tmp_path / "payload.txt"
    payload.write_bytes(b"encrypted watch payload")
    encrypted = tmp_path / "incoming.7z"
    password = "watch-retained-password"
    subprocess.run(
        [str(package.tools / "7z.exe"), "a", "-t7z", "-mhe=on", f"-p{password}",
         str(encrypted), str(payload)],
        check=True, capture_output=True,
    )
    table = package.data / "builtin_passwords.json"
    table.write_text(json.dumps({"passwords": [{"value": password}]}), encoding="utf-8")
    assert package.json("passwords")["items"][0]["builtin_passwords"] == [password]
    package.json("watch", "add", watched, "-o", output)
    package.json("watch", "start", "--no-tray")

    malformed = table.with_suffix(".tmp")
    malformed.write_text('{"passwords":[', encoding="utf-8")
    malformed.replace(table)
    assert package.json("watch", "reload")["summary"]["reloaded"]
    encrypted.replace(watched / encrypted.name)
    _wait_for(lambda: any(output.rglob(payload.name)), "Watch stopped after a malformed password edit")
    assert [path.read_bytes() for path in output.rglob(payload.name)] == [payload.read_bytes()]
