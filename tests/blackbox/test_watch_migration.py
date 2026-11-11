import json
import os
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


def test_watch_rebuild_preserves_completed_generations_and_recovers_offline_arrivals(package, tmp_path):
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
    retained = watched / "retained.zip"
    changed = watched / "changed.zip"
    _zip(retained, "retained.txt", b"already completed")
    _zip(changed, "changed.txt", b"old generation")

    package.json("watch", "add", watched, "-o", output)
    blocked = package.run("watch", "start", "--once", "--no-tray", "--json")
    assert blocked.returncode == 1, (blocked.stdout, blocked.stderr)
    assert not list(output.rglob(payload.name))
    retained_outputs = list(output.rglob("retained.txt"))
    assert len(retained_outputs) == 1
    assert [path.read_bytes() for path in output.rglob("changed.txt")] == [b"old generation"]
    assert retained.is_file() and changed.is_file()
    assert package.run("--persistent-shutdown").returncode == 0

    # Lose only the disposable catalog. Kept successful sources must not replay,
    # but a new offline file, a content edit with identical metadata, and a
    # previously missing volume must all be admitted through the rebuilt view.
    state = package.data / ".sunpack_watch"
    roots = package.data / "sunpack_watch_roots.txt"
    assert roots.read_text(encoding="utf-8").split("|")[3].strip() == "true"
    catalog = list(state.glob("catalog.*.bin"))
    assert catalog
    for path in catalog:
        path.unlink()
    missing.replace(parts[1])
    _zip(watched / "offline.zip", "offline.txt", b"arrived while stopped")
    before = changed.stat()
    _zip(changed, "changed.txt", b"new generation")
    os.utime(changed, ns=(before.st_atime_ns, before.st_mtime_ns))
    assert changed.stat().st_size == before.st_size
    package.json("watch", "start", "--once", "--no-tray")
    assert [path.read_bytes() for path in output.rglob(payload.name)] == [content]
    assert list(output.rglob("retained.txt")) == retained_outputs
    assert retained_outputs[0].read_bytes() == b"already completed"
    assert [path.read_bytes() for path in output.rglob("offline.txt")] == [b"arrived while stopped"]
    assert sorted(path.read_bytes() for path in output.rglob("changed.txt")) == [
        b"new generation", b"old generation",
    ]
    completed = sorted(path.relative_to(output) for path in output.rglob("*") if path.is_file())
    assert package.run("--persistent-shutdown").returncode == 0
    for path in state.glob("catalog.*.bin"):
        path.unlink()
    package.json("watch", "start", "--once", "--no-tray")
    assert sorted(path.relative_to(output) for path in output.rglob("*") if path.is_file()) == completed


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


@pytest.mark.parametrize("cancel_before_crash", [False, True], ids=["interrupted", "cancelled"])
def test_watch_hard_crash_recovers_pending_work_but_preserves_cancellation(package, tmp_path, cancel_before_crash):
    watched = tmp_path / "watched"
    watched.mkdir()
    output = tmp_path / "out"
    incoming = tmp_path / ("incoming.zip" if cancel_before_crash else "incoming.opaque")
    source = watched / incoming.name
    _zip(incoming, "payload.txt", b"original generation")
    nested_content = random.Random(73).randbytes(4500)
    if not cancel_before_crash:
        # Main's former process-death matrix covered disguise, carriers, nested
        # archives, encryption and volumes separately. Combine these in one
        # recovery path rather than repeat the expensive process setup five times.
        fixtures = tmp_path / "fixtures"
        fixtures.mkdir()
        payload = fixtures / "nested-payload.bin"
        payload.write_bytes(nested_content)
        subprocess.run(
            [str(package.tools / "7z.exe"), "a", "-t7z", "-mx=0", "-mhe=on",
             "-pcrash-key", "-v1k", str(fixtures / "nested.data"), payload.name],
            cwd=fixtures, check=True, capture_output=True,
        )
        parts = sorted(fixtures.glob("nested.data.*"))
        assert len(parts) >= 3
        with zipfile.ZipFile(incoming, "a") as archive:
            for part in parts:
                archive.write(part, part.name)
        sibling = fixtures / "sibling.zip"
        _zip(sibling, "sibling.txt", b"second carrier segment")
        incoming.write_bytes(
            b"carrier prefix" + incoming.read_bytes() + b"between segments" +
            sibling.read_bytes() + b"carrier suffix"
        )
        (package.data / "builtin_passwords.json").write_text(
            json.dumps({"passwords": [{"value": "crash-key"}]}), encoding="utf-8",
        )
        package.configure(recursive_extract="*")
    package.json("watch", "add", watched, "-o", output, "--deep-detect")
    package.json("watch", "start", "--no-tray")
    worker = _staged_worker(package, tmp_path)
    owner = worker.parent()
    events = package.data / ".sunpack_watch" / "events.json"
    batch = None

    def admitted():
        nonlocal batch
        container = output / "incoming"
        if not container.is_dir():
            return False
        if not cancel_before_crash and not any(path.is_dir() for path in container.iterdir()):
            # Wait for the first logical segment's output reservation, which
            # used to overwrite the carrier's durable ownership under one key.
            return False
        try:
            history = native_fixture("display_events", path=str(events))["history"]
        except subprocess.CalledProcessError:
            return False
        batch = next((row["owner"] for row in history
                      if row["event"] == "pipeline_request_started"), None)
        return batch is not None

    # Hold the worker so hard process death (with or without prior cancellation)
    # cannot be mistaken for completed cleanup or an ordinary Watch shutdown.
    worker.suspend()
    owner_stopped = False
    try:
        incoming.replace(source)
        _wait_for(admitted, "Watch did not admit the archive before cancellation")
        # An uncommitted output must be removed on replay, not adopted as a
        # completed extraction or left as an orphan beside the retried output.
        partial = output / "incoming" / "uncommitted.txt"
        partial.write_bytes(b"incomplete output")
        if cancel_before_crash:
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
    assert not list(output.rglob("uncommitted.txt"))
    expected = [] if cancel_before_crash else [b"original generation"]
    assert [path.read_bytes() for path in output.rglob("payload.txt")] == expected
    if not cancel_before_crash:
        assert [path.read_bytes() for path in output.rglob("sibling.txt")] == [b"second carrier segment"]
        assert [path.name for path in output.iterdir()] == ["incoming"]
        nested_outputs = list(output.rglob("nested-payload.bin"))
        assert len(nested_outputs) == 1
        assert nested_outputs[0].read_bytes() == nested_content
        assert not list(output.rglob("nested.data.*"))
        assert not list(watched.glob("nested.data.*"))
        # A second fresh runtime must not replay the recovered generation again.
        assert package.run("--persistent-shutdown").returncode == 0
        package.json("watch", "start", "--once", "--no-tray")
        assert [path.read_bytes() for path in output.rglob("payload.txt")] == expected
        assert list(output.rglob("nested-payload.bin")) == nested_outputs
        assert nested_outputs[0].read_bytes() == nested_content
        return
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
