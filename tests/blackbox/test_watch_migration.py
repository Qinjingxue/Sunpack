import json
import os
import random
import subprocess
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
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


def test_live_watch_cancel_preserves_concurrent_cli_output_with_same_name(package, tmp_path):
    """Overlapping output claims and rollback must stay scoped to each request."""
    watched = tmp_path / "watched"
    watched.mkdir()
    output = tmp_path / "output"
    existing = output / "same"
    existing.mkdir(parents=True)
    (existing / "member.txt").write_bytes(b"user data")

    incoming = tmp_path / "staged.zip"
    source = watched / "same.zip"
    foreground = tmp_path / "same.zip"
    _zip(incoming, "member.txt", b"cancelled Watch archive")
    _zip(foreground, "member.txt", b"successful CLI archive")
    package.configure(post_extract={"archive_cleanup_mode": "d"})
    package.json("watch", "add", watched, "-o", output)
    with package.watch_session(), ThreadPoolExecutor(max_workers=1) as executor:
        worker = _staged_worker(package, tmp_path)
        worker.suspend()
        try:
            incoming.replace(source)
            started = package.await_watch_event("pipeline_request_started", root=watched)
            watch_output = output / "same(1)"
            _wait_for(watch_output.is_dir, "Watch did not reserve its collision output")
            cli = executor.submit(package.json, "extract", "-c", "d", "-o", output, foreground)
            cli_output = output / "same(2)"
            _wait_for(cli_output.is_dir, "CLI did not reserve a distinct output during the Watch batch")
            assert not cli.done() and not (watch_output / "member.txt").exists()
            cancelled = package.run("--cancel-watch-batch", started["owner"])
            assert cancelled.returncode == 0, (cancelled.stdout, cancelled.stderr)
        finally:
            worker.resume()

        assert cli.result()["summary"]["success_count"] == 1
        package.await_watch_event("pipeline_request_interrupted", path=source.name, root=watched)

    assert {path.name for path in output.iterdir()} == {existing.name, cli_output.name}
    assert (existing / "member.txt").read_bytes() == b"user data"
    assert (cli_output / "member.txt").read_bytes() == b"successful CLI archive"
    assert source.is_file()
    assert not foreground.exists()


def test_live_watch_cancel_replays_the_new_generation_of_the_same_file(package, tmp_path):
    """Cancellation of an admitted generation must leave an in-place update eligible."""
    watched = tmp_path / "watched"
    watched.mkdir()
    output = tmp_path / "output"
    incoming = tmp_path / "staged.zip"
    replacement = tmp_path / "updated.zip"
    source = watched / "source.zip"
    _zip(incoming, "member.txt", b"cancelled generation")
    _zip(replacement, "member.txt", b"rewritten generation")
    updated = replacement.read_bytes()
    assert len(updated) == incoming.stat().st_size

    package.json("watch", "add", watched, "-o", output)
    with package.watch_session():
        worker = _staged_worker(package, tmp_path)
        worker.suspend()
        try:
            incoming.replace(source)
            started = package.await_watch_event("pipeline_request_started", root=watched)
            _wait_for((output / "source").is_dir, "Watch did not admit the original generation")
            # Rewrite the mapped source in place while its old request still owns the output.
            with source.open("r+b") as writer:
                assert writer.write(updated) == len(updated)
            cancelled = package.run("--cancel-watch-batch", started["owner"])
            assert cancelled.returncode == 0, (cancelled.stdout, cancelled.stderr)
        finally:
            worker.resume()

        done = package.await_watch_event("done", path=source.name, root=watched)
        assert done["owner"] != started["owner"]

    assert [path.read_bytes() for path in output.rglob("member.txt")] == [b"rewritten generation"]
    assert source.read_bytes() == updated


def test_foreground_nested_output_survives_watch_pause_during_extraction(package, tmp_path):
    """Pausing Watch must preserve suppression of a CLI output still being produced."""
    watched = tmp_path / "watched"
    watched.mkdir()
    watch_output = tmp_path / "watch-output"
    inner = tmp_path / "inner.zip"
    _zip(inner, "generated.txt", b"keep this archive for the user")
    outer = tmp_path / "outer.zip"
    inner_bytes = inner.read_bytes()
    _zip(outer, inner.name, inner_bytes)
    incoming = tmp_path / "live.zip"
    _zip(incoming, "live.txt", b"independent Watch work")

    package.json("watch", "add", "-R", watched, "-o", watch_output)
    package.json("daemon", "start", "-nt")
    produced = watched / "outer" / inner.name
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            worker = _staged_worker(package, tmp_path)
            owner = worker.parent()
            worker.suspend()
            try:
                cli = executor.submit(package.json, "extract", "-r", "1", "-nf", "-o", watched, outer)
                _wait_for(produced.parent.is_dir, "CLI did not reserve output before the Watch resume")
                assert package.json("watch", "disable")["summary"]["enabled"] is False
                package.json("watch", "enable")
                assert owner.is_running() and not cli.done() and not produced.exists()
            finally:
                worker.resume()
            assert cli.result()["summary"]["success_count"] == 1

        incoming.replace(watched / incoming.name)
        package.await_watch_event("done", path=incoming.name, root=watched)
    finally:
        assert package.json("watch", "disable")["summary"]["enabled"] is False

    assert produced.read_bytes() == inner_bytes
    assert [path.read_bytes() for path in watch_output.rglob("*") if path.is_file()] == [
        b"independent Watch work",
    ]


def test_watch_catalog_loss_rebuilds_baseline_without_replaying_existing_sources(package, tmp_path):
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
    with package.watch_session():
        package.await_watch_event("suspended_missing_volume", path=parts[0].name)
        package.await_watch_event("done", path=retained.name)
        package.await_watch_event("done", path=changed.name)
    assert not list(output.rglob(payload.name))
    retained_outputs = list(output.rglob("retained.txt"))
    assert len(retained_outputs) == 1
    assert [path.read_bytes() for path in output.rglob("changed.txt")] == [b"old generation"]
    assert retained.is_file() and changed.is_file()
    state = package.data / ".sunpack_watch"
    display = native_fixture("display_events", path=str(state / "events.json"))
    assert any(
        row["event"] == "suspended_missing_volume"
        for row in (*display["history"], *display["live"])
    )
    assert package.run("--persistent-shutdown").returncode == 0

    # Without trusted history, kept sources, offline arrivals, and offline
    # edits all become the baseline. Only the explicit missing-volume blocker
    # still authorizes recovery when its missing peer appears.
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
    with package.watch_session():
        package.await_watch_event("done", path=parts[0].name)
    assert [path.read_bytes() for path in output.rglob(payload.name)] == [content]
    assert list(output.rglob("retained.txt")) == retained_outputs
    assert retained_outputs[0].read_bytes() == b"already completed"
    assert not list(output.rglob("offline.txt"))
    assert [path.read_bytes() for path in output.rglob("changed.txt")] == [b"old generation"]
    completed = sorted(path.relative_to(output) for path in output.rglob("*") if path.is_file())
    assert package.run("--persistent-shutdown").returncode == 0
    for path in state.glob("catalog.*.bin"):
        path.unlink()
    package.json("daemon", "start", "-nt")
    # A new arrival after the baseline is established must still be processed.
    # Stage it outside the root so Watch sees the completed input move into place.
    incoming = tmp_path / "live.zip"
    _zip(incoming, "live.txt", b"arrived while watching")
    incoming.replace(watched / incoming.name)
    _wait_for(lambda: bool(list(output.rglob("live.txt"))), "Watch ignored an arrival after catalog rebuild")
    assert package.json("daemon", "stop")["summary"]["running"] is False
    assert [path.read_bytes() for path in output.rglob("live.txt")] == [b"arrived while watching"]
    assert sorted(
        path.relative_to(output) for path in output.rglob("*")
        if path.is_file() and path.name != "live.txt"
    ) == completed


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
    package.json("daemon", "start", "-nt")
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
        # Claimed sources only become dirty until release, as in main.
        # A pending-count barrier would require premature probing of the new
        # generation. Validate its durable replay after the worker is released.
    finally:
        worker.resume()

    # Stop checkpoints all roots before joining observers, then drains the
    # admitted batch. It therefore captures the overwrite even if its ordinary
    # notification has not arrived yet. Keep the root absent during restart so
    # the durable deferred source can only be resumed when the root returns.
    assert package.json("daemon", "stop")["summary"]["running"] is False
    assert package.run("--persistent-shutdown").returncode == 0
    owner.wait(timeout=30)
    worker.wait(timeout=30)
    watched.replace(staging)
    package.json("daemon", "start", "-nt")
    staging.replace(watched)
    _wait_for(
        lambda: b"fresh generation" in [path.read_bytes() for path in output.rglob("source.txt")],
        "Watch did not recover the durable source when the root returned",
    )
    assert package.json("daemon", "stop")["summary"]["running"] is False
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
        # Recovery needs the small nested volumes admitted by recursive Deep.
        package.configure(
            recursive_extract="*", embedded_scan={"recursive_candidate_ratio": 0.001},
        )
    package.json("watch", "add", watched, "-o", output, "-d")
    package.json("daemon", "start", "-nt")
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

    with package.watch_session():
        if cancel_before_crash:
            package.await_watch_admission()
        else:
            package.await_watch_event("done", path=source.name)
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
        with package.watch_session():
            package.await_watch_admission()
        assert [path.read_bytes() for path in output.rglob("payload.txt")] == expected
        assert list(output.rglob("nested-payload.bin")) == nested_outputs
        assert nested_outputs[0].read_bytes() == nested_content
        return
    _zip(incoming, "payload.txt", b"replacement generation")
    incoming.replace(source)
    with package.watch_session():
        _wait_for(lambda: any(output.rglob("payload.txt")), "Watch did not process the replacement generation")
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
    package.json("daemon", "start", "-nt")

    malformed = table.with_suffix(".tmp")
    malformed.write_text('{"passwords":[', encoding="utf-8")
    malformed.replace(table)
    assert not package.json("watch", "reload")["summary"]["reloaded"]
    encrypted.replace(watched / encrypted.name)
    _wait_for(lambda: any(output.rglob(payload.name)), "Watch stopped after a malformed password edit")
    assert [path.read_bytes() for path in output.rglob(payload.name)] == [payload.read_bytes()]


def test_watch_reload_noop_and_invalid_configuration_keep_main_contract(package, tmp_path):
    watched = tmp_path / "watched"
    watched.mkdir()
    package.json("watch", "add", watched)
    package.json("daemon", "start", "-nt")
    assert not package.json("watch", "reload")["summary"]["reloaded"]
    config = package.data / "sunpack_config.json"
    raw = json.loads(config.read_text(encoding="utf-8"))
    config.write_text(json.dumps(raw, indent=4, sort_keys=True), encoding="utf-8")
    assert not package.json("watch", "reload")["summary"]["reloaded"]
    try:
        config.write_text('{"watch":', encoding="utf-8")
        reply = package.json("watch", "reload")
        assert reply["summary"]["running"]
        assert not reply["summary"]["reloaded"]
    finally:
        config.write_text(json.dumps(raw), encoding="utf-8")
    assert package.json("watch", "status")["summary"]["running"]


def test_watch_configured_user_passwords_decrypt_and_retry_after_reload(package, tmp_path):
    watched = tmp_path / "watched"
    watched.mkdir()
    output = tmp_path / "out"
    for name, password in [("first", "configured-only"), ("later", "edited-only")]:
        payload = tmp_path / f"{name}.txt"
        payload.write_text(name, encoding="utf-8")
        subprocess.run(
            [str(package.tools / "7z.exe"), "a", "-t7z", "-mhe=on", f"-p{password}",
             str(watched / f"{name}.7z"), str(payload)],
            check=True, capture_output=True,
        )
    package.configure(user_passwords=["configured-only", "configured-only"])
    package.json("watch", "add", watched, "-o", output)
    package.json("daemon", "start", "-nt")
    _wait_for(lambda: any(output.rglob("first.txt")), "Configured Watch password was not used")
    events = package.data / ".sunpack_watch" / "events.json"
    def blocked():
        try:
            display = native_fixture("display_events", path=str(events))
        except subprocess.CalledProcessError:
            # The writer can still be publishing the display manifest after
            # the first output appears; business completion is separate.
            return False
        # Password blockers remain live until the source change resolves them;
        # completed task rows, such as first.7z, belong to history.
        return any(
            row.get("event") == "failed_password" and "later.7z" in str(row)
            for row in (*display["history"], *display["live"])
        )
    _wait_for(blocked, "Second archive did not reach its password blocker")
    assert not list(output.rglob("later.txt"))
    package.configure(live=True, user_passwords=["configured-only", "edited-only"])
    package.json("watch", "reload")
    _wait_for(lambda: any(output.rglob("later.txt")), "Config-only password edit did not retry blocker")
    assert [path.read_text(encoding="utf-8") for path in output.rglob("first.txt")] == ["first"]
    assert [path.read_text(encoding="utf-8") for path in output.rglob("later.txt")] == ["later"]
