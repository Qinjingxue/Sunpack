"""Exercise identity and root routing through Watch notification and USN recovery."""

import os
from zipfile import ZipFile

import psutil
import pytest

from tests.helpers.marker_utils import open_shared_file


pytestmark = pytest.mark.requires_watch_broker


def _write_archive(path, payload):
    with ZipFile(path, "w") as archive:
        archive.writestr("payload.txt", payload)


def _watch_root(package, root, output):
    root.mkdir(exist_ok=True)
    package.json("watch", "add", "-R", root, "-o", output)


def _await_done(package, source):
    event = package.await_watch_event(
        "done", "failed_terminal", "no_tasks_found", path=source.name,
        root=source.parent,
    )
    assert event["event"] == "done", event


def _payloads(output):
    return sorted(path.read_bytes() for path in output.rglob("payload.txt"))


def test_watch_routes_an_open_archive_after_cross_root_rename_and_path_reuse(package, tmp_path):
    left, right = tmp_path / "left", tmp_path / "right"
    left_out, right_out = tmp_path / "left-out", tmp_path / "right-out"
    package.configure(post_extract={"archive_cleanup_mode": "d"})
    _watch_root(package, left, left_out)
    _watch_root(package, right, right_out)

    original = tmp_path / "initial.zip"
    replacement = tmp_path / "replacement.zip"
    original_payload, new_payload = b"the moved object", b"new at old path."
    _write_archive(original, original_payload)
    _write_archive(replacement, new_payload)
    metadata = original.stat()
    os.utime(replacement, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
    assert replacement.stat().st_size == metadata.st_size

    left_path, right_path = left / "delivery.zip", right / "delivery.zip"
    with package.watch_session():
        # This writer allows the archive to move and prevents Watch admission.
        with open_shared_file(original, "ab"):
            original.rename(left_path)
            package.await_watch_event("candidate_busy", path=left_path.name, root=left)
            left_path.rename(right_path)
            replacement.rename(left_path)
            assert right_path.stat().st_ino == metadata.st_ino
            _await_done(package, left_path)
            assert right_path.is_file() and not _payloads(right_out)
        _await_done(package, right_path)

    assert not left_path.exists() and not right_path.exists()
    assert _payloads(left_out) == [new_payload]
    assert _payloads(right_out) == [original_payload]


def test_watch_recovers_same_size_and_mtime_child_after_offline_directory_replacement(package, tmp_path):
    left, right = tmp_path / "left", tmp_path / "right"
    left_out, right_out = tmp_path / "left-out", tmp_path / "right-out"
    watch_sources = [left / "intake" / "nested" / "delivery.zip", right / "intake" / "nested" / "delivery.zip"]
    staged_dirs = [tmp_path / "incoming-left", tmp_path / "incoming-right"]
    staged_sources = [directory / "nested" / "delivery.zip" for directory in staged_dirs]
    old_payloads = (b"left-old!", b"right-old")
    new_payloads = (b"left-new!", b"right-new with a changed size")
    control = tmp_path / "standalone.zip"
    _write_archive(control, b"direct USN arrival")

    pairs = zip(watch_sources, staged_sources, old_payloads, new_payloads, strict=True)
    for old_source, new_source, before, after in pairs:
        old_source.parent.mkdir(parents=True)
        new_source.parent.mkdir(parents=True)
        _write_archive(old_source, before)
        _write_archive(new_source, after)
    original = watch_sources[0].stat()
    os.utime(staged_sources[0], ns=(original.st_atime_ns, original.st_mtime_ns))
    incoming = staged_sources[0].stat()
    assert (incoming.st_size, incoming.st_mtime_ns) == (original.st_size, original.st_mtime_ns)
    assert incoming.st_ino != original.st_ino

    _watch_root(package, left, left_out)
    _watch_root(package, right, right_out)
    with package.watch_session():
        for source in watch_sources:
            _await_done(package, source)
        # daemon stop removes the published endpoint while shutting down.
        state, = package.data.glob("runtime-*.state")
        owner = psutil.Process(int(state.read_text(encoding="utf-8").splitlines()[3]))
    owner.wait(timeout=30)

    # During downtime only the parent directories move. No file-level write or
    # rename occurs for either incoming archive after the first Watch session.
    for root, staged in zip((left, right), staged_dirs, strict=True):
        (root / "intake").rename(tmp_path / f"retired-{root.name}")
        staged.rename(root / "intake")
    # A direct rename during the same downtime is the USN replay control.
    control.rename(right / control.name)

    with package.watch_session():
        package.await_watch_admission()

    assert (_payloads(left_out), _payloads(right_out)) == (
        sorted([old_payloads[0], new_payloads[0]]),
        sorted([old_payloads[1], new_payloads[1], b"direct USN arrival"]),
    )
