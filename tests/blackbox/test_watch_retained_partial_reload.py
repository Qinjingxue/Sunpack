"""A real failed composition keeps complete members for policy-only Watch retry."""
import io
import random
import subprocess
import time
import zipfile
from pathlib import Path

import pytest

from tests.helpers.native_fixture import native_fixture

pytestmark = pytest.mark.requires_watch_broker


def _wait_display(events, predicate):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            display = native_fixture("display_events", path=str(events))
        except subprocess.CalledProcessError:
            pass
        else:
            result = predicate(display)
            if result:
                return result
        time.sleep(0.05)
    pytest.fail("Retained missing-volume policy transition did not settle")


def _retained_carrier(package, tmp_path):
    # The correct middle volume is absent. Two supplied candidates for its slot
    # both fail after the first complete member; the real worker exhausts them.
    # A separate successful ZIP in the head carrier keeps the failed segment's
    # best-effort output under complete, so allow_partial has real evidence to
    # reconsider rather than trying to resurrect already-deleted content.
    watched = tmp_path / "watched"
    watched.mkdir()
    nested = io.BytesIO()
    with zipfile.ZipFile(nested, "w") as archive:
        archive.writestr("nested.txt", b"verified nested member")
    first = nested.getvalue()
    (tmp_path / "a.zip").write_bytes(first)
    (tmp_path / "b.txt").write_bytes(random.Random(2026).randbytes(2600))
    # Compress each member separately so the inner ZIP signature is not a
    # second top-level embedded input. Stored (-mx=0) bytes exercise carrier
    # boundary discovery instead of this retained-member recovery transition.
    subprocess.run(
        [str(package.tools / "7z.exe"), "a", "-t7z", "-mx=1", "-ms=off", "-v1k",
         str(watched / "series.7z"), "a.zip", "b.txt"],
        cwd=tmp_path, check=True, capture_output=True,
    )
    parts = sorted(watched.glob("series.7z.*"))
    assert len(parts) == 3
    correct_middle = parts[1].read_bytes()
    first_candidate = bytearray(correct_middle)
    first_candidate[20] ^= 0xFF
    parts[1].write_bytes(first_candidate)
    second_candidate = bytearray(first_candidate)
    second_candidate[30] ^= 0xFF
    (watched / "series.7z.02").write_bytes(second_candidate)
    sibling = io.BytesIO()
    with zipfile.ZipFile(sibling, "w") as archive:
        archive.writestr("sibling.txt", b"independent successful segment")
    head = parts[0]
    head.write_bytes(b"prefix" + sibling.getvalue() + b"between" + head.read_bytes())
    return watched, head, parts, correct_middle, first


def _retained_blocker(display, head):
    # Diagnostic history is size-bounded and may omit owner/path after a large
    # recovery payload. The live blocker is the durable completion boundary;
    # callers verify the actual retained member bytes below.
    for row in display["live"]:
        if (row.get("event") == "suspended_missing_volume"
                and Path(row.get("path", "")) == head):
            return row["task_id"].split("|", 1)[0]
    return None


def _accepted(display, head, owner):
    if any(row.get("event") == "suspended_missing_volume"
           and Path(row.get("path", "")) == head for row in display["live"]):
        return False
    return any(row.get("event") == "done" and Path(row.get("path", "")) == head
               and row.get("owner") != owner for row in display["history"])


def test_policy_reload_accepts_retained_missing_volume_members(package, tmp_path):
    watched, head, parts, correct_middle, first = _retained_carrier(package, tmp_path)
    before = {path.name: (path.read_bytes(), path.stat().st_mtime_ns)
              for path in watched.iterdir()}
    output = tmp_path / "out"
    # This case tests recovery eligibility, not main's independent size/project
    # authorization gate (the large partial b.txt would reject the small ZIP).
    package.configure(extraction={"content_requirement": "complete"},
                      recursive_authorization={"enabled": False},
                      post_extract={"flatten_single_directory": False})
    package.json("watch", "add", watched, "--deep-detect", "-o", output)
    package.json("watch", "start", "--no-tray")
    events = package.data / ".sunpack_watch" / "events.json"

    owner = _wait_display(events, lambda display: _retained_blocker(display, head))
    assert [p.read_bytes() for p in output.rglob("a.zip")] == [first]
    assert [p.read_bytes() for p in output.rglob("sibling.txt")] == [b"independent successful segment"]
    assert not any(row.get("event") == "done" and row.get("owner") == owner
                   for row in native_fixture("display_events", path=str(events))["history"])
    assert not list(output.rglob("nested.txt"))
    package.configure(extraction={"content_requirement": "allow_partial"})
    # The config observer may have already applied this snapshot; an explicit
    # reload is allowed to report no semantic change in that case (as in main).
    package.json("watch", "reload")

    _wait_display(events, lambda display: _accepted(display, head, owner))
    assert package.json("watch", "stop")["summary"]["stopped"]
    # Main re-evaluates retained members against the new content policy without
    # recursively scanning those unchanged outputs again.
    assert [p.read_bytes() for p in output.rglob("a.zip")] == [first]
    assert [p.read_bytes() for p in output.rglob("sibling.txt")] == [b"independent successful segment"]
    assert not list(output.rglob("nested.txt"))
    assert before == {path.name: (path.read_bytes(), path.stat().st_mtime_ns)
                      for path in watched.iterdir()}



@pytest.mark.parametrize("cleanup_locked", [False, True])
def test_changed_middle_volume_reuses_only_its_retained_segment_slot(package, tmp_path, cleanup_locked):
    import ctypes
    from ctypes import wintypes

    watched, head, parts, correct_middle, first = _retained_carrier(package, tmp_path)
    output = tmp_path / "out"
    package.configure(recursive_extract=1,
                      extraction={"content_requirement": "complete"},
                      post_extract={"archive_cleanup_mode": "k", "flatten_single_directory": False})
    package.json("watch", "add", watched, "--deep-detect", "-o", output)
    package.json("watch", "start", "--no-tray")
    events = package.data / ".sunpack_watch" / "events.json"
    owner = _wait_display(events, lambda display: _retained_blocker(display, head))
    retained, = output.rglob("a.zip")
    sibling, = output.rglob("sibling.txt")
    original_slot = retained.parent
    original_container = sibling.parent.parent
    assert original_slot.parent == original_container
    slots = sorted(path.name for path in original_container.iterdir())
    sibling_before = (sibling.stat().st_ino, sibling.stat().st_mtime_ns, sibling.read_bytes())
    head_before = (head.stat().st_ino, head.stat().st_mtime_ns, head.read_bytes())
    stale = original_slot / "previous-attempt.txt"
    stale.write_bytes(b"must not survive a successful cleanup")
    handle = None
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    if cleanup_locked:
        # Main retries in the same slot after best-effort cleanup fails. Its
        # worker still rejects ambiguous volume trials in a nonempty directory;
        # this must be a new terminal failure, not reuse of the old receipt.
        handle = kernel.CreateFileW(str(stale), 0x80000000, 3, None, 3, 0x80, None)
        assert handle != wintypes.HANDLE(-1).value, ctypes.get_last_error()
    try:
        # Only a failed segment's dependency changes. The carrier and proven
        # successful sibling retain their generation and output identities.
        parts[1].write_bytes(correct_middle)
        if cleanup_locked:
            def rejected_retry(display):
                for row in display["history"]:
                    retry_owner = row.get("owner")
                    if (row.get("event") == "failed_terminal"
                            and Path(row.get("path", "")) == head
                            and retry_owner != owner
                            and any(event.get("event") == "pipeline_cleanup_failed"
                                    and event.get("owner") == retry_owner
                                    and event.get("cleanup", {}).get("error_code") == 32
                                    and Path(event["cleanup"]["path"]) == original_slot
                                    for event in display["history"])):
                        return retry_owner
                return None
            _wait_display(events, rejected_retry)
        else:
            _wait_display(events, lambda display: _accepted(display, head, owner))
    finally:
        if handle is not None:
            assert kernel.CloseHandle(handle), ctypes.get_last_error()
    assert package.json("watch", "stop")["summary"]["stopped"]
    if cleanup_locked:
        # Cleanup may remove other old files before hitting the locked one.
        # The locked bytes and owning slot must survive; do not manufacture a
        # successful new extraction or damage the independent successful sibling.
        assert stale.read_bytes() == b"must not survive a successful cleanup"
    else:
        assert list(output.rglob("a.zip")) == [retained]
        assert retained.read_bytes() == first
        assert list(output.rglob("b.txt")) == [original_slot / "b.txt"]
        assert (original_slot / "b.txt").read_bytes() == (tmp_path / "b.txt").read_bytes()
    assert list(output.rglob("sibling.txt")) == [sibling]
    assert (sibling.stat().st_ino, sibling.stat().st_mtime_ns, sibling.read_bytes()) == sibling_before
    assert (head.stat().st_ino, head.stat().st_mtime_ns, head.read_bytes()) == head_before
    assert sorted(path.name for path in original_container.iterdir()) == slots
    assert stale.exists() == cleanup_locked
