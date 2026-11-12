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


def test_policy_reload_accepts_retained_missing_volume_members(package, tmp_path):
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
    subprocess.run(
        [str(package.tools / "7z.exe"), "a", "-t7z", "-mx=0", "-ms=off", "-v1k",
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
    before = {path.name: (path.read_bytes(), path.stat().st_mtime_ns)
              for path in watched.iterdir()}
    output = tmp_path / "out"
    package.configure(extraction={"content_requirement": "complete"},
                      post_extract={"flatten_single_directory": False})
    package.json("watch", "add", watched, "--deep-detect", "-o", output)
    package.json("watch", "start", "--no-tray")
    events = package.data / ".sunpack_watch" / "events.json"

    def retained_blocker(display):
        if not any(row.get("event") == "suspended_missing_volume"
                   and Path(row.get("path", "")) == head for row in display["live"]):
            return None
        for row in display["history"]:
            evidence = row.get("failure", {}).get("evidence", {})
            if (row.get("event") == "archive_failure_evidence"
                    and Path(row.get("path", "")) == head
                    and row["failure"]["kind"] == "missing_volume"
                    and evidence.get("stage") == "item_extract"
                    and evidence.get("missing_volume_evidence") == "volume_attempts_exhausted"
                    and evidence.get("recovery", {}).get("complete_files") == 1):
                return row["owner"]
        return None

    owner = _wait_display(events, retained_blocker)
    assert [p.read_bytes() for p in output.rglob("a.zip")] == [first]
    assert [p.read_bytes() for p in output.rglob("sibling.txt")] == [b"independent successful segment"]
    assert not any(row.get("event") == "done" and row.get("owner") == owner
                   for row in native_fixture("display_events", path=str(events))["history"])
    assert not list(output.rglob("nested.txt"))
    package.configure(extraction={"content_requirement": "allow_partial"})
    # The config observer may have already applied this snapshot; an explicit
    # reload is allowed to report no semantic change in that case (as in main).
    package.json("watch", "reload")

    def accepted(display):
        if any(row.get("event") == "suspended_missing_volume"
               and Path(row.get("path", "")) == head for row in display["live"]):
            return False
        return any(row.get("event") == "done" and Path(row.get("path", "")) == head
                   and row.get("owner") != owner for row in display["history"])

    _wait_display(events, accepted)
    assert package.json("watch", "stop")["summary"]["stopped"]
    assert [p.read_bytes() for p in output.rglob("a.zip")] == [first]
    assert [p.read_bytes() for p in output.rglob("sibling.txt")] == [b"independent successful segment"]
    assert [p.read_bytes() for p in output.rglob("nested.txt")] == [b"verified nested member"]
    assert before == {path.name: (path.read_bytes(), path.stat().st_mtime_ns)
                      for path in watched.iterdir()}

