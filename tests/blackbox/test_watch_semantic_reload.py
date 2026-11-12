"""Policy reload reconsiders durable blockers without requiring new file events."""
import random
import subprocess
import time
from pathlib import Path

import pytest

from tests.helpers.native_fixture import native_fixture


pytestmark = pytest.mark.requires_watch_broker


def _wait_for_blocker(events, source, previous_owner=None):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            display = native_fixture("display_events", path=str(events))
        except subprocess.CalledProcessError:
            pass
        else:
            blocked = any(row.get("event") == "suspended_missing_volume"
                          and Path(row.get("path", "")) == source
                          for row in display["live"])
            if blocked:
                for row in display["history"]:
                    if (row.get("event") == "archive_failure_evidence"
                            and Path(row.get("path", "")) == source
                            and row.get("failure", {}).get("kind") == "missing_volume"
                            and row.get("owner")
                            and row["owner"] != previous_owner):
                        return row["owner"]
        time.sleep(0.05)
    pytest.fail("Semantic reload did not retry the unchanged missing-volume blocker")


def test_semantic_reload_retries_unchanged_missing_volume_blocker(package, tmp_path):
    # This verifies the lifecycle admission boundary, not partial acceptance:
    # the absent middle volume still prevents extraction under either policy.
    # The new failure-evidence request owner proves a second pipeline attempt, rather
    # than merely observing a rewritten settings file or display timestamp.
    # Live task IDs identify stable display groups and intentionally survive retries.
    watched = tmp_path / "watched"
    watched.mkdir()
    payload = tmp_path / "payload.txt"
    payload.write_bytes(random.Random(612).randbytes(4500))
    subprocess.run(
        [str(package.tools / "7z.exe"), "a", "-t7z", "-mx=0", "-v1k",
         str(watched / "series.7z"), str(payload)],
        check=True, capture_output=True,
    )
    parts = sorted(watched.glob("series.7z.*"))
    assert len(parts) >= 3
    parts[1].replace(tmp_path / parts[1].name)
    before = [(path.name, path.stat().st_size, path.stat().st_mtime_ns)
              for path in watched.iterdir()]
    output = tmp_path / "out"
    package.configure(extraction={"content_requirement": "complete"})
    package.json("watch", "add", watched, "-o", output)
    package.json("watch", "start", "--no-tray")
    events = package.data / ".sunpack_watch" / "events.json"
    owner = _wait_for_blocker(events, parts[0])
    package.configure(extraction={"content_requirement": "allow_partial"})
    package.json("watch", "reload")
    _wait_for_blocker(events, parts[0], owner)
    assert package.json("watch", "stop")["summary"]["stopped"]
    assert before == [(path.name, path.stat().st_size, path.stat().st_mtime_ns)
                      for path in watched.iterdir()]
    assert not list(output.rglob("payload.txt"))


def test_watch_restart_keeps_flattened_carrier_and_retries_promoted_child(package, tmp_path):
    import io
    import zipfile

    watched = tmp_path / "watched"
    watched.mkdir()
    (tmp_path / "secret.txt").write_bytes(b"promoted child")
    locked = tmp_path / "locked.zip"
    subprocess.run(
        [str(package.tools / "7z.exe"), "a", "-tzip", "-mem=AES256", "-precovered-key",
         str(locked), "secret.txt"], cwd=tmp_path, check=True, capture_output=True,
    )
    first = io.BytesIO()
    with zipfile.ZipFile(first, "w") as archive:
        archive.writestr("locked.zip", locked.read_bytes())
    second = io.BytesIO()
    with zipfile.ZipFile(second, "w") as archive:
        archive.writestr("wrapper/leaf/ordinary.txt", b"retained ordinary")
    source = watched / "carrier.bin"
    source.write_bytes(b"prefix" + first.getvalue() + b"between" + second.getvalue() + b"tail")
    output = tmp_path / "out"
    package.configure(recursive_extract="*", recursive_authorization={"enabled": False},
                      post_extract={"flatten_single_directory": True})
    package.json("watch", "add", watched, "--deep-detect", "-o", output)
    package.json("watch", "start", "--no-tray")
    events = package.data / ".sunpack_watch" / "events.json"
    ordinary = output / "carrier" / "ordinary.txt"
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            display = native_fixture("display_events", path=str(events))
            blocked = any(row.get("event") == "failed_password"
                          for row in (*display["history"], *display["live"]))
            if blocked and ordinary.is_file():
                break
        except subprocess.CalledProcessError:
            pass
        time.sleep(0.05)
    else:
        pytest.fail("Carrier did not finish flattening beside its promoted password blocker")
    assert package.json("watch", "stop")["summary"]["stopped"]
    identity = (ordinary.stat().st_ino, ordinary.stat().st_mtime_ns)
    assert ordinary.read_bytes() == b"retained ordinary"
    assert package.run("--persistent-shutdown").returncode == 0
    package.configure(user_passwords=["recovered-key"])
    package.json("watch", "start", "--once", "--no-tray")
    assert [path.read_bytes() for path in output.rglob("secret.txt")] == [b"promoted child"]
    assert list(output.rglob("ordinary.txt")) == [ordinary]
    assert (ordinary.stat().st_ino, ordinary.stat().st_mtime_ns) == identity
    assert not list((output / "carrier").rglob("wrapper"))
    assert source.is_file()
