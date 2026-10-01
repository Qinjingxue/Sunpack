"""Real Windows process death, fresh-process replay, and extraction recovery."""
from __future__ import annotations

import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading

import psutil
import pytest

from tests.helpers.tool_config import require_7z


REPO = Path(__file__).resolve().parents[2]


def _run_child(root, family, mode, *, kill=False):
    messages = queue.Queue()
    with (root / f"{family}-{mode}.stderr.txt").open("w", encoding="utf-8") as errors:
        process = subprocess.Popen(
            [sys.executable, "-u", "-m", "tests.helpers.wal_crash_worker", family, str(root), mode],
            cwd=REPO, stdout=subprocess.PIPE, stderr=errors, text=True, encoding="utf-8",
            env={**os.environ, "PYTHONIOENCODING": "utf-8"})

        def read():
            for line in process.stdout:
                if line.startswith("WAL_TEST "):
                    messages.put(json.loads(line[len("WAL_TEST "):]))
            messages.put(None)

        reader = threading.Thread(target=read, daemon=True)
        reader.start()
        try:
            if kill:
                result = messages.get(timeout=75)
                assert result and result["kind"] == "crash", (
                    f"Fault boundary was not reached: {result}\n" + _error(root, family, mode))
                # Only descendants of our disposable child are terminated.
                descendants = psutil.Process(process.pid).children(recursive=True)
                process.kill()  # Windows TerminateProcess; bypasses atexit/finally.
                process.wait(timeout=15)
                for descendant in descendants:
                    try:
                        descendant.kill()
                    except psutil.NoSuchProcess:
                        pass
                psutil.wait_procs(descendants, timeout=15)
                assert process.returncode != 0
                (root / f"{family}-{mode}.crash.json").write_text(
                    json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
                return result
            process.wait(timeout=75)
            reader.join(timeout=5)
            assert process.returncode == 0, _error(root, family, mode)
            result = None
            while not messages.empty():
                item = messages.get_nowait()
                if item is not None:
                    result = item
            return result
        finally:
            if process.poll() is None:
                descendants = psutil.Process(process.pid).children(recursive=True)
                process.kill()
                process.wait(timeout=15)
                for descendant in descendants:
                    try:
                        descendant.kill()
                    except psutil.NoSuchProcess:
                        pass
                psutil.wait_procs(descendants, timeout=15)
            reader.join(timeout=5)
            process.stdout.close()


def _error(root, family, mode):
    return (root / f"{family}-{mode}.stderr.txt").read_text(encoding="utf-8")


@pytest.mark.parametrize("boundary", ["wal", "before_snapshot", "after_snapshot", "after_retire"])
def test_concurrent_durable_wal_survives_process_death(tmp_path, boundary):
    result = _run_child(tmp_path, "state", boundary, kill=True)
    count = 120 if boundary == "wal" else 160
    assert result["seq"] == count
    recovered = _run_child(tmp_path, "state", "inspect")
    assert recovered["seq"] == count
    assert {Path(item["path"]).name for item in recovered["pending"]} == {
        f"source-{index}.dat" for index in range(count)}
    assert all(item["durable_owner"] for item in recovered["pending"])
    if boundary != "wal":
        assert recovered["checkpoint"] == (0 if boundary == "before_snapshot" else 120)
    _run_child(tmp_path, "state", "append")
    again = _run_child(tmp_path, "state", "inspect")
    assert again["seq"] == count + 1
    assert len(again["pending"]) == count + 1


def test_torn_final_wal_append_can_recover_and_continue(tmp_path):
    _run_child(tmp_path, "state", "wal", kill=True)
    [segment] = list(tmp_path.glob("state.journal.*.jsonl"))
    with segment.open("a", encoding="utf-8", newline="") as stream:
        stream.write('{"version":18,"seq":121,"operations":[')
        stream.flush()
        os.fsync(stream.fileno())
    assert _run_child(tmp_path, "state", "inspect")["seq"] == 120
    _run_child(tmp_path, "state", "append")
    recovered = _run_child(tmp_path, "state", "inspect")
    assert recovered["seq"] == 121
    assert len(recovered["pending"]) == 121


def _archive(root, kind):
    seven_zip = str(require_7z())
    payload = root / "payload"
    input_root = root / "input"
    payload.mkdir()
    input_root.mkdir()
    marker = payload / "wal-marker.txt"
    marker.write_text("WAL recovery verified\n" * 8192, encoding="utf-8")

    def pack(destination, source, *options):
        subprocess.run([seven_zip, "a", "-y", "-mx=0", *options, str(destination), str(source)],
                       check=True, capture_output=True, text=True)

    source = input_root / "disguised.video"
    if kind in {"nested", "nested_encrypted"}:
        inner = payload / "inner.data"
        if kind == "nested_encrypted":
            pack(inner, marker, "-t7z", "-pwal-test-secret", "-mhe=on")
        else:
            pack(inner, marker, "-tzip")
        pack(source, inner, "-tzip")
    elif kind == "encrypted":
        pack(source, marker, "-t7z", "-pwal-test-secret", "-mhe=on")
    elif kind == "split":
        source = input_root / "split.video"
        pack(source, marker, "-t7z", "-v64k")
        source = Path(str(source) + ".001")
    elif kind == "carrier":
        archive = root / "carrier.zip"
        pack(archive, marker, "-tzip")
        # Fixture binary I/O is delegated to an external runtime, never Python.
        script = ("$ErrorActionPreference='Stop'; "
                  "$d=[IO.File]::Create($env:WAL_CARRIER_DEST); "
                  "try { $p=[Text.Encoding]::UTF8.GetBytes(('prefix-' * 512)); "
                  "$d.Write($p,0,$p.Length); $s=[IO.File]::OpenRead($env:WAL_CARRIER_SRC); "
                  "try {$s.CopyTo($d)} finally {$s.Dispose()}; "
                  "$d.Write($p,0,$p.Length) } finally {$d.Dispose()}")
        subprocess.run(["powershell.exe", "-NoProfile", "-Command", script], check=True,
                       env={**os.environ, "WAL_CARRIER_SRC": str(archive), "WAL_CARRIER_DEST": str(source)},
                       capture_output=True, text=True)
    else:
        pack(source, marker, "-tzip")
    (root / "manifest.json").write_text(json.dumps({"sources": [str(source)]}), encoding="utf-8")
    return marker.read_text(encoding="utf-8")


@pytest.mark.requires_watch_broker
@pytest.mark.parametrize("kind", ["disguised", "nested", "encrypted", "split", "carrier"])
@pytest.mark.parametrize("boundary", ["started", "finished"])
def test_real_watch_extraction_recovers_after_process_death(tmp_path, kind, boundary):
    expected = _archive(tmp_path, kind)
    killed = _run_child(tmp_path, "watch", boundary, kill=True)
    assert killed["pending"]
    if boundary == "started":
        assert any(item["active_outputs"] for item in killed["pending"])
    else:
        assert any(item["committed_roots"] for item in killed["pending"])
    recovered = _run_child(tmp_path, "watch", "recover")
    assert recovered["pending"] == 0
    assert recovered["entries"] == []
    markers = list((tmp_path / "output").rglob("wal-marker.txt"))
    assert len(markers) == 1
    assert markers[0].read_text(encoding="utf-8") == expected
    assert not list((tmp_path / "output").rglob("crash-partial.txt"))
    # A second restart must neither duplicate extraction nor restore stale owners.
    assert _run_child(tmp_path, "watch", "recover")["pending"] == 0
    assert list((tmp_path / "output").rglob("wal-marker.txt")) == markers


@pytest.mark.requires_watch_broker
def test_multiple_watch_requests_recover_without_duplicate_outputs(tmp_path):
    sources = []
    for kind in ["disguised", "nested", "encrypted", "split", "carrier"]:
        directory = tmp_path / kind
        directory.mkdir()
        expected = _archive(directory, kind)
        sources.extend(json.loads((directory / "manifest.json").read_text(encoding="utf-8"))["sources"])
    (tmp_path / "manifest.json").write_text(json.dumps({"sources": sources}), encoding="utf-8")
    killed = _run_child(tmp_path, "watch", "concurrent", kill=True)
    assert killed["started"] == 5
    recovered = _run_child(tmp_path, "watch", "recover")
    assert recovered["pending"] == 0
    assert recovered["entries"] == []
    markers = list((tmp_path / "output").rglob("wal-marker.txt"))
    assert len(markers) == 5
    assert all(marker.read_text(encoding="utf-8") == expected for marker in markers)
    assert _run_child(tmp_path, "watch", "recover")["pending"] == 0
    assert list((tmp_path / "output").rglob("wal-marker.txt")) == markers


@pytest.mark.requires_watch_broker
@pytest.mark.parametrize("kind", ["encrypted", "nested_encrypted", "split", "split_disguised"])
def test_waiting_input_survives_death_and_retries_when_resolved(tmp_path, kind):
    expected = _archive(tmp_path, "split" if kind == "split_disguised" else kind)
    manifest_path = tmp_path / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    missing = None
    if kind in {"split", "split_disguised"}:
        parts = sorted((tmp_path / "input").glob("split.video.*"))
        if kind == "split":
            renamed = []
            for part in parts:
                destination = part.with_name(part.name.replace(".video.", ".7z."))
                part.rename(destination)
                renamed.append(destination)
            parts = renamed
            manifest["sources"] = [str(parts[0])]
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        # Keep the final 7z header available; the middle volume is absent.
        assert len(parts) >= 3
        missing = parts[1]
        missing.rename(tmp_path / "withheld-volume")
    else:
        manifest["unknown_password"] = True
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    killed = _run_child(tmp_path, "watch", "blocked", kill=True)
    expected_status = "suspended_missing_volume" if kind.startswith("split") else "failed_password"
    if kind.startswith("split"):
        assert killed["status"] in {expected_status, "untracked_missing_volume"}
    else:
        assert killed["status"] == expected_status
    # Password blockers survive, including nested retry sources. An incomplete
    # 7z may be unrecognizable; its later volume is recovered by the USN gap.
    still_blocked = _run_child(tmp_path, "watch", "recover")
    if killed["status"] != "untracked_missing_volume":
        assert any(item["status"] == expected_status for item in still_blocked["entries"])
    else:
        assert still_blocked["entries"] == []
    assert not list((tmp_path / "output").rglob("wal-marker.txt"))
    if missing is not None:
        (tmp_path / "withheld-volume").rename(missing)
    else:
        (tmp_path / "input" / "sunpack-passwords.txt").write_text("wal-test-secret\n", encoding="utf-8")
    recovered = _run_child(tmp_path, "watch", "recover")
    assert recovered["pending"] == 0
    assert recovered["entries"] == []
    [marker] = list((tmp_path / "output").rglob("wal-marker.txt"))
    assert marker.read_text(encoding="utf-8") == expected
