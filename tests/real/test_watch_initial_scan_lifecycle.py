"""Scan flag and split recovery coverage through one live runtime lifecycle."""
from __future__ import annotations

import io
import shutil
import zipfile
from pathlib import Path

import pytest

from tests.helpers.marker_utils import marker_present
from tests.real.plan7_watch_downloads.plan7_support import (
    FACTORY, PASSWORD, Watch, download, wait_for, write_passwords,
)


pytestmark = pytest.mark.requires_watch_broker


def test_scan_flags_survive_live_edits_restart_and_split_recovery(package, tmp_path):
    fixtures = tmp_path / "fixtures"
    inner = FACTORY.create(fixtures, "nested", "7z", password=PASSWORD, payload_size=16 * 1024)
    ignored = FACTORY.create(fixtures, "already-scanned", "zip", payload_size=8 * 1024)
    split = FACTORY.create(
        fixtures, "partial", "7z", password=PASSWORD, split=True,
        payload_size=128 * 1024, split_volume_size=48 * 1024,
    )
    old, pending, added = [
        Watch(package, tmp_path / name, tmp_path / f"{name}-out")
        for name in ("old", "pending", "added")
    ]
    for watch in (old, pending, added):
        watch.root.mkdir()
    shutil.copy2(ignored.entry_path, old.root / "old.zip")
    carrier = io.BytesIO()
    with zipfile.ZipFile(carrier, "w") as archive:
        archive.write(inner.entry_path, "hidden.payload")
    (pending.root / "carrier.data").write_bytes(b"carrier-prefix\0" + carrier.getvalue() + b"carrier-tail\0")
    volumes = sorted(split.archive_dir.glob("*.7z.*"))
    assert len(volumes) >= 2
    for volume in volumes[:-1]:
        shutil.copy2(volume, added.root / volume.name.replace(".7z.", ".opaque."))

    roots_file = package.data / "sunpack_watch_roots.txt"

    def save_roots(text):
        next_file = roots_file.with_suffix(".tmp")
        next_file.write_text(text, encoding="utf-8")
        next_file.replace(roots_file)

    def scan_events():
        return [
            [Path(root).name.lower() for root in row["roots"]]
            for row in pending.display()["history"]
            if row["event"] == "initial_scan_completed"
        ]

    def scanned_count():
        return sum(
            line.split("|")[3].strip() == "true" for line in roots_file.read_text(encoding="utf-8").splitlines()
            if "|" in line
        )

    package.configure(recursive_extract="*")
    write_passwords(package, tmp_path, ["wrong", PASSWORD])
    save_roots(f"{old.root} | {old.output} | false | true\n{pending.root} | {pending.output} | true\n")
    generation = pending.start()["generation"]
    pending.await_archive(inner)
    wait_for(lambda: scan_events() == [["pending"]] and scanned_count() == 2, "one pending-root scan")
    assert not marker_present(old.output, ignored.marker_name)

    alias = str(pending.root).upper().replace("\\", "/") + "/."
    save_roots(
        f"# policy-neutral edit\n{alias} | {str(pending.output).upper()} | true | true\n"
        f"{old.root} | {old.output} | false | true\n"
    )
    assert package.json("watch", "reload")["summary"]["generation"] == generation
    assert scan_events() == [["pending"]]
    assert not marker_present(old.output, ignored.marker_name)

    save_roots(f"{pending.root} | {pending.output} | true | true\n{old.root} | {old.output} | false | false\n")
    old.await_archive(ignored)
    wait_for(lambda: scan_events() == [["pending"], ["old"]], "live scan-flag reset")
    assert package.json("watch", "status")["summary"]["generation"] == generation

    package.json("watch", "add", "-d", "-o", added.output, added.root)
    added.await_event("suspended_missing_volume", path=volumes[0].name.replace(".7z.", ".opaque."))
    assert scanned_count() == 3
    assert scan_events() == [["pending"], ["old"], ["added"]]
    pending.restart()

    last = fixtures / volumes[-1].name.replace(".7z.", ".opaque.")
    shutil.copy2(volumes[-1], last)
    download(added, last)
    added.await_archive(split)
    pending.stop()
    assert scan_events() == [["pending"], ["old"], ["added"]]
    assert scanned_count() == 3
    assert len(list(added.output.rglob(split.marker_name))) == 1
