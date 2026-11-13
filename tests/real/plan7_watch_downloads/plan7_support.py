from __future__ import annotations

import json
import os
import random
import shutil
import subprocess
import time
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path

import psutil
import pytest

from tests.helpers.marker_utils import marker_was_extracted, open_shared_file
from tests.helpers.native_fixture import file_inventory, native_fixture
from tests.helpers.real_archives import ArchiveFixtureFactory, STREAM_FORMATS
from tests.real.archive_boundary import assert_extracted


PASSWORD = "sunpack-plan7-acceptance"
WRONG_PASSWORDS = tuple(f"wrong-{index:02d}" for index in range(24))
DOWNLOAD_CHUNK_SIZE = 16 * 1024
FACTORY = ArchiveFixtureFactory()


@dataclass
class Watch:
    package: object
    root: Path
    output: Path

    @property
    def event_file(self):
        return self.package.data / ".sunpack_watch" / "events.json"

    def start(self):
        return self.package.json("watch", "start", "--no-tray")["summary"]

    def stop(self):
        assert self.package.json("watch", "stop")["summary"]["stopped"]

    def restart(self):
        self.stop()
        assert self.package.run("--persistent-shutdown").returncode == 0
        return self.start()

    def passwords(self, passwords):
        write_passwords(self.package, self.root, passwords)

    def display(self):
        return native_fixture("display_events", path=str(self.event_file))

    def event(self, kind, *, path=None):
        if not self.event_file.is_file():
            return None
        try:
            display = self.display()
            rows = (*display["history"], *display["live"])
        except subprocess.CalledProcessError:
            return None
        return next((row for row in rows if row["event"] == kind and (
            path is None or Path(row.get("path", "")).name == path
        )), None)

    def await_event(self, kind, *, path=None):
        return wait_for(lambda: self.event(kind, path=path), f"Watch event {kind} for {path}", timeout=15)

    def await_archive(self, case):
        wait_for(
            lambda: marker_was_extracted(self.output, case.marker_name, case.marker_text),
            f"Watch output for {case.case_id}",
        )

    def assert_no_terminal_failures(self):
        failures = [
            row for row in self.display()["history"]
            if row["event"] in {"failed_terminal", "error"}
        ]
        assert not failures, failures

    def memory(self):
        state, = self.package.data.glob("runtime-*.state")
        owner = psutil.Process(int(state.read_text(encoding="utf-8").splitlines()[3]))
        children = [child for child in owner.children(recursive=True)
                    if child.name() == "sunpack_sevenzip_worker.exe"]
        return owner.memory_info().rss, sum(child.memory_info().rss for child in children), len(children)


def write_passwords(package, root, passwords):
    path = package.data / "builtin_passwords.json"
    pending = path.with_suffix(".tmp")
    entries = [{"value": password, "scopes": [str(root)]} for password in passwords]
    pending.write_text(json.dumps({"passwords": entries}), encoding="utf-8")
    pending.replace(path)


def watch_setup(package, base, *, passwords=(*WRONG_PASSWORDS, PASSWORD),
                cleanup="k", flatten=False, recursive=False, start=True):
    root = base / "watch"
    output = base / "out"
    root.mkdir(parents=True, exist_ok=True)
    package.configure(
        recursive_extract="*",
        post_extract={"archive_cleanup_mode": cleanup, "flatten_single_directory": flatten},
    )
    write_passwords(package, root, passwords)
    arguments = ["-R"] if recursive else []
    package.json("watch", "add", "-d", *arguments, root, "-o", output)
    watch = Watch(package, root, output)
    if start:
        watch.start()
    return watch


def wait_for(condition, description, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = condition()
        if value:
            return value
        time.sleep(0.025)
    pytest.fail(f"Did not observe {description}")


def download(watch, source, *, mode="rename", directory=None, interrupt=False, resume=False):
    directory = directory or watch.root
    directory.mkdir(parents=True, exist_ok=True)
    final = directory / source.name
    pending = final.with_name(f"{final.name}.downloading") if mode == "rename" else final
    offset = pending.stat().st_size if resume else 0
    with source.open("rb") as reader, open_shared_file(pending, "ab" if resume else "wb") as writer:
        reader.seek(offset)
        while data := reader.read(DOWNLOAD_CHUNK_SIZE):
            writer.write(data)
            writer.flush()
            os.fsync(writer.fileno())
            if interrupt:
                return pending
            time.sleep(0.001)
        # Keep write ownership through publication. main's readiness probe
        # denies rename after the writer closes, so close-then-rename races it.
        if pending != final:
            pending.replace(final)
    return final


def download_interleaved(watch, sources, *, mode="rename", separate=False):
    with ExitStack() as handles:
        streams = []
        for index, source in enumerate(sources):
            directory = watch.root / f"download-{index}" if separate else watch.root
            directory.mkdir(parents=True, exist_ok=True)
            final = directory / source.name
            pending = final.with_name(f"{final.name}.downloading") if mode == "rename" else final
            reader = handles.enter_context(source.open("rb"))
            writer = handles.enter_context(open_shared_file(pending, "wb"))
            streams.append((reader, writer, pending, final))
        active = streams.copy()
        while active:
            for stream in active.copy():
                reader, writer, pending, final = stream
                if data := reader.read(DOWNLOAD_CHUNK_SIZE):
                    writer.write(data)
                    writer.flush()
                    os.fsync(writer.fileno())
                else:
                    if pending != final:
                        pending.replace(final)
                    writer.close()
                    active.remove(stream)
            time.sleep(0.001)
        return [final for _, _, _, final in streams]


def split_order(case, *, order="head_last", seed=7):
    parts = sorted(path for path in case.archive_dir.iterdir() if path.is_file())
    companion = [path for path in parts if case.sfx and case.archive_format in {"zip", "7z"}
                 and path.suffix.lower() == ".exe"]
    volumes = [path for path in parts if path not in companion]
    head = case.entry_path if case.entry_path in volumes else volumes[0]
    rest = [path for path in volumes if path != head]
    random.Random(seed).shuffle(rest)
    if order == "launcher_first":
        return [*companion, *rest, head]
    if order == "head_first":
        return [head, *rest, *companion]
    return [*rest, head, *companion]


def assert_once(watch, case):
    assert_extracted(case, watch.output)
    if case.archive_format in STREAM_FORMATS:
        expected, = case.metadata["expected_files"].values()
        matches = [path for path, entry in file_inventory(watch.output).items() if entry == expected]
    else:
        matches = list(watch.output.rglob(case.marker_name))
    assert len(matches) == 1, (case.case_id, matches)


def stage_initial(watch, source):
    shutil.copy2(source, watch.root / source.name)
