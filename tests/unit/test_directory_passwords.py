from types import SimpleNamespace

import os
import asyncio
import threading
import zipfile
from concurrent.futures import ThreadPoolExecutor
from threading import Event, Lock

from sunpack.core.passwords.directory_context import DirectoryPasswordContextStore
from sunpack.core.passwords.internal.clipboard import _plausible_passwords
from sunpack.core.passwords.internal.local_files import (
    DIRECTORY_PASSWORD_CONTEXT_KEY,
    discover_directory_passwords_for_archive,
    is_directory_password_file,
)


def test_discovers_same_directory_sunpack_passwords(tmp_path):
    archive = tmp_path / "archive.zip"
    archive.write_bytes(b"not really an archive")
    (tmp_path / "sunpack-passwords.txt").write_text("#secret\nouter-secret\n password \n\n", encoding="utf-8")

    assert discover_directory_passwords_for_archive(str(archive), {}) == ["#secret", "outer-secret", " password "]


def test_ignores_other_same_directory_txt_files(tmp_path):
    archive = tmp_path / "archive.zip"
    archive.write_bytes(b"not really an archive")
    (tmp_path / "passwords.txt").write_text("wrong-source\n", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("also-wrong\n", encoding="utf-8")

    assert discover_directory_passwords_for_archive(str(archive), {}) == []
    assert is_directory_password_file(str(tmp_path / "sunpack-passwords.txt"), {})
    assert not is_directory_password_file(str(tmp_path / "passwords.txt"), {})


def test_directory_password_context_inherits_and_extends(tmp_path):
    parent = tmp_path / "parent"
    parent.mkdir()
    child = parent / "child"
    child.mkdir()
    archive = child / "nested.zip"
    archive.write_bytes(b"not really an archive")
    (child / "sunpack-passwords.txt").write_text("inner-secret\nouter-secret\n", encoding="utf-8")

    store = DirectoryPasswordContextStore({})
    parent_task = SimpleNamespace(runtime={
        DIRECTORY_PASSWORD_CONTEXT_KEY: ["outer-secret"],
    })
    store.remember(str(parent), parent_task)
    task = SimpleNamespace(main_path=str(archive), runtime={})

    store.annotate([task])

    assert task.runtime[DIRECTORY_PASSWORD_CONTEXT_KEY] == ["outer-secret", "inner-secret"]


def test_clipboard_password_filter_rejects_obvious_non_text_payloads():
    assert _plausible_passwords(["ok", "bad\x00value", "x" * 600], max_password_length=512) == ["ok"]


def test_directory_password_batch_reuses_contents_and_invalidates_on_changes(tmp_path, monkeypatch):
    from sunpack.core.passwords.internal import local_files

    password_file = tmp_path / "SUNPACK-PASSWORDS.TXT"
    password_file.write_text("first\n", encoding="utf-8")
    original_stat = password_file.stat()
    reads = []
    read = local_files.read_password_file

    def capture(path):
        reads.append(path)
        return read(path)

    monkeypatch.setattr(local_files, "read_password_file", capture)
    store = DirectoryPasswordContextStore({})
    tasks = [SimpleNamespace(main_path=str(tmp_path / f"{index}.blob"), runtime={}) for index in range(1000)]
    store.annotate(tasks)
    store.annotate(tasks)
    assert len(reads) == 1
    assert all(task.runtime[DIRECTORY_PASSWORD_CONTEXT_KEY] == ["first"] for task in tasks)

    password_file.write_text("other\n", encoding="utf-8")
    os.utime(password_file, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
    store.annotate(tasks)
    assert len(reads) == 2
    assert all(task.runtime[DIRECTORY_PASSWORD_CONTEXT_KEY] == ["other"] for task in tasks)

    password_file.unlink()
    store.annotate(tasks)
    assert all(task.runtime[DIRECTORY_PASSWORD_CONTEXT_KEY] == [] for task in tasks)
    password_file.write_text("again\n", encoding="utf-8")
    store.annotate(tasks)
    assert len(reads) == 3
    assert all(task.runtime[DIRECTORY_PASSWORD_CONTEXT_KEY] == ["again"] for task in tasks)


def test_concurrent_directory_password_reads_share_one_load_without_blocking_other_directories(tmp_path, monkeypatch):
    from sunpack.core.passwords.internal import local_files

    slow_dir = tmp_path / "slow"
    fast_dir = tmp_path / "fast"
    for directory in (slow_dir, fast_dir):
        directory.mkdir()
        (directory / "sunpack-passwords.txt").write_text(directory.name, encoding="utf-8")
    store = DirectoryPasswordContextStore({})
    read = local_files.read_password_file
    entered, release = Event(), Event()
    reads = []
    lock = Lock()

    def capture(path):
        with lock:
            reads.append(path)
        if os.path.dirname(path) == os.path.normcase(str(slow_dir)):
            entered.set()
            assert release.wait(3)
        return read(path)

    monkeypatch.setattr(local_files, "read_password_file", capture)
    tasks = [SimpleNamespace(main_path=str(slow_dir / f"{index}.blob"), runtime={}) for index in range(8)]
    fast_task = SimpleNamespace(main_path=str(fast_dir / "item.blob"), runtime={})
    with ThreadPoolExecutor(max_workers=9) as pool:
        pending = [pool.submit(store.annotate, [task]) for task in tasks]
        try:
            assert entered.wait(2)
            pool.submit(store.annotate, [fast_task]).result(timeout=2)
            assert fast_task.runtime[DIRECTORY_PASSWORD_CONTEXT_KEY] == ["fast"]
        finally:
            release.set()
        for future in pending:
            future.result(timeout=2)
    assert len(reads) == 2
    assert all(task.runtime[DIRECTORY_PASSWORD_CONTEXT_KEY] == ["slow"] for task in tasks)


def test_pipeline_reads_directory_passwords_once_off_the_event_loop(tmp_path, monkeypatch):
    from sunpack.core.passwords.internal import local_files
    from sunpack.pipeline.coordinator.engine import PipelineEngine

    for name in ("first", "second"):
        with zipfile.ZipFile(tmp_path / f"{name}.zip", "w") as archive:
            archive.writestr("payload.txt", name)
    (tmp_path / "sunpack-passwords.txt").write_text("secret\n", encoding="utf-8")
    threads = []
    read = local_files.read_password_file

    def capture(path):
        threads.append(threading.get_ident())
        return read(path)

    monkeypatch.setattr(local_files, "read_password_file", capture)

    async def scenario():
        owner = threading.get_ident()
        async with PipelineEngine({"post_extract": {"archive_cleanup_mode": "keep"}}) as engine:
            response = await engine.run([str(tmp_path)])
            assert response.summary.success_count == 2
        assert len(threads) == 1
        assert threads[0] != owner

    asyncio.run(scenario())
