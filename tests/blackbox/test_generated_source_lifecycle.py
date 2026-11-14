"""Generated inventory is a dependency, not a permanent admission permission."""
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
from pathlib import Path
import random
import subprocess
from zipfile import ZipFile

import pytest
import psutil

from tests.real.plan7_watch_downloads.plan7_support import download, wait_for, watch_setup


def zip_bytes(entries):
    buffer = BytesIO()
    with ZipFile(buffer, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return buffer.getvalue()


@pytest.mark.requires_watch_broker
@pytest.mark.parametrize("gate", ["depth", "authorization"])
def test_unchanged_generated_inventory_does_not_enqueue_children(package, tmp_path, gate):
    watch = watch_setup(package, tmp_path, recursive=False, output_inside=False, start=False)
    package.configure(recursive_extract=1 if gate == "depth" else "*",
                      recursive_authorization={"enabled": gate == "authorization",
                          "byte_ratio_exponent": 1, "project_ratio_exponent": 1,
                          "minimum_authorization_score": 0.99})
    inner = zip_bytes({"forbidden.txt": b"must remain archived"})
    outer = tmp_path / "outer.zip"
    outer.write_bytes(zip_bytes({"inner.zip": inner, "ordinary.bin": b"x" * 100_000}))
    watch.start()
    source = download(watch, outer)
    watch.await_event("done", path=source.name)
    package.json("watch", "start", "--once", "--no-tray")
    watch.restart()
    package.json("watch", "start", "--once", "--no-tray")
    watch.stop()
    assert [p.read_bytes() for p in watch.output.rglob("inner.zip")] == [inner]
    assert not list(watch.output.rglob("forbidden.txt"))
    assert not any(Path(row.get("path", "")).name == "inner.zip"
                   and row["event"] == "candidate_active" for row in watch.display()["history"])


@pytest.mark.requires_watch_broker
@pytest.mark.parametrize("recursive,gate", [(False, "depth"), (True, "depth"), (False, "authorization")],
                         ids=["shallow-depth", "recursive-depth", "shallow-score"])
def test_raw_tail_arrival_resolves_generated_head_without_inheriting_its_old_gate(package, tmp_path, recursive, gate):
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    payload = fixtures / "completed.txt"
    payload.write_bytes(random.Random(875).randbytes(5000))
    subprocess.run([str(package.tools / "7z.exe"), "a", "-t7z", "-mx=0", "-v1k", "-mhe=on", "-psecret-key",
                    str(fixtures / "raw.7z"), str(payload)], check=True, capture_output=True)
    parts = [part.rename(part.with_name(part.name + ".blob")) for part in sorted(fixtures.glob("raw.7z.*"))]
    assert all(not part.read_bytes().startswith(b"7z\xbc\xaf\x27\x1c") for part in parts[1:])
    outer = fixtures / "outer.zip"
    outer.write_bytes(zip_bytes({parts[0].name: parts[0].read_bytes(), "ordinary.bin": b"x" * 100_000}))
    watch = watch_setup(package, tmp_path, passwords=["wrong"], recursive=recursive, output_inside=recursive, start=False)
    package.configure(recursive_extract=1 if gate == "depth" else "*",
                      recursive_authorization={"enabled": gate == "authorization",
                          "byte_ratio_exponent": 1, "project_ratio_exponent": 1,
                          "minimum_authorization_score": 0.99})
    watch.start()
    downloaded = download(watch, outer)
    watch.await_event("done", path=downloaded.name)
    package.json("watch", "start", "--once", "--no-tray")
    assert not list(watch.output.rglob(payload.name))
    head, = (path for path in watch.output.rglob(parts[0].name) if path.is_file())
    arrivals = [download(watch, part) for part in parts[1:]]
    watch.await_event("failed_password", path=parts[0].name)
    package.json("watch", "start", "--once", "--no-tray")
    watch.restart()
    watch.passwords(["secret-key"])
    package.json("watch", "start", "--once", "--no-tray")
    watch.stop()
    assert [path.read_bytes() for path in watch.output.rglob(payload.name)] == [payload.read_bytes()]
    assert not head.exists(), "the generated head is consumed under keep"
    assert downloaded.is_file() and all(path.is_file() for path in arrivals)


@pytest.mark.requires_watch_broker
@pytest.mark.parametrize("mutation", [None, "move", "replace", "rewrite", "directory"],
                         ids=["resume-depth", "moved-source", "replaced-source", "rewritten-source", "moved-parent"])
def test_in_place_recovery_expires_with_its_source(package, tmp_path, mutation):
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    (fixtures / "leaf.zip").write_bytes(zip_bytes({"third-level.txt": b"no extra recursive grant"}))
    locked = fixtures / "locked.7z"
    subprocess.run([str(package.tools / "7z.exe"), "a", "-t7z", "-mhe=on", "-psecret-key",
                    str(locked), "leaf.zip"], cwd=fixtures, check=True, capture_output=True)
    outer = fixtures / "outer.zip"
    outer.write_bytes(zip_bytes({locked.name: locked.read_bytes()}))
    watch = watch_setup(package, tmp_path, passwords=["wrong"], recursive=False,
                        output_inside=False, start=False)
    package.configure(recursive_extract=2)
    watch.start()
    source = download(watch, outer)
    blocker = watch.await_event("failed_password", path=locked.name)
    retained = Path(blocker["path"])
    assert retained.is_file() and retained.is_relative_to(watch.output)
    assert not (watch.root / locked.name).exists()
    if mutation in (None, "replace"):
        # A semantic reload must restore dependency subscriptions and retain
        # the original recovery budget even when the global limit increases.
        package.configure(recursive_extract=3)
        package.json("watch", "reload")
    if mutation == "move":
        retained.rename(retained.with_name("moved.7z"))
    elif mutation == "replace":
        replacement = tmp_path / "replacement.7z"
        replacement.write_bytes(locked.read_bytes())
        # Windows cannot overwrite a mapped destination. Publish a replacement
        # identity at the same path using the supported rename sequence.
        retained.rename(fixtures / "original.7z")
        replacement.replace(retained)
    elif mutation == "rewrite":
        retained.write_bytes(locked.read_bytes())
    elif mutation == "directory":
        state, = package.data.glob("runtime-*.state")
        owner = psutil.Process(int(state.read_text(encoding="utf-8").splitlines()[3]))
        workers = owner.children(recursive=True)
        watch.stop()
        assert package.run("--persistent-shutdown").returncode == 0
        owner.wait(timeout=30)
        for worker in workers:
            worker.wait(timeout=30)
        retained.parent.rename(retained.parent.with_name("moved-directory"))
        watch.start()
    if mutation:
        # This barrier precedes password changes/restart: invalidation must be
        # driven by the live observer, not deferred until the next retry.
        def recovery_retired():
            try:
                live = watch.display()["live"]
            except subprocess.CalledProcessError:
                return False  # The display store can be publishing its manifest.
            return not any(Path(row.get("path", "")) == retained for row in live)
        wait_for(recovery_retired, "live recovery retirement before retry")
    watch.passwords(["secret-key"])
    package.json("watch", "start", "--once", "--no-tray")
    watch.restart()
    package.json("watch", "start", "--once", "--no-tray")
    watch.stop()
    assert source.is_file(), "keep applies to the original outer source"
    assert not list(watch.output.rglob("third-level.txt")), "retry must preserve the remaining recursion depth"
    if mutation:
        assert not list(watch.output.rglob("leaf.zip")), "a changed source cannot inherit recovery permission"
    else:
        assert len(list(watch.output.rglob("leaf.zip"))) == 1
        assert not retained.exists(), "generated sources are consumed even under keep"


@pytest.mark.parametrize("cleanup", ["k", "d", "r"])
def test_source_cleanup_removes_only_its_empty_direct_parent(package, tmp_path, cleanup):
    ancestor = tmp_path / "ancestor"
    folder = ancestor / "source"
    folder.mkdir(parents=True)
    archive = folder / "archive.zip"
    archive.write_bytes(zip_bytes({"payload.txt": b"verified"}))
    package.json("extract", "-c", cleanup, "-o", tmp_path / "out", archive)
    assert archive.exists() == (cleanup == "k")
    assert folder.exists() == (cleanup == "k")
    assert ancestor.is_dir(), "cleanup never walks up to another parent"


@pytest.mark.parametrize("cleanup", ["d", "r"])
def test_source_cleanup_preserves_a_concurrent_parent_arrival(package, tmp_path, cleanup):
    folder = tmp_path / "source"
    folder.mkdir()
    payload = tmp_path / "payload.txt"
    payload.write_bytes(b"verified")
    source = folder / "archive.7z"
    subprocess.run([str(package.tools / "7z.exe"), "a", "-t7z", "-mhe=on", "-psecret-key",
                    str(source), str(payload)], check=True, capture_output=True)

    def await_password_prompt(stream):
        marker = "Enter new passwords and retry extraction?"
        tail = ""
        while character := stream.read(1):
            tail = (tail + character)[-len(marker):]
            if tail == marker:
                return True
        return False

    # A live task has already opened the archive in a single-file parent. Add
    # an unrelated child while that task is awaiting its password, then let
    # the same task finish cleanup. Parent emptiness cannot be cached early.
    command = [str(package.launcher), "extract", "-c", cleanup, "-o", str(tmp_path / "out"),
               "--no-builtin-pw", "--no-pause", "-p", "wrong", str(source)]
    with ThreadPoolExecutor(max_workers=1) as executor, subprocess.Popen(
        command, cwd=package.data, env=package.env, encoding="utf-8",
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ) as process:
        try:
            assert executor.submit(await_password_prompt, process.stdout).result(timeout=60)
            arrival = folder / "new-user-file.txt"
            arrival.write_bytes(b"external arrival")
            stdout, stderr = process.communicate("y\nsecret-key\n\n", timeout=60)
            assert process.returncode == 0, (stdout, stderr)
        finally:
            if process.poll() is None:
                process.kill()
    assert arrival.read_bytes() == b"external arrival"
    assert not source.exists()
