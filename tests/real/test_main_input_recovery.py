"""Source replacement and nested in-place recovery through real entry points."""

import os
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from tests.helpers.native_fixture import assemble_carrier, assert_exact_tree
from tests.real.archive_boundary import extract_report, failure_kinds
from tests.real.plan7_watch_downloads.plan7_support import FACTORY, download, wait_for, watch_setup


WATCH = pytest.param("watch", marks=pytest.mark.requires_watch_broker)


@pytest.mark.parametrize("entry_mode", ["cli", WATCH])
def test_replaced_carrier_with_same_length_and_mtime_gets_rediscovered(package, tmp_path, entry_mode):
    # Both generations contain the same encrypted extent. The new generation
    # changes its plain ZIP peer without changing file size or timestamps.
    secret = "replacement-key"
    locked = FACTORY.create(tmp_path / "fixtures", "locked", "7z", password=secret, payload_size=8 * 1024)
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"
    for archive, name, payload in ((first, "before.txt", b"generation A"), (second, "after_.txt", b"generation B")):
        with ZipFile(archive, "w") as peer:
            peer.writestr(name, payload)
    source = tmp_path / "carrier.图片"
    replacement = tmp_path / "replacement"
    for target, peer in ((source, first), (replacement, second)):
        assemble_carrier(target, [locked.entry_path, peer], seed=75)
    assert replacement.stat().st_size == source.stat().st_size
    output = tmp_path / "out"
    if entry_mode == "cli":
        report = extract_report(package, source, output, passwords=["wrong"], cleanup="d", code=1)
        failure, = report["tasks"][0]["failures"]
        assert any(cause["kind"] == "wrong_password" for cause in failure["causes"]) or (
            failure["kind"] == "wrong_password"
        ), report
    else:
        watch = watch_setup(package, tmp_path, passwords=["wrong"], cleanup="d")
        source = download(watch, source)
        watch.await_event("failed_password", path=source.name)
        watch.stop()
    before, = output.rglob("before.txt")
    assert before.read_bytes() == b"generation A"
    assert not list(output.rglob(locked.marker_name))

    original = source.stat()
    os.utime(replacement, ns=(original.st_atime_ns, original.st_mtime_ns))
    # Keep the old file at a different path. Windows allows renaming an open
    # file with delete sharing but can reject replacing it in place.
    source.rename(tmp_path / "previous-generation")
    replacement.rename(source)
    assert source.stat().st_ino != original.st_ino
    assert source.stat().st_mtime_ns == original.st_mtime_ns

    if entry_mode == "cli":
        report = extract_report(package, source, output, passwords=[secret], cleanup="d")
        assert report["summary"]["success_count"] == 1, report
    else:
        assert package.run("--persistent-shutdown").returncode == 0
        watch.passwords([secret])
        watch.start()
        watch.await_archive(locked)
        watch.stop()
        watch.assert_no_terminal_failures()
    assert [path.read_bytes() for path in output.rglob("before.txt")] == [b"generation A"]
    assert [path.read_bytes() for path in output.rglob("after_.txt")] == [b"generation B"]
    marker, = output.rglob(locked.marker_name)
    assert_exact_tree(marker.parent, locked.metadata["expected_files"])
    assert not source.exists()


@pytest.mark.parametrize("entry_mode", ["cli", WATCH])
@pytest.mark.parametrize("layout", ["carrier", "split", "wrapped-split-head"])
def test_retained_carrier_retries_without_touching_user_file(package, tmp_path, entry_mode, layout):
    secret = "recovery-key"
    split = layout != "carrier"
    locked = FACTORY.create(
        tmp_path / "fixtures", "inner", "7z", password=secret, split=split,
        payload_size=16 * 1024, split_volume_size=7 * 1024,
    )
    if split:
        head, middle, tail = sorted(locked.archive_dir.iterdir())
    inner = tmp_path / ("inner.7z.001.opaque" if split else "inner.opaque")
    if layout == "split":
        inner.write_bytes(head.read_bytes())
    else:
        assemble_carrier(inner, [locked.entry_path], seed=76)
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    outer = inputs / "wrapper.zip"
    with ZipFile(outer, "w", compression=ZIP_DEFLATED) as archive:
        archive.write(inner, inner.name)
        if split:
            archive.write(middle, f"{middle.name}.opaque")
        archive.writestr("outer.txt", b"successful outer archive")
    original = b"preexisting user data"
    package.configure(recursive_authorization={"enabled": False})
    output = tmp_path / "out"
    if entry_mode == "cli":
        collision = inputs / inner.name
        collision.write_bytes(original)
        report = extract_report(package, outer, output, passwords=["wrong"], code=1)
        expected = {"missing_volume"} if split else {"wrong_password"}
        assert failure_kinds(report) == expected, report
        failure, = report["tasks"][0]["failures"]
        retained = Path(failure["details"]["path"])
    else:
        watch = watch_setup(package, tmp_path, passwords=["wrong"])
        collision = watch.root / inner.name
        collision.write_bytes(original)
        outer = download(watch, outer)
        status = "suspended_missing_volume" if split else "failed_password"
        blocker = watch.await_event(status)
        retained = Path(blocker["path"])
    assert retained.is_relative_to(output) and retained != collision
    assert retained.read_bytes() == inner.read_bytes()
    assert collision.read_bytes() == original
    assert not list(output.rglob(locked.marker_name))

    if split:
        tail = tail.rename(tail.with_name(f"{tail.name}.opaque"))
        if entry_mode == "cli":
            tail = tail.rename(retained.parent / tail.name)
        else:
            if layout == "wrapped-split-head":
                # Drain the retry at a real Watch boundary so a persistent
                # missing-volume result fails with evidence, not a long wait.
                watch.stop()
            delivered_tail = download(watch, tail, mode="direct")
    if entry_mode == "cli":
        report = extract_report(package, retained, output, passwords=[secret], cleanup="d", code=(0, 1))
        assert report["summary"]["success_count"] == 1, (
            failure_kinds(report), [str(path) for path in output.rglob("inner.7z.002.opaque")],
        )
        assert report["summary"]["failed_count"] == 0, report
    elif layout == "wrapped-split-head":
        watch.passwords([secret])
        package.json("watch", "start", "--once", "--no-tray")
        assert list(output.rglob(locked.marker_name)), (
            [row for row in watch.display()["live"] if row["event"] == "suspended_missing_volume"],
            [str(path) for path in output.rglob("inner.7z.002.opaque")],
        )
        watch.assert_no_terminal_failures()
    else:
        watch.passwords([secret])
        watch.await_archive(locked)
        wait_for(lambda: not retained.exists(), "cleanup of the retained archive")
        watch.stop()
        watch.assert_no_terminal_failures()
    assert [path.read_bytes() for path in output.rglob("outer.txt")] == [b"successful outer archive"]
    marker, = output.rglob(locked.marker_name)
    assert_exact_tree(marker.parent, locked.metadata["expected_files"])
    assert not retained.exists()
    assert collision.read_bytes() == original
    assert outer.is_file()
    if split:
        assert not list(collision.parent.glob("inner.7z.002.opaque*"))
        if entry_mode == "watch":
            assert delivered_tail.read_bytes() == tail.read_bytes()
        else:
            assert not tail.exists()


@pytest.mark.requires_watch_broker
def test_watch_recovers_retained_password_and_missing_volume_blockers_in_separate_steps(package, tmp_path):
    # Main's discovery-failure recovery mixes a password blocker found in a
    # carrier, a directly detected encrypted input, and a missing-volume set.
    secret = "nested-recovery-key"
    fixtures = tmp_path / "fixtures"
    wrapped = FACTORY.create(fixtures, "wrapped", "7z", password=secret, payload_size=8 * 1024)
    direct = FACTORY.create(fixtures, "direct", "zip", password=secret, payload_size=8 * 1024)
    split = FACTORY.create(fixtures, "split", "7z", split=True,
                           payload_size=62 * 1024, split_volume_size=24 * 1024)
    head, middle, tail = sorted(split.archive_dir.iterdir())
    carrier = tmp_path / "wrapped.图片"
    assemble_carrier(carrier, [wrapped.entry_path], seed=77)
    outer = tmp_path / "outer.zip"
    with ZipFile(outer, "w", compression=ZIP_DEFLATED) as archive:
        archive.write(carrier, carrier.name)
        archive.write(direct.entry_path, "direct.图片")
        for part in (head, middle):
            archive.write(part, f"{part.name}.图片")
        archive.writestr("outer.txt", b"complete outer output")

    package.configure(
        recursive_authorization={"enabled": False}, embedded_scan={"recursive_candidate_ratio": 0.01},
    )
    watch = watch_setup(package, tmp_path, passwords=["wrong"], flatten=True)
    outer = download(watch, outer)
    retained = [Path(watch.await_event("failed_password", path=name)["path"])
                for name in (carrier.name, "direct.图片")]
    split_head = f"{head.name}.图片"
    blocked = Path(watch.await_event("suspended_missing_volume", path=split_head)["path"])
    assert all(path.is_relative_to(watch.output) and path.is_file() for path in [*retained, blocked])
    assert all(not list(watch.output.rglob(case.marker_name)) for case in (wrapped, direct, split))
    watch.restart()

    watch.passwords([secret])
    for case in (wrapped, direct):
        watch.await_archive(case)
    wait_for(lambda: not any(path.exists() for path in retained), "cleanup of password retries")
    assert blocked.is_file() and not list(watch.output.rglob(split.marker_name))
    renamed_tail = tail.rename(tail.with_name(f"{tail.name}.图片"))
    delivered_tail = download(watch, renamed_tail, mode="direct")
    watch.await_archive(split)
    watch.stop()

    for case in (wrapped, direct, split):
        marker, = watch.output.rglob(case.marker_name)
        assert_exact_tree(marker.parent, case.metadata["expected_files"])
    assert [path.read_bytes() for path in watch.output.rglob("outer.txt")] == [b"complete outer output"]
    assert not blocked.exists()
    assert delivered_tail.read_bytes() == renamed_tail.read_bytes()
    assert set(watch.root.iterdir()) == {outer, delivered_tail}
    watch.assert_no_terminal_failures()
