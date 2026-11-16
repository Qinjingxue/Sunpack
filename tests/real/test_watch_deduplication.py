"""Live logical-input deduplication, not an extraction-success history cache."""

import os
import shutil
import time
from pathlib import Path
from zipfile import ZipFile

import pytest

from tests.helpers.native_fixture import assemble_carrier
from tests.real.plan7_watch_downloads.plan7_support import FACTORY, download, watch_setup


pytestmark = pytest.mark.requires_watch_broker


def _switch(watch, mode):
    after = time.time()
    watch.package.configure(watch={"deduplication": mode})
    watch.package.await_watch_event("service_reloaded", after=after)


def _copy(source, destination):
    # Publish only completed contents, so these tests isolate admission rather
    # than repeating the existing writer/quiet-boundary matrix.
    pending = destination.with_name(destination.name + ".downloading")
    shutil.copyfile(source, pending)
    pending.replace(destination)
    return destination


def _duplicate(watch, path):
    watch.await_event("watch_deduplicated", path=path.name)
    assert path.is_file(), "Deduplication must not clean skipped sources"
    assert watch.event("done", path=path.name) is None
    rows = [row for row in _history(watch) if Path(row.get("path", "")) == path]
    assert sum(row["event"] == "watch_deduplicated" for row in rows) == 1
    assert not any(row["event"] == "no_tasks_found" for row in rows)


def _history(watch):
    display = watch.display()
    return [*display["history"], *display["live"]]


def test_watch_deduplication_modes_retry_presence_and_restart(package, tmp_path):
    # One lifecycle covers distinct contracts: no-op mode, identity versus
    # content equivalence, failed owner retry, mode rebuild, durable replay,
    # and removal of the final live representative. No output-success cache
    # can satisfy all of these checks.
    source = tmp_path / "ordinary.zip"
    with ZipFile(source, "w") as archive:
        archive.writestr("ordinary-marker.txt", b"ordinary payload")
    secret = FACTORY.create(tmp_path / "fixtures", "secret", "zip", password="secret-key")
    package.configure(watch={"deduplication": "none"})
    watch = watch_setup(package, tmp_path, passwords=["wrong-key"])
    ordinary = download(watch, source)
    watch.await_event("done", path=ordinary.name)
    link_none = watch.root / "none-link.zip"
    os.link(ordinary, link_none)
    watch.await_event("done", path=link_none.name)

    _switch(watch, "file_id")
    link_identity = watch.root / "identity-link.zip"
    os.link(ordinary, link_identity)
    _duplicate(watch, link_identity)
    # Equal bytes in a distinct file are not identity duplicates.
    copy_identity = _copy(source, watch.root / "identity-copy.zip")
    watch.await_event("done", path=copy_identity.name)

    owner = download(watch, secret.entry_path)
    watch.await_event("failed_password", path=owner.name)
    failed_link = watch.root / "failed-owner-link.zip"
    os.link(owner, failed_link)
    _duplicate(watch, failed_link)
    # A rebuilt index may pick another equal path first. The persisted password
    # recovery owner must retain its permission to finish its existing task.
    _switch(watch, "hash")
    watch.passwords(["secret-key"])
    watch.await_archive(secret)
    watch.await_event("done", path=owner.name)
    assert len(list(watch.output.rglob(secret.marker_name))) == 1

    copy_hash = _copy(source, watch.root / "hash-copy.zip")
    _duplicate(watch, copy_hash)
    assert len(list(watch.output.rglob("ordinary-marker.txt"))) == 3

    restarted = time.time()
    watch.restart()
    copy_restart = _copy(source, watch.root / "restart-copy.zip")
    _duplicate(watch, copy_restart)
    assert not [row for row in _history(watch)
                if row["event"] == "watch_dedup_rebuilt" and row["ts"] > restarted]

    # All aliases/copies leave the monitored scope. Keeping the output is
    # deliberately irrelevant: a future download must be processed again.
    for path in (ordinary, link_none, link_identity, copy_identity, copy_hash, copy_restart):
        path.unlink()
    watch.restart()
    fresh = _copy(source, watch.root / "fresh-after-removal.zip")
    watch.await_event("done", path=fresh.name)
    assert len(list(watch.output.rglob("ordinary-marker.txt"))) == 4

    _switch(watch, "none")
    again = _copy(source, watch.root / "none-again.zip")
    watch.await_event("done", path=again.name)
    watch.stop()
    assert len(list(watch.output.rglob("ordinary-marker.txt"))) == 5
    assert not (package.data / ".sunpack_watch" / "dedup.wal.bin").exists()
    watch.assert_no_terminal_failures()


def test_watch_deduplication_waits_for_a_determined_split_input(package, tmp_path):
    # Whole-family hashing must include all ordered volumes. A matching head
    # on its own is not enough to suppress a missing-volume proposal; once
    # complete, an exact copy can be suppressed without extracting it again.
    case = FACTORY.create(
        tmp_path / "fixtures", "split-dedup", "7z", split=True,
        payload_size=104 * 1024, split_volume_size=40 * 1024,
    )
    parts = sorted(case.archive_dir.iterdir())
    assert len(parts) >= 3 and parts[0] == case.entry_path
    package.configure(watch={"deduplication": "hash"})
    watch = watch_setup(package, tmp_path, recursive=True)
    initial = tmp_path / "initial"
    shutil.copytree(case.archive_dir, initial)
    initial = initial.rename(watch.root / "initial")
    package.await_watch_event("done", path=parts[0].name, root=initial)
    watch.await_archive(case)

    later = watch.root / "later"
    later.mkdir()
    head = download(watch, parts[0], directory=later)
    package.await_watch_event("suspended_missing_volume", path=head.name, root=later)
    assert not [row for row in _history(watch) if row["event"] == "watch_deduplicated"
                and Path(row.get("path", "")) == head]
    for part in parts[1:]:
        download(watch, part, directory=later)
    package.await_watch_event("watch_deduplicated", path=head.name, root=later)
    watch.stop()
    assert len(list(watch.output.rglob(case.marker_name))) == 1
    assert all((later / part.name).is_file() for part in parts)
    watch.assert_no_terminal_failures()


def test_watch_hash_deduplicates_effective_ranges_not_carrier_padding_or_subsets(package, tmp_path):
    # A whole-file hash misses equal effective ranges at different offsets;
    # a per-segment admission cache incorrectly drops the new sibling in A+B.
    # Both errors are invisible to the ordinary-file and fixed-volume tests.
    fixtures = tmp_path / "fixtures"
    a = FACTORY.create(fixtures, "range-a", "7z", payload_size=48 * 1024)
    b = FACTORY.create(fixtures, "range-b", "zip", payload_size=40 * 1024)
    source = tmp_path / "carrier-a.bin"
    alias = tmp_path / "carrier-a-other-padding.bin"
    combined = tmp_path / "carrier-a-plus-b.bin"
    combined_alias = tmp_path / "carrier-a-plus-b-other-padding.bin"
    assemble_carrier(source, [a.entry_path], seed=101, prefix_lengths=[257])
    assemble_carrier(alias, [a.entry_path], seed=102, prefix_lengths=[4099])
    assemble_carrier(combined, [a.entry_path, b.entry_path], seed=103, prefix_lengths=[521, 1031])
    assemble_carrier(combined_alias, [a.entry_path, b.entry_path], seed=104, prefix_lengths=[2053, 4099])
    assert source.read_bytes() != alias.read_bytes()
    assert combined.read_bytes() != combined_alias.read_bytes()
    package.configure(watch={"deduplication": "hash"})
    watch = watch_setup(package, tmp_path)

    owner = download(watch, source)
    watch.await_event("done", path=owner.name)
    watch.await_archive(a)
    duplicate = download(watch, alias)
    _duplicate(watch, duplicate)
    assert len(list(watch.output.rglob(a.marker_name))) == 1

    # The already-seen A is only a subset of this physical carrier's task.
    # Preserve normal whole-task behavior, including both independent outputs.
    both = download(watch, combined)
    watch.await_event("done", path=both.name)
    watch.await_archive(b)
    assert watch.event("watch_deduplicated", path=both.name) is None
    assert len(list(watch.output.rglob(a.marker_name))) == 2
    assert len(list(watch.output.rglob(b.marker_name))) == 1

    both_duplicate = download(watch, combined_alias)
    _duplicate(watch, both_duplicate)
    watch.stop()
    assert len(list(watch.output.rglob(a.marker_name))) == 2
    assert len(list(watch.output.rglob(b.marker_name))) == 1
    assert all(path.is_file() for path in (owner, duplicate, both, both_duplicate))
    watch.assert_no_terminal_failures()


def test_watch_hash_scope_lifecycle_and_nested_root_ownership(package, tmp_path):
    # One running daemon proves namespace selection, representative turnover,
    # scope retirement and overlapping-root ownership. Distinct payloads avoid
    # confusing a real duplicate with a root projection/self-admission error.
    def archive(name):
        path = tmp_path / f"{name}.zip"
        with ZipFile(path, "w") as output:
            output.writestr(f"{name}-marker.txt", name.encode())
        return path

    a, b, c = (archive(name) for name in ("scope-a", "scope-b", "scope-c"))
    package.configure(watch={"deduplication": "hash"})  # default scope is root
    watch = watch_setup(package, tmp_path, recursive=True)
    second = tmp_path / "second-root"
    second.mkdir()
    second_output = tmp_path / "second-output"
    package.json("watch", "add", "-R", "-d", second, "-o", second_output)

    first_owner = _copy(a, watch.root / "a-original.zip")
    watch.await_event("done", path=first_owner.name)
    second_owner = _copy(a, second / "a-other-root.zip")
    watch.await_event("done", path=second_owner.name)
    assert len(list(watch.output.rglob("scope-a-marker.txt"))) == 1
    assert len(list(second_output.rglob("scope-a-marker.txt"))) == 1

    after = time.time()
    package.configure(watch={"deduplication_scope": "global"})
    package.await_watch_event("service_reloaded", after=after)
    duplicate = _copy(a, second / "a-global-copy.zip")
    _duplicate(watch, duplicate)

    # The first representative leaves the monitored namespace. A surviving
    # duplicate is itself a live representative, even though never extracted.
    first_owner.rename(tmp_path / "a-moved-out.zip")
    second_owner.unlink()
    survivor_peer = _copy(a, second / "a-survivor-peer.zip")
    _duplicate(watch, survivor_peer)
    assert len(list(second_output.rglob("scope-a-marker.txt"))) == 1

    only_second = _copy(b, second / "b-only-second-root.zip")
    watch.await_event("done", path=only_second.name)
    package.json("watch", "remove", second)
    assert only_second.is_file(), "removing a Watch root does not delete its files"
    watch.restart()
    fresh_a = _copy(a, watch.root / "a-after-scopes-left.zip")
    fresh_b = _copy(b, watch.root / "b-after-root-removed.zip")
    watch.await_event("done", path=fresh_a.name)
    watch.await_event("done", path=fresh_b.name)
    assert watch.event("watch_deduplicated", path=fresh_a.name) is None
    assert watch.event("watch_deduplicated", path=fresh_b.name) is None

    # Explicit pause absorbs offline changes, but cannot keep an index entry
    # alive after its final source moved out. Resume validates without rehash.
    package.json("watch", "disable")
    fresh_b.rename(tmp_path / "b-moved-while-disabled.zip")
    package.json("watch", "enable")
    resumed_b = _copy(b, watch.root / "b-after-disabled-removal.zip")
    watch.await_event("done", path=resumed_b.name)
    assert watch.event("watch_deduplicated", path=resumed_b.name) is None

    # A nested root replaces its parent's membership for this same path; two
    # overlapping observers must not turn one new archive into its own duplicate.
    nested = watch.root / "nested"
    nested.mkdir()
    nested_output = tmp_path / "nested-output"
    package.json("watch", "add", "-R", "-d", nested, "-o", nested_output)
    nested_input = _copy(c, nested / "c-nested-root.zip")
    watch.await_event("done", path=nested_input.name)
    watch.stop()
    rows = [row for row in _history(watch) if Path(row.get("path", "")) == nested_input]
    assert sum(row["event"] == "done" for row in rows) == 1
    assert not any(row["event"] == "watch_deduplicated" for row in rows)
    assert len(list(nested_output.rglob("scope-c-marker.txt"))) == 1
    assert not list(watch.output.rglob("scope-c-marker.txt"))
    assert len(list(watch.output.rglob("scope-a-marker.txt"))) == 2
    assert len(list(watch.output.rglob("scope-b-marker.txt"))) == 2
    watch.assert_no_terminal_failures()


def test_watch_hash_matches_whole_carrier_and_differently_split_byte_streams(package, tmp_path):
    # Unlike the carrier-vs-carrier regression, these paths previously had
    # different open modes and per-volume size signatures despite equal bytes.
    case = FACTORY.create(tmp_path / "fixtures", "byte-stream", "7z", payload_size=104 * 1024)
    raw = case.entry_path.read_bytes()
    assert len(raw) > 1024
    package.configure(watch={"deduplication": "hash"})
    watch = watch_setup(package, tmp_path, passwords=[], recursive=True)
    whole = _copy(case.entry_path, watch.root / "whole.7z")
    watch.await_event("done", path=whole.name)
    watch.await_archive(case)
    # A metadata-only timestamp change must retain the lazy representative,
    # while refreshing its IO generation before the first required hash.
    stat = whole.stat()
    os.utime(whole, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000_000))
    carrier = tmp_path / "carrier.bin"
    assemble_carrier(carrier, [case.entry_path], seed=201, prefix_lengths=[517])
    _duplicate(watch, _copy(carrier, watch.root / carrier.name))
    link = watch.root / "whole-link.7z"
    os.link(whole, link)
    _duplicate(watch, link)
    for label, width in (("split-three", (len(raw) + 2) // 3), ("split-five", (len(raw) + 4) // 5)):
        staging = tmp_path / label
        staging.mkdir()
        for number, start in enumerate(range(0, len(raw), width), 1):
            (staging / f"{label}.7z.{number:03}").write_bytes(raw[start:start + width])
        target = staging.rename(watch.root / label)
        package.await_watch_event("watch_deduplicated", path=f"{label}.7z.001", root=target)
    # Persisted hashes still bridge shapes after a clean process restart.
    watch.restart()
    after = tmp_path / "after-restart.bin"
    assemble_carrier(after, [case.entry_path], seed=202, prefix_lengths=[4099])
    _duplicate(watch, _copy(after, watch.root / after.name))
    watch.stop()
    assert len(list(watch.output.rglob(case.marker_name))) == 1
    watch.assert_no_terminal_failures()


def test_watch_hash_same_size_write_invalidates_digest_even_with_restored_mtime(package, tmp_path):
    sources = []
    for label, payload in (("a", b"AAAA"), ("b", b"BBBB")):
        source = tmp_path / f"{label}.zip"
        with ZipFile(source, "w") as archive:
            archive.writestr("same-marker.txt", payload)
        sources.append(source)
    assert sources[0].stat().st_size == sources[1].stat().st_size
    package.configure(watch={"deduplication": "hash"})
    watch = watch_setup(package, tmp_path)
    owner = _copy(sources[0], watch.root / "owner.zip")
    watch.await_event("done", path=owner.name)
    peer = _copy(sources[0], watch.root / "peer.zip")
    _duplicate(watch, peer)
    peer.unlink()
    old = owner.stat()
    changed = time.time()
    owner.write_bytes(sources[1].read_bytes())
    os.utime(owner, ns=(old.st_atime_ns, old.st_mtime_ns))
    package.await_watch_event("done", path=owner.name, after=changed)
    watch.restart()
    # No live old-content representative remains, including in the WAL.
    fresh = _copy(sources[0], watch.root / "old-content-again.zip")
    watch.await_event("done", path=fresh.name)
    assert watch.event("watch_deduplicated", path=fresh.name) is None
    _duplicate(watch, _copy(sources[1], watch.root / "new-content-copy.zip"))
    watch.stop()
    watch.assert_no_terminal_failures()
