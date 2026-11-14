"""Real CLI and Watch regressions for archive extents and output names."""

import io
import lzma
import tarfile
from zipfile import ZipFile

import pytest

from tests.helpers.native_fixture import assemble_carrier, file_inventory, native_fixture
from tests.helpers.real_archives import create_zip_multidisk_archive
from tests.real.archive_boundary import assert_extracted, extract_report, failure_kinds
from tests.real.plan7_watch_downloads.plan7_support import (
    FACTORY, Watch, download, download_interleaved, stage_initial, wait_for, watch_setup,
)


WATCH = pytest.param("watch", marks=pytest.mark.requires_watch_broker)


@pytest.mark.parametrize("entry_mode", ["cli", WATCH])
def test_zipx_short_terminal_disk_survives_size_filter(package, tmp_path, entry_mode):
    # The last PKZIP disk carries the directory and is smaller than the
    # configured threshold. The .zx01/.zipx names must still form one set.
    case = create_zip_multidisk_archive(tmp_path / "fixtures", "short-tail", payload_size=20 * 1024)
    head, terminal = case.metadata["volume_paths"]
    head = head.rename(head.with_suffix(".zx01"))
    terminal = terminal.rename(terminal.with_suffix(".zipx"))
    minimum = head.stat().st_size
    assert terminal.stat().st_size < minimum
    package.configure(filesystem={"scan_filters_enabled": True, "scan_filters": [
        {"name": "size_range", "enabled": True, "min_bytes": minimum},
    ]})
    output = tmp_path / "out"
    if entry_mode == "cli":
        report = extract_report(package, case.archive_dir, output, deep=False, cleanup="d")
        assert report["summary"]["success_count"] == 1, report
        sources = [head, terminal]
    else:
        # The ordinary Watch root keeps the configured size filter active.
        root = tmp_path / "watch"
        root.mkdir()
        watch = Watch(package, root, output)
        package.configure(post_extract={"archive_cleanup_mode": "d"})
        package.json("watch", "add", root, "-o", output)
        stage_initial(watch, head)
        watch.start()
        watch.await_event("suspended_missing_volume", path=head.name)
        sources = [root / head.name, download(watch, terminal, mode="direct")]
        watch.await_archive(case)
        watch.stop()
        watch.assert_no_terminal_failures()
    assert_extracted(case, output, exact=True)
    assert not any(path.exists() for path in sources)


@pytest.mark.parametrize("entry_mode", ["cli", WATCH])
def test_pax_size_override_keeps_later_zip_visible_in_carrier(package, tmp_path, entry_mode):
    # PAX supplies the actual size even when the ordinary TAR size is zero
    # or points far beyond the member. A wrong extent can hide the next ZIP.
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    expected = {}
    for raw_size in (0, 16384):
        name = f"pax-{raw_size}"
        payload = name.encode()
        member = tarfile.TarInfo(f"{name}.txt")
        member.size = raw_size
        member.pax_headers = {"size": str(len(payload))}
        tar = tmp_path / f"{name}.tar"
        tar.write_bytes(member.tobuf(format=tarfile.PAX_FORMAT) + payload + bytes(-len(payload) % 512 + 1024))
        peer = tmp_path / f"{name}.zip"
        with ZipFile(peer, "w") as archive:
            archive.writestr(f"peer-{raw_size}.txt", payload[::-1])
        assemble_carrier(inputs / f"{name}.图片", [tar, peer], seed=42)
        expected.update({member.name: payload, f"peer-{raw_size}.txt": payload[::-1]})

    output = tmp_path / "out"
    if entry_mode == "cli":
        report = extract_report(package, inputs, output, cleanup="d")
        assert report["summary"]["failed_count"] == 0, report
        assert not any(inputs.iterdir())
    else:
        watch = watch_setup(package, tmp_path, passwords=[], cleanup="d")
        sources = download_interleaved(watch, sorted(inputs.iterdir()))
        wait_for(lambda: not any(path.exists() for path in sources), "both PAX carriers to finish")
        watch.stop()
        watch.assert_no_terminal_failures()
    for name, payload in expected.items():
        assert [path.read_bytes() for path in output.rglob(name)] == [payload]
    assert len(file_inventory(output)) == len(expected)


@pytest.mark.parametrize("entry_mode", ["cli", WATCH])
def test_unnamed_xz_keeps_nested_archive_name_when_output_already_exists(package, tmp_path, entry_mode):
    case = FACTORY.create(tmp_path / "fixtures", "inner", "7z", payload_size=8 * 1024)
    # XZ carries no original filename. Preserve the .7z suffix inferred from
    # the input, even though the surrounding output directory gets numbered.
    stream = tmp_path / "raw.xz"
    stream.write_bytes(lzma.compress(case.entry_path.read_bytes()))
    source = tmp_path / "inner.7z.xz"
    assemble_carrier(source, [stream], seed=126)
    original = source.read_bytes()
    output = tmp_path / "out"
    collision = output / "inner"
    collision.mkdir(parents=True)
    sentinel = collision / "existing.txt"
    sentinel.write_bytes(b"existing data")
    package.configure(recursive_authorization={"enabled": False})
    if entry_mode == "cli":
        report = extract_report(package, source, output)
        assert report["summary"]["success_count"] == 2, report
        assert report["summary"]["failed_count"] == 0, report
    else:
        watch = watch_setup(package, tmp_path, passwords=[])
        source = download(watch, source, mode="direct")
        watch.await_archive(case)
        watch.stop()
        watch.assert_no_terminal_failures()
    numbered = output / "inner(1)"
    assert {path.name for path in output.iterdir()} == {collision.name, numbered.name}
    assert list(collision.iterdir()) == [sentinel]
    assert sentinel.read_bytes() == b"existing data"
    assert_extracted(case, numbered, exact=True)
    assert not list(numbered.rglob("*.7z"))
    assert source.read_bytes() == original


@pytest.mark.parametrize("entry_mode", ["cli", WATCH])
def test_tar_windows_projection_collisions_preserve_all_members(package, tmp_path, entry_mode):
    # Distinct TAR paths can map to the same Windows name. Verify every
    # payload so a successful result cannot conceal an overwritten member.
    entries = [
        ("a?.txt", "a_.txt"), ("a*.txt", "a_(1).txt"),
        ("a_(2).txt", "a_(2).txt"), ("a?.txt", "a_(3).txt"),
        ("con.txt", "_con.txt"), ("_con.txt", "_con(1).txt"),
        ("./same.txt", "same.txt"), ("same.txt", "same(1).txt"),
        ("sub//file.txt", "sub/file.txt"), ("sub/file.txt", "sub/file(1).txt"),
        (" leading.txt", " leading.txt"), ("trailing.txt ", "trailing.txt_"),
    ]
    source = tmp_path / "映射.图片"
    expected = {}
    with tarfile.open(source, "w") as archive:
        for index, (name, projected) in enumerate(entries):
            payload = f"member-{index}".encode()
            member = tarfile.TarInfo(name)
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
            expected[projected] = payload

    output = tmp_path / "out"
    if entry_mode == "cli":
        report = extract_report(package, source, output, cleanup="d")
        assert report["summary"]["success_count"] == 1, report
    else:
        watch = watch_setup(package, tmp_path, passwords=[], cleanup="d")
        source = download(watch, source)
        watch.await_event("done", path=source.name)
        watch.stop()
        watch.assert_no_terminal_failures()
    target = output / source.stem
    actual = {path.relative_to(target).as_posix(): path.read_bytes()
              for path in target.rglob("*") if path.is_file()}
    assert actual == expected
    assert not source.exists()


@pytest.mark.parametrize("entry_mode", ["cli", WATCH])
def test_part_inside_word_does_not_change_standalone_archive_name(package, tmp_path, entry_mode):
    # These digit-bearing stems are complete archives. In particular the
    # files named .rar contain ZIP data, so a suffix-based guess is wrong.
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    expected = {}
    for name in ("Counterpart2.zip", "Counterpart3.zip", "Rampart1.rar", "Rampart2.rar"):
        source = inputs / name
        payload = name.encode()
        with ZipFile(source, "w") as archive:
            archive.writestr("payload.txt", payload)
        expected[f"{source.stem}/payload.txt"] = payload

    output = tmp_path / "out"
    if entry_mode == "cli":
        report = extract_report(package, inputs, output, cleanup="d")
        assert report["summary"]["success_count"] == len(expected), report
        assert not any(inputs.iterdir())
    else:
        watch = watch_setup(package, tmp_path, passwords=[], cleanup="d")
        sources = download_interleaved(watch, sorted(inputs.iterdir()), mode="direct")
        wait_for(lambda: not any(path.exists() for path in sources), "all four standalone archives to finish")
        watch.stop()
        watch.assert_no_terminal_failures()
    actual = {path.relative_to(output).as_posix(): path.read_bytes()
              for path in output.rglob("*") if path.is_file()}
    assert actual == expected


@pytest.mark.parametrize("entry_mode", ["cli", WATCH])
def test_unsupported_zipx_method_does_not_block_zstd_peer(package, tmp_path, entry_mode):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    good = inputs / "zstd.zipx"
    unsupported = inputs / "wavpack.zipx"
    expected = native_fixture("zip_method", output=str(good), method=93)["expected_files"]
    native_fixture("zip_method", output=str(unsupported), method=97)
    original = unsupported.read_bytes()
    output = tmp_path / "out"
    if entry_mode == "cli":
        report = extract_report(package, inputs, output, cleanup="d", code=1)
        assert report["summary"]["success_count"] == 1, report
        assert failure_kinds(report) == {"unsupported"}, report
    else:
        watch = watch_setup(package, tmp_path, passwords=[], cleanup="d")
        good, unsupported = download_interleaved(watch, [good, unsupported])
        failure = watch.await_event("archive_failure_evidence", path=unsupported.name)
        assert failure["failure"]["kind"] == "unsupported", failure
        watch.await_event("done", path=good.name)
        watch.stop()
    assert not good.exists()
    assert unsupported.read_bytes() == original
    assert file_inventory(output) == {f"zstd/{name}": record for name, record in expected.items()}
