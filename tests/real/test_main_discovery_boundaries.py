"""Main's discovery boundary cases through the public CLI and Watch."""

from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from tests.helpers.marker_utils import marker_present
from tests.helpers.native_fixture import assemble_carrier
from tests.real.archive_boundary import assert_extracted, extract_report, failure_kinds
from tests.real.plan7_watch_downloads.plan7_support import (
    FACTORY, Watch, download, stage_initial, wait_for, watch_setup,
)


@pytest.fixture(params=["cli", pytest.param("watch", marks=pytest.mark.requires_watch_broker)])
def entry_mode(request):
    return request.param


def test_nested_carrier_ratio_is_local_to_each_extracted_tree(package, tmp_path, entry_mode):
    # Main compares a carrier to its own extracted tree. Two equal-sized
    # carriers must make opposite decisions in one batch because only one
    # of their trees contains a large unrelated file.
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    expected = b"nested payload selected by its own tree's size"
    for name in ("sparse", "dense"):
        archive = tmp_path / f"{name}-inner.zip"
        with ZipFile(archive, "w") as inner:
            inner.writestr(f"{name}-leaf.txt", expected)
        carrier = tmp_path / f"{name}.opaque"
        assemble_carrier(carrier, [archive], seed=42)
        with ZipFile(inputs / f"{name}.zip", "w", compression=ZIP_DEFLATED) as outer:
            outer.write(carrier, carrier.name)
            if name == "dense":
                outer.writestr("asset.bin", b"x" * (10 * carrier.stat().st_size))

    package.configure(
        embedded_scan={"enabled": True, "recursive_candidate_ratio": 0.3},
        filesystem={"scan_filters_enabled": False},
        recursive_authorization={"enabled": False},
    )
    output = tmp_path / "out"
    if entry_mode == "cli":
        report = extract_report(package, inputs, output, cleanup="d")
        assert report["summary"]["success_count"] == 3, report
        assert report["summary"]["failed_count"] == 0, report
        assert not any(inputs.iterdir())
    else:
        watch = watch_setup(package, tmp_path, passwords=[], cleanup="d", recursive=True)
        target = inputs.rename(watch.root / inputs.name)
        wait_for(lambda: not any(target.iterdir()), "cleanup of both extracted outer archives")
        watch.stop()
        watch.assert_no_terminal_failures()

    assert [path.read_bytes() for path in output.rglob("sparse-leaf.txt")] == [expected]
    assert not marker_present(output, "dense-leaf.txt")
    assert not marker_present(output, "sparse.opaque")
    assert [path.read_bytes() for path in output.rglob("dense.opaque")] == [
        (tmp_path / "dense.opaque").read_bytes()
    ]


def test_blacklisted_middle_volume_is_admitted_after_rename(package, tmp_path, entry_mode):
    # Main applies filename rules before relation planning. An otherwise
    # valid and readable middle volume must not be borrowed through its head.
    case = FACTORY.create(
        tmp_path / "fixtures", "filtered", "7z", split=True, password="filter-key",
        payload_size=104 * 1024, split_volume_size=40 * 1024,
    )
    head, middle, tail = sorted(case.archive_dir.iterdir())
    parts = [path.rename(path.with_name(f"{path.name}.图片")) for path in (head, middle, tail)]
    package.configure(filesystem={"scan_filters_enabled": True, "scan_filters": [{
        "name": "blacklist", "enabled": True,
        "full_names": [{"value": r"\Afiltered\.7z\.002\.图片\z", "regex": True}],
    }]})
    passwords = ["wrong", case.password]
    output = tmp_path / "out"
    if entry_mode == "cli":
        blocked = extract_report(package, case.archive_dir, output, passwords=passwords, cleanup="d", deep=False, code=1)
        assert failure_kinds(blocked) == {"missing_volume"}, blocked
    else:
        root = tmp_path / "watch"
        root.mkdir()
        watch = Watch(package, root, output)
        package.configure(post_extract={"archive_cleanup_mode": "d"})
        watch.passwords(passwords)
        package.json("watch", "add", root, "-o", output)
        for part in parts:
            stage_initial(watch, part)
        parts = [root / part.name for part in parts]
        # All three volumes are complete before initial discovery. A missing
        # volume result therefore cannot come from a download still in flight.
        watch.start()
        evidence = watch.await_event("archive_failure_evidence", path=parts[0].name)
        assert evidence["failure"]["kind"] == "missing_volume", evidence

    assert not marker_present(output, case.marker_name)
    assert all(path.is_file() for path in parts)
    parts[1] = parts[1].rename(parts[1].with_suffix(".允许"))
    if entry_mode == "cli":
        report = extract_report(package, case.archive_dir, output, passwords=passwords, cleanup="d", deep=False)
        assert report["summary"]["success_count"] == 1, report
        assert report["summary"]["failed_count"] == 0, report
    else:
        watch.await_archive(case)
        watch.stop()
        watch.assert_no_terminal_failures()
    assert_extracted(case, output, exact=True)
    assert not any(path.exists() for path in parts)


def test_zipcrypto_header_collision_does_not_block_later_password(package, tmp_path, repo_root, entry_mode):
    # Both passwords decode the fixed vector's header check byte to 0xbb.
    # The first fails payload verification. Put the data in a carrier so the
    # same fallback is required with nonzero input offsets in both modes.
    vector = repo_root / "tests/data/zipcrypto_empty_header_match.bin"
    source = tmp_path / "legacy.图片"
    assemble_carrier(source, [vector], seed=712)
    collision = "collision-wrong-712"
    correct = "real-archive-password"
    expected = b"valid zipcrypto payload\n" * 192
    output = tmp_path / "out"
    if entry_mode == "cli":
        report = extract_report(package, source, output, passwords=[collision, correct], cleanup="d")
        assert report["summary"]["success_count"] == 1, report
    else:
        watch = watch_setup(package, tmp_path, passwords=[collision], cleanup="d")
        source = download(watch, source, mode="direct")
        watch.await_event("failed_password", path=source.name)
        assert source.is_file()
        assert not list(output.rglob("payload.txt"))
        watch.passwords([collision, correct])
        watch.await_event("done", path=source.name)
        watch.stop()
        watch.assert_no_terminal_failures()
    assert [path.read_bytes() for path in output.rglob("payload.txt")] == [expected]
    assert not source.exists()
