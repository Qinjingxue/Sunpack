"""Real inputs that exercise multiple archive stages in the same request."""

from pathlib import Path
from shutil import copyfile

import pytest

from tests.helpers.marker_utils import marker_present
from tests.helpers.native_fixture import assemble_carrier, assert_exact_tree, create_lz4_frames
from tests.helpers.real_archives import create_tar_archive, create_zip_multidisk_archive
from tests.real.archive_boundary import extract_report
from tests.real.enc_support import ENC_PASSWORD, create_enc_case
from tests.real.plan7_watch_downloads.plan7_support import FACTORY, download, wait_for, watch_setup


def _payload_directory(output, case):
    marker, = output.rglob(case.marker_name)
    assert_exact_tree(marker.parent, case.metadata["expected_files"])
    return marker.parent


@pytest.fixture(params=["cli", pytest.param("watch", marks=pytest.mark.requires_watch_broker)])
def entry_mode(request):
    return request.param


@pytest.fixture
def shared_head(tmp_path):
    fixtures = tmp_path / "fixtures"
    seven = FACTORY.create(
        fixtures, "seven", "7z", split=True, password="seven-key",
        payload_size=104 * 1024, split_volume_size=40 * 1024,
    )
    zip_case = create_zip_multidisk_archive(
        fixtures, "pkzip", password="zip-key", encryption="AES256",
        payload_size=104 * 1024, split_volume_size=40 * 1024,
    )
    seven_head, *seven_tails = sorted(seven.archive_dir.iterdir())
    zip_head, *zip_tails = zip_case.metadata["volume_paths"]
    assert len(seven_tails) == len(zip_tails) == 2
    batch = tmp_path / "batch"
    batch.mkdir()
    carrier = batch / "同名.001.图片"
    assemble_carrier(carrier, [zip_head, seven_head], seed=271)
    for path in seven_tails:
        copyfile(path, batch / f"同名.{path.name.split('.', 1)[1]}.图片")
    for path in zip_tails:
        copyfile(path, batch / f"同名{path.suffix}.图片")
    return carrier, seven, zip_case


def test_one_carrier_supplies_two_independent_split_heads(package, tmp_path, entry_mode, shared_head):
    # Both logical inputs have the same physical head and overlapping volume
    # names, but use different disk layouts, contents and passwords.
    carrier, seven, zip_case = shared_head
    batch = carrier.parent

    passwords = ["wrong", seven.password, zip_case.password]
    output = tmp_path / "out"
    if entry_mode == "cli":
        report = extract_report(package, batch, output, passwords=passwords, cleanup="d")
        assert report["summary"]["failed_count"] == 0, report
        sources = batch
    else:
        watch = watch_setup(package, tmp_path, passwords=passwords, cleanup="d", recursive=True)
        sources = batch.rename(watch.root / batch.name)
        wait_for(lambda: not any(sources.iterdir()), "cleanup after both split inputs commit")
        watch.stop()
        watch.assert_no_terminal_failures()
    assert _payload_directory(output, seven) != _payload_directory(output, zip_case)
    assert not any(sources.iterdir())


@pytest.mark.requires_watch_broker
def test_watch_password_retry_preserves_completed_split_input_with_shared_head(package, tmp_path, shared_head):
    # Only the PKZIP disks are blocked. The successful 7z still shares their
    # physical head, which must survive until the ZIP password is supplied.
    carrier, seven, zip_case = shared_head
    original = carrier.read_bytes()
    watch = watch_setup(package, tmp_path, passwords=["wrong", seven.password], cleanup="d", recursive=True)
    sources = carrier.parent.rename(watch.root / carrier.parent.name)
    carrier = sources / carrier.name
    watch.await_event("failed_password", path=carrier.name)
    watch.await_archive(seven)
    watch.stop()

    first, = watch.output.rglob(seven.marker_name)
    before = (first.stat().st_ino, first.stat().st_mtime_ns)
    assert not marker_present(watch.output, zip_case.marker_name)
    assert carrier.read_bytes() == original

    # Remove the successful branch's password before reopening the runtime.
    # Its previous result must remain valid when the other input resumes.
    assert package.run("--persistent-shutdown").returncode == 0
    watch.passwords(["wrong", zip_case.password])
    watch.start()
    watch.await_archive(zip_case)
    wait_for(lambda: not any(sources.iterdir()), "cleanup of the shared carrier and both sets of volumes")
    watch.stop()

    assert _payload_directory(watch.output, seven) == first.parent
    assert (first.stat().st_ino, first.stat().st_mtime_ns) == before
    assert _payload_directory(watch.output, zip_case) != first.parent
    watch.assert_no_terminal_failures()


def test_compressed_tar_promotes_pkzip_disks_and_an_enc_inside_lz4(package, tmp_path, entry_mode):
    # One outer extraction introduces both a set of disk-relative ZIP inputs
    # and a separately encrypted stream that needs another discovery pass.
    fixtures = tmp_path / "fixtures"
    zip_case = create_zip_multidisk_archive(
        fixtures, "inner", password="inner-key", encryption="AES256",
        payload_size=104 * 1024, split_volume_size=40 * 1024,
    )
    enc = create_enc_case(fixtures, "enc", input_suffix=".opaque")
    stage = fixtures / "stage"
    stage.mkdir()
    for part in zip_case.metadata["volume_paths"]:
        copyfile(part, stage / f"{part.name}.图片")
    create_lz4_frames(stage / "layer.opaque.lz4", [enc.entry_path])
    source = tmp_path / "nested-data.图片"
    tar = fixtures / "nested.tar.xz"
    create_tar_archive(stage, tar, "tar.xz")
    assemble_carrier(source, [tar], seed=819)
    package.configure(
        filesystem={"scan_filters_enabled": False}, recursive_authorization={"enabled": False},
    )
    passwords = ["wrong", zip_case.password, ENC_PASSWORD]
    output = tmp_path / "out"
    if entry_mode == "cli":
        report = extract_report(package, source, output, passwords=passwords, cleanup="d")
        assert report["summary"]["failed_count"] == 0, report
    else:
        watch = watch_setup(package, tmp_path, passwords=passwords, cleanup="d")
        source = download(watch, source, mode="direct")
        watch.await_archive(zip_case)
        watch.await_archive(enc)
        watch.stop()
        watch.assert_no_terminal_failures()

    _payload_directory(output, zip_case)
    enc_output, = output.rglob(enc.marker_name)
    assert enc_output.read_bytes() == enc.marker_text.encode()
    assert not source.exists()
    assert not list(output.rglob("*.图片"))
    assert not list(output.rglob("*.lz4"))
