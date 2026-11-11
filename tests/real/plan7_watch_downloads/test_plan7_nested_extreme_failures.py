import zipfile
from pathlib import Path

import pytest

from tests.helpers.real_archives import create_encrypted_zip_archive
from tests.real.archive_boundary import extract_report, failure_kinds
from tests.real.plan7_watch_downloads.plan7_support import FACTORY, download, watch_setup


INNER_PASSWORD = "nested-inner-password-only-fixture"


def nested_fixture(tmp_path, kind):
    if kind == "password":
        inner = create_encrypted_zip_archive(
            tmp_path / "fixtures", "inner-encrypted", password=INNER_PASSWORD,
            encryption="ZipCrypto", payload_size=32 * 1024,
        )
        entries = [inner.entry_path]
        expected = inner.entry_path.name
    else:
        inner = FACTORY.create(
            tmp_path / "fixtures", "inner-split", "7z", split=True,
            payload_size=620 * 1024, split_volume_size=80 * 1024,
        )
        parts = sorted(inner.archive_dir.iterdir())
        assert len(parts) >= 3
        entries = [path for path in parts if not path.name.endswith(".002")]
        expected = inner.entry_path.name
    outer = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer, "w") as archive:
        archive.writestr("outer-note.txt", b"healthy outer payload")
        for path in entries:
            archive.write(path, path.name)
    return outer, inner, expected


@pytest.mark.parametrize("kind", ["password", "missing_volume"])
def test_plan7_nested_failure_is_attributed_to_the_inner_input_in_cli(package, tmp_path, kind):
    outer, inner, expected = nested_fixture(tmp_path, kind)
    output = tmp_path / "out"
    report = extract_report(package, outer, output, passwords=["wrong"], code=1)
    assert report["summary"]["success_count"] == 1
    assert report["summary"]["partial_success_count"] == 0
    assert failure_kinds(report) == {"wrong_password" if kind == "password" else "missing_volume"}
    failure, = report["tasks"][0]["failures"]
    retry_input = Path(failure["details"]["path"])
    assert retry_input.name == expected and retry_input.is_file()
    assert failure["details"]["promoted_nested_input"] is True
    assert not list(output.rglob(inner.marker_name))
    assert next(output.rglob("outer-note.txt")).read_bytes() == b"healthy outer payload"


@pytest.mark.requires_watch_broker
@pytest.mark.parametrize("kind", ["password", "missing_volume"])
def test_plan7_nested_watch_failure_is_a_retryable_inner_input(package, tmp_path, kind):
    outer, inner, expected = nested_fixture(tmp_path, kind)
    watch = watch_setup(package, tmp_path, passwords=["wrong"])
    source = download(watch, outer)
    status = "failed_password" if kind == "password" else "suspended_missing_volume"
    event = watch.await_event(status, path=expected)
    retry = Path(event["path"])
    assert retry.parent == watch.root and retry.is_file() and retry != source
    assert not list(watch.output.rglob(inner.marker_name))
    watch.stop()
    assert source.is_file()
    assert next(watch.output.rglob("outer-note.txt")).read_bytes() == b"healthy outer payload"
    watch.assert_no_terminal_failures()
