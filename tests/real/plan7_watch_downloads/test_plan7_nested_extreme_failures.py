import zipfile
from pathlib import Path

import pytest

from tests.helpers.real_archives import create_7z_archive, create_encrypted_zip_archive
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
    # Exercise inner failures, not the size-ratio exclusion of small volumes.
    package.configure(embedded_scan={"recursive_candidate_ratio": 0})
    outer, inner, expected = nested_fixture(tmp_path, kind)
    output = tmp_path / "out"
    report = extract_report(package, outer, output, passwords=["wrong"], code=1)
    assert report["summary"]["success_count"] == 1
    assert report["summary"]["partial_success_count"] == 0
    assert failure_kinds(report) == {"wrong_password" if kind == "password" else "missing_volume"}
    failure, = report["tasks"][0]["failures"]
    retry_input = Path(failure["details"]["path"])
    assert retry_input.name == expected and retry_input.is_file()
    assert failure["details"]["nested_input"] is True
    assert not list(output.rglob(inner.marker_name))
    assert next(output.rglob("outer-note.txt")).read_bytes() == b"healthy outer payload"


@pytest.mark.requires_watch_broker
@pytest.mark.parametrize("kind", ["password", "missing_volume"])
def test_plan7_nested_watch_failure_is_a_retryable_inner_input(package, tmp_path, kind):
    # Exercise inner failures, not the size-ratio exclusion of small volumes.
    package.configure(embedded_scan={"recursive_candidate_ratio": 0})
    outer, inner, expected = nested_fixture(tmp_path, kind)
    watch = watch_setup(package, tmp_path, passwords=["wrong"])
    source = download(watch, outer)
    status = "failed_password" if kind == "password" else "suspended_missing_volume"
    event = watch.await_event(status, path=expected)
    retry = Path(event["path"])
    assert retry.is_relative_to(watch.output) and retry.is_file() and retry != source
    assert not (watch.root / retry.name).exists()
    assert not list(watch.output.rglob(inner.marker_name))
    watch.stop()
    assert source.is_file()
    assert next(watch.output.rglob("outer-note.txt")).read_bytes() == b"healthy outer payload"
    watch.assert_no_terminal_failures()


@pytest.mark.requires_watch_broker
@pytest.mark.parametrize("naming,second_kind", [("outer", "password"), ("inner", "missing_volume")])
def test_plan7_watch_finishes_original_task_after_recursive_blockers(package, tmp_path, naming, second_kind):
    leaf_password = "nested-leaf-password-only-fixture"
    other_password = "nested-other-password-only-fixture"
    first = create_encrypted_zip_archive(tmp_path / "fixtures", "first", password=leaf_password)
    wrapper_input = tmp_path / "first-wrapper-input"
    wrapper_input.mkdir()
    (wrapper_input / "leaf.jpg").write_bytes(first.entry_path.read_bytes())
    wrapper = tmp_path / "first.7z"
    create_7z_archive(wrapper_input, wrapper, password=INNER_PASSWORD)
    missing = None
    if second_kind == "password":
        second = create_encrypted_zip_archive(tmp_path / "fixtures", "second", password=other_password)
        inputs = [(second.entry_path, "second.jpg")]
        second_status, second_name = "failed_password", "second.jpg"
    else:
        second = FACTORY.create(tmp_path / "fixtures", "second", "7z", split=True,
                                payload_size=320 * 1024, split_volume_size=80 * 1024)
        parts = sorted(second.archive_dir.iterdir())
        missing = parts[1]
        inputs = [(part, part.name) for part in parts if part != missing]
        second_status, second_name = "suspended_missing_volume", second.entry_path.name
    outer = tmp_path / "sample.zip"
    with zipfile.ZipFile(outer, "w") as archive:
        archive.write(wrapper, "wrapper/first.jpg")
        for path, name in inputs:
            archive.write(path, f"wrapper/{name}")

    package.configure(embedded_scan={"recursive_candidate_ratio": 0},
                      post_extract={"flatten_directory_name": naming})
    watch = watch_setup(package, tmp_path, passwords=[], cleanup="d" if missing is None else "k", flatten=True)
    source = download(watch, outer)
    watch.await_event("failed_password", path="first.jpg")
    watch.await_event(second_status, path=second_name)
    assert not watch.event("done", path=outer.name)

    watch.passwords([INNER_PASSWORD, leaf_password])
    watch.await_archive(first)
    watch.stop()
    assert not [row for row in watch.display()["history"] if row["event"] == "done"]
    assert (watch.output / "sample" / "wrapper").is_dir()
    assert source.is_file() == (missing is not None)
    assert package.run("--persistent-shutdown").returncode == 0
    late_volume = download(watch, missing) if missing is not None else None
    watch.start()

    if missing is None:
        watch.passwords([INNER_PASSWORD, leaf_password, other_password])
    done = watch.await_event("done", path=outer.name)
    watch.stop()
    final = watch.output / ("sample" if naming == "outer" else "wrapper")
    assert [Path(path) for path in done["output_dirs"]] == [final]
    assert done["success_count"] == 4
    assert len(list(final.iterdir())) == 2
    for case in (first, second):
        marker, = final.rglob(case.marker_name)
        assert len(marker.relative_to(final).parts) == 2
        assert marker.read_bytes() == case.marker_text.encode()
    assert list(watch.output.iterdir()) == [final]
    if late_volume is not None:
        assert late_volume.is_file()
    display = watch.display()
    assert [Path(row["path"]).name for row in display["history"] if row["event"] == "done"] == [outer.name]
    assert not [row for row in display["live"] if row["event"] in {
        "processing_started", "failed_password", "suspended_missing_volume"}]
    watch.assert_no_terminal_failures()
