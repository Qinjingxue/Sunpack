"""Exercise physical files used by several independently verifiable archives."""

from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from tests.helpers.native_fixture import assemble_carrier, file_inventory
from tests.helpers.real_archives import create_encrypted_rar_archive, run_cmd
from tests.real.archive_boundary import extract_report, require_generator
from tests.real.plan7_watch_downloads.plan7_support import (
    FACTORY, source_directory_cleaned, watch_setup,
)


WATCH = pytest.param("watch", marks=pytest.mark.requires_watch_broker)


def _test_archive(package, entry, archive_type, password):
    seven_zip = str(package.tools / "7z.exe")
    run_cmd([seven_zip, "t", f"-t{archive_type}", f"-p{password}", str(entry)], entry.parent)


def _assert_payloads(output, cases):
    assert output.is_dir(), output
    actual = file_inventory(output)
    for case in cases:
        markers = list(output.rglob(case.marker_name))
        assert len(markers) == 1, (case.case_id, markers, actual)
        for name, expected in case.metadata["expected_files"].items():
            relative = (markers[0].parent / name).relative_to(output).as_posix()
            assert actual.pop(relative, None) == expected, (case.case_id, relative)
    assert not actual, actual


def _extract_batch(package, tmp_path, entry_mode, head, cases, passwords):
    inputs = head.parent
    passwords = ["wrong-password", *passwords]
    package.configure(
        filesystem={"scan_filters_enabled": False},
        recursive_authorization={"enabled": False},
    )
    output = tmp_path / "out"
    if entry_mode == "cli":
        report = extract_report(package, inputs, output, passwords=passwords, cleanup="d", code=(0, 1))
        summary = report["summary"]
        assert summary["failed_count"] == summary["partial_success_count"] == 0, report
    else:
        watch = watch_setup(package, tmp_path, passwords=passwords, cleanup="d", recursive=True)
        inputs = inputs.rename(watch.root / inputs.name)
        try:
            event = package.await_watch_event(
                "done", "failed_terminal", "failed_password", "suspended_missing_volume",
                root=inputs, path=head.name,
            )
        except pytest.fail.Exception as error:
            pytest.fail(f"{error}\nWatch events: {watch.display()}", pytrace=False)
        finally:
            watch.stop()
        assert event["event"] == "done", event
        watch.assert_no_terminal_failures()
    _assert_payloads(output, cases)
    assert source_directory_cleaned(inputs)


@pytest.mark.parametrize("entry_mode", ["cli", WATCH])
def test_nested_split_rar_sfx_head_also_carries_an_independent_archive(package, tmp_path, entry_mode):
    # The real PE is the first RAR data disk. A second archive follows its
    # RAR end block and shares the executable's source lifetime. The entire
    # layout is discovered only after the outer ZIP has been extracted.
    require_generator("rar", sfx=True)
    generated = tmp_path / "generated"
    rar = FACTORY.create(
        generated, "updater", "rar", password="rar-key", split=True, sfx=True,
        payload_size=120 * 1024, split_volume_size=48 * 1024,
    )
    peer = FACTORY.create(generated, "overlay", "7z", password="overlay-key", payload_size=8192)
    head = rar.entry_path
    tails = sorted(path for path in rar.archive_dir.iterdir() if path != head)
    assert head.suffix == ".exe" and len(tails) >= 2
    sfx = head.read_bytes()
    assert sfx.startswith(b"MZ")
    head.write_bytes(sfx + b"\0unrelated executable overlay bytes\0" + peer.entry_path.read_bytes())
    # Force each parser on the very same executable, with the untouched RAR
    # continuations still next to it, before disguising those continuations.
    _test_archive(package, head, "rar5", rar.password)
    _test_archive(package, head, "7z", peer.password)
    wrapped_tails = []
    for index, tail in enumerate(tails):
        wrapped = generated / f"{tail.name}.图片"
        assemble_carrier(wrapped, [tail], seed=161 + index)
        wrapped_tails.append(wrapped)
    outer = generated / "bundle.zip"
    with ZipFile(outer, "w", compression=ZIP_DEFLATED) as archive:
        for part in [head, *wrapped_tails]:
            archive.write(part, part.name)

    inputs = tmp_path / "batch"
    inputs.mkdir()
    carrier = inputs / "交付图片.jpg"
    assemble_carrier(carrier, [outer], seed=875)
    _extract_batch(package, tmp_path, entry_mode, carrier, [rar, peer], [rar.password, peer.password])


@pytest.mark.parametrize("entry_mode", ["cli", WATCH])
def test_two_rar_groups_use_different_ranges_of_each_shared_carrier(package, tmp_path, entry_mode):
    # The same paths and visible volume numbers describe both complete groups.
    # Reversing range order on the middle disk prevents pairing by offset rank.
    # Per-file encryption leaves the real RAR5 volume headers independently
    # recognizable and gives each group its own correct password.
    require_generator("rar")
    generated = tmp_path / "generated"
    cases = []
    passwords = []
    for name in ("first", "second"):
        password = f"{name}-key"
        case = create_encrypted_rar_archive(
            generated, name, password=password, header_encrypt=False,
            split=True, payload_size=103 * 1024, split_volume_size=40 * 1024,
        )
        _test_archive(package, case.entry_path, "rar5", password)
        cases.append(case)
        passwords.append(password)
    volumes = [sorted(case.archive_dir.iterdir()) for case in cases]
    for parts, case in zip(volumes, cases, strict=True):
        assert len(parts) == 3 and parts[0] == case.entry_path
    inputs = tmp_path / "batch"
    inputs.mkdir()
    for index, (left, right) in enumerate(zip(*volumes, strict=True), start=1):
        parts = [right, left] if index == 2 else [left, right]
        assemble_carrier(inputs / f"共享.part{index}.rar.图片", parts, seed=825 + index)
    _extract_batch(package, tmp_path, entry_mode, inputs / "共享.part1.rar.图片", cases, passwords)
