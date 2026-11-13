"""Real worker failures after an earlier member has completed, not probe failures."""

import io
import struct
import subprocess
import zipfile

import pytest


def _nested_zip():
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("must-not-recurse.txt", b"failed inputs cannot authorize recursion")
    return data.getvalue()


def _mixed_password_zip(package, root, source, nested):
    # ZIP has no encrypted global header. Updating one entry leaves the earlier
    # AES member encrypted with its original password; both are genuinely AES.
    for name, data, password in [
        ("a-nested.zip", nested, "first-key"),
        ("z-failed.txt", b"a different member password", "second-key"),
    ]:
        (root / name).write_bytes(data)
        subprocess.run(
            [str(package.tools / "7z.exe"), "a", "-tzip", "-mx=0", "-mem=AES256",
             f"-p{password}", str(source), name],
            cwd=root, check=True, capture_output=True,
        )
    with zipfile.ZipFile(source) as archive:
        entries = archive.infolist()
        assert [entry.filename for entry in entries] == ["a-nested.zip", "z-failed.txt"]
        assert all(entry.compress_type == 99 and entry.flag_bits & 1 for entry in entries)


def _unsupported_later_member(source, nested):
    with zipfile.ZipFile(source, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("a-nested.zip", nested)
        archive.writestr("z-failed.txt", b"unsupported method payload")
        failed = archive.getinfo("z-failed.txt")
    with zipfile.ZipFile(source) as archive:
        central = archive.start_dir
    data = bytearray(source.read_bytes())
    # Keep the archive and member lengths valid. Only the later member's
    # compression method is unknown, in both local and central declarations.
    struct.pack_into("<H", data, failed.header_offset + 8, 0xFFFF)
    for _ in range(2):
        assert data[central:central + 4] == b"PK\x01\x02"
        name_len, extra_len, comment_len = struct.unpack_from("<HHH", data, central + 28)
        name = data[central + 46:central + 46 + name_len]
        if name == b"z-failed.txt":
            struct.pack_into("<H", data, central + 10, 0xFFFF)
            break
        central += 46 + name_len + extra_len + comment_len
    else:
        raise AssertionError("missing second ZIP central entry")
    source.write_bytes(data)


@pytest.mark.parametrize("failure", ["wrong_password", "unsupported"])
def test_allow_partial_rejects_nonrecoverable_worker_failure_after_complete_member(package, tmp_path, failure):
    # A single wrongly encrypted member is insufficient: Rust's fast verifier
    # would reject it before worker extraction and miss the acceptance bug.
    nested = _nested_zip()
    source = tmp_path / "mixed.zip"
    if failure == "wrong_password":
        _mixed_password_zip(package, tmp_path, source, nested)
    else:
        _unsupported_later_member(source, nested)
    reference = tmp_path / "reference"
    result = subprocess.run(
        [str(package.tools / "7z.exe"), "x", "-y", "-pfirst-key", f"-o{reference}", str(source)],
        capture_output=True,
    )
    assert result.returncode == 2, (result.stdout, result.stderr)
    assert (reference / "a-nested.zip").read_bytes() == nested

    package.configure(
        extraction={"content_requirement": "allow_partial"},
        recursive_authorization={"enabled": False},
    )
    output = tmp_path / "out"
    report = package.json(
        "extract", "--direct-file", "--no-builtin-pw", "-p", "first-key",
        "-r", "*", "-c", "d", "-o", output, source, code=1,
    )
    assert report["summary"]["failed_count"] == 1, report
    assert report["summary"]["success_count"] == 0, report
    assert report["summary"]["partial_success_count"] == 0, report
    assert report["tasks"][0]["failures"][0]["kind"] == failure, report
    assert report["tasks"][0]["failures"][0]["stage"] == "extraction", report
    assert "failure_details" not in report["summary"], report
    assert source.is_file()
    assert not list(output.rglob("must-not-recurse.txt"))


def test_complete_carrier_keeps_damaged_segment_output_beside_success(package, tmp_path):
    # Direct complete-mode failure may discard its output. A physical carrier
    # with an independent successful sibling must aggregate first and preserve
    # the failed segment's useful bytes, while still reporting failure.
    (tmp_path / "success.txt").write_bytes(b"independent successful segment")
    first = tmp_path / "first.7z"
    subprocess.run(
        [str(package.tools / "7z.exe"), "a", "-t7z", str(first), "success.txt"],
        cwd=tmp_path, check=True, capture_output=True,
    )
    second = tmp_path / "second.zip"
    with zipfile.ZipFile(second, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("recovered.txt", b"complete member from damaged segment")
        archive.writestr("damaged.txt", b"member with invalid checksum")
        failed = archive.getinfo("damaged.txt")
    data = bytearray(second.read_bytes())
    name_len, extra_len = struct.unpack_from("<HH", data, failed.header_offset + 26)
    data[failed.header_offset + 30 + name_len + extra_len] ^= 1
    second.write_bytes(data)
    carrier = tmp_path / "carrier.bin"
    carrier.write_bytes(b"opaque prefix" + first.read_bytes() + b"between" + data + b"suffix")
    package.configure(
        extraction={"content_requirement": "complete"},
        post_extract={"flatten_single_directory": False},
    )
    output = tmp_path / "out"
    report = package.json("extract", "-d", "-r", "1", "-c", "d", "-o", output, carrier, code=1)
    assert report["summary"]["failed_count"] == 1, report
    assert report["summary"]["partial_success_count"] == 0, report
    assert report["tasks"][0]["failures"][0]["kind"] == "damaged", report
    good, = output.rglob("success.txt")
    recovered, = output.rglob("recovered.txt")
    assert good.read_bytes() == b"independent successful segment"
    assert recovered.read_bytes() == b"complete member from damaged segment"
    assert good.parent != recovered.parent
    assert carrier.is_file()


def test_completed_roots_keep_nested_results_passwords_and_failures(package, tmp_path):
    # Completed roots are reduced to sparse CLI facts while other roots are
    # still running. Exercise all three consumers together, without ordering
    # assumptions, artificial delays or a production-only test hook.
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    nested = io.BytesIO()
    with zipfile.ZipFile(nested, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("nested-result.txt", b"nested root result")
    outer = inputs / "outer.zip"
    with zipfile.ZipFile(outer, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("child.zip", nested.getvalue())
    (tmp_path / "encrypted-result.txt").write_bytes(b"encrypted root result")
    encrypted = inputs / "encrypted.7z"
    subprocess.run(
        [str(package.tools / "7z.exe"), "a", "-t7z", "-mhe=on", "-proot-key",
         str(encrypted), "encrypted-result.txt"],
        cwd=tmp_path, check=True, capture_output=True,
    )
    unsupported = inputs / "unsupported.zip"
    _unsupported_later_member(unsupported, _nested_zip())
    original = {source: source.read_bytes() for source in inputs.iterdir()}
    package.configure(recursive_authorization={"enabled": False})
    output = tmp_path / "out"
    report = package.json(
        "extract", "-d", "--no-builtin-pw", "-p", "root-key",
        "-r", "*", "-c", "k", "-o", output, inputs, code=1,
    )
    # main counts physical tasks (including the nested task), not segments.
    for summary in (report["summary"], report["tasks"][0]):
        assert summary["success_count"] == 3, report
        assert summary["failed_count"] == 1, report
        assert summary["processed_count"] == 4, report
        assert summary["partial_success_count"] == 0, report
    failure, = report["tasks"][0]["failures"]
    assert failure["kind"] == "unsupported", report
    assert "root-key" in report["items"][0]["recent_passwords"], report
    for name, expected in (("nested-result.txt", b"nested root result"),
                           ("encrypted-result.txt", b"encrypted root result")):
        result, = output.rglob(name)
        assert result.read_bytes() == expected
    assert not list(output.rglob("must-not-recurse.txt"))
    assert all(source.read_bytes() == data for source, data in original.items())
