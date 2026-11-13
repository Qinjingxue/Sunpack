"""Physical discovery errors and final output namespace parity."""
import ctypes
from ctypes import wintypes
import io
import subprocess
import zipfile

import pytest


def test_direct_read_failure_is_reported_once_without_fallback(package, tmp_path):
    source = tmp_path / "unreadable.bin"
    source.write_bytes(b"unrecognized bytes" * 1024)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    # Metadata remains readable, but neither detection nor Direct may read data.
    handle = kernel.CreateFileW(str(source), 0x40000000, 6, None, 3, 0x80, None)
    assert handle != wintypes.HANDLE(-1).value, ctypes.get_last_error()
    try:
        report = package.json("extract", "--direct-file", "-d", source, code=1)
    finally:
        kernel.CloseHandle(handle)
    assert report["summary"]["scan_error_count"] == 1, report
    assert report["summary"]["processed_count"] == 0, report
    assert report["summary"]["failed_count"] == 0, report


@pytest.mark.parametrize("keep_first_segment", [False, True])
def test_carrier_flattens_only_final_remaining_branch(package, tmp_path, keep_first_segment):
    (tmp_path / "secret.txt").write_text("secret", encoding="utf-8")
    locked = tmp_path / "locked.zip"
    subprocess.run([str(package.tools / "7z.exe"), "a", "-tzip", "-mem=AES256", "-punknown",
                    str(locked), "secret.txt"], cwd=tmp_path, check=True, capture_output=True)
    first = io.BytesIO()
    with zipfile.ZipFile(first, "w") as archive:
        archive.writestr("locked.zip", locked.read_bytes())
        if keep_first_segment:
            archive.writestr("first.txt", b"first survives")
    second = io.BytesIO()
    with zipfile.ZipFile(second, "w") as archive:
        archive.writestr("ordinary.txt", b"ordinary")
    source = tmp_path / "carrier.bin"
    source.write_bytes(b"prefix" + first.getvalue() + b"between" + second.getvalue() + b"tail")
    output = tmp_path / "out"
    package.configure(post_extract={"flatten_single_directory": True}, recursive_authorization={"enabled": False})
    report = package.json("extract", "-d", "-r", "*", "-c", "k", "--no-builtin-pw", "-o", output, source, code=1)
    ordinary, = output.rglob("ordinary.txt")
    assert ordinary.read_bytes() == b"ordinary"
    if keep_first_segment:
        first_file, = output.rglob("first.txt")
        assert first_file.parent != ordinary.parent
        assert ordinary.parent.parent == output / "carrier"
    else:
        assert ordinary == output / "carrier" / "ordinary.txt", report
    assert source.is_file()


def test_numbered_collision_normalizes_unicode_decimal_suffix(package, tmp_path):
    source = tmp_path / "archive(１).zip"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("item.txt", b"payload")
    output = tmp_path / "out"
    existing = output / "archive(１)"
    existing.mkdir(parents=True)
    (existing / "untouched.txt").write_bytes(b"existing")
    package.json("extract", "-r", "1", "-o", output, source)
    assert (output / "archive(2)" / "item.txt").read_bytes() == b"payload"
    assert (existing / "untouched.txt").read_bytes() == b"existing"


@pytest.mark.parametrize("cleanup", ["k", "d", "r"])
@pytest.mark.parametrize("embedded", [False, True], ids=["split", "embedded-split"])
def test_recursive_shared_walk_preserves_each_file_relation_scope(
    package, tmp_path, cleanup, embedded,
):
    root = tmp_path / "inputs"
    child = root / "child"
    other = root / "other"
    child.mkdir(parents=True)
    other.mkdir()
    payload = tmp_path / "payload.txt"
    content = bytes(range(256)) * 12
    payload.write_bytes(content)
    subprocess.run(
        [str(package.tools / "7z.exe"), "a", "-t7z", "-mx=0", "-v1k",
         str(child / "split.7z"), str(payload)],
        check=True, capture_output=True,
    )
    head, *tails = sorted(child.glob("split.7z.*"))
    assert tails
    if embedded:
        head.write_bytes(b"carrier prefix\0" + head.read_bytes())
    tails = [tail.rename(other / tail.name) for tail in tails]
    original = {part: part.read_bytes() for part in [head, *tails]}
    ordinary = root / "ordinary.zip"
    with zipfile.ZipFile(ordinary, "w") as archive:
        archive.writestr("ordinary.txt", b"ordinary")
    package.configure(filesystem={"scan_filters_enabled": False})

    # Adding an unrelated ancestor target may share its recursive walk, but
    # cannot make this child's missing siblings visible to discovery/retry.
    alone = package.json("extract", "-d", "-R", "-c", "k", "-r", "1",
                         "-o", tmp_path / "alone", head, code=1)
    combined_out = tmp_path / "combined"
    combined = package.json("extract", "-d", "-R", "-c", cleanup, "-r", "1",
                            "-o", combined_out, ordinary, head, code=1)
    assert alone["summary"]["failed_count"] == combined["summary"]["failed_count"] == 1
    assert combined["summary"]["success_count"] == 1
    assert next(combined_out.rglob("ordinary.txt")).read_bytes() == b"ordinary"
    assert not list(combined_out.rglob(payload.name))
    assert {part: part.read_bytes() for part in original} == original

    # The same tails inside the original recursive boundary must still work,
    # including the embedded split route, proving this is not a blanket reject.
    nested = child / "download"
    nested.mkdir()
    for tail in tails:
        tail.rename(nested / tail.name)
    recovered = tmp_path / "recovered"
    report = package.json("extract", "-d", "-R", "-c", "k", "-r", "1",
                          "-o", recovered, head)
    assert report["summary"]["success_count"] == 1
    assert next(recovered.rglob(payload.name)).read_bytes() == content
