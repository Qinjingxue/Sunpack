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
