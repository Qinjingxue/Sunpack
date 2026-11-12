import ctypes
from ctypes import wintypes
import zipfile


def test_text_cleanup_warning_names_the_failed_source_and_os_error(package, tmp_path):
    source = tmp_path / "locked-source.zip"
    output = tmp_path / "output"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("payload.txt", b"successful extraction")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    # Allow data reads/writes, but hold the source against deletion.
    handle = kernel.CreateFileW(str(source), 0x80000000, 3, None, 3, 0x80, None)
    assert handle != wintypes.HANDLE(-1).value, ctypes.get_last_error()
    try:
        result = package.run("extract", "--no-pause", "-c", "d", "-o", output, source)
    finally:
        assert kernel.CloseHandle(handle), ctypes.get_last_error()
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert source.exists()
    assert [p.read_bytes() for p in output.rglob("payload.txt")] == [b"successful extraction"]
    detail = next(line for line in result.stderr.splitlines() if str(source) + ": " in line)
    assert detail.split(str(source) + ": ", 1)[1].strip(), result.stderr
