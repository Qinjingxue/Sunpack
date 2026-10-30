from __future__ import annotations

import ctypes
from ctypes import wintypes
import sys

import pytest

import sunpack.runtime.watch.scanner as scanner


def test_validate_ntfs_watch_roots_propagates_non_ntfs_error(monkeypatch, tmp_path):
    def reject(path: str) -> None:
        raise RuntimeError(f"watch mode requires NTFS: '{path}' is on exFAT")

    monkeypatch.setattr(scanner, "_native_validate_ntfs_watch_root", reject)

    with pytest.raises(RuntimeError, match="requires NTFS.*exFAT"):
        scanner.validate_ntfs_watch_roots([str(tmp_path)])


@pytest.mark.skipif(sys.platform != "win32", reason="Windows file sharing is required")
def test_readiness_allows_readers_but_waits_for_write_and_delete_handles(tmp_path):
    # The old writer-only test missed DELETE handles and accidental reader blocking.
    # One real sharing scenario covers admission and release without a broker.
    archive = tmp_path / "sample.zip"
    archive.touch()
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = (
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    )
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel.CloseHandle.restype = wintypes.BOOL

    assert scanner.watch_file_is_ready(str(archive))
    for access, ready in (
        (0x80000000, True),  # GENERIC_READ
        (0x40000000, False),  # GENERIC_WRITE
        (0x00010000, False),  # DELETE: permits rename/delete without a writer
    ):
        # The existing handle permits all sharing; the probe enforces the policy.
        handle = kernel.CreateFileW(str(archive), access, 7, None, 3, 0x80, None)
        if handle == wintypes.HANDLE(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            assert scanner.watch_file_is_ready(str(archive)) is ready
        finally:
            assert kernel.CloseHandle(handle)
        assert scanner.watch_file_is_ready(str(archive))

    # A successful probe must release its own handle before publication.
    archive.rename(tmp_path / "published.zip")
