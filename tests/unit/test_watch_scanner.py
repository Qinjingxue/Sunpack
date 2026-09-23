from __future__ import annotations

import pytest

import sunpack.watch.scanner as scanner


def test_validate_ntfs_watch_roots_propagates_non_ntfs_error(monkeypatch, tmp_path):
    def reject(path: str) -> None:
        raise RuntimeError(f"watch mode requires NTFS: '{path}' is on exFAT")

    monkeypatch.setattr(scanner, "_native_validate_ntfs_watch_root", reject)

    with pytest.raises(RuntimeError, match="requires NTFS.*exFAT"):
        scanner.validate_ntfs_watch_roots([str(tmp_path)])
