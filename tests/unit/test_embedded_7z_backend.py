"""Prove the native worker embeds 7-Zip and needs no runtime 7z.dll."""

from __future__ import annotations

import json
import shutil
import subprocess
import zipfile
from pathlib import Path

from tests.helpers.native_build import sevenzip_artifact


PAYLOAD_FILES = {
    "hello.txt": b"hello sunpack\n" * 40,
    "nested/note.txt": b"nested payload\n" * 25,
}


def _stage_without_7z_dll(tmp_path: Path, *names: str) -> Path:
    staging = tmp_path / "embedded-backend"
    staging.mkdir(parents=True, exist_ok=True)
    for name in names:
        shutil.copy2(sevenzip_artifact(name), staging / name)
    assert list(staging.glob("7z.dll")) == []
    return staging


def _make_zip(path: Path) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in PAYLOAD_FILES.items():
            archive.writestr(name, data)


def _run_worker(worker: Path, payload: dict) -> dict:
    completed = subprocess.run(
        [str(worker)],
        input=json.dumps(payload, ensure_ascii=False),
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    results = [
        json.loads(line)
        for line in completed.stdout.splitlines()
        if line.strip().startswith("{") and '"type":"result"' in line.replace(" ", "")
    ]
    assert results, f"worker produced no result line: {completed.stdout!r} {completed.stderr!r}"
    return results[-1]


def test_worker_extracts_zip_without_7z_dll(tmp_path):
    worker = _stage_without_7z_dll(tmp_path, "sunpack_sevenzip_worker.exe") / "sunpack_sevenzip_worker.exe"
    archive = tmp_path / "carrier.zip"
    _make_zip(archive)
    output_dir = tmp_path / "out"

    result = _run_worker(
        worker,
        {
            "job_id": "embedded-backend-worker",
            "archive_path": str(archive),
            "output_dir": str(output_dir),
            "password": "",
            "format_hint": "",
            "dry_run": False,
        },
    )

    assert result["status"] == "ok", result
    for name, data in PAYLOAD_FILES.items():
        extracted = output_dir / name
        assert extracted.is_file(), f"{name} was not extracted"
        assert extracted.read_bytes() == data
