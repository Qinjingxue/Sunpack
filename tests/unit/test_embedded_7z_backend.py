"""Prove the 7-Zip backend is embedded, i.e. needs no 7z.dll to do real work.

The migration compiled the trimmed 7-Zip sources into sunpack_sevenzip.dll and
sunpack_sevenzip_worker.exe. The regression that matters is not the PE import
table (the old backend used LoadLibrary, so 7z.dll never appeared there) but
whether real archive work still succeeds when no 7z.dll is reachable.

Every test here stages the built artifacts in an otherwise empty directory and
asserts that directory contains no 7z.dll before exercising them.

Note: the repository still ships tools\\7z.dll on purpose. It belongs to
tools\\7z.exe, the 7-Zip CLI the test suite uses to *generate* fixtures, and it
is excluded from the release package (see scripts\\verify_windows_package_arch.ps1).
That is a build-time tool, not a runtime dependency of the product.
"""

from __future__ import annotations

import ctypes
import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from sunpack.support.resources import get_sevenzip_bridge_worker_path

REPO_ROOT = Path(__file__).resolve().parents[2]
BUILD_CANDIDATES = (
    REPO_ROOT / "native" / "sevenzip_bridge" / "build-x64" / "Release",
    REPO_ROOT / "native" / "sevenzip_bridge" / "build-arm64" / "Release",
    REPO_ROOT / "native" / "sevenzip_bridge" / "build" / "Release",
)

PAYLOAD_FILES = {
    "hello.txt": b"hello sunpack\n" * 40,
    "nested/note.txt": b"nested payload\n" * 25,
}


def _built_artifact(name: str) -> Path:
    for candidate in BUILD_CANDIDATES:
        artifact = candidate / name
        if artifact.is_file():
            return artifact
    pytest.skip(f"{name} has not been built under native/sevenzip_bridge/build*")


def _stage_without_7z_dll(tmp_path: Path, *names: str) -> Path:
    """Copy the given built artifacts into an empty dir and prove no 7z.dll."""
    staging = tmp_path / "embedded-backend"
    staging.mkdir(parents=True, exist_ok=True)
    for name in names:
        shutil.copy2(_built_artifact(name), staging / name)
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
    worker = _stage_without_7z_dll(tmp_path, "sunpack_sevenzip_worker.exe") / (
        "sunpack_sevenzip_worker.exe"
    )
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


def test_dll_serves_probe_and_resources_without_7z_dll(tmp_path):
    staging = _stage_without_7z_dll(tmp_path, "sunpack_sevenzip.dll")
    archive = tmp_path / "carrier.zip"
    _make_zip(archive)

    from sunpack.support.sevenzip_bridge import NativePasswordTester

    tester = NativePasswordTester(wrapper_path=str(staging / "sunpack_sevenzip.dll"))
    assert tester.available() is True

    probe = tester.probe_archive(str(archive))
    assert probe.ok is True, probe
    assert probe.is_archive is True

    analysis = tester.analyze_archive_resources(str(archive))
    assert analysis.ok is True, analysis
    assert analysis.item_count == len(PAYLOAD_FILES)
    assert analysis.total_unpacked_size == sum(len(v) for v in PAYLOAD_FILES.values())


def test_dll_loads_with_no_7z_dll_on_disk(tmp_path):
    """_load() must not require 7z.dll to exist anywhere."""
    staging = _stage_without_7z_dll(tmp_path, "sunpack_sevenzip.dll")

    from sunpack.support.sevenzip_bridge import NativePasswordTester

    tester = NativePasswordTester(wrapper_path=str(staging / "sunpack_sevenzip.dll"))
    library = tester._load()
    assert library is not None
    assert (staging / "sunpack_sevenzip.dll").is_file()
    assert not (staging / "7z.dll").exists()


def _find_dumpbin() -> str | None:
    import glob

    found = shutil.which("dumpbin")
    if found:
        return found
    for base in (
        r"C:\Program Files (x86)\Microsoft Visual Studio",
        r"C:\Program Files\Microsoft Visual Studio",
    ):
        matches = glob.glob(
            os.path.join(base, "*", "*", "VC", "Tools", "MSVC", "*", "bin", "Hostx64", "x64", "dumpbin.exe")
        )
        if matches:
            return sorted(matches)[-1]
    return None


def test_built_binaries_do_not_import_7z_dll():
    """Guard against re-introducing 7z.dll as a link-time dependency.

    Note the historical backend used LoadLibrary, so this alone never proved
    much; the behavioural tests above are the real evidence. This is the cheap
    structural companion that catches a future import-library regression.
    """
    dumpbin = _find_dumpbin()
    if not dumpbin:
        pytest.skip("dumpbin is required to inspect PE imports")

    for name in ("sunpack_sevenzip.dll", "sunpack_sevenzip_worker.exe"):
        completed = subprocess.run(
            [dumpbin, "/nologo", "/dependents", str(_built_artifact(name))],
            capture_output=True,
            text=True,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
        modules = [
            line.strip().lower()
            for line in completed.stdout.splitlines()
            if line.strip().lower().endswith(".dll")
        ]
        assert modules, f"dumpbin reported no imports for {name}"
        assert "7z.dll" not in modules, modules
