"""Exercise real NTFS disk exhaustion through the packaged launcher and worker."""

from __future__ import annotations

import ctypes
import os
import random
import shutil
import subprocess
import sys
import time
import uuid
import zipfile
from contextlib import contextmanager
from ctypes import wintypes
from pathlib import Path

import psutil
import pytest


MIB = 1 << 20
VHD_MIB = 32
PAYLOAD_BYTES = 8 * MIB
DEADLINE_SECONDS = 60
pytestmark = pytest.mark.skipif(
    sys.platform != "win32" or not ctypes.windll.shell32.IsUserAnAdmin(),
    reason="DiskPart requires an elevated Windows process",
)


@contextmanager
def _diskpart_lock():
    # Drive-letter selection and attachment are one operation across xdist
    # workers. A killed worker's mutex is released by Windows.
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateMutexW.argtypes = (wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR)
    kernel.CreateMutexW.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.ReleaseMutex.argtypes = (wintypes.HANDLE,)
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    handle = kernel.CreateMutexW(None, False, r"Local\SunPackVhdTests")
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if kernel.WaitForSingleObject(handle, 120_000) not in (0, 0x80):
            raise RuntimeError("could not acquire the DiskPart test mutex")
        try:
            yield
        finally:
            kernel.ReleaseMutex(handle)
    finally:
        kernel.CloseHandle(handle)


def _diskpart(*commands):
    result = subprocess.run(
        ["diskpart.exe"], input="\n".join((*commands, "exit", "")), text=True,
        capture_output=True, errors="replace", timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout + result.stderr


def _volume_label(root):
    label = ctypes.create_unicode_buffer(261)
    if not ctypes.windll.kernel32.GetVolumeInformationW(
        str(root), label, len(label), None, None, None, None, 0,
    ):
        return None
    return label.value


@contextmanager
def _vhd(tmp_path):
    directory = Path(os.environ.get("SUNPACK_SPACE_TEST_VHD_DIR") or tmp_path).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    if shutil.disk_usage(directory).free < (VHD_MIB + 32) * MIB:
        pytest.skip("not enough host space for a private 32 MiB VHD and 32 MiB reserve")
    label = f"SP{uuid.uuid4().hex[:12]}"
    image = directory / f"{label}.vhdx"
    select = f'select vdisk file="{image}"'
    try:
        with _diskpart_lock():
            drives = ctypes.windll.kernel32.GetLogicalDrives()
            assert drives, "could not enumerate current drive letters"
            letter = next((chr(65 + index) for index in range(25, 3, -1)
                           if not drives & (1 << index)), None)
            if letter is None:
                pytest.skip("no free drive letter for a private VHD")
            root = Path(f"{letter}:\\")
            transcript = _diskpart(
                f'create vdisk file="{image}" maximum={VHD_MIB} type=fixed',
                select, "attach vdisk", "create partition primary",
                f"format fs=ntfs quick label={label}", f"assign letter={letter}",
            )
            # DiskPart can return success even when a subcommand fails. Never
            # put filler or output on a drive without this run's volume label.
            assert _volume_label(root) == label, transcript
        yield root
    finally:
        if image.exists():
            with _diskpart_lock():
                _diskpart(select, "detach vdisk")
                image.unlink()


def _fill(root):
    filler = root / "filler.bin"
    free = shutil.disk_usage(root).free
    assert free > PAYLOAD_BYTES + MIB, "formatted VHD cannot hold the test payload"
    chunk = bytes(range(256)) * 256
    with filler.open("xb") as handle:
        while free > MIB + len(chunk):
            handle.write(chunk)
            free -= len(chunk)
        handle.flush()
        os.fsync(handle.fileno())
    assert 0 < shutil.disk_usage(root).free <= 2 * MIB
    return filler


def _archive(tmp_path, name, seed):
    archive = tmp_path / f"{name}.zip"
    content = random.Random(seed).randbytes(PAYLOAD_BYTES)
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as zipped:
        zipped.writestr("payload.bin", content)
    return archive, content


def _wait_for(predicate, message):
    deadline = time.monotonic() + DEADLINE_SECONDS
    while True:
        if predicate():
            return
        if time.monotonic() >= deadline:
            pytest.fail(message() if callable(message) else message)
        time.sleep(0.05)


@contextmanager
def _extract(package, diagnostic_dir, *archives, output=None):
    stderr = diagnostic_dir / "extract.stderr"
    stdout = diagnostic_dir / "extract.stdout"
    arguments = ["extract", "--direct-file", "-c", "k", "-r", "1", "--no-flatten", "--no-pause"]
    if output is not None:
        arguments.extend(("-o", str(output)))
    with stdout.open("wb") as out, stderr.open("wb") as err:
        process = subprocess.Popen(
            [str(package.launcher), *arguments, *map(str, archives)],
            cwd=package.data, env=package.env, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        try:
            def paused():
                diagnostic = stderr.read_text(encoding="utf-8", errors="replace")
                assert process.poll() is None, diagnostic + stdout.read_text(encoding="utf-8", errors="replace")
                return all(
                    any(f"{archive.name}: {status}" in diagnostic
                        for status in ("Disk full", "Waiting for memory/disk"))
                    for archive in archives
                )

            # A slow or queued request is not evidence of actual exhaustion.
            _wait_for(paused, lambda: "not all archives reported a full-disk pause:\n"
                      + stderr.read_text(encoding="utf-8", errors="replace"))
            yield process
        finally:
            if process.poll() is None:
                process.kill()  # Closing the launcher pipe cancels this request.
            process.wait(timeout=DEADLINE_SECONDS)


@contextmanager
def _runtime(package):
    package.json("config", "show")
    state, = package.data.glob("runtime-*.state")
    owner = psutil.Process(int(state.read_text(encoding="utf-8").splitlines()[3]))
    try:
        yield owner
    finally:
        if owner.is_running():
            stopped = package.run("--persistent-shutdown", timeout=DEADLINE_SECONDS)
            assert stopped.returncode == 0, (stopped.stdout, stopped.stderr)
            owner.wait(timeout=DEADLINE_SECONDS)


def test_full_volumes_resume_independently(package, tmp_path):
    # Run with a single host execution slot to force the original blocked wait
    # path. Two inputs in one request force parallel-iterator dispatch on the
    # old implementation; a single input could run on the request thread.
    package.env["RAYON_NUM_THREADS"] = "1"
    with _vhd(tmp_path) as a, _vhd(tmp_path) as b, _runtime(package):
        archive_a, payload_a = _archive(a, "resume-a", 17)
        archive_b, payload_b = _archive(b, "resume-b", 29)
        filler_a, filler_b = _fill(a), _fill(b)
        out_a, out_b = (archive.with_suffix("") / "payload.bin" for archive in (archive_a, archive_b))
        # Both native jobs must reach disk wait before either volume is freed.
        with _extract(package, tmp_path, archive_a, archive_b) as process:
            filler_a.unlink()
            _wait_for(lambda: out_a.is_file() and out_a.stat().st_size == len(payload_a),
                      "the first extraction did not resume while the other volume remained full")
            assert filler_b.is_file()
            assert process.poll() is None
            filler_b.unlink()
            assert process.wait(timeout=DEADLINE_SECONDS) == 0
            assert out_a.read_bytes() == payload_a
            assert out_b.read_bytes() == payload_b


@pytest.mark.parametrize("stop", ["launcher-disconnect", "runtime-shutdown"])
def test_full_disk_cancellation_removes_owned_output_without_freeing_space(package, tmp_path, stop):
    archive, _ = _archive(tmp_path, "interrupted", 37)
    with _vhd(tmp_path) as root, _runtime(package) as owner:
        output = root / "out"
        output.mkdir()
        filler = _fill(root)
        with _extract(package, tmp_path, archive, output=output) as process:
            # Keep the same real volume full while cancelling. These are two
            # different wake paths: client EOF versus persistent server stop.
            if stop == "launcher-disconnect":
                process.kill()
                process.wait(timeout=DEADLINE_SECONDS)
            else:
                result = package.run("--persistent-shutdown", timeout=DEADLINE_SECONDS)
                assert result.returncode == 0, (result.stdout, result.stderr)
                owner.wait(timeout=DEADLINE_SECONDS)
                assert process.wait(timeout=DEADLINE_SECONDS) != 0
            _wait_for(lambda: not any(output.iterdir()), "cancelled extraction left owned output")
            assert filler.is_file()
            assert archive.is_file()
            assert shutil.disk_usage(root).free < PAYLOAD_BYTES
