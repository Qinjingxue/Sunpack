"""Physical discovery errors and final output namespace parity."""
import ctypes
from concurrent.futures import ThreadPoolExecutor
from ctypes import wintypes
import io
import subprocess
import time
import zipfile

import psutil
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
    assert report["summary"]["scan_error_count"] == 0, report
    assert report["summary"]["processed_count"] == 0, report
    assert report["summary"]["failed_count"] == 1, report
    assert report["tasks"][0]["failures"][0]["stage"] == "embedded_boundary"


def test_recursive_authorization_counts_split_sfx_data_members(package, tmp_path):
    split = tmp_path / "split"
    split.mkdir()
    payload = tmp_path / "inner.txt"
    payload.write_bytes(bytes(range(256)) * 9)
    stub = package.tools / "7zCon.sfx"
    subprocess.run(
        [str(package.tools / "7z.exe"), "a", "-t7z", "-mx=0", "-v2k", f"-sfx{stub}",
         str(split / "same.exe"), str(payload)],
        check=True, capture_output=True,
    )
    launcher = split / "same.exe"
    parts = sorted(split.glob("same.7z.*"))
    assert len(parts) == 2
    assert launcher.stat().st_size > sum(part.stat().st_size for part in parts)
    source = tmp_path / "outer.zip"
    with zipfile.ZipFile(source, "w") as archive:
        for item in [launcher, *parts]:
            archive.write(item, item.name)
    output = tmp_path / "out"
    package.configure(recursive_authorization={"enabled": True, "byte_ratio_exponent": 1,
                      "project_ratio_exponent": 1, "minimum_authorization_score": 0.85})

    report = package.json("extract", "-r", "*", "-o", output, source)

    assert report["summary"]["success_count"] == 1
    assert sorted(item.name for item in (output / "outer").iterdir()) == [
        "same.7z.001", "same.7z.002", "same.exe",
    ]


def test_overlapping_recursive_targets_keep_ancestor_scan_filters(package, tmp_path):
    root = tmp_path / "inputs"
    child = root / "child"
    child.mkdir(parents=True)
    archive = child / "archive.zip"
    with zipfile.ZipFile(archive, "w") as stream:
        stream.writestr("item.txt", b"payload")
    package.configure(filesystem={"scan_filters_enabled": True, "scan_filters": [
        {"name": "blacklist", "enabled": True, "paths": [{"value": "child", "regex": False}]},
    ]})
    filtered = package.json("scan", "-R", root, child, archive)
    assert filtered["items"] == []

    package.configure(filesystem={"scan_filters": [
        {"name": "size_range", "enabled": True, "min_bytes": 1},
    ]})
    admitted = package.json("scan", "-R", "-v", root, child, archive)
    item, = admitted["items"]
    assert item["discovery_source"] == "relations"


def test_flat_output_with_long_name_does_not_need_flatten_work_path(package, tmp_path):
    # The archive and destination names fit NTFS. The unused staging suffix does not.
    source = tmp_path / ("a" * 248 + ".zip")
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("item.txt", b"payload")

    output = tmp_path / "out"
    report = package.json("extract", "-f", "-r", "1", "-o", output, source)

    assert report["summary"]["cleanup_results"] == []
    assert (output / source.stem / "item.txt").read_bytes() == b"payload"


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
def test_recursive_file_targets_share_embedded_relation_candidates(
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

    # A lone selection sees only its original scope. An ancestor file target
    # contributes its snapshot to embedded volume resolution.
    alone = package.json("extract", "-d", "-R", "-c", "k", "-r", "1",
                         "-o", tmp_path / "alone", head, code=1)
    combined_out = tmp_path / "combined"
    assert alone["summary"]["failed_count"] == 1
    combined = package.json("extract", "-d", "-R", "-c", cleanup, "-r", "1",
                            "-o", combined_out, ordinary, head, code=0 if embedded else 1)
    assert combined["summary"]["failed_count"] == int(not embedded)
    assert combined["summary"]["success_count"] == 1 + int(embedded)
    assert next(combined_out.rglob("ordinary.txt")).read_bytes() == b"ordinary"
    if embedded:
        assert next(combined_out.rglob(payload.name)).read_bytes() == content
        assert all(part.exists() == (cleanup == "k") for part in [head, *tails])
        return

    assert not list(combined_out.rglob(payload.name))
    assert {part: part.read_bytes() for part in original} == original

    # Ordinary split discovery picks up the tails inside the original boundary.
    nested = child / "download"
    nested.mkdir()
    for tail in tails:
        tail.rename(nested / tail.name)
    recovered = tmp_path / "recovered"
    report = package.json("extract", "-d", "-R", "-c", "k", "-r", "1",
                          "-o", recovered, head)
    assert report["summary"]["success_count"] == 1
    assert next(recovered.rglob(payload.name)).read_bytes() == content


def _nested_mixed_carrier(package, tmp_path, *, recursive_child=False):
    # Unlike a successful segment containing a blocked child, this carrier's
    # own sibling segment fails. Promotion must settle the carrier itself.
    (tmp_path / "secret.txt").write_bytes(b"secret")
    locked = tmp_path / "locked.7z"
    # Encrypted headers block this segment before the worker writes any files.
    # A payload-encrypted ZIP can leave an unverified member and a second branch.
    subprocess.run([str(package.tools / "7z.exe"), "a", "-t7z", "-mhe=on", "-punknown",
                    str(locked), "secret.txt"], cwd=tmp_path, check=True, capture_output=True)
    ordinary = io.BytesIO()
    with zipfile.ZipFile(ordinary, "w") as archive:
        if recursive_child:
            child = io.BytesIO()
            with zipfile.ZipFile(child, "w") as nested:
                nested.writestr("hello.txt", b"independent success")
            archive.writestr("next.zip", child.getvalue())
        else:
            archive.writestr("hello.txt", b"independent success")
    carrier = b"prefix" + locked.read_bytes() + b"between" + ordinary.getvalue() + b"tail"
    outer = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer, "w") as archive:
        archive.writestr("keep.txt", b"prevent outer flatten")
        archive.writestr("carrier.bin", carrier)
    return outer, carrier


def test_nested_mixed_carrier_promotes_before_flattening_successful_segment(package, tmp_path):
    outer, carrier = _nested_mixed_carrier(package, tmp_path)
    output = tmp_path / "out"
    package.configure(post_extract={"flatten_single_directory": True}, recursive_authorization={"enabled": False},
                      filesystem={"scan_filters_enabled": False})
    report = package.json("extract", "-d", "-r", "*", "-c", "k", "--no-builtin-pw", "-o", output, outer, code=1)
    assert (output / "outer" / "carrier" / "hello.txt").read_bytes() == b"independent success", report
    assert (output / "outer" / "keep.txt").is_file()
    assert (tmp_path / "carrier.bin").read_bytes() == carrier
    assert outer.is_file()


def test_nested_mixed_carrier_survives_cancel_during_successful_sibling_recursion(package, tmp_path):
    outer, carrier = _nested_mixed_carrier(package, tmp_path, recursive_child=True)
    output = tmp_path / "out"
    package.configure(recursive_authorization={"enabled": False},
                      post_extract={"flatten_single_directory": True},
                      filesystem={"scan_filters_enabled": False})

    def wait_for_round(stream, number):
        marker = f"[CLI] Round {number} finished. Continue recursive extraction? (y/n): "
        tail = ""
        while character := stream.read(1):
            tail = (tail + character)[-len(marker):]
            if tail == marker:
                return True
        return False

    command = [str(package.launcher), "extract", "-d", "-r", "?", "-c", "k",
               "--no-builtin-pw", "--no-pause", "-o", str(output), str(outer)]
    with ThreadPoolExecutor(max_workers=1) as reader, subprocess.Popen(
        command, cwd=package.data, env=package.env, encoding="utf-8",
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ) as process:
        try:
            for depth in (1, 2):
                assert reader.submit(wait_for_round, process.stdout, depth).result(timeout=60)
                process.stdin.write("y\n")
                process.stdin.flush()
            # The depth-three archive has now actually extracted its payload.
            # Its ordinary recursion prompt holds the request before ancestor
            # commits, without sleeps, huge archives, or production test hooks.
            assert reader.submit(wait_for_round, process.stdout, 3).result(timeout=60)
            assert list(output.rglob("hello.txt"))
            state, = package.data.glob("runtime-*.state")
            owner = psutil.Process(int(state.read_text(encoding="utf-8").splitlines()[3]))
            # Kill only the CLI client. The existing IPC disconnect path cancels
            # its request in the still-running host and performs normal rollback.
            process.kill()
            process.wait(timeout=30)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=30)

    deadline = time.monotonic() + 30
    while (output / "outer").exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not (output / "outer").exists(), "cancelled request did not roll back its uncommitted output"
    assert outer.is_file()
    assert (tmp_path / "carrier.bin").read_bytes() == carrier
    # A successful second connection proves this was request cancellation, not
    # runtime process death (which would test a different recovery boundary).
    assert owner.is_running()
    assert package.json("config", "show")["items"]
