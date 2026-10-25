import asyncio
import binascii
import ctypes
from ctypes import wintypes
import gzip
import io
import json
import lzma
import os
import subprocess
import struct
import tarfile
import time
import zipfile

import pytest

from sunpack.core.contracts.archive_input import ArchiveInputDescriptor
from sunpack.core.contracts.failures import FailureKind
from tests.helpers.archive_tasks import make_archive_task, make_task_from_descriptor
from tests.helpers.worker_events import worker_trace_item
from sunpack.pipeline.extraction.internal.sevenzip.sevenzip_runner import (
    SevenZipRunner,
    _NativeWorkerProcess,
    _apply_native_environment,
)
from sunpack.pipeline.extraction.internal.sevenzip.worker_diagnostics import worker_result_payload
from sunpack.pipeline.extraction.scheduler import ExtractionScheduler
from sunpack.core.support.resources import get_sevenzip_bridge_worker_path
from tests.helpers.tool_config import get_test_tools


def _invoke_worker(worker, request, *, env=None, timeout=10):
    return subprocess.run([worker], input=json.dumps(request, ensure_ascii=False),
                          capture_output=True, text=True, encoding="utf-8", env=env, timeout=timeout)


def _require_worker_or_skip():
    try:
        return get_sevenzip_bridge_worker_path()
    except Exception as exc:
        pytest.skip(f"sunpack_sevenzip_worker.exe is required: {exc}")


def _require_7z_or_skip():
    seven_zip = get_test_tools()["seven_zip"]
    if not seven_zip or not seven_zip.is_file():
        pytest.skip("7z.exe is required to build worker extraction fixtures")
    _require_worker_or_skip()
    return seven_zip


@pytest.mark.parametrize("tar_format", [tarfile.GNU_FORMAT, tarfile.PAX_FORMAT])
def test_worker_resolves_hard_link_graph_and_rejects_invalid_targets(tmp_path, tar_format):
    # Other extraction tests only exercise payload-bearing members. This one
    # catches empty successful links, forward chains, collision misbinding and
    # invalid references, including beyond a source-manifest retention cap.
    from sunpack_native import archive_state_tar_manifest_native

    worker = _require_worker_or_skip()
    archive = tmp_path / "links.blob"
    long_name = "nested/" + "目标" * 65 + "/target.txt"
    members = [("bad:name", b"first"), ("bad_name", b"collision"),
               ("old", "dup"), ("dup", b"before"), ("prior", "dup"),
               ("dup", b"after"), ("latest", "dup"),
               ("chain", "forward"), ("forward", long_name),
               (long_name, b"forward payload"), ("empty", b""), ("empty-link", "empty"),
               ("collision-link", "bad:name")]
    with tarfile.open(archive, "w", format=tar_format) as handle:
        for name, value in members:
            item = tarfile.TarInfo(name)
            if isinstance(value, str):
                item.type, item.linkname = tarfile.LNKTYPE, value
                handle.addfile(item)
            else:
                item.size = len(value)
                handle.addfile(item, io.BytesIO(value))
    # Exercise the same link model on carrier and cross-part byte views.
    data = archive.read_bytes()
    source = {"entry_path": str(archive), "format_hint": "tar"}
    if tar_format == tarfile.GNU_FORMAT:
        prefix = b"carrier prefix"
        archive.write_bytes(prefix + data + b"carrier suffix")
        source.update(open_mode="file_range", parts=[{
            "path": str(archive), "start": len(prefix), "end": len(prefix) + len(data)}])
    else:
        second = tmp_path / "second.blob"
        archive.write_bytes(data[:4099])
        second.write_bytes(data[4099:])
        source.update(open_mode="concat_ranges", ranges=[
            {"path": str(archive), "start": 0}, {"path": str(second), "start": 0}])
    output = tmp_path / "out"
    result = _invoke_worker(worker, {"job_id": "links", "archive_path": str(archive), "archive_input": source,
                                    "output_dir": str(output), "format_hint": "tar"})
    final = _worker_result(result.stdout)
    assert result.returncode == 0, result.stdout + result.stderr
    assert final["status"] == "ok" and final["verified_manifest"]["validated"]
    pairs = [("old", "dup"), ("prior", "dup"), ("latest", "dup(1)"),
             ("chain", long_name), ("forward", long_name),
             ("empty-link", "empty"), ("collision-link", "bad_name")]
    for alias, target in pairs:
        assert (output / alias).read_bytes() == (output / target).read_bytes()
        assert os.path.samefile(output / alias, output / target)
    manifest = archive_state_tar_manifest_native(source)
    expected = sum(path.stat().st_size for path in output.rglob("*") if path.is_file())
    assert manifest.archive_walk_complete and manifest.total_unpacked_size == expected
    assert manifest.file_count == len(members)
    sizes = {row["path"]: row["size"] for row in manifest.entry_page(0, 100)}
    assert all((output / name).stat().st_size == size for name, size in sizes.items())
    capped = archive_state_tar_manifest_native(source, max_items=2)
    assert len(capped) == 2 and capped.total_unpacked_size == expected

    for index, bad in enumerate([[("missing", "absent")], [("empty-target", "")], [("self", "self")],
                                 [("a", "b"), ("b", "a")], [("escape", "../outside")]]):
        broken = tmp_path / f"broken-{index}.tar"
        with tarfile.open(broken, "w") as handle:
            for name, target in bad:
                item = tarfile.TarInfo(name)
                item.type, item.linkname = tarfile.LNKTYPE, target
                handle.addfile(item)
        result = _invoke_worker(worker, {"job_id": "bad-link", "archive_path": str(broken),
                                        "output_dir": str(tmp_path / f"bad-{index}"), "format_hint": "tar"})
        final = _worker_result(result.stdout)
        assert result.returncode != 0 and not final["verified_manifest"]["validated"]
        assert not archive_state_tar_manifest_native({"entry_path": str(broken)}, max_items=0).archive_walk_complete


@pytest.mark.parametrize("origin", ["foreground", "watch"])
@pytest.mark.parametrize("layout", ["tar", "tar.gz", "rar5", "rar5-encrypted", "rar5-split", "rar5-corrupted"])
def test_hard_links_survive_pipeline_verification(tmp_path, origin, layout):
    # The worker graph test cannot catch TAR source-size disagreement, nested
    # scheduling, password selection, volume planning or cleanup after success.
    from sunpack.pipeline.coordinator.engine import PipelineEngine
    from tests.helpers.config_factory import make_config

    _require_worker_or_skip()
    payload = b"hard-link content\n" * 1024
    archive = tmp_path / "archive.blob"
    if layout.startswith("tar"):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as handle:
            item = tarfile.TarInfo("target.txt")
            item.size = len(payload)
            handle.addfile(item, io.BytesIO(payload))
            item = tarfile.TarInfo("alias.txt")
            item.type, item.linkname = tarfile.LNKTYPE, "target.txt"
            handle.addfile(item)
        archive.write_bytes(gzip.compress(stream.getvalue()) if layout.endswith("gz") else stream.getvalue())
    else:
        rar = get_test_tools()["rar_exe"]
        if not rar or not rar.is_file():
            pytest.skip("Rar.exe is required to build real hard-link fixtures")
        source = tmp_path / "source"
        source.mkdir()
        (source / "target.txt").write_bytes(payload)
        os.link(source / "target.txt", source / "alias.txt")
        archive = tmp_path / "archive.rar"
        switches = ["-paudit-secret"] if layout.endswith("encrypted") else []
        if layout.endswith("split"):
            switches += ["-v5k"]
        subprocess.run([str(rar), "a", "-ma5", "-oh", "-m0", "-s-", "-ds", "-idq", "-ep1",
                        *switches, str(archive), "target.txt", "alias.txt"], cwd=source, check=True, capture_output=True)
        if layout.endswith("corrupted"):
            # A link may inherit only a successfully verified target, even if
            # the decoder accepted the payload and its later CRC check fails.
            data = bytearray(archive.read_bytes())
            offset = data.index(payload)
            data[offset] ^= 1
            archive.write_bytes(data)
        if switches == ["-v5k"]:
            archive = tmp_path / "archive.part1.rar"
        elif not switches:
            disguised = tmp_path / "archive.blob"
            archive.rename(disguised)
            archive = disguised
    config = make_config({"cli": {"quiet": True}, "recursive_extract": 3,
                          "user_passwords": ["audit-secret"],
                          "post_extract": {"archive_cleanup_mode": "k", "flatten_single_directory": False}})

    async def run():
        async with PipelineEngine(config) as engine:
            return (await engine.run([str(archive)], direct=True, origin=origin)).summary

    summary = asyncio.run(run())
    if layout.endswith("corrupted"):
        assert summary.success_count == 0 and summary.failed_count == 1
        assert summary.target_results[0].verification["content_integrity"] != "verified_complete"
        assert archive.exists()
        return
    assert summary.success_count >= 1 and summary.failed_count == 0
    aliases = [path for path in tmp_path.rglob("alias.txt") if path.parent.name != "source"]
    assert len(aliases) == 1
    alias = aliases[0]
    assert alias.read_bytes() == payload and os.path.samefile(alias, alias.with_name("target.txt"))


def _file_times_ns(path, values=None):
    """Read/set all three Windows timestamps without opening the file's data."""
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    time_args = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 3
    kernel.GetFileTime.argtypes = time_args
    kernel.SetFileTime.argtypes = time_args
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.CreateFileW(str(path), 0x180 if values else 0x80, 7, None, 3, 0x02000000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        stamps = [wintypes.FILETIME() for _ in range(3)]
        if values is not None:
            for stamp, ns in zip(stamps, values):
                ticks = ns // 100 + 116444736000000000
                stamp.dwLowDateTime = ticks & 0xFFFFFFFF
                stamp.dwHighDateTime = ticks >> 32
            if not kernel.SetFileTime(handle, *(ctypes.byref(stamp) for stamp in stamps)):
                raise ctypes.WinError(ctypes.get_last_error())
        if not kernel.GetFileTime(handle, *(ctypes.byref(stamp) for stamp in stamps)):
            raise ctypes.WinError(ctypes.get_last_error())
        return tuple((((stamp.dwHighDateTime << 32) | stamp.dwLowDateTime)
                      - 116444736000000000) * 100 for stamp in stamps)
    finally:
        kernel.CloseHandle(handle)


def _file_attributes(path, value=None):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
    kernel.GetFileAttributesW.restype = wintypes.DWORD
    kernel.SetFileAttributesW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
    if value is not None and not kernel.SetFileAttributesW(str(path), value or 0x80):
        raise ctypes.WinError(ctypes.get_last_error())
    attributes = kernel.GetFileAttributesW(str(path))
    if attributes == 0xFFFFFFFF:
        raise ctypes.WinError(ctypes.get_last_error())
    return attributes


@pytest.mark.parametrize("archive_type", ["7z", "zip", "rar4", "rar5"])
def test_worker_preserves_archived_metadata_like_7z(tmp_path, archive_type):
    # Real archive -> async writer -> inventory, compared with 7z.exe.
    # Other tests miss directory finalization and writable attribute restoration.
    # Empty/tiny/multi-buffer files and nested/empty directories share one job.
    seven_zip = _require_7z_or_skip()
    worker = _require_worker_or_skip()
    rar = get_test_tools()["rar_exe"] if archive_type.startswith("rar") else None
    if archive_type.startswith("rar") and (not rar or not rar.is_file()):
        pytest.skip("Rar.exe is required to build metadata fixtures")
    source = tmp_path / "source"
    source.mkdir()
    payloads = {"folder/deep/video.mp4": b"video" * (1 << 20),
                "folder/photo.jpg": b"picture", "empty.bin": b""}
    expected = {}
    for index, (name, payload) in enumerate(payloads.items()):
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        expected[name] = _file_times_ns(path, (
            1577836800123456700 + index * 1000000000,
            1577923200234567800 + index * 1000000000,
            1578009600345678900 + index * 1000000000,
        ))
    (source / "folder/empty").mkdir()
    directories = ["folder", "folder/deep", "folder/empty"]
    for index, name in enumerate(directories):
        expected[name] = _file_times_ns(source / name, (
            1546300800123456700 + index * 1000000000,
            1546387200234567800 + index * 1000000000,
            1546473600345678900 + index * 1000000000,
        ))
    attributes = dict(zip(payloads, [0x21, 0x26, 0]))
    attributes.update(dict(zip(directories, [0x07, 0x02, 0x01])))
    for name, value in attributes.items():
        _file_attributes(source / name, value)
    archive = tmp_path / "archive.disguised"
    format_hint = "rar" if rar else archive_type
    try:
        if rar:
            # RAR4/5 have different timestamp encodings and precision.
            subprocess.run([str(rar), "a", f"-ma{archive_type[-1]}", "-m0", "-tsm3", "-tsc3", "-tsa3",
                            "-r", "-y", str(archive), "folder", "empty.bin"],
                           cwd=source, check=True, capture_output=True)
        else:
            subprocess.run([str(seven_zip), "a", f"-t{archive_type}", str(archive),
                            "-mtc=on", "-mta=on", "-mtm=on", "-mx=0", "-y", "folder", "empty.bin"],
                           cwd=source, check=True, capture_output=True)
    finally:
        for name in attributes:
            _file_attributes(source / name, 0)
    oracle = tmp_path / "oracle"
    subprocess.run([str(seven_zip), "x", str(archive), f"-o{oracle}", "-y"],
                   check=True, capture_output=True)
    if rar:
        expected = {name: _file_times_ns(oracle / name) for name in expected}
    output = tmp_path / "output"
    result = _invoke_worker(worker, {
        "job_id": "file-times", "archive_path": str(archive),
        "output_dir": str(output), "format_hint": format_hint,
    })
    final = _worker_result(result.stdout)
    assert result.returncode == 0, result.stdout + result.stderr
    assert final["status"] == "ok" and "metadata_warning" not in final
    rows = final["verified_manifest"]["native_rows"].file_page(0, len(payloads))
    rows = {row["path"].replace("\\", "/"): row for row in rows}
    try:
        for name in expected:
            assert _file_times_ns(output / name) == _file_times_ns(oracle / name) == expected[name], name
            assert _file_attributes(output / name) & 0x3127 == _file_attributes(oracle / name) & 0x3127, name
        for name, payload in payloads.items():
            assert rows[name]["mtime_ns"] == expected[name][2]
            assert (output / name).read_bytes() == payload
    finally:
        for root in (output, oracle):
            for name in expected:
                _file_attributes(root / name, 0)


@pytest.mark.parametrize(("archive_type", "layout"), [
    ("zip", "file"), ("tar", "file"), ("tar-pre-epoch", "file"),
    ("gzip", "file"), ("gzip-no-time", "file"),
    ("xz", "file"), ("xz", "carrier"), ("xz", "split"),
])
def test_worker_preserves_partial_or_missing_file_times(tmp_path, archive_type, layout):
    # Formats without CTime/ATime must not inherit MTime as a fabricated value.
    # Also covers DOS local time, negative Unix time and streams with no time.
    # Each distinct property layout needs only one tiny in-memory fixture.
    worker = _require_worker_or_skip()
    payload = b"historical payload"
    archive = tmp_path / "payload.blob"
    mtime_ns = 946684800000000000
    if archive_type == "zip":
        date = (2000, 1, 2, 12, 34, 56)
        with zipfile.ZipFile(archive, "w") as handle:
            handle.writestr(zipfile.ZipInfo("payload", date_time=date), payload)
        mtime_ns = int(time.mktime((*date, 0, 0, -1))) * 1000000000
    elif archive_type.startswith("tar"):
        item = tarfile.TarInfo("payload")
        item.size = len(payload)
        item.mtime = -157766400 if archive_type == "tar-pre-epoch" else mtime_ns // 1000000000
        item.mode = 0o444 if archive_type == "tar-pre-epoch" else 0o644
        mtime_ns = item.mtime * 1000000000
        archive_format = tarfile.GNU_FORMAT if item.mtime < 0 else tarfile.USTAR_FORMAT
        with tarfile.open(archive, "w", format=archive_format) as handle:
            handle.addfile(item, io.BytesIO(payload))
            directory = tarfile.TarInfo("recorded")
            directory.type = tarfile.DIRTYPE
            directory.mode = 0o555
            directory.mtime = item.mtime
            handle.addfile(directory)
    elif archive_type.startswith("gzip"):
        stamp = 0 if archive_type == "gzip-no-time" else mtime_ns // 1000000000
        archive.write_bytes(gzip.compress(payload, mtime=stamp))
        if not stamp:
            mtime_ns = None
    else:
        archive.write_bytes(lzma.compress(payload))
        mtime_ns = None
    archive_mtime_ns = 1514764800765432100
    os.utime(archive, ns=(archive_mtime_ns, archive_mtime_ns))
    input_path = archive
    descriptor = {}
    if layout != "file":
        data = archive.read_bytes()
        input_path = tmp_path / "payload.disguised"
        descriptor = {"entry_path": str(input_path), "format_hint": "xz"}
        if layout == "carrier":
            prefix = b"carrier prefix"
            input_path.write_bytes(prefix + data + b"carrier suffix")
            descriptor.update(open_mode="file_range", parts=[{
                "path": str(input_path), "start": len(prefix), "end": len(prefix) + len(data),
            }])
        else:
            second = tmp_path / "second.disguised"
            midpoint = len(data) // 2
            input_path.write_bytes(data[:midpoint])
            second.write_bytes(data[midpoint:])
            os.utime(second, ns=(946684800000000000, 946684800000000000))
            descriptor.update(open_mode="concat_ranges", ranges=[
                {"path": str(input_path), "start": 0}, {"path": str(second), "start": 0},
            ])
        os.utime(input_path, ns=(archive_mtime_ns, archive_mtime_ns))
    output = tmp_path / "output"
    started = time.time_ns()
    result = _invoke_worker(worker, {
        "job_id": "partial-file-times", "archive_path": str(input_path),
        "output_dir": str(output),
        "archive_input": descriptor,
        "format_hint": "gzip" if archive_type.startswith("gzip") else archive_type.split("-")[0],
    })
    finished = time.time_ns()
    final = _worker_result(result.stdout)
    assert result.returncode == 0, result.stdout + result.stderr
    assert final["status"] == "ok" and "metadata_warning" not in final
    created, accessed, modified = _file_times_ns(output / "payload")
    assert started <= created <= finished
    assert started <= accessed <= finished
    if mtime_ns is None:
        assert modified == archive_mtime_ns
    else:
        assert modified == mtime_ns
    row = final["verified_manifest"]["native_rows"].file_page(0, 1)[0]
    assert row.get("mtime_ns") == (modified if modified >= 0 else None)
    assert (output / "payload").read_bytes() == payload
    if mtime_ns is None or archive_type.startswith("tar"):
        oracle = tmp_path / "oracle"
        subprocess.run([str(_require_7z_or_skip()), "x", str(archive), f"-o{oracle}", "-y"],
                       check=True, capture_output=True)
        assert _file_times_ns(oracle / "payload")[2] == modified
        if archive_type.startswith("tar"):
            assert _file_times_ns(output / "recorded")[2] == _file_times_ns(oracle / "recorded")[2]
            for name in ("payload", "recorded"):
                assert _file_attributes(output / name) & 0x27 == _file_attributes(oracle / name) & 0x27
                _file_attributes(output / name, 0)
                _file_attributes(oracle / name, 0)


def test_worker_directory_metadata_uses_allocated_paths_and_archive_order(tmp_path):
    # Unlike fresh-output oracle cases, a file forces directory renaming here.
    # Duplicate and late directory records must still affect the allocated path;
    # one small ZIP also checks implicit parents and ignored root metadata.
    seven_zip = _require_7z_or_skip()
    worker = _require_worker_or_skip()
    archive = tmp_path / "ordered.zip"
    entries = [("./", 0), ("tree/", 1), ("tree/deep/payload", 2),
               ("tree/deep/", 3), ("tree/empty/", 4), ("tree/", 5),
               ("implicit/payload", 6)]
    with zipfile.ZipFile(archive, "w") as handle:
        for name, index in entries:
            item = zipfile.ZipInfo(name)
            item.create_system = 0
            item.external_attr = 0x12 if name.endswith("/") else 0x20
            stamps = tuple(132223104001234567 + index * 10000000 + delta
                           for delta in (0, 100000000000, 200000000000))
            item.extra = struct.pack("<HHIHHQQQ", 0x000A, 32, 0, 1, 24, *stamps)
            if index == 5:
                with pytest.warns(UserWarning, match="Duplicate name"):
                    handle.writestr(item, b"")
            else:
                handle.writestr(item, b"" if name.endswith("/") else b"payload")
    oracle = tmp_path / "oracle"
    subprocess.run([str(seven_zip), "x", str(archive), f"-o{oracle}", "-y"],
                   check=True, capture_output=True)
    output = tmp_path / "output"
    output.mkdir()
    collision = output / "tree"
    collision.write_bytes(b"existing file")
    collision_time = _file_times_ns(collision)
    started = time.time_ns()
    result = _invoke_worker(worker, {"job_id": "directory-paths", "archive_path": str(archive),
                                     "output_dir": str(output), "format_hint": "zip"})
    finished = time.time_ns()
    final = _worker_result(result.stdout)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "metadata_warning" not in final
    rows = final["verified_manifest"]["native_rows"].file_page(0, 2)
    child = next(output / row["output_path"] for row in rows if "deep" in row["path"])
    tree = child.parent.parent
    assert tree != collision and child.read_bytes() == b"payload"
    assert collision.read_bytes() == b"existing file" and _file_times_ns(collision) == collision_time
    for relative in ("", "deep", "empty"):
        assert _file_times_ns(tree / relative) == _file_times_ns(oracle / "tree" / relative)
        assert _file_attributes(tree / relative) & 0x27 == _file_attributes(oracle / "tree" / relative) & 0x27
    assert started <= _file_times_ns(output)[2] <= finished
    assert started <= _file_times_ns(output / "implicit")[2] <= finished


def test_worker_reports_timestamp_failure_without_losing_content(tmp_path):
    # A real invalid ZIP NTFS timestamp exercises SetFileTime and the complete
    # warning transport, which successful archives and writer-only tests cannot.
    # Two files and a directory verify aggregation across both output paths.
    worker = _require_worker_or_skip()
    archive = tmp_path / "invalid-times.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        for name in ("one.txt", "two.txt"):
            item = zipfile.ZipInfo(name)
            item.extra = struct.pack("<HHIHHQQQ", 0x000A, 32, 0, 1, 24,
                                     1 << 63, 132223104000000000, 132223104000000000)
            handle.writestr(item, b"intact")
        directory = zipfile.ZipInfo("directory/")
        directory.extra = item.extra
        handle.writestr(directory, b"")
    output = tmp_path / "output"
    result = _invoke_worker(worker, {
        "job_id": "timestamp-warning", "archive_path": str(archive),
        "output_dir": str(output), "format_hint": "zip",
    })
    final = _worker_result(result.stdout)
    assert result.returncode == 0, result.stdout + result.stderr
    assert final["status"] == "ok" and final["files_written"] == 2
    warning = final["metadata_warning"]
    assert warning["file_count"] == 2 and warning["win32_error"] != 0
    assert warning["directory_count"] == 1 and warning["time_failure_count"] == 3
    assert warning["attribute_failure_count"] == 0 and warning["operation"] == "time"
    assert warning["first_item_index"] == 0 and warning["first_item"] == "one.txt"
    rows = final["verified_manifest"]["native_rows"].file_page(0, 2)
    for row in rows:
        path = output / row["path"]
        assert row["mtime_ns"] == _file_times_ns(path)[2]
        assert path.read_bytes() == b"intact"


def test_worker_duplicate_invalid_names_report_failure_without_spinning(tmp_path):
    worker = _require_worker_or_skip()
    archive = tmp_path / "duplicate-invalid.zip"
    literal = str(archive).replace("'", "''")
    subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command",
         "$ErrorActionPreference='Stop'; Add-Type -AssemblyName System.IO.Compression; "
         f"$f=[IO.File]::Open('{literal}',[IO.FileMode]::Create); "
         "$z=[IO.Compression.ZipArchive]::new($f,[IO.Compression.ZipArchiveMode]::Create); "
         "1..1000 | ForEach-Object { [void]$z.CreateEntry(('entry'+$_+'.txt')) }; "
         "$n=('a'*260)+'.txt'; 1..12 | ForEach-Object { [void]$z.CreateEntry($n) }; "
         "$z.Dispose(); $f.Dispose()"],
        check=True, capture_output=True,
    )
    for attempt in range(3):
        result = subprocess.run(
            [worker], input=json.dumps({"job_id": "invalid-name-regression", "archive_path": str(archive),
                                       "output_dir": str(tmp_path / f"out-{attempt}"), "format_hint": "zip"}),
            capture_output=True, text=True, encoding="utf-8", timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        final = _worker_result(result.stdout)
        assert result.returncode != 0
        assert final["status"] == "failed"
        assert final["failure_kind"] == "output_filesystem"


def _create_7z(tmp_path, name: str, text: str):
    seven_zip = _require_7z_or_skip()
    source = tmp_path / f"{name}.txt"
    source.write_text(text, encoding="utf-8")
    archive = tmp_path / f"{name}.7z"
    result = subprocess.run(
        [str(seven_zip), "a", str(archive), str(source), "-mx=0", "-y"],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"7z failed:\n{result.stdout}\n{result.stderr}")
    return archive, source.name


def _create_7z_with_nested_file(tmp_path):
    seven_zip = _require_7z_or_skip()
    nested_dir = tmp_path / "conflict"
    nested_dir.mkdir()
    child = nested_dir / "child.txt"
    child.write_text("nested payload", encoding="utf-8")
    archive = tmp_path / "nested.7z"
    result = subprocess.run(
        [str(seven_zip), "a", str(archive), "conflict\\child.txt", "-mx=0", "-y"],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"7z failed:\n{result.stdout}\n{result.stderr}")
    return archive


def _create_shift_jis_zip(tmp_path):
    archive = tmp_path / "shift-jis.zip"
    expected_name = "日本語/説明.txt"
    raw_name = expected_name.encode("cp932")
    payload = b"shift-jis payload"
    crc = binascii.crc32(payload) & 0xFFFFFFFF
    local = struct.pack(
        "<IHHHHHIIIHH",
        0x04034B50, 20, 0, 0, 0, 0, crc,
        len(payload), len(payload), len(raw_name), 0,
    ) + raw_name + payload
    central = struct.pack(
        "<IHHHHHHIIIHHHHHII",
        0x02014B50, 20, 20, 0, 0, 0, 0, crc,
        len(payload), len(payload), len(raw_name),
        0, 0, 0, 0, 0, 0,
    ) + raw_name
    eocd = struct.pack(
        "<IHHHHIIH",
        0x06054B50, 0, 0, 1, 1, len(central), len(local), 0,
    )
    archive.write_bytes(local + central + eocd)
    return archive, expected_name, payload


def test_worker_does_not_classify_unencrypted_open_failure_as_wrong_password(tmp_path):
    worker = _require_worker_or_skip()
    archive = tmp_path / "malformed.7z"
    archive.write_bytes(b"7z\xbc\xaf'\x1c" + b"\x00" * 26)
    payload = {
        "job_id": "unencrypted-open-failure",
        "archive_path": str(archive),
        "output_dir": str(tmp_path / "out"),
        "password": "irrelevant",
    }

    result = _invoke_worker(worker, payload)
    lines = [json.loads(line) for line in result.stdout.splitlines() if line.strip().startswith("{")]
    worker_result = next(item for item in lines if item.get("type") == "result")

    assert result.returncode != 0
    assert worker_result["wrong_password"] is False
    assert worker_result["encrypted"] is False
    assert worker_result["failure_kind"] != "encrypted_or_wrong_password"


def test_native_worker_result_escapes_control_characters(tmp_path):
    worker_path = _require_worker_or_skip()
    archive = tmp_path / "control-name.zip"
    # Control characters are mapped to '_' on disk, so an over-long component
    # forces the item to fail while its raw name still reaches the result.
    failed_name = "control-\x01-name" + "x" * 300 + ".txt"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr(failed_name, "unsafe filename payload")
    payload = {
        "job_id": "control-name",
        "archive_path": str(archive),
        "output_dir": str(tmp_path / "out"),
    }
    runner = SevenZipRunner({})
    runner.worker_path = worker_path
    try:
        completed = runner.submit_attempt(
            payload,
            startupinfo=None,
            task=_task(archive),
        ).result(timeout=10)
    finally:
        runner.close()

    worker_result = worker_result_payload(completed)
    assert completed.returncode != 0
    assert "timed out" not in completed.stderr.lower()
    assert worker_result["job_id"] == "control-name"
    assert worker_result["failed_item"] == failed_name
    assert worker_result["diagnostics"]["failed_item"]["path"] == failed_name


def test_native_worker_asyncio_event_controller_completes_job(tmp_path):
    worker_path = _require_worker_or_skip()
    archive = tmp_path / "async.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("async.txt", "async payload")
    out_dir = tmp_path / "async-out"
    payload = {
        "job_id": "async-event-controller",
        "archive_path": str(archive),
        "output_dir": str(out_dir),
    }

    async def run_attempt():
        runner = SevenZipRunner({})
        runner.worker_path = worker_path
        try:
            return await asyncio.wait_for(
                runner.submit_attempt_asyncio(payload, task=_task(archive)),
                timeout=10,
            )
        finally:
            await runner.aclose()

    completed = asyncio.run(run_attempt())

    assert completed.returncode == 0
    assert (out_dir / "async.txt").read_text(encoding="utf-8") == "async payload"


def test_native_worker_asyncio_process_exit_completes_pending_job(tmp_path):
    worker = tmp_path / "exit_worker.cmd"
    worker.write_text(
        '@echo {"type":"worker_ready","process_mode":"normal","process_mode_applied":true}\r\n@set /p request=\r\n@exit /b 7\r\n',
        encoding="utf-8",
    )
    runner = SevenZipRunner({})
    runner.worker_path = str(worker)

    async def run_attempt():
        try:
            return await asyncio.wait_for(
                runner.submit_attempt_asyncio(
                    {"job_id": "async-process-exit"},
                    task=_task(worker),
                ),
                timeout=3,
            )
        finally:
            await runner.aclose()

    completed = asyncio.run(run_attempt())

    assert completed.returncode == -101
    assert completed.worker_diagnostics["process_failure"]["failure_kind"] == "worker_lost"


@pytest.mark.parametrize("completion", ["job_finished", "worker_exit", "worker_closed"])
def test_cancelled_request_retains_input_lease_until_native_work_stops(tmp_path, completion):
    from sunpack.pipeline.coordinator.engine import PipelineEngine

    worker = tmp_path / "cancel_worker.cmd"
    ending = (
        '@echo {"type":"result","job_id":"cancel-job","status":"failed"}\r\n'
        '@echo {"type":"native_event","event":"job_finished","job_id":"cancel-job"}\r\n'
        '@set /p shutdown=\r\n'
        if completion == "job_finished"
        else '@set /p ignored=\r\n' if completion == "worker_closed"
        else '@exit /b 7\r\n'
    )
    worker.write_text(
        '@echo {"type":"worker_ready","process_mode":"normal","process_mode_applied":true}\r\n'
        '@set /p request=\r\n'
        '@echo {"type":"native_event","event":"job_started","job_id":"cancel-job"}\r\n'
        '@set /p cancellation=\r\n'
        '@echo {"type":"cancel_ack","job_id":"cancel-job"}\r\n'
        '@echo {"type":"native_event","event":"job_cancelling","job_id":"cancel-job"}\r\n'
        '@set /p finish=\r\n' + ending,
        encoding="utf-8",
    )

    async def scenario():
        runner = SevenZipRunner({})
        runner.worker_path = str(worker)
        started, cancelling = asyncio.Event(), asyncio.Event()

        def event(_task, value):
            if value.get("event") == "job_started":
                started.set()
            elif value.get("event") == "job_cancelling":
                cancelling.set()

        runner.native_event_callback = event

        class Runtime:
            def __init__(self, services, submission, options, leases):
                self.submission, self.leases = submission, leases

            async def execute_async(self, broker, cancellation):
                await self.leases.acquire(self.submission.request_id, [str(worker)])
                await runner.submit_attempt_asyncio({"job_id": "cancel-job"}, task=_task(worker))
                raise AssertionError("the request must remain cancelled")

        async with PipelineEngine({}) as engine:
            engine._request_runtime_factory = Runtime
            request = asyncio.create_task(engine.run([str(worker)]))
            waiting = None
            try:
                await asyncio.wait_for(started.wait(), 2)
                request.cancel()
                await asyncio.wait_for(cancelling.wait(), 2)
                request.cancel()
                waiting = asyncio.create_task(engine._path_leases.acquire("second", [str(worker)]))
                await asyncio.sleep(0)
                assert not request.done()
                assert not waiting.done()
                assert not engine.is_idle()
                native = await runner._async_worker_holder_or_create().get_or_start(None)
                if completion == "worker_closed":
                    await native.close()
                else:
                    await native.send('{"worker_command":"finish"}')
                with pytest.raises(asyncio.CancelledError):
                    await asyncio.wait_for(request, 2)
                await asyncio.wait_for(waiting, 2)
                assert engine.is_idle()
            finally:
                await runner.aclose()
                await asyncio.gather(request, return_exceptions=True)
                if waiting is not None:
                    waiting.cancel()
                    await asyncio.gather(waiting, return_exceptions=True)
                await engine._path_leases.release("second")

    asyncio.run(scenario())


@pytest.mark.parametrize("layout", ["plain", "carrier", "split"])
def test_worker_header_encrypted_7z_tries_candidates_with_disguised_names(tmp_path, layout):
    seven_zip = _require_7z_or_skip()
    worker = _require_worker_or_skip()
    source = tmp_path / "payload.txt"
    source.write_text("encrypted payload", encoding="utf-8")
    original_mtime_ns = 1578009600345678900
    os.utime(source, ns=(original_mtime_ns, original_mtime_ns))
    _file_attributes(source, 0x27)
    archive = tmp_path / "encrypted.7z"
    subprocess.run(
        [str(seven_zip), "a", str(archive), str(source), "-psecret", "-mhe=on", "-mx=0", "-y"],
        check=True, capture_output=True,
    )
    _file_attributes(source, 0)
    data = archive.read_bytes()
    disguised = tmp_path / "input.blob"
    descriptor = {"entry_path": str(disguised), "format_hint": "7z", "open_mode": "file"}
    if layout == "plain":
        disguised.write_bytes(data)
    elif layout == "carrier":
        prefix = b"carrier prefix"
        disguised.write_bytes(prefix + data + b"carrier suffix")
        descriptor.update(open_mode="file_range", parts=[{
            "path": str(disguised), "start": len(prefix), "end": len(prefix) + len(data),
        }])
    else:
        second = tmp_path / "part.disguised"
        midpoint = len(data) // 2
        disguised.write_bytes(data[:midpoint])
        second.write_bytes(data[midpoint:])
        descriptor.update(open_mode="concat_ranges", ranges=[
            {"path": str(disguised), "start": 0}, {"path": str(second), "start": 0},
        ])
    out = tmp_path / "out"
    result = _invoke_worker(worker, {
            "job_id": "header-passwords", "archive_path": str(disguised),
            "output_dir": str(out), "format_hint": "7z", "archive_input": descriptor,
            "password_candidates": ["wrong", "secret"],
        }, timeout=10)
    final = _worker_result(result.stdout)
    assert result.returncode == 0, result.stdout + result.stderr
    assert final["status"] == "ok"
    assert final["matched_index"] == 1
    assert final["password_attempts"] == 2
    assert (out / source.name).read_text(encoding="utf-8") == "encrypted payload"
    assert (out / source.name).stat().st_mtime_ns == original_mtime_ns
    assert _file_attributes(out / source.name) & 0x27 == 0x27
    _file_attributes(out / source.name, 0)


def test_native_worker_starts_in_neutral_working_directory(tmp_path, monkeypatch):
    captured = {}

    class StartObserved(RuntimeError):
        pass

    def fake_popen(*args, **kwargs):
        captured.update(kwargs)
        raise StartObserved

    monkeypatch.setattr(
        "sunpack.pipeline.extraction.internal.sevenzip.sevenzip_runner.runtime_working_directory",
        lambda: str(tmp_path),
    )
    monkeypatch.setattr("sunpack.pipeline.extraction.internal.sevenzip.sevenzip_runner.subprocess.Popen", fake_popen)

    with pytest.raises(StartObserved):
        _NativeWorkerProcess("worker.exe", None)

    assert captured["cwd"] == str(tmp_path)


def test_native_environment_zero_thread_capacity_uses_native_auto_capacity():
    environment = {"SUNPACK_NATIVE_WORKER_THREAD_CAPACITY": "8"}

    _apply_native_environment(
        environment,
        {
            "thread_capacity": 0,
        },
    )

    assert "SUNPACK_NATIVE_WORKER_THREAD_CAPACITY" not in environment


def test_native_environment_configures_memory_guard():
    environment = {}
    _apply_native_environment(
        environment,
        {
            "minimum_available_memory_ratio": 0.10,
        },
    )

    assert environment["SUNPACK_NATIVE_MIN_AVAILABLE_MEMORY_RATIO"] == "0.1"


def test_native_environment_does_not_freeze_worker_process_mode_at_startup():
    environment = {"SUNPACK_NATIVE_PROCESS_MODE": "background"}

    _apply_native_environment(environment, {"windows_process_mode": "background"})

    assert "SUNPACK_NATIVE_PROCESS_MODE" not in environment

    _apply_native_environment(environment, {})

    assert "SUNPACK_NATIVE_PROCESS_MODE" not in environment


def test_native_worker_reports_cpu_credit_sizing_plan():
    worker_path = _require_worker_or_skip()
    environment = os.environ.copy()
    for key in (
        "SUNPACK_NATIVE_WORKER_THREAD_CAPACITY",
        "SUNPACK_NATIVE_PROCESS_MODE",
        "SUNPACK_NATIVE_WORKER_PROFILE",
    ):
        environment.pop(key, None)
    completed = subprocess.run(
        [worker_path],
        input='{"worker_command":"shutdown","job_id":"shutdown"}\n',
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=environment,
        timeout=10,
        check=True,
    )
    handshake = json.loads(completed.stdout.splitlines()[0])

    logical_processors = max(1, int(handshake["logical_processors"]))
    assert handshake["type"] == "worker_ready"
    assert handshake["sizing_mode"] == "dynamic"
    assert int(handshake["thread_capacity"]) == logical_processors
    assert int(handshake["nominal_cpu_budget"]) == logical_processors
    assert int(handshake["memory_poll_interval_ms"]) == 1000
    assert float(handshake["minimum_available_memory_ratio"]) == 0.1


def test_worker_event_rejects_non_objects_and_malformed_rows():
    from sunpack.pipeline.extraction.internal.sevenzip.worker_diagnostics import parse_worker_json_line

    assert parse_worker_json_line(json.dumps({
        "type": "result", "verified_manifest": {"rows": [[0, "a.txt", "", 3, 3, 1, 7, 1, 7, 1, 1, 1, 123, "616263"]]},
    })) == {}
    assert parse_worker_json_line(json.dumps({
        "type": "result", "diagnostics": {"output_trace": {"items": [{"path": "a.txt"}]}},
    })) == {}
    assert parse_worker_json_line("not json") == {}
    assert parse_worker_json_line("[1, 2]") == {}
    assert parse_worker_json_line('{"type":"progress"} trailing') == {}
    assert parse_worker_json_line(
        '{"type":"result","verified_manifest":{"inventory":[1,1,0,3,1],"rows":[[0,"a.txt"]]}}'
    ) == {}
    assert parse_worker_json_line('{"type":"progress","completed_bytes":5}') == {
        "type": "progress", "completed_bytes": 5,
    }


def test_preparsed_worker_result_avoids_stdout_reparse_and_bounds_tail():
    from sunpack.pipeline.extraction.internal.sevenzip.worker_diagnostics import (
        build_worker_diagnostics,
        native_worker_manifest,
        parse_worker_json_line,
    )

    result_payload = parse_worker_json_line(json.dumps({
        "type": "result",
        "status": "ok",
        "verified_manifest": {
            "validated": True,
            "rows": [[0, "source.txt", "output.txt", 3, 3, 1, 7, 1, 7, 1, 1, 1, 123, "616263"]],
            "inventory": [1, 1, 0, 3, 0],
        },
    }))
    diagnostics = build_worker_diagnostics(
        stdout="x" * 100_000,
        stderr="",
        returncode=0,
        result_payload=result_payload,
    )

    assert diagnostics["result"] is result_payload
    assert "rows" not in result_payload["verified_manifest"]
    assert "files" not in result_payload["verified_manifest"]
    files = native_worker_manifest(result_payload).file_page(0, 10)
    assert files[0]["path"] == "source.txt"
    assert files[0]["output_path"] == "output.txt"
    assert sum(len(line) for line in diagnostics["process"]["stdout_tail"]) <= 4000


def test_complete_worker_inventory_drops_transient_native_rows_and_output_trace():
    from sunpack.pipeline.extraction.internal.sevenzip.worker_diagnostics import (
        build_worker_diagnostics,
        compact_success_worker_diagnostics,
        parse_worker_json_line,
    )

    result = parse_worker_json_line(json.dumps({
        "status": "ok",
        "verified_manifest": {
            "validated": True,
            "inventory": [1, 1, 0, 3, 1],
            "rows": [[0, "a.txt", "", 3, 3, 1, 7, 1, 7, 1, 1, 1, 123, "616263"]],
        },
        "diagnostics": {
            "output_trace": {
                "items": [worker_trace_item(path="a.txt")],
                "files_written": 1,
            }
        },
    }))
    diagnostics = build_worker_diagnostics(stdout="", stderr="", returncode=0, result_payload=result)
    assert "native_items" in result["diagnostics"]["output_trace"]

    compact_success_worker_diagnostics(diagnostics)

    assert "native_items" not in result["diagnostics"]["output_trace"]
    assert "native_rows" not in result["verified_manifest"]


def test_worker_output_trace_includes_per_item_failure(tmp_path):
    worker = _require_worker_or_skip()
    archive = tmp_path / "directory-failure.zip"
    # File/directory collisions are now renamed. An overlong parent still
    # exercises directory creation failure, separately from async file-open errors.
    with zipfile.ZipFile(archive, "w") as stream:
        stream.writestr("conflict" + "x" * 260 + "/child.txt", "payload")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    payload = {
        "job_id": "output-trace",
        "archive_path": str(archive),
        "output_dir": str(out_dir),
    }

    result = _invoke_worker(worker, payload)
    worker_result = _worker_result(result.stdout)
    native = worker_result["diagnostics"]["output_trace"]["native_items"]
    output_items = native.item_page(0, len(native))
    failed_items = [item for item in output_items if item["failed"]]

    assert result.returncode != 0
    assert worker_result["failure_stage"] == "output_write"
    assert failed_items
    assert failed_items[-1]["bytes_written"] == 0
    assert "conflict" in failed_items[-1]["path"].replace("\\", "/")


def test_worker_propagates_delayed_async_file_open_failure(tmp_path):
    worker = _require_worker_or_skip()
    archive = tmp_path / "async-open-failure.zip"
    # A component longer than NTFS allows passes archive path validation (even
    # through the extended-length prefix), but CreateFileW rejects it. The async writer must
    # report that delayed failure after draining instead of publishing a
    # successful extraction.
    invalid_name = "x" * 300 + ".txt"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr(invalid_name, "payload")
    out_dir = tmp_path / "out"
    payload = {
        "job_id": "async-open-failure",
        "archive_path": str(archive),
        "output_dir": str(out_dir),
        "format_hint": "zip",
    }

    result = _invoke_worker(worker, payload)
    worker_result = _worker_result(result.stdout)
    native = worker_result["diagnostics"]["output_trace"]["native_items"]
    output_items = native.item_page(0, len(native))

    assert result.returncode != 0
    assert worker_result["status"] == "failed"
    assert worker_result["failure_stage"] == "output_write"
    assert worker_result["failure_kind"] == "output_filesystem"
    assert worker_result["files_written"] == 0
    assert worker_result["failed_item"] == invalid_name
    assert worker_result["diagnostics"]["failed_item"]["path"] == invalid_name
    assert output_items[-1]["failed"] is True
    assert output_items[-1]["bytes_written"] == 0
    assert not any(out_dir.glob("*.txt"))


def test_worker_dry_run_reports_success_diagnostics_without_writing(tmp_path):
    worker = _require_worker_or_skip()
    archive, filename = _create_7z(tmp_path, "dryrun", "dry-run payload")
    dry_output = tmp_path / "dry_output"
    payload = {
        "job_id": "dry-run",
        "archive_path": str(archive),
        "output_dir": str(dry_output),
        "format_hint": "7z",
        "dry_run": True,
    }

    result = _invoke_worker(worker, payload)
    worker_result = _worker_result(result.stdout)
    output_trace = worker_result["diagnostics"]["output_trace"]

    assert result.returncode == 0
    assert worker_result["status"] == "ok"
    assert worker_result["dry_run"] is True
    assert worker_result["files_written"] == 1
    assert worker_result["bytes_written"] == len("dry-run payload")
    assert len(output_trace["native_items"]) == 1
    item = output_trace["native_items"].item_page(0, 1)[0]
    assert item["path"].endswith(filename)
    assert item["has_source_crc32"] is True
    assert item["has_output_crc32"] is True
    assert item["output_crc32"] == item["source_crc32"]
    assert item["crc_verified"] is True
    assert not dry_output.exists()


@pytest.mark.parametrize("dry_run", [False, True])
def test_worker_skips_output_crc_when_source_crc_is_missing(tmp_path, dry_run):
    worker = _require_worker_or_skip()
    payload = b"tar payload without an archive CRC"
    source = tmp_path / "payload.bin"
    source.write_bytes(payload)
    archive = tmp_path / "payload.tar"
    with tarfile.open(archive, "w") as handle:
        handle.add(source, arcname=source.name)
    output_dir = tmp_path / ("dry-output" if dry_run else "out")
    result = _invoke_worker(worker, {
            "job_id": f"{'dry-run' if dry_run else 'extract'}-no-source-crc",
            "archive_path": str(archive),
            "output_dir": str(output_dir),
            "format_hint": "tar",
            "dry_run": dry_run,
        })
    worker_result = _worker_result(result.stdout)

    assert result.returncode == 0, result.stdout + result.stderr
    assert worker_result["status"] == "ok"
    assert worker_result["dry_run"] is dry_run
    if dry_run:
        item = next(
            row for row in worker_result["diagnostics"]["output_trace"]["native_items"].item_page(0, 128)
            if not row["is_dir"]
        )
        assert item["has_source_crc32"] is False
        assert item["has_output_crc32"] is False
        assert item["crc_verified"] is True
        assert not output_dir.exists()
    else:
        # Successful real extraction intentionally omits verbose diagnostics.
        # The dry-run branch above verifies the no-output-CRC trace contract;
        # this branch verifies that the same path still writes correct bytes.
        assert "diagnostics" not in worker_result
        assert (output_dir / source.name).read_bytes() == payload
        row = worker_result["verified_manifest"]["native_rows"].file_page(0, 1)[0]
        assert row["mtime_ns"] > 0 and row["magic"] == payload


def test_runner_serializes_only_codepage_for_filename_override(tmp_path):
    archive = tmp_path / "legacy.zip"
    archive.write_bytes(b"PK")
    task = make_archive_task(archive, format_hint="zip")
    runner = SevenZipRunner({})

    job = runner._build_job(
        archive_path=str(archive),
        part_paths=[str(archive)],
        out_dir=str(tmp_path / "out"),
        password=None,
        password_candidates=None,
        selected_codepage="932",
        task=task,
    )

    assert job["codepage"] == "932"
    assert "decoded_names" not in job


def test_worker_applies_explicit_shift_jis_item_paths(tmp_path):
    worker = _require_worker_or_skip()
    archive, expected_name, payload_bytes = _create_shift_jis_zip(tmp_path)
    out_dir = tmp_path / "out"
    payload = {
        "job_id": "shift-jis",
        "archive_path": str(archive),
        "output_dir": str(out_dir),
        "format_hint": "zip",
        "codepage": "932",
    }

    result = _invoke_worker(worker, payload)
    worker_result = _worker_result(result.stdout)

    assert result.returncode == 0, result.stdout + result.stderr
    assert worker_result["requested_codepage"] == "932"
    assert worker_result["applied_codepage"] == "932"
    assert worker_result["filename_decoder"] == "sevenzip_zip_codepage"
    assert (out_dir / "日本語" / "説明.txt").read_bytes() == payload_bytes


def test_native_worker_queue_isolates_failed_job_and_continues(tmp_path):
    worker = _require_worker_or_skip()
    archive = tmp_path / "ok.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("ok.txt", "batch payload")
    runner = SevenZipRunner({"thread_capacity": 2})
    runner.worker_path = worker
    try:
        bad = runner.submit_attempt(
            {
                "job_id": "bad",
                "archive_path": str(tmp_path / "missing.zip"),
                "part_paths": [str(tmp_path / "missing.zip")],
                "output_dir": str(tmp_path / "bad"),
            },
            task=_task(tmp_path / "missing.zip"),
        ).result(timeout=10)
        good = runner.submit_attempt(
            {
                "job_id": "ok",
                "archive_path": str(archive),
                "part_paths": [str(archive)],
                "output_dir": str(tmp_path / "ok"),
            },
            task=_task(archive),
        ).result(timeout=10)
    finally:
        runner.close()

    assert worker_result_payload(bad)["status"] == "failed"
    assert worker_result_payload(good)["status"] == "ok"
    assert (tmp_path / "ok" / "ok.txt").read_text(encoding="utf-8") == "batch payload"


def test_extraction_scheduler_saves_process_failure_diagnostics(tmp_path):
    archive = tmp_path / "sample.bin"
    archive.write_bytes(b"not an archive")
    scheduler = ExtractionScheduler(max_retries=1)
    scheduler.sevenzip_runner.worker_path = str(tmp_path / "missing_worker.exe")

    try:
        result = scheduler.extract(_task(archive), str(tmp_path / "out"))
    finally:
        scheduler.close()

    assert result.success is False
    assert result.diagnostics["process_failure"]["failure_stage"] == "worker_start"
    assert result.diagnostics["process_failure"]["failure_kind"] == "process_start"
    assert result.diagnostics["repro"]["request"]["archive_path"] == str(archive)


def test_extraction_scheduler_classifies_malformed_worker_output_as_process_exit(tmp_path):
    worker = tmp_path / "malformed_worker.cmd"
    worker.write_text("@echo not-json\r\n@exit /b 2\r\n", encoding="utf-8")
    archive = tmp_path / "sample.7z"
    archive.write_bytes(b"not used")
    scheduler = ExtractionScheduler(max_retries=1)
    scheduler.sevenzip_runner.worker_path = str(worker)

    try:
        result = scheduler.extract(_task(archive), str(tmp_path / "out"))
    finally:
        scheduler.close()

    assert result.success is False
    assert result.diagnostics["failure_stage"] == "worker_communication"
    assert result.diagnostics["failure_kind"] == "worker_lost"
    assert result.diagnostics["process_failure"]["message"]


def _task(path, archive_input=None):
    if archive_input:
        descriptor = ArchiveInputDescriptor.from_any(
            archive_input,
            archive_path=str(path),
        )
        return make_task_from_descriptor(descriptor, key=str(path))
    return make_archive_task(path, key=str(path))


def _worker_result(stdout: str) -> dict:
    from sunpack_native import NativeWorkerResultAccumulator, parse_worker_transport_event

    accumulators = {}
    for line in stdout.splitlines():
        if not line.strip():
            continue
        payload = parse_worker_transport_event(line)
        job_id = payload.get("job_id")
        if payload["type"] not in {"manifest_chunk", "trace_chunk", "result"}:
            continue
        accumulator = accumulators.setdefault(job_id, NativeWorkerResultAccumulator(job_id))
        accumulator.accept(payload)
        if payload["type"] == "result":
            return payload
    raise AssertionError("worker did not emit a result")


def test_extraction_scheduler_uses_worker_for_file_range(tmp_path, monkeypatch):
    monkeypatch.setenv("SUNPACK_SEVENZIP_PROFILE_READS", "1")
    archive, filename = _create_7z(tmp_path, "payload", "range payload")
    data = archive.read_bytes()
    prefix = b"SHELLDATA"
    mixed = tmp_path / "mixed.bin"
    mixed.write_bytes(prefix + data + b"TAIL")

    task = _task(mixed, {
        "kind": "archive_input",
        "entry_path": str(mixed),
        "open_mode": "file_range",
        "format_hint": "7z",
        "parts": [{
            "path": str(mixed),
            "role": "main",
            "start": len(prefix),
            "end": len(prefix) + len(data),
        }],
    })
    result = ExtractionScheduler(max_retries=1).extract(task, str(tmp_path / "out"))

    assert result.success is True
    assert (tmp_path / "out" / filename).read_text(encoding="utf-8") == "range payload"
    assert result.diagnostics["result"]["input_trace"]["prefetch_enabled"] is True


def test_confirmed_truncated_file_range_open_failure_is_damaged(tmp_path):
    _require_worker_or_skip()
    archive, _ = _create_7z(tmp_path, "truncated-range", "payload")
    data = archive.read_bytes()
    prefix = b"SFX-STUB"
    truncated = tmp_path / "truncated.exe"
    truncated.write_bytes(prefix + data[:-1])

    task = _task(truncated, {
        "kind": "archive_input",
        "entry_path": str(truncated),
        "open_mode": "file_range",
        "format_hint": "7z",
        "parts": [{
            "path": str(truncated),
            "role": "main",
            "start": len(prefix),
            "end": len(prefix) + len(data),
        }],
    })
    result = ExtractionScheduler(max_retries=1).extract(task, str(tmp_path / "out"))

    assert result.success is False
    assert result.failure.kind is FailureKind.DAMAGED
    worker = result.diagnostics["result"]
    assert worker["native_status"] == "damaged"
    assert worker["damaged"] is True
    assert worker["failure_stage"] == "archive_open"
    assert worker["failure_kind"] == "structure_recognition"


def test_extraction_scheduler_saves_worker_diagnostics_on_failure(tmp_path):
    _require_worker_or_skip()
    missing = tmp_path / "missing.7z"
    result = ExtractionScheduler(max_retries=1).extract(_task(missing), str(tmp_path / "out"))

    assert result.success is False
    assert result.diagnostics["result"]["failure_stage"] == "input_open"
    assert result.diagnostics["result"]["failure_kind"] == "input_stream"
    assert result.diagnostics["result"]["diagnostics"]["input_trace"]["read_error"] is True
    assert result.diagnostics["repro"]["request"]["archive_path"] == str(missing)


def test_extraction_scheduler_uses_worker_for_concat_ranges(tmp_path, monkeypatch):
    monkeypatch.setenv("SUNPACK_SEVENZIP_PROFILE_READS", "1")
    archive, filename = _create_7z(tmp_path, "payload", "concat payload")
    data = archive.read_bytes()
    midpoint = len(data) // 2
    part_a = tmp_path / "part_a.bin"
    part_b = tmp_path / "part_b.bin"
    part_a.write_bytes(data[:midpoint])
    part_b.write_bytes(data[midpoint:])

    virtual = tmp_path / "payload.virtual"
    virtual.write_bytes(b"not used directly")
    task = _task(virtual, {
        "kind": "archive_input",
        "entry_path": str(virtual),
        "open_mode": "concat_ranges",
        "format_hint": "7z",
        "ranges": [
            {"path": str(part_a), "start": 0},
            {"path": str(part_b), "start": 0},
        ],
    })
    result = ExtractionScheduler(max_retries=1).extract(task, str(tmp_path / "out"))

    assert result.success is True
    assert (tmp_path / "out" / filename).read_text(encoding="utf-8") == "concat payload"
    assert result.diagnostics["result"]["input_trace"]["prefetch_enabled"] is True


def test_worker_maps_windows_invalid_entry_names_like_the_verifier(tmp_path):
    from sunpack.pipeline.extraction.output_inventory import collect_output_inventory
    from sunpack.pipeline.verification.methods._archive_output_match import (
        archive_files_from_names,
        coverage_from_native_inventory,
    )

    worker = _require_worker_or_skip()
    archive = tmp_path / "windows-names.zip"
    entries = {
        "logs/12:30.log": "stream",
        "a?b*c.txt": "wildcards",
        "trailing.": "dot",
        "con.txt": "device",
        "sub/NUL": "device-dir",
    }
    with zipfile.ZipFile(archive, "w") as zf:
        for name, payload in entries.items():
            zf.writestr(name, payload)
    out_dir = tmp_path / "out"
    payload = {
        "job_id": "windows-names",
        "archive_path": str(archive),
        "output_dir": str(out_dir),
        "format_hint": "zip",
    }

    result = _invoke_worker(worker, payload)
    worker_result = _worker_result(result.stdout)

    assert result.returncode == 0, result.stdout + result.stderr
    assert worker_result["status"] == "ok"
    expected_on_disk = {
        "logs/12_30.log": "stream",
        "a_b_c.txt": "wildcards",
        "trailing_": "dot",
        "_con.txt": "device",
        "sub/_NUL": "device-dir",
    }
    written = {
        entry.name
        for entry in os.scandir(out_dir)
    } | {f"logs/{entry.name}" for entry in os.scandir(out_dir / "logs")} | {
        f"sub/{entry.name}" for entry in os.scandir(out_dir / "sub")
    }
    assert set(expected_on_disk) <= written
    # Mapped names are ordinary Win32 names: plain paths can open them.
    for relative, content in expected_on_disk.items():
        assert (out_dir / relative).read_text(encoding="utf-8") == content
    # No alternate data stream was created on a file named "12".
    assert not (out_dir / "logs" / "12").exists()

    coverage, _ = coverage_from_native_inventory(
        archive_files_from_names(list(entries)),
        collect_output_inventory(str(out_dir)),
        method="test",
    )
    assert coverage.missing_files == 0
    assert coverage.failed_files == 0
    assert coverage.matched_files == len(entries)


def test_worker_manifest_protocol(subtests):
    from sunpack.pipeline.extraction.internal.sevenzip.worker_diagnostics import (
        native_worker_manifest, parse_worker_json_line,
    )
    path = '目录/"quoted"\\name.txt'
    fields = [("rows", [[0, path, "", 3, 3, 1, 1, 1, 1, 1, 1, 1, 123, "616263"]]),
              ("inventory", [1, 1, 0, 3, 1])]
    for order in (fields, fields[::-1]):
        with subtests.test(rows_first=order[0][0] == "rows"):
            result = parse_worker_json_line(json.dumps({"type": "result", "verified_manifest": dict(order)}))
            manifest = result["verified_manifest"]
            assert "rows" not in manifest and "files" not in manifest
            assert manifest["inventory"]["complete"] and manifest["inventory"]["identity_paths"]
            native = native_worker_manifest(result)
            assert len(native) == 1 and native.all_complete()
            row = native.file_page(0, 1)[0]
            assert row["path"] == path and row["magic"] == b"abc" and row["mtime_ns"] == 123
            assert row["status"] == "complete" and "output_path" not in row


def test_worker_password_candidates(tmp_path, subtests):
    from sunpack.core.passwords.verifier.zip_fast import ZipFastVerifier
    worker = _require_worker_or_skip()
    filename = "encrypted-source.txt"
    archive = tmp_path / "encrypted.zip"
    # Generated once with 7z a -tzip -mx=0 -psecret. Keep its encrypted header
    # fixed: weak-collision-106 passes the header byte but cannot decrypt payload.
    archive.write_bytes(bytes.fromhex(
        "504b030414000100000034b6485d948d9273240000001800000014000000"
        "656e637279707465642d736f757263652e7478740007aac394e221fd2271e576"
        "e14e4b5ef054b1a73dea25e21d78403ed8dc850bd4acbf74504b01023f0014"
        "000100000034b6485d948d9273240000001800000014002400000000000000"
        "2000000000000000656e637279707465642d736f757263652e7478740a002000"
        "00000000010018003ea1e33e3457dd0100000000000000000000000000000000"
        "504b0506000000000100010066000000560000000000"
    ))
    collision = "weak-collision-106"
    proof = ZipFastVerifier().verify_batch(str(archive), [collision, "secret"])
    assert proof.matched_indices == (0, 1)
    assert proof.match_evidence == "zipcrypto_header_byte"
    assert proof.final_confirmation_required
    cases = [(["secret"], True), (["wrong-password-1", "wrong-password-2"], False),
             ([collision], False), ([collision, "secret"], True)]
    for index, (candidates, accepted) in enumerate(cases):
        with subtests.test(candidates=candidates):
            out = tmp_path / f"out-{index}"
            result = _invoke_worker(worker, {
                "job_id": str(index), "archive_path": str(archive), "output_dir": str(out),
                "format_hint": "zip", "password": "placeholder", "password_candidates": candidates,
            })
            final = _worker_result(result.stdout)
            assert (result.returncode == 0) is accepted, result.stdout + result.stderr
            assert (final["status"] == "ok") is accepted
            if accepted:
                assert final["matched_index"] == candidates.index("secret")
                assert (out / filename).read_text(encoding="utf-8") == "encrypted worker payload"
            else:
                assert final["native_status"] == "wrong_password"
                assert final["password_candidates_all_rejected"] and final["matched_index"] == -1
                if len(candidates) > 1:
                    assert not (out / filename).exists()
