"""Composition trials: real execution, terminal decisions and shared ownership.

Existing unique-volume cases cannot detect speculative error publication,
candidate output contamination, or deletion of a losing physical candidate.
These small real archives cover those failures together instead of testing
individual implementation helpers.
"""
import asyncio
import json
from pathlib import Path
import subprocess
import zipfile
import random
import struct

import pytest

from sunpack.core.contracts.archive_input import ArchiveInputDescriptor
from sunpack.core.passwords.internal.store import PasswordStore
from sunpack.pipeline.coordinator.task_provider import ArchiveTaskProvider
from sunpack.pipeline.extraction.scheduler import ExtractionScheduler
from tests.helpers.config_factory import make_config
from tests.helpers.native_build import sevenzip_artifact
from tests.helpers.passwords import write_password_json
from tests.helpers.real_archives import ArchiveFixtureFactory


def _ambiguous_case(tmp_path, archive_format="7z", password=None, carrier=False):
    case = ArchiveFixtureFactory().create(tmp_path, "attempt", archive_format, split=True,
        password=password, compression_level=0, payload_size=160 * 1024, split_volume_size=48 * 1024)
    paths = []
    for n, source in enumerate(sorted(case.archive_dir.iterdir()), 1):
        # The stronger lexical channel is deliberately wrong. The second
        # channel is globally valid; the loose domain also overlaps both.
        target = source.with_name(f"shared.build{ {2: 3, 3: 2}.get(n, n):02}.chunk{n:02}.opaque")
        source.rename(target)
        paths.append(target)
    if carrier:
        prefix = b"carrier-prefix\0" * 211
        paths[0].write_bytes(prefix + paths[0].read_bytes() + b"carrier suffix" * 37)
    config = make_config({"embedded_scan": {"enabled": True}})
    if password:
        config["password_snapshot"] = write_password_json(tmp_path / "passwords.json", scopes=[
            (value, [str(case.archive_dir)]) for value in ["wrong", password]])
    tasks = ArchiveTaskProvider(config).discover_targets([str(case.archive_dir)]).tasks
    task = next(task for task in tasks if any(node.descriptor.volume_attempts for node in task.inputs))
    return case, paths, config, task


@pytest.mark.parametrize("archive_format,carrier,password", [
    ("7z", False, "test-password"), ("zip", False, "test-password"),
    ("7z", True, None), ("zip", True, None),
])
def test_attempt_plan_survives_passwords_carrier_ranges_and_serialization(tmp_path, archive_format, carrier, password):
    case, paths, config, task = _ambiguous_case(tmp_path, archive_format, password, carrier)
    descriptor = next(node.descriptor for node in task.inputs if node.descriptor.volume_attempts)
    restored = ArchiveInputDescriptor.from_dict(descriptor.to_dict())
    assert restored.same_retry_input(descriptor)
    assert restored.with_path_mapping(lambda p: p).same_retry_input(descriptor)
    output = tmp_path / "out"
    extractor = ExtractionScheduler(password_store=PasswordStore.from_config(config))
    extractor.sevenzip_runner.worker_path = str(sevenzip_artifact("sunpack_sevenzip_worker.exe"))
    try:
        result = extractor.extract(task, str(output))
    finally:
        extractor.close()
    assert result.success, (result.error, result.diagnostics)
    assert next(output.rglob(case.marker_name)).read_text(encoding="utf-8") == case.marker_text
    assert all(node.descriptor.volume_attempts is None for node in task.inputs)
    assert not any("(1)" in path.name for path in output.rglob("*"))
    if password:
        request = {"job_id": "wrong-password", "archive_input": descriptor.to_dict(),
                   "output_dir": str(tmp_path / "wrong-password"), "password": "wrong"}
        run = subprocess.run([str(sevenzip_artifact("sunpack_sevenzip_worker.exe"))],
                             input=json.dumps(request), text=True, capture_output=True)
        final = next(json.loads(line) for line in run.stdout.splitlines() if json.loads(line).get("type") == "result")
        assert not final["missing_volume"]
        if archive_format == "7z":
            assert final["volume_attempts"] == 1 and final["wrong_password"]
        else:
            # ZIP may read variable bytes before rejecting its weak header.
            # Without fixed-byte evidence it cannot reject every composition.
            assert final["volume_attempts"] == 2
            assert final["failure_kind"] == "password_or_volume_inconclusive"


def test_worker_attempts_emit_one_result_and_stop_on_independent_errors(tmp_path):
    _, paths, _, task = _ambiguous_case(tmp_path)
    descriptor = task.archive_input().to_dict()
    worker = str(sevenzip_artifact("sunpack_sevenzip_worker.exe"))

    def invoke(label, payload, **kwargs):
        output = tmp_path / label
        request = {"job_id": label, "archive_input": payload, "output_dir": str(output), **kwargs}
        run = subprocess.run([worker], input=json.dumps(request), text=True, capture_output=True, check=False)
        events = [json.loads(line) for line in run.stdout.splitlines()]
        results = [e for e in events if e.get("type") == "result"]
        assert len(results) == 1, run.stdout + run.stderr
        assert not any(e.get("event") == "item_failed" for e in events)
        return results[0]

    # Same plan, concurrent foreground/watch jobs: no process-global cursor.
    requests = [{"job_id": origin, "origin": origin, "archive_input": descriptor,
                 "output_dir": str(tmp_path / origin)} for origin in ("foreground", "watch")]
    run = subprocess.run([worker], input="\n".join(map(json.dumps, requests)), text=True, capture_output=True)
    events = [json.loads(line) for line in run.stdout.splitlines()]
    results = [e for e in events if e.get("type") == "result"]
    assert len(results) == 2 and not any(e.get("event") == "item_failed" for e in events)
    assert all(r["status"] == "ok" and r["volume_attempts"] == 2 for r in results)

    # Corrupt the fixed start header after discovery. No rearrangement can
    # repair it; the worker must preserve the damage verdict after one trial.
    head = paths[0].read_bytes()
    paths[0].write_bytes(b"broken!!" + head[8:])
    damaged = invoke("bad-head", descriptor)
    assert damaged["volume_attempts"] == 1 and not damaged["missing_volume"]
    paths[0].write_bytes(head)

    # Every composition contains these bytes: exhaustion must report missing
    # volumes only after all distinct combinations were actually attempted.
    paths[1].write_bytes(b"\0" * paths[1].stat().st_size)
    exhausted = invoke("exhausted", descriptor)
    assert exhausted["missing_volume"] and exhausted["missing_volume_evidence"] == "volume_attempts_exhausted"
    assert exhausted["volume_attempts"] == 2

    (tmp_path / "occupied").mkdir()
    sentinel = tmp_path / "occupied" / "keep.txt"
    sentinel.write_text("user output", encoding="utf-8")
    failed = invoke("occupied", descriptor)
    assert failed["failure_kind"] == "output_filesystem"
    assert sentinel.read_text(encoding="utf-8") == "user output"


def test_unnumbered_gap_domains_share_storage_and_backtrack_without_reusing_sources(tmp_path):
    # Numbered alternatives do not exercise one domain reused at several slots,
    # or source exclusion during backtracking.
    case, paths, config, _ = _ambiguous_case(tmp_path)
    paths[1].rename(paths[1].with_name("shared.beta.opaque"))
    paths[2].rename(paths[2].with_name("shared.alpha.opaque"))
    paths[3].with_name("shared.build04.chunk04.other").write_bytes(paths[3].read_bytes())
    tasks = ArchiveTaskProvider(config).discover_targets([str(case.archive_dir)]).tasks
    task = next(t for t in tasks if t.archive_input().volume_attempts)
    descriptor = task.archive_input()
    plan = descriptor.volume_attempts
    assert plan.layouts[0][1].choices is plan.layouts[0][2].choices
    restored = ArchiveInputDescriptor.from_dict(descriptor.to_dict())
    assert restored.same_retry_input(descriptor)
    assert restored.volume_attempts.layouts[0][1].choices is restored.volume_attempts.layouts[0][2].choices
    worker = str(sevenzip_artifact("sunpack_sevenzip_worker.exe"))
    run = subprocess.run([worker], input=json.dumps({"job_id": "shared", "archive_input": restored.to_dict(),
        "output_dir": str(tmp_path / "shared-out")}), text=True, capture_output=True)
    final = next(json.loads(line) for line in run.stdout.splitlines() if json.loads(line).get("type") == "result")
    assert final["status"] == "ok" and final["volume_attempts"] == 3, final
    assert next((tmp_path / "shared-out").rglob(case.marker_name)).read_text(encoding="utf-8") == case.marker_text


@pytest.mark.parametrize("origin", ["foreground", "watch"])
def test_nested_attempt_plan_uses_the_normal_pipeline(tmp_path, origin):
    # Direct extraction cannot detect losing the plan during nested discovery,
    # task scheduling or completion/cleanup in the two interaction modes.
    from sunpack.pipeline.coordinator.engine import PipelineEngine
    from sunpack.core.config.schema import normalize_config
    case, paths, config, _ = _ambiguous_case(tmp_path)
    outer = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer, "w") as archive:
        for path in paths:
            archive.write(path, path.name)
    output = tmp_path / "nested-output"
    config["output"] = {"root": str(output)}
    config["recursive_extract"] = "3"
    config["post_extract"] = {"archive_cleanup_mode": "k"}
    config = normalize_config(config)

    async def run():
        async with PipelineEngine(config) as engine:
            return await engine.run([str(outer)], origin=origin)

    response = asyncio.run(run())
    assert not response.summary.failed_tasks
    assert response.summary.success_count == 2
    assert next(output.rglob(case.marker_name)).read_text(encoding="utf-8") == case.marker_text


@pytest.mark.parametrize("carrier_slices", [False, True])
def test_conflicting_rar_slot_uses_winner_without_claiming_loser(tmp_path, carrier_slices):
    case = ArchiveFixtureFactory().create(tmp_path, "rar_trial", "rar", split=True,
        compression_level=0, payload_size=160 * 1024, split_volume_size=48 * 1024)
    parts = []
    for n, source in enumerate(sorted(case.archive_dir.iterdir()), 1):
        target = source.with_name(f"shared.part{n}.z.opaque")
        source.rename(target)
        parts.append(target)
    bad = parts[1].with_name("shared.part2.a.opaque")
    damaged = bytearray(parts[1].read_bytes())
    damaged[len(damaged) // 2] ^= 1
    if carrier_slices:
        # Two alternatives in one physical carrier must retain their ranges;
        # a path-only candidate model silently loses the second slice.
        parts[1].write_bytes(b"prefix" * 19 + damaged + b"gap" * 31 + parts[1].read_bytes())
        parts[0].write_bytes(b"prefix" * 19 + parts[0].read_bytes())
    else:
        bad.write_bytes(damaged)
    task = ArchiveTaskProvider(make_config({"embedded_scan": {"enabled": True}})).discover_targets([str(case.archive_dir)]).tasks[0]
    assert task.archive_input().volume_attempts
    if not carrier_slices:
        assert str(bad) in task.cleanup_parts
    from sunpack.pipeline.coordinator.cleanup_refs import CleanupRefTable
    refs = CleanupRefTable()
    refs.register(task)
    extractor = ExtractionScheduler()
    extractor.sevenzip_runner.worker_path = str(sevenzip_artifact("sunpack_sevenzip_worker.exe"))
    try:
        result = extractor.extract(task, str(tmp_path / "out"))
    finally:
        extractor.close()
    assert result.success, (result.error, result.diagnostics)
    assert task.archive_input().part_paths() == [str(path) for path in parts]
    refs.refresh(task)
    refs.mark_cleanup_eligible(task)
    release = refs.release(task)
    assert set(release.cleanup_paths) == set(map(str, parts))
    if not carrier_slices:
        assert bad.exists()


def _run_trial(tmp_path, descriptor, **kwargs):
    request = {"job_id": "trial", "archive_input": descriptor.to_dict(),
               "output_dir": str(tmp_path / "worker-out"), **kwargs}
    run = subprocess.run([str(sevenzip_artifact("sunpack_sevenzip_worker.exe"))],
                         input=json.dumps(request), text=True, capture_output=True)
    results = [event for line in run.stdout.splitlines()
               if (event := json.loads(line)).get("type") == "result"]
    assert len(results) == 1, run.stdout + run.stderr
    return results[0]


def test_single_zipcrypto_member_does_not_reject_password_on_wrong_volume_order(tmp_path):
    # Unlike the multi-member encryption fixture, no small member can prove
    # the password before a CRC failure in a reordered encrypted stream.
    from tests.helpers.tool_config import require_7z
    source = tmp_path / "only.bin"
    expected = random.Random(13).randbytes(160 * 1024)
    source.write_bytes(expected)
    archive = tmp_path / "encrypted.zip"
    subprocess.run([require_7z(), "a", "-tzip", "-mx=0", "-psecret", str(archive), str(source)],
                   check=True, capture_output=True)
    root = tmp_path / "parts"
    root.mkdir()
    data = archive.read_bytes()
    for index, offset in enumerate(range(0, len(data), 48 * 1024), 1):
        build = {2: 3, 3: 2}.get(index, index)
        (root / f"shared.build{build:02}.chunk{index:02}.opaque").write_bytes(data[offset:offset + 48 * 1024])
    task = ArchiveTaskProvider(make_config()).discover_targets([str(root)]).tasks[0]
    descriptor = task.archive_input()
    assert descriptor.volume_attempts
    # Exercise extraction confirmation, not the already-verified password path.
    final = _run_trial(tmp_path, descriptor, password_candidates=["secret", "wrong"])
    assert final["status"] == "ok" and final["volume_attempts"] == 2, final
    assert not final["password_candidates_all_rejected"] and final["matched_index"] == 0
    assert (tmp_path / "worker-out/only.bin").read_bytes() == expected


@pytest.mark.parametrize("total_delta", [0, 3])
def test_zip_carrier_competing_tails_trim_the_selected_geometry(tmp_path, total_delta):
    case, paths, config, _ = _ambiguous_case(tmp_path, "zip", carrier=True)
    tail = paths[-1]
    bad = tail.with_name(tail.name.replace(".opaque", ".a.opaque"))
    data = bytearray(tail.read_bytes())
    data[100] ^= 1
    eocd = data.rfind(b"PK\x05\x06")
    struct.pack_into("<I", data, eocd + 16, struct.unpack_from("<I", data, eocd + 16)[0] + total_delta)
    bad.write_bytes(data)
    tasks = ArchiveTaskProvider(config).discover_targets([str(case.archive_dir)]).tasks
    task = next(t for t in tasks if t.archive_input().volume_attempts)
    plan = task.archive_input().volume_attempts
    assert len(plan.tail_totals) == 2
    final = _run_trial(tmp_path, task.archive_input())
    assert final["status"] == "ok", final
    selected = task.archive_input().select_volumes(final["volume_selection"])
    assert selected.parts[0].extent.end < paths[0].stat().st_size
    assert str(bad) not in selected.part_paths()

    assert next((tmp_path / "worker-out").rglob(case.marker_name)).read_text(encoding="utf-8") == case.marker_text


@pytest.mark.parametrize("archive_format", ["7z", "zip"])
def test_sparse_raw_labels_with_competing_member_are_ranked(tmp_path, archive_format):
    case = ArchiveFixtureFactory().create(tmp_path, "sparse", archive_format, split=True,
        compression_level=0, payload_size=160 * 1024, split_volume_size=48 * 1024)
    parts = []
    originals = sorted(case.archive_dir.iterdir())
    assert len(originals) == 4
    for label, source in zip((1, 3, 10, 11), originals):
        target = source.with_name(f"shared.part{label:03}.z.opaque")
        source.rename(target)
        parts.append(target)
    bad = parts[1].with_name(parts[1].name.replace(".z.", ".a."))
    bad.write_bytes(b"\0" * (parts[1].stat().st_size + 1))
    if archive_format == "zip":
        # A competing larger tail carries impossible central-directory geometry.
        # It cannot stand in for the good tail when ranking the whole domain.
        tail = bytearray(parts[-1].read_bytes())
        eocd = tail.rfind(b"PK\x05\x06")
        struct.pack_into("<I", tail, eocd + 16, len(tail) + 1024 * 1024)
        parts[-1].with_name(parts[-1].name.replace(".z.", ".a.")).write_bytes(tail + b"x")
    task = ArchiveTaskProvider(make_config()).discover_targets([str(case.archive_dir)]).tasks[0]
    assert task.archive_input().volume_attempts
    final = _run_trial(tmp_path, task.archive_input())
    assert final["status"] == "ok", final
    assert next((tmp_path / "worker-out").rglob(case.marker_name)).read_text(encoding="utf-8") == case.marker_text


def test_callback_volume_sharing_error_is_not_candidate_exhaustion(tmp_path):
    # A real Windows sharing violation reaches the RAR callback stream's lazy
    # CreateFile; existence/size checks still succeed. No sleeps or races.
    import ctypes
    from ctypes import wintypes
    case = ArchiveFixtureFactory().create(tmp_path, "locked", "rar", split=True,
        compression_level=0, payload_size=160 * 1024, split_volume_size=48 * 1024)
    parts = sorted(case.archive_dir.iterdir())
    bad = parts[1].with_name("locked.part2.a.opaque")
    bad.write_bytes(parts[1].read_bytes())
    task = ArchiveTaskProvider(make_config()).discover_targets([str(case.archive_dir)]).tasks[0]
    assert task.archive_input().volume_attempts
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    plan = task.archive_input().volume_attempts
    locked = plan.sources[plan.layouts[0][1].choices[0]].path
    from sunpack_native import release_reader_handles_under
    release_reader_handles_under(str(case.archive_dir))
    handle = kernel.CreateFileW(locked, 0x80000000, 0, None, 3, 0, None)
    assert handle != wintypes.HANDLE(-1).value
    try:
        final = _run_trial(tmp_path, task.archive_input())
        # The ordinary native-volume path opens peers through GetStream;
        # explicit plan ranges also exercise the primary concatenated reader.
        selected = task.archive_input().select_volumes({"layout": 0,
            "sources": [slot.choices[0] for slot in plan.layouts[0]]})
        ordinary = selected.to_dict()
        for part in ordinary["parts"]:
            part.pop("start", None)
            part.pop("end", None)
        callback = _run_trial(tmp_path, ArchiveInputDescriptor.from_dict(ordinary))
    finally:
        kernel.CloseHandle(handle)
    assert final["volume_attempts"] == 1 and not final["missing_volume"], final
    assert final["diagnostics"]["input_trace"]["read_error"]
    assert final["diagnostics"]["input_trace"]["last_win32_error"] == 32, json.dumps(final)
    assert callback["failure_kind"] == "input_stream" and not callback["missing_volume"], callback
    assert callback["diagnostics"]["input_trace"]["last_win32_error"] == 32
    Path(locked).unlink()
    missing = _run_trial(tmp_path, task.archive_input())
    assert missing["status"] == "ok" and missing["volume_attempts"] == 2, missing


@pytest.mark.parametrize("password", [None, "secret"])
def test_rejected_candidate_keeps_its_independent_embedded_archive(tmp_path, password):
    import io
    case = ArchiveFixtureFactory().create(tmp_path, "mixed", "rar", split=True,
        compression_level=0, payload_size=160 * 1024, split_volume_size=48 * 1024, password=password)
    parts = sorted(case.archive_dir.iterdir())
    extra = io.BytesIO()
    with zipfile.ZipFile(extra, "w") as archive:
        archive.writestr("independent.txt", "independent content")
    damaged = bytearray(parts[1].read_bytes())
    damaged[len(damaged) // 2] ^= 1
    bad = parts[1].with_name("mixed.part2.a.opaque")
    bad.write_bytes(damaged + b"carrier gap" * 19 + extra.getvalue())
    config = make_config({"embedded_scan": {"enabled": True}})
    if password:
        config["password_snapshot"] = write_password_json(tmp_path / "passwords.json", scopes=[(password, [str(case.archive_dir)])])
        from sunpack.pipeline.discovery.relations.scheduler import RelationsScheduler
        from sunpack.pipeline.discovery.filesystem.directory_scanner import DirectoryScanner
        # The same retry also serves a relations-only API whose rows must all
        # remain groups, rather than filesystem scan jobs.
        assert RelationsScheduler(config).build_candidate_groups(DirectoryScanner(str(case.archive_dir), config=config).scan())
    tasks = ArchiveTaskProvider(config).discover_targets([str(case.archive_dir)]).tasks
    extractor = ExtractionScheduler(password_store=PasswordStore.from_config(config))
    extractor.sevenzip_runner.worker_path = str(sevenzip_artifact("sunpack_sevenzip_worker.exe"))
    try:
        for index, task in enumerate(tasks):
            result = extractor.extract(task, str(tmp_path / "outputs" / str(index)))
            assert result.success, (result.error, result.diagnostics)
    finally:
        extractor.close()
    assert len(list((tmp_path / "outputs").rglob(case.marker_name))) == 1
    assert [p.read_text(encoding="utf-8") for p in (tmp_path / "outputs").rglob("independent.txt")] == ["independent content"]


def test_variable_zipcrypto_password_header_and_weak_password_exhaustion(tmp_path):
    # The old single encrypted member starts in the fixed head. Put the next
    # encrypted member/header in an ambiguous volume and test real execution.
    from tests.helpers.tool_config import require_7z
    from sunpack.core.contracts.input_plan import InputCheckpoint, LogicalArchiveInput
    from sunpack.core.contracts.failures import FailureKind
    from sunpack.pipeline.extraction.internal.workflow.errors import classify_extract_failure
    source = tmp_path / "z-encrypted.bin"
    expected = random.Random(27).randbytes(80 * 1024)
    source.write_bytes(expected)
    archive = tmp_path / "mixed.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("plain.bin", random.Random(19).randbytes(50 * 1024))
    subprocess.run([require_7z(), "a", "-tzip", "-mx=0", "-psecret", str(archive), str(source)],
                   check=True, capture_output=True)
    data = archive.read_bytes()
    with zipfile.ZipFile(archive) as output:
        info = output.getinfo(source.name)
    name_len, extra_len = struct.unpack_from("<HH", data, info.header_offset + 26)
    header = info.header_offset + 30 + name_len + extra_len
    assert 48 * 1024 <= header < 96 * 1024
    root = tmp_path / "parts"
    root.mkdir()
    parts = []
    for index, offset in enumerate(range(0, len(data), 48 * 1024), 1):
        part = root / f"shared.part{index:03}.z.opaque"
        part.write_bytes(data[offset:offset + 48 * 1024])
        parts.append(part)
    damaged = bytearray(parts[1].read_bytes())
    damaged[header - 48 * 1024 + 11] ^= 1
    bad = parts[1].with_name(parts[1].name.replace(".z.", ".a."))
    bad.write_bytes(damaged)
    descriptor = ArchiveTaskProvider(make_config()).discover_targets([str(root)]).tasks[0].archive_input()
    assert descriptor.volume_attempts
    good = _run_trial(tmp_path / "correct", descriptor, password_candidates=["secret", "wrong"])
    assert good["status"] == "ok" and good["volume_attempts"] == 2, good
    assert (tmp_path / "correct/worker-out/z-encrypted.bin").read_bytes() == expected
    verified = _run_trial(tmp_path / "verified", descriptor, password="secret", password_verified=True)
    assert verified["status"] == "ok" and verified["volume_attempts"] == 2, verified
    # Find a wrong password which passes this real ZipCrypto header's one-byte
    # check. No worker loop/probe is mocked; CRC failure must stay inconclusive.
    check = (info._raw_time >> 8) & 255 if info.flag_bits & 8 else info.CRC >> 24
    encrypted_header = data[header:header + 12]
    candidate = 0
    while True:
        weak = f"wrong-{candidate}"
        if zipfile._ZipDecrypter(weak.encode())(encrypted_header)[-1] == check:
            break
        candidate += 1
    # Keep the same password header in both alternatives for this half: every
    # candidate reaches CRC failure, independently of the header-rejection case.
    damaged = bytearray(parts[1].read_bytes())
    damaged[header - 48 * 1024 + 120] ^= 1
    bad.write_bytes(damaged)
    failed = _run_trial(tmp_path / "wrong", descriptor, password_candidates=[weak])
    assert not failed["missing_volume"] and not failed["password_candidates_all_rejected"], failed
    assert failed["failure_kind"] == "password_or_volume_inconclusive", failed
    run = subprocess.CompletedProcess([], 2)
    # Match the normal runner's diagnostic projection.
    run.worker_diagnostics = {"result": failed}
    failure = classify_extract_failure(run, "", is_split_archive=True)
    assert failure.kind == FailureKind.PASSWORD_INCONCLUSIVE
    checkpoint = InputCheckpoint(LogicalArchiveInput(descriptor), (), failure=failure)
    assert checkpoint.blockers == {"password", "missing_volume"}
    assert checkpoint.input.volume_completeness != "missing"


@pytest.mark.parametrize("archive_format", ["rar", "7z", "zip"])
def test_candidate_carrier_retains_an_independent_split_head(tmp_path, archive_format):
    first = ArchiveFixtureFactory().create(tmp_path, "first", archive_format, split=True,
        compression_level=0, payload_size=160 * 1024, split_volume_size=48 * 1024)
    second = ArchiveFixtureFactory().create(tmp_path, "second", archive_format, split=True,
        compression_level=0, payload_size=160 * 1024, split_volume_size=48 * 1024)
    parts = sorted(first.archive_dir.iterdir())
    other = sorted(second.archive_dir.iterdir())
    damaged = bytearray(parts[1].read_bytes())
    damaged[len(damaged) // 2] ^= 1
    carrier = parts[1].with_name("first.part2.a.opaque")
    carrier.write_bytes(damaged + b"carrier gap" * 19 + other[0].read_bytes())
    for index, part in enumerate(other[1:], 2):
        part.rename(first.archive_dir / f"first.part{index}.other.opaque")
    tasks = ArchiveTaskProvider(make_config({"embedded_scan": {"enabled": True}})).discover_targets([str(first.archive_dir)]).tasks
    extractor = ExtractionScheduler()
    extractor.sevenzip_runner.worker_path = str(sevenzip_artifact("sunpack_sevenzip_worker.exe"))
    try:
        for index, task in enumerate(tasks):
            result = extractor.extract(task, str(tmp_path / "outputs" / str(index)))
            assert result.success, (result.error, result.diagnostics)
    finally:
        extractor.close()
    for case in (first, second):
        assert [p.read_text(encoding="utf-8") for p in (tmp_path / "outputs").rglob(case.marker_name)] == [case.marker_text]
