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
        assert final["volume_attempts"] == 1 and not final["missing_volume"]
        assert final["wrong_password"]


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
