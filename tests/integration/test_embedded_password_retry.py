"""Real carrier continuations across CLI rounds and durable Watch recovery."""
from __future__ import annotations

import asyncio
import os
from pathlib import Path
import subprocess
import shutil
from types import SimpleNamespace
import uuid
import zipfile

import pytest

from sunpack.core.contracts.retry_targets import password_retry_failures
from sunpack.core.contracts.failures import FailureKind
from sunpack.pipeline.coordinator.engine import PipelineEngine
from sunpack.runtime.cli.cli_context import CliContext
from sunpack.runtime.cli.cli_reporter import CliReporter
from sunpack.runtime.cli.commands import extract
from sunpack.runtime.watch import scheduler as scheduler_module
from sunpack.runtime.watch.scheduler import WatchScheduler
from tests.helpers.config_factory import make_config
from tests.helpers.native_fixture import assemble_carrier
from tests.helpers.passwords import write_password_json
from tests.helpers.tool_config import require_7z


@pytest.fixture
def carrier_case(tmp_path):
    source = tmp_path / "source"
    watch = tmp_path / "watch"
    source.mkdir()
    watch.mkdir()
    passwords = [uuid.uuid4().hex for _ in range(3)]
    archives = []
    for index in range(4):
        name = f"marker-{index}.txt"
        (source / name).write_text(f"payload-{index}", encoding="utf-8")
        archive = tmp_path / f"segment-{index}.zip"
        subprocess.run([str(require_7z()), "a", "-tzip", "-mx=0", str(archive), name,
                        *([f"-p{passwords[index - 1]}", "-mem=AES256"] if index else [])],
                       cwd=source, check=True, capture_output=True)
        archives.append(archive)
    carrier = watch / "capture.pcapng"
    assemble_carrier(carrier, archives)
    config = make_config({
        "recursive_extract": 3, "user_passwords": [], "builtin_passwords": [],
        "output": {"root": str(tmp_path / "out")},
        "post_extract": {"archive_cleanup_mode": "k", "flatten_single_directory": False},
        "watch": {"clipboard_monitor_enabled": False, "password_retry_debounce_seconds": 0},
        "cli": {"quiet": True},
    })
    return SimpleNamespace(carrier=carrier, watch=watch, config=config, passwords=passwords, archives=archives)


def assert_outputs(tmp_path, count=4):
    roots = set()
    for index in range(count):
        files = list((tmp_path / "out").rglob(f"marker-{index}.txt"))
        assert len(files) == 1
        assert files[0].read_text(encoding="utf-8") == f"payload-{index}"
        roots.add(files[0].parent.parent)
    assert len(roots) == 1, "all independent segments must stay under the first carrier output"
    return roots.pop()


def test_cli_retries_only_remaining_password_segments(tmp_path, monkeypatch, carrier_case):
    # Ordinary archive retry tests cannot see successful siblings re-extracted.
    # Two rounds also catch replay of an encrypted sibling unlocked in round one.
    case = carrier_case
    responses = []
    conflict = tmp_path / "out" / "capture"
    conflict.mkdir(parents=True)
    (conflict / "existing.txt").write_text("keep", encoding="utf-8")

    class RecordingEngine(PipelineEngine):
        async def run(self, paths, **kwargs):
            response = await super().run(paths, **kwargs)
            responses.append(response)
            return response

    answers = iter(["y", "wrong-retry", "", "y", case.passwords[1], "", "y", case.passwords[2], ""])
    monkeypatch.setattr(extract, "load_request_config", lambda cwd: case.config)
    monkeypatch.setattr(extract, "pipeline_engine", RecordingEngine)
    monkeypatch.setattr(extract, "collect_clipboard_passwords", lambda cfg: [])
    args = SimpleNamespace(
        paths=[str(case.carrier)], password=[case.passwords[0]], password_file=None,
        prompt_passwords=False, no_builtin_passwords=True, recursive_extract=None,
        archive_cleanup_mode=None, flatten_single_directory=None, json=False,
        quiet=False, verbose=False, recursive=False,
    )
    code, result = asyncio.run(extract.handle(args, CliContext(
        language="en", reporter=CliReporter(quiet=True), cwd=str(tmp_path),
        input_reader=lambda prompt: next(answers),
    )))
    assert code == 0, result.errors
    assert result.summary["password_retry_count"] == 3
    assert [r.summary.failed_count for r in responses] == [1, 1, 1, 0]
    root = assert_outputs(tmp_path)
    assert root == conflict.with_name("capture(1)")
    assert (conflict / "existing.txt").read_text(encoding="utf-8") == "keep"
    assert {r.summary.target_results[0].output_dir for r in responses} == {str(root)}


def test_watch_restart_retries_promoted_carrier_without_replaying_siblings(
    tmp_path, monkeypatch, carrier_case,
):
    # CLI cannot exercise WAL serialization or descriptor path remapping during
    # nested promotion. Reopening the scheduler makes both part of one scenario.
    case = carrier_case
    from sunpack.core.passwords.internal import builtin
    monkeypatch.setattr(scheduler_module, "validate_ntfs_watch_roots", lambda roots: None)
    wrapper = tmp_path / "outer-source" / "wrapper"
    wrapper.mkdir(parents=True)
    shutil.copy2(case.carrier, wrapper / case.carrier.name)
    outer = case.watch / "outer.zip"
    subprocess.run([str(require_7z()), "a", "-tzip", "-mx=0", str(outer), "wrapper"],
                   cwd=wrapper.parent, check=True, capture_output=True)
    case.carrier.unlink()
    case.config["post_extract"]["flatten_single_directory"] = True
    write_password_json(builtin.builtin_password_path(), scopes=[(case.passwords[0], [str(case.watch)])])

    async def scenario():
        async with PipelineEngine(case.config) as engine:
            def scheduler():
                return WatchScheduler(
                    case.config, [str(case.watch)],
                    output_roots={str(case.watch): str(tmp_path / "out")},
                    state_path=str(tmp_path / "state.snapshot"), cold_start_seconds=0,
                    pipeline_engine=engine,
                )

            watcher = scheduler()
            try:
                watcher.enqueue(str(outer))
                await watcher.run_once()
                await watcher.drain()
                entries = list(watcher.state.entries.values())
                assert len(entries) == 1
                assert entries[0].failure_payload["details"]["retry_generation"]
                assert Path(entries[0].path).parent == case.watch
                root = assert_outputs(tmp_path, 2)
                assert entries[0].failure_payload["details"]["retry_output_dir"] == str(root)
                # Simulate process loss after a retry recorded its output start.
                # Recovery must not treat the retained container as disposable.
                candidate = scheduler_module._candidate_for_event_path(entries[0].path)
                watcher.state.queue_active(candidate, source_input_root=str(case.watch), durable_owner=True)
                watcher.state.record_task_output_started(entries[0].path, entries[0].path, str(root))
                watcher.state.flush()
            finally:
                await watcher.aclose()
            watcher = scheduler()
            try:
                watcher._recover_persisted_work()
                assert_outputs(tmp_path, 2)
                watcher._reconcile_persisted_blockers()
                for password in case.passwords[1:]:
                    write_password_json(builtin.builtin_password_path(), scopes=[(password, [str(case.watch)])])
                    watcher.notify_password_source_changed("builtin_password_file")
                    await watcher.run_once()
                    await watcher.drain()
                assert not watcher.state.entries
            finally:
                await watcher.aclose()

    asyncio.run(scenario())
    root = assert_outputs(tmp_path)
    assert root == tmp_path / "out" / "outer"


def test_changed_carrier_invalidates_password_continuation(tmp_path, carrier_case):
    # A stale scope can silently omit new plaintext payloads while all password
    # retries succeed. Neither unchanged-source scenario can detect that loss.
    case = carrier_case

    async def scenario():
        async with PipelineEngine(case.config) as engine:
            response = await engine.run([str(case.carrier)], request_config={
                **case.config, "user_passwords": ["wrong-initial"],
            })
            retry = password_retry_failures(response.summary)
            assert retry
            # Replace with a new file identity while preserving valid ranges.
            replacement = tmp_path / "replacement"
            previous = case.carrier.stat()
            replacement.write_bytes(case.carrier.read_bytes())
            os.utime(replacement, ns=(previous.st_atime_ns, previous.st_mtime_ns))
            case.carrier.unlink()
            replacement.rename(case.carrier)
            response = await engine.run([str(case.carrier)], request_config={
                **case.config, "user_passwords": case.passwords, "password_retry_failures": retry,
            })
            assert not response.summary.failed_tasks

    asyncio.run(scenario())
    assert len(list((tmp_path / "out").rglob("marker-0.txt"))) == 2
    for index in range(1, 4):
        assert len(list((tmp_path / "out").rglob(f"marker-{index}.txt"))) == 1


def test_password_continuation_preserves_unrelated_damage_and_source(tmp_path, carrier_case):
    # Subset extraction can falsely report whole-carrier success and authorize
    # deletion. Only a real non-password sibling failure exercises that veto.
    case = carrier_case
    damaged = tmp_path / "damaged.zip"
    name = "damaged.txt"
    with zipfile.ZipFile(damaged, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr(name, b"damaged sibling payload" * 128)
    raw = bytearray(damaged.read_bytes())
    raw[30 + len(name)] ^= 0xFF  # Break payload CRC, preserving all ZIP boundaries.
    damaged.write_bytes(raw)
    assemble_carrier(case.carrier, [*case.archives, damaged])
    config = {**case.config, "post_extract": {
        **case.config["post_extract"], "archive_cleanup_mode": "d",
    }}

    async def scenario():
        async with PipelineEngine(config) as engine:
            response = await engine.run([str(case.carrier)], request_config={
                **config, "user_passwords": [case.passwords[0]],
            })
            assert response.summary.failures[0].contains(FailureKind.DAMAGED)
            for password in case.passwords[1:]:
                response = await engine.run([str(case.carrier)], request_config={
                    **config, "user_passwords": [password],
                    "password_retry_failures": password_retry_failures(response.summary),
                })
            assert response.summary.failed_count == 1
            failure = response.summary.failures[0]
            assert failure.contains(FailureKind.DAMAGED) and not failure.is_password_failure
            assert case.carrier.is_file()

    asyncio.run(scenario())
    assert_outputs(tmp_path)


def test_cancelled_continuation_cleans_only_new_segment_roots(tmp_path, monkeypatch, carrier_case):
    # Completed/failed retries cannot expose whole-root cancellation rollback.
    # Interrupt at the worker boundary, then retry again to cover reservation
    # release and preservation of earlier plaintext/encrypted siblings together.
    from sunpack.pipeline.extraction.internal.sevenzip.sevenzip_runner import SevenZipRunner

    case = carrier_case
    build_job = SevenZipRunner._build_job
    partials = []

    def interrupted_job(runner, **kwargs):
        path = Path(kwargs["out_dir"]) / "interrupted.partial"
        path.write_text("incomplete", encoding="utf-8")
        partials.append(path)
        raise asyncio.CancelledError

    async def scenario():
        async with PipelineEngine(case.config) as engine:
            response = await engine.run([str(case.carrier)], request_config={
                **case.config, "user_passwords": [case.passwords[0]],
            })
            root = assert_outputs(tmp_path, 2)
            config = {**case.config, "user_passwords": case.passwords,
                      "password_retry_failures": password_retry_failures(response.summary)}
            monkeypatch.setattr(SevenZipRunner, "_build_job", interrupted_job)
            response = await engine.run([str(case.carrier)], request_config=config)
            assert response.interrupted and not response.interruption_cleanup_errors
            assert partials and all(not path.parent.exists() for path in partials)
            assert assert_outputs(tmp_path, 2) == root
            monkeypatch.setattr(SevenZipRunner, "_build_job", build_job)
            response = await engine.run([str(case.carrier)], request_config=config)
            assert not response.summary.failed_tasks
            assert assert_outputs(tmp_path) == root

    asyncio.run(scenario())
