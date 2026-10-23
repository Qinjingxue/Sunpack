from __future__ import annotations

import asyncio
import shutil
import threading
from types import SimpleNamespace

import pytest

from sunpack.core.contracts.extraction import ExtractionResult
from sunpack.core.contracts.failures import FailureInfo, FailureKind
from sunpack.core.contracts.results import OutcomeKind
from sunpack.core.contracts.run_state import RunState
from sunpack.core.i18n import I18nContext
from sunpack.pipeline.coordinator.archive_job import (
    ArchiveJobExecutor,
    ArchiveJobOutcome,
    ContentRecoveryPolicy,
)
from sunpack.pipeline.postprocess.failed_output_cleanup import (
    cleanup_failed_output_if_eligible,
)
from sunpack.pipeline.coordinator.async_work import AsyncWorkBroker
from sunpack.pipeline.extraction.output_inventory import collect_output_inventory
from tests.helpers.archive_tasks import make_archive_task


def test_cleanup_removes_failed_empty_output(tmp_path):
    output = tmp_path / "output"
    output.mkdir()

    result = cleanup_failed_output_if_eligible(
        str(output),
        planned_output_dir=str(output),
        failed=True,
    )

    assert result.cleaned is True
    assert not output.exists()


@pytest.mark.parametrize(
    ("failed", "planned_matches", "expected_reason"),
    [
        (False, True, "task_not_failed"),
        (True, False, "unowned_output_dir"),
    ],
)
def test_cleanup_preserves_output_when_gate_is_not_satisfied(
    tmp_path,
    failed,
    planned_matches,
    expected_reason,
):
    output = tmp_path / "output"
    output.mkdir()

    result = cleanup_failed_output_if_eligible(
        str(output),
        planned_output_dir=str(output if planned_matches else tmp_path / "different"),
        failed=failed,
    )

    assert result.reason == expected_reason
    assert output.is_dir()


def test_cleanup_preserves_failed_output_with_nonzero_payload(tmp_path):
    output = tmp_path / "output"
    output.mkdir()
    (output / ".sunpack").mkdir()
    (output / ".sunpack" / "payload.bin").write_bytes(b"x")

    result = cleanup_failed_output_if_eligible(
        str(output),
        planned_output_dir=str(output),
        failed=True,
    )

    assert result.reason == "nonempty_payload"
    assert result.payload_bytes == 1
    assert output.is_dir()


def test_complete_embedded_children_are_not_policy_rejected_with_failed_siblings():
    child = ExtractionResult(True, "child")
    failure = FailureInfo(
        kind=FailureKind.EMBEDDED_SEGMENTS_FAILED,
        stage="embedded_segments",
        message="one encrypted child failed",
    )
    outer = ExtractionResult(
        success=False,

        out_dir="output",

        failure=failure,
        partial_outputs=True,
        embedded_results=[({"segment_id": "plain"}, child)],
    )

    assert ArchiveJobOutcome(result=outer).policy_rejected_partial_output is False


@pytest.mark.parametrize("with_zero_file", [False, True])
def test_collect_result_records_cleanup_and_preserves_zero_byte_files(tmp_path, with_zero_file, monkeypatch):
    archive = tmp_path / "broken.zip"
    archive.write_bytes(b"broken")
    output = tmp_path / "broken"
    output.mkdir()
    if with_zero_file:
        (output / "empty.txt").write_bytes(b"")
    task = make_archive_task(
        archive,
        logical_name="broken",
        format_hint="zip",
    )
    extraction = ExtractionResult(
        success=False,

        out_dir=str(output),

        error="damaged",
        output_inventory=collect_output_inventory(str(output)),
    )
    if with_zero_file:
        def unexpected_walk(_path):
            raise AssertionError("positive native inventory must be reused")
        monkeypatch.setattr("sunpack.pipeline.postprocess.output_cleanup._payload_inventory", unexpected_walk)
    outcome = ArchiveJobOutcome(result=extraction, planned_out_dir=str(output))
    runner = object.__new__(ArchiveJobExecutor)
    runner.context = RunState()
    runner.i18n = I18nContext("en")
    runner.config = {}
    runner.content_policy = ContentRecoveryPolicy.from_config(runner.config)

    returned = runner.collect_result(task, outcome)

    assert returned.outcome_kind == OutcomeKind.FAILURE
    assert returned.output_dir == str(output)
    cleanup = extraction.diagnostics["failed_output_cleanup"]
    assert cleanup["cleaned"] is (not with_zero_file)
    assert cleanup["reason"] == ("nonempty_payload" if with_zero_file else "cleaned")
    assert output.exists() is with_zero_file
    if with_zero_file:
        assert (output / "empty.txt").read_bytes() == b""
        assert cleanup["payload_file_count"] == 1
        assert cleanup["payload_bytes"] == 0
    assert [item.failure_message for item in runner.context.target_results] == [
        "broken.zip [damaged]"
    ]


@pytest.mark.parametrize("origin", ["foreground", "watch"])
def test_async_terminal_cleanup_yields_to_loop_and_finishes_before_watch_event(tmp_path, monkeypatch, origin):
    # Synchronous cleanup tests cannot detect blocking the shared event loop.
    # An event handshake checks responsiveness without a timing benchmark.
    output = tmp_path / "owned-output"
    output.mkdir()
    (output / "partial.txt").write_bytes(b"partial")
    task = make_archive_task(tmp_path / "broken.bin", logical_name="broken")
    extraction = ExtractionResult(False, str(output), error="damaged", partial_outputs=True)
    outcome = ArchiveJobOutcome(extraction, planned_out_dir=str(output))
    runner = object.__new__(ArchiveJobExecutor)
    runner.context, runner.i18n, runner.config = RunState(), I18nContext("en"), {}
    runner.content_policy = ContentRecoveryPolicy.from_config({})
    runner.origin, runner.request_id = origin, "cleanup-request"
    semantic = []
    runner.extractor = SimpleNamespace(emit_semantic_event=lambda *a, **kw: semantic.append(kw))

    async def extract(*args, **kwargs):
        return task, outcome

    runner._execute_one_async = extract
    remove_tree = shutil.rmtree

    async def run():
        loop = asyncio.get_running_loop()
        loop_thread = threading.get_ident()
        entered, release = asyncio.Event(), threading.Event()

        def blocked_cleanup(path):
            assert threading.get_ident() != loop_thread
            assert str(path) == str(output)
            loop.call_soon_threadsafe(entered.set)
            assert release.wait(2), "event loop did not respond during cleanup"
            remove_tree(path)

        monkeypatch.setattr("sunpack.pipeline.postprocess.output_cleanup.shutil.rmtree", blocked_cleanup)
        broker = AsyncWorkBroker(thread_capacity=2)
        work = asyncio.create_task(runner.execute_async(task, depth=1, output_dir_resolver=None,
            broker=broker, cancellation=None))
        try:
            await asyncio.wait_for(entered.wait(), 2)
            assert not work.done() and not semantic
            release.set()
            _, _, result = await asyncio.wait_for(work, 2)
            assert result.outcome_kind == OutcomeKind.FAILURE
            assert not output.exists()
            assert extraction.diagnostics["failed_output_cleanup"]["cleaned"] is True
            assert len(semantic) == (1 if origin == "watch" else 0)
        finally:
            release.set()
            await asyncio.gather(work, return_exceptions=True)
            await broker.close()

    asyncio.run(run())
