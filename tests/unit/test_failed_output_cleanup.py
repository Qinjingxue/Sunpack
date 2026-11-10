from __future__ import annotations

from sunpack.core.contracts.input_plan import LogicalArchiveInput
from sunpack.core.contracts.archive_input import ArchiveInputDescriptor

import asyncio
import threading
from types import SimpleNamespace

import pytest

from sunpack.core.contracts.extraction import ExtractionResult, InputExecutionResult
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


@pytest.mark.parametrize("requirement", ["complete", "allow_partial"])
@pytest.mark.parametrize("with_directory", [False, True], ids=["empty", "directory-only"])
def test_complete_empty_inputs_survive_failed_sibling_cleanup_and_retry(
    tmp_path, monkeypatch, requirement, with_directory,
):
    # File-bearing carrier tests cannot detect deleting valid empty output
    # while its persisted checkpoint still tells the retry to skip that input.
    from pathlib import Path
    from sunpack.core.contracts.archive_input import ArchiveInputPart, InputExtent
    from sunpack.core.contracts.retry_targets import apply_input_retry
    from sunpack.core.contracts.tasks import ArchiveTask
    from sunpack.core.support.path_keys import path_key
    from sunpack.pipeline.coordinator.cleanup_refs import CleanupRefTable
    from sunpack.pipeline.coordinator.input_completion import checkpoint_inputs
    from sunpack.pipeline.extraction.internal.workflow.single_archive_extractor import SingleArchiveExtractor

    carrier = str(tmp_path / "carrier.bin")
    nodes = tuple(LogicalArchiveInput(ArchiveInputDescriptor(
        carrier, open_mode="file_range", format_hint="zip", logical_name=name,
        parts=[ArchiveInputPart(InputExtent(carrier, start, start + 10))],
    ), position=position) for position, (start, name) in enumerate(
        ((0, "empty.zip"), (10, "encrypted.zip")), 1))
    output = tmp_path / "output"
    complete_output = output / "empty.zip"
    complete_output.mkdir(parents=True)
    if with_directory:
        (complete_output / "important-directory").mkdir()
    generation = ((path_key(carrier), "same-generation"),)
    task = ArchiveTask.from_archive_input(nodes[0].descriptor, discovery_source="test", logical_inputs=nodes)
    task.runtime["input_generation"] = generation
    password = FailureInfo(FailureKind.PASSWORD_REQUIRED, "extract", "password required")
    extraction = ExtractionResult(
        False, str(output), partial_outputs=True,
        failure=FailureInfo(FailureKind.INPUTS_FAILED, "inputs", "sibling failed"),
        input_results=[
            InputExecutionResult(nodes[0], ExtractionResult(True, str(complete_output))),
            InputExecutionResult(nodes[1], ExtractionResult(False, str(output / "encrypted.zip"), failure=password)),
        ],
    )
    runner = object.__new__(ArchiveJobExecutor)
    runner.scanning, runner.context, runner.i18n = False, RunState(), I18nContext("en")
    runner.content_policy = ContentRecoveryPolicy(requirement)

    def unexpected_walk(_path):
        raise AssertionError("completed inputs must be retained without an output walk")

    monkeypatch.setattr("sunpack.pipeline.postprocess.output_cleanup._payload_inventory", unexpected_walk)

    checkpoint_inputs(task, extraction)
    outcome = ArchiveJobOutcome(extraction, planned_out_dir=str(output))
    reported = runner.collect_result(task, outcome)
    assert reported.outcome_kind == OutcomeKind.FAILURE
    assert not outcome.policy_rejected_partial_output
    assert not extraction.diagnostics["failed_output_cleanup"]["cleaned"]
    assert complete_output.is_dir()
    if with_directory:
        assert (complete_output / "important-directory").is_dir()
    refs = CleanupRefTable()
    refs.register(task)
    assert not refs.release(task).cleanup_paths

    retry = ArchiveTask.from_archive_input(nodes[0].descriptor, discovery_source="test", logical_inputs=nodes)
    apply_input_retry(retry, reported.failure, generation, password_changed=True)
    assert [node.position for node in retry.inputs] == [2]
    assert retry.runtime["retry_output_dir"] == str(output)

    def worker(child_task, out_dir, **_kwargs):
        assert child_task.inputs[0].position == 2
        Path(out_dir).mkdir(parents=True)
        (Path(out_dir) / "good.txt").write_text("good", encoding="utf-8")
        if False:
            yield
        return ExtractionResult(True, out_dir)

    extractor = object.__new__(SingleArchiveExtractor)
    extractor.scanning, extractor.i18n = False, runner.i18n
    extractor._log = lambda *_args: None
    extractor.sevenzip_runner = SimpleNamespace(emit_semantic_event=lambda *_args, **_kwargs: None)
    extractor._extract_one_state_machine = worker
    state = extractor._extract_inputs_state_machine(retry, str(output), retry.inputs)
    with pytest.raises(StopIteration) as stopped:
        next(state)
    retried = stopped.value.value
    final = runner.collect_result(retry, ArchiveJobOutcome(retried, planned_out_dir=str(output)))
    assert final.outcome_kind == OutcomeKind.COMPLETE_SUCCESS
    assert complete_output.is_dir()
    if with_directory:
        assert (complete_output / "important-directory").is_dir()
    refs.register(retry)
    refs.mark_cleanup_eligible(retry)
    assert refs.release(retry).cleanup_paths == (carrier,)


@pytest.mark.parametrize("with_zero_file", [False, True])
@pytest.mark.parametrize("embedded", [False, True])
def test_collect_result_records_cleanup_and_preserves_zero_byte_files(tmp_path, with_zero_file, embedded, monkeypatch):
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
    if embedded:
        # A carrier retains only child inventories. Ordinary-archive cleanup
        # cannot catch loss of its aggregate zero-byte-file count.
        extraction = ExtractionResult(
            success=False, out_dir=str(output), error="damaged",
            files_written=extraction.output_inventory.stats.file_count,
            bytes_written=extraction.output_inventory.stats.total_size,
            input_results=[InputExecutionResult(task.inputs[0], extraction)],
        )
    if with_zero_file:
        def unexpected_walk(_path):
            raise AssertionError("positive native inventory must be reused")
        monkeypatch.setattr("sunpack.pipeline.postprocess.output_cleanup._payload_inventory", unexpected_walk)
    outcome = ArchiveJobOutcome(result=extraction, planned_out_dir=str(output))
    runner = object.__new__(ArchiveJobExecutor)
    runner.scanning = False
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


@pytest.mark.parametrize("origin,output_started", [("foreground", False), ("watch", False), ("watch", True)])
def test_async_terminal_cleanup_yields_to_loop_and_finishes_before_watch_event(tmp_path, monkeypatch, origin, output_started):
    # Synchronous cleanup tests cannot detect blocking the shared event loop.
    # An event handshake checks responsiveness without a timing benchmark.
    output = tmp_path / "owned-output"
    output.mkdir()
    (output / "partial.txt").write_bytes(b"partial")
    task = make_archive_task(tmp_path / "broken.bin", logical_name="broken")
    extraction = ExtractionResult(False, str(output), error="damaged", partial_outputs=True)
    outcome = ArchiveJobOutcome(extraction, planned_out_dir=str(output))
    runner = object.__new__(ArchiveJobExecutor)
    runner.scanning = False
    runner.context, runner.i18n, runner.config = RunState(), I18nContext("en"), {}
    runner.content_policy = ContentRecoveryPolicy.from_config({})
    runner.origin, runner.request_id = origin, "cleanup-request"
    runner.progress_reporter = None
    runner._uncommitted_outputs = {}
    semantic = []
    runner.extractor = SimpleNamespace(emit_semantic_event=lambda *a, **kw: semantic.append(kw))

    async def extract(*args, **kwargs):
        if output_started:
            task.runtime["watch_active_output"] = (task.main_path, str(output))
            runner._uncommitted_outputs[str(output)] = task
        return task, outcome

    runner._execute_one_async = extract
    from sunpack.pipeline.postprocess.output_cleanup import OutputCleanupExecutor
    remove_tree = OutputCleanupExecutor.remove_tree

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

        monkeypatch.setattr(OutputCleanupExecutor, "remove_tree", staticmethod(blocked_cleanup))
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
            runner.finish_outputs()
            assert len(semantic) == (1 if output_started else 0)
        finally:
            release.set()
            await asyncio.gather(work, return_exceptions=True)
            await broker.close()

    asyncio.run(run())
