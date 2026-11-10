from types import SimpleNamespace

from sunpack.core.contracts.archive_input import ArchiveInputDescriptor, ArchiveInputPart, InputExtent
from sunpack.core.contracts.extraction import ExtractionResult, InputExecutionResult
from sunpack.core.contracts.failures import FailureInfo, FailureKind
from sunpack.core.contracts.input_plan import InputCheckpoint, InputRecovery, LogicalArchiveInput
from sunpack.core.contracts.results import OutcomeKind
from sunpack.pipeline.coordinator.content_recovery import ContentRecoveryPolicy


def test_recovery_policy_reduces_leaf_evidence_without_promoting_other_failures():
    """Scalar-only tests miss carrier wrappers and mixed input outcomes.

    This cheap matrix uniquely covers shared evidence rules across all shapes,
    including empty completed siblings and failures that happen to write files.
    """
    cases = (
        (FailureKind.DAMAGED, "failed", 2, (), True),
        (FailureKind.MISSING_VOLUME, "failed", 2, (), True),
        (FailureKind.DAMAGED, "failed", 0, (), False),
        (FailureKind.DAMAGED, "ok", 2, (), False),
        (FailureKind.DAMAGED, "failed", 2, (FailureInfo(FailureKind.UNKNOWN, "extract", "unknown"),), False),
        *((kind, "failed", 2, (), False) for kind in (
            FailureKind.WRONG_PASSWORD, FailureKind.PASSWORD_REQUIRED,
            FailureKind.PASSWORD_INCONCLUSIVE, FailureKind.FILESYSTEM_ERROR,
            FailureKind.PROCESS_ERROR, FailureKind.UNKNOWN,
        )),
    )
    for requirement in ("complete", "allow_partial"):
        policy = ContentRecoveryPolicy(requirement)
        for kind, status, complete_files, causes, eligible in cases:
            leaf = ExtractionResult(
                False, "out/partial", partial_outputs=True,
                failure=FailureInfo(kind, "extract", "failed", causes=causes),
                progress_manifest_payload=SimpleNamespace(
                    worker_status=status, summary={"complete": complete_files},
                ),
                # Unverified physical files are never recovery evidence.
                files_written=100, bytes_written=1000,
            )
            expected = (OutcomeKind.PARTIAL_SUCCESS
                        if requirement == "allow_partial" and eligible else OutcomeKind.FAILURE)
            for siblings in ([], [InputExecutionResult(None, ExtractionResult(True, "out/empty"))]):
                wrapped = ExtractionResult(
                    False, "out", failure=FailureInfo(FailureKind.INPUTS_FAILED, "inputs", "failed"),
                    partial_outputs=True,
                    input_results=[InputExecutionResult(None, leaf), *siblings],
                )
                decision = policy.decide(wrapped)
                assert decision.outcome_kind == policy.decide(leaf).outcome_kind == expected
                assert decision.complete_files == (complete_files if expected == OutcomeKind.PARTIAL_SUCCESS else 0)
                assert wrapped.input_results[0].outcome_kind == expected
                assert decision.rejected_partial_output == (requirement == "complete" and not siblings)
            blocked = ExtractionResult(False, "out", input_results=[
                InputExecutionResult(None, leaf),
                InputExecutionResult(None, ExtractionResult(False, "out/unknown")),
            ])
            assert policy.decide(blocked).outcome_kind == OutcomeKind.FAILURE


def test_partial_input_checkpoint_keeps_evidence_but_never_becomes_complete(tmp_path):
    """Ordinary completed-checkpoint tests cannot catch lost partial evidence.

    Check one persisted password retry and an old-format receipt without any
    native file rows. Counts, blockers and output reuse are independently at risk.
    """
    from sunpack.core.contracts.retry_targets import apply_input_retry
    from sunpack.core.contracts.tasks import ArchiveTask
    from sunpack.core.support.path_keys import path_key
    from sunpack.pipeline.coordinator.input_completion import checkpoint_inputs

    carrier = str(tmp_path / "carrier.bin")
    nodes = tuple(LogicalArchiveInput(ArchiveInputDescriptor(
        carrier, open_mode="file_range", format_hint="zip",
        parts=[ArchiveInputPart(InputExtent(carrier, offset, offset + 10))],
    ), position=index) for index, offset in enumerate((0, 10), 1))
    generation = ((path_key(carrier), "generation"),)
    password = FailureInfo(FailureKind.PASSWORD_REQUIRED, "extract", "password")
    partial = ExtractionResult(
        False, str(tmp_path / "out/partial"),
        failure=FailureInfo(FailureKind.DAMAGED, "extract", "damaged"),
        files_written=10, bytes_written=100,
        progress_manifest_payload=SimpleNamespace(worker_status="failed", summary={"complete": 2}),
    )
    result = ExtractionResult(False, str(tmp_path / "out"), failure=password, input_results=[
        InputExecutionResult(nodes[0], partial),
        InputExecutionResult(nodes[1], ExtractionResult(False, str(tmp_path / "out/password"), failure=password)),
    ])
    task = ArchiveTask.from_archive_input(nodes[0].descriptor, discovery_source="test", logical_inputs=nodes)
    task.runtime["input_generation"] = generation
    checkpoint_inputs(task, result)
    restored = InputRecovery.from_failure(result.failure)
    checkpoint = restored.checkpoints[0]
    assert not checkpoint.complete and checkpoint.recovered_complete_files == 2
    assert checkpoint.failure.kind == FailureKind.DAMAGED
    retry = ArchiveTask.from_archive_input(nodes[0].descriptor, discovery_source="test", logical_inputs=nodes)
    apply_input_retry(retry, result.failure, generation)
    assert retry.inputs == (nodes[1],)
    assert retry.runtime["retry_output_dir"] == result.out_dir
    retained = next(item for item in retry.recovery.checkpoints if item.input.input_id == nodes[0].input_id)
    resumed = ExtractionResult(False, result.out_dir, input_results=[
        InputExecutionResult(retained.input, ExtractionResult(
            retained.complete, retained.output_dir, failure=retained.failure,
            files_written=retained.files_written, recovered_complete_files=retained.recovered_complete_files,
        ), retained=True),
        InputExecutionResult(nodes[1], ExtractionResult(True, "out/password", files_written=3)),
    ])
    decision = ContentRecoveryPolicy("allow_partial").decide(resumed)
    assert decision.outcome_kind == OutcomeKind.PARTIAL_SUCCESS and decision.complete_files == 5
    assert ContentRecoveryPolicy("complete").decide(resumed).outcome_kind == OutcomeKind.FAILURE
    old = checkpoint.to_dict()
    del old["recovered_complete_files"]
    assert InputCheckpoint.from_dict(old).recovered_complete_files == 0


def test_carrier_partial_output_survives_password_retry_and_uses_child_scan_roots(tmp_path):
    """Exercise real aggregation, cleanup, continuation and recursive projection.

    Leaf-policy tests cannot catch lost child evidence, scanning a blocked root,
    using physical counts as recovered counts, or retaining native tables in a
    checkpoint. One supplied worker per input avoids external archive tooling.
    """
    import weakref

    from sunpack.core.contracts.retry_targets import apply_input_retry
    from sunpack.core.contracts.run_state import RunState
    from sunpack.core.contracts.tasks import ArchiveTask
    from sunpack.core.i18n import I18nContext
    from sunpack.core.support.path_keys import path_key
    from sunpack.pipeline.coordinator.archive_job import ArchiveJobExecutor, ArchiveJobOutcome
    from sunpack.pipeline.coordinator.cleanup_refs import CleanupRefTable
    from sunpack.pipeline.coordinator.input_completion import checkpoint_inputs
    from sunpack.pipeline.coordinator.output_scan_policy import NestedOutputScanPolicy
    from sunpack.pipeline.extraction.internal.workflow.single_archive_extractor import SingleArchiveExtractor
    from sunpack.pipeline.extraction.output_inventory import collect_output_inventory

    class Manifest:
        worker_status = "failed"
        summary = {"complete": 1}

    carrier = str(tmp_path / "carrier.bin")
    nodes = tuple(LogicalArchiveInput(ArchiveInputDescriptor(
        carrier, open_mode="file_range", format_hint="zip", logical_name=name,
        parts=[ArchiveInputPart(InputExtent(carrier, offset, offset + 10))],
    ), position=index) for index, (offset, name) in enumerate(((0, "partial.zip"), (10, "password.zip")), 1))
    generation = ((path_key(carrier), "same-generation"),)
    out_dir = str(tmp_path / "output")
    task = ArchiveTask.from_archive_input(nodes[0].descriptor, discovery_source="direct", logical_inputs=nodes)
    task.runtime["input_generation"] = generation
    extractor = object.__new__(SingleArchiveExtractor)
    extractor.scanning, extractor.i18n = False, I18nContext("en")
    extractor._log = lambda *_args: None
    extractor.sevenzip_runner = SimpleNamespace(emit_semantic_event=lambda *_args, **_kwargs: None)
    unlocked = False
    seen = []

    def worker(child_task, output, **_kwargs):
        from pathlib import Path

        position = child_task.inputs[0].position
        seen.append(position)
        if position == 2 and not unlocked:
            failure = FailureInfo(FailureKind.PASSWORD_REQUIRED, "extract", "password required")
            result = ExtractionResult(False, output, failure=failure)
        else:
            path = Path(output)
            path.mkdir(parents=True, exist_ok=True)
            (path / "good.txt").write_text("good", encoding="utf-8")
            if position == 1:
                (path / "unfinished.bin").write_bytes(b"partial")
            result = ExtractionResult(
                position == 2, output,
                failure=FailureInfo(FailureKind.DAMAGED, "extract", "damaged") if position == 1 else None,
                partial_outputs=position == 1,
                progress_manifest_payload=Manifest() if position == 1 else None,
                output_inventory=collect_output_inventory(output),
            )
        if False:
            yield
        return result

    extractor._extract_one_state_machine = worker
    runner = object.__new__(ArchiveJobExecutor)
    runner.scanning, runner.context, runner.i18n = False, RunState(), extractor.i18n
    runner.content_policy = ContentRecoveryPolicy("allow_partial")

    def execute(current):
        state = extractor._extract_state_machine(current, out_dir)
        try:
            next(state)
        except StopIteration as stopped:
            extracted = stopped.value
        else:
            raise AssertionError("supplied worker must not submit native work")
        checkpoint_inputs(current, extracted)
        reported = runner.collect_result(current, ArchiveJobOutcome(extracted, planned_out_dir=out_dir))
        return extracted, reported

    first, reported = execute(task)
    assert reported.outcome_kind == OutcomeKind.FAILURE
    assert reported.failure.is_password_failure
    assert first.has_retained_outputs and not first.has_complete_inputs
    projected = NestedOutputScanPolicy.project_logical_scan_roots(out_dir, first)
    assert [root for root, _ in projected] == [first.input_results[0].result.out_dir]
    owner = weakref.ref(first.input_results[0].result.progress_manifest_payload)
    retry = ArchiveTask.from_archive_input(nodes[0].descriptor, discovery_source="direct", logical_inputs=nodes)
    retry.runtime["input_generation"] = generation
    apply_input_retry(retry, reported.failure, generation)
    assert retry.inputs == (nodes[1],) and retry.runtime["retry_output_dir"] == out_dir
    assert not next(item for item in retry.recovery.checkpoints if item.input.input_id == nodes[0].input_id).complete
    del projected, first
    assert owner() is None, "checkpoint must not hold native manifest owners"
    unlocked = True
    second, final = execute(retry)
    assert seen == [1, 2, 2]
    assert final.outcome_kind == OutcomeKind.PARTIAL_SUCCESS
    assert final.recovery["complete_files"] == 2  # Not the three physical files.
    assert not second.success
    assert [root for root, _ in NestedOutputScanPolicy.project_logical_scan_roots(out_dir, second)] == [
        next(item.result.out_dir for item in second.input_results if item.complete)
    ]
    from dataclasses import replace

    split_task = ArchiveTask.from_archive_input(
        replace(nodes[0].descriptor, open_mode="native_volumes", volume_style="numeric_suffix", parts=[
            replace(nodes[0].descriptor.parts[0], volume_number=1, canonical_name="carrier.001"),
        ]), discovery_source="test", logical_inputs=nodes,
    )
    warned = runner.collect_result(split_task, ArchiveJobOutcome(second, planned_out_dir=out_dir))
    assert warned.recovery["warning"]["details"]["missing_volume_confirmed"] is False
    assert InputRecovery.from_failure(warned.failure).to_dict() == retry.recovery.to_dict()
    assert warned.failure.details["retry_output_dir"] == out_dir
    refs = CleanupRefTable()
    refs.register(retry)
    if final.outcome_kind == OutcomeKind.COMPLETE_SUCCESS:
        refs.mark_cleanup_eligible(retry)
    assert not refs.release(retry).cleanup_paths

    # Switching requirements cannot revive a receipt after its owned partial
    # output was deleted. This also covers the normal single-input fast path.
    out_dir = str(tmp_path / "single_output")
    single = ArchiveTask.from_archive_input(nodes[0].descriptor, discovery_source="test")
    single.runtime["input_generation"] = generation
    extracted, accepted = execute(single)
    assert accepted.outcome_kind == OutcomeKind.PARTIAL_SUCCESS
    single_retry = ArchiveTask.from_archive_input(nodes[0].descriptor, discovery_source="test")
    single_retry.runtime["input_generation"] = generation
    apply_input_retry(single_retry, accepted.failure, generation)
    assert not single_retry.inputs and single_retry.runtime["retry_output_dir"] == out_dir
    runner.content_policy = ContentRecoveryPolicy("complete")
    rejected, final = execute(single_retry)
    assert final.outcome_kind == OutcomeKind.FAILURE
    assert rejected.diagnostics["failed_output_cleanup"]["cleaned"]
    assert not single_retry.runtime.get("retry_output_dir")
    restored = InputRecovery.from_failure(final.failure)
    assert not restored.output_dir
    assert all(not item.output_dir and not item.recovered_complete_files for item in restored.checkpoints)
    assert restored.checkpoints[0].discarded_recoverable_output

    # A discarded receipt cannot prove recovery, but allowing partial content
    # later must rerun that input instead of carrying its evidence-less failure.
    out_dir = str(tmp_path / "rejected_carrier")
    unlocked = False
    task = ArchiveTask.from_archive_input(nodes[0].descriptor, discovery_source="test", logical_inputs=nodes)
    task.runtime["input_generation"] = generation
    rejected, failed = execute(task)
    assert failed.outcome_kind == OutcomeKind.FAILURE and failed.failure.is_password_failure
    assert rejected.diagnostics["failed_output_cleanup"]["cleaned"]
    assert not (tmp_path / "rejected_carrier").exists()
    discarded = InputRecovery.from_failure(failed.failure)
    assert [item.discarded_recoverable_output for item in discarded.checkpoints] == [True, False]
    assert all(not item.output_dir and not item.recovered_complete_files for item in discarded.checkpoints)

    def resume(failure, *, recover_partial=False, password_changed=True):
        current = ArchiveTask.from_archive_input(nodes[0].descriptor, discovery_source="test", logical_inputs=nodes)
        current.runtime["input_generation"] = generation
        apply_input_retry(current, failure, generation, password_changed=password_changed,
                          recover_partial=recover_partial)
        return current

    unchanged = resume(failed.failure, password_changed=False)
    assert not unchanged.inputs
    # The same complete requirement wakes only the password-dependent sibling.
    same_policy = resume(failed.failure)
    assert same_policy.inputs == (nodes[1],)
    assert same_policy.recovery.checkpoints[0].discarded_recoverable_output
    retry = resume(failed.failure, recover_partial=True)
    assert retry.inputs == nodes and not retry.recovery.output_dir
    assert not retry.runtime.get("retry_output_dir")
    seen.clear()
    unlocked = True
    runner.content_policy = ContentRecoveryPolicy("allow_partial")
    recovered, final = execute(retry)
    assert seen == [1, 2]
    assert final.outcome_kind == OutcomeKind.PARTIAL_SUCCESS
    assert final.recovery["complete_files"] == 2
    assert not recovered.success
    assert not any(item.discarded_recoverable_output for item in retry.recovery.checkpoints)
    repeated = resume(final.failure, recover_partial=True)
    assert not repeated.inputs and repeated.runtime["retry_output_dir"] == out_dir
