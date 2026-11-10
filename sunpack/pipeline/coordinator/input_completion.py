from dataclasses import replace

from sunpack.core.contracts.input_plan import InputCheckpoint, InputRecovery, source_generation


def checkpoint_inputs(task, result):
    generation = task.runtime.get("input_generation", ())
    if not generation:
        return
    generation = {row[0]: tuple(row) for row in generation}
    checkpoints = {item.input.input_id: item for item in task.recovery.checkpoints}
    current = ((item.input, item.result) for item in result.input_results) if result.input_results else (
        (result.logical_input, result),)
    for node, extracted in current:
        if node is not None:
            checkpoints[node.input_id] = InputCheckpoint(
                node, source_generation(node, generation), extracted.out_dir,
                extracted.success, extracted.failure, extracted.files_written, extracted.bytes_written,
            )
    recovery = InputRecovery(tuple(checkpoints.values()), result.out_dir,
                             task.recovery.input_count or len(task.inputs))
    task.recovery = recovery
    if result.failure is not None:
        result.failure = replace(result.failure, details={
            **result.failure.details, "input_recovery": recovery.to_dict(),
        })
