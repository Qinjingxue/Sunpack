import asyncio

from sunpack.coordinator.async_work import AsyncWorkBroker


def _send(state, result):
    try:
        return False, state.send(result)
    except StopIteration as completed:
        return True, completed.value


def run_extract_verify(runner, task, out_dir, *, missing_volume_retry=None):
    async def scenario():
        broker = AsyncWorkBroker(thread_capacity=2)
        state = runner._extract_verify_state_machine(
            task, out_dir, missing_volume_retry=missing_volume_retry
        )
        try:
            try:
                request = next(state)
            except StopIteration as completed:
                return completed.value
            while True:
                result = await broker.run(
                    "test_extract", task.key or task.main_path,
                    runner.extractor.extract, request["task"], request["out_dir"],
                    request_id="test",
                )
                done, value = await broker.run(
                    "test_verify_extract", task.key or task.main_path,
                    _send, state, result, request_id="test",
                )
                if done:
                    return value
                request = value
        finally:
            await broker.close()

    return asyncio.run(scenario())
