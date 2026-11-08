import asyncio

from sunpack.pipeline.coordinator.async_work import AsyncWorkBroker, CancellationToken


def run_extract(extractor, task, out_dir):
    async def scenario():
        broker = AsyncWorkBroker(thread_capacity=2)
        try:
            return await extractor.extract_asyncio(
                broker, task, out_dir, request_id="test",
                file_id=task.key or task.main_path, cancellation=CancellationToken(),
            )
        finally:
            try:
                close = getattr(extractor.sevenzip_runner, "aclose", None)
                if close is not None:
                    await close()
            finally:
                await broker.close()

    return asyncio.run(scenario())


def stub_worker_attempt(runner, callback):
    async def submit(job, **_context):
        return callback(**job)

    runner._build_job = dict
    runner.submit_attempt_asyncio = submit
    return runner
