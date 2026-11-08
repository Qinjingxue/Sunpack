import asyncio
from concurrent.futures import Future

import pytest

from sunpack.pipeline.extraction.internal.sevenzip.sevenzip_runner import SevenZipRunner, _NativeQueueCapacity


def test_rejected_job_waits_for_an_admitted_job_to_finish():
    capacity = _NativeQueueCapacity()
    resubmitted = []

    capacity.park("rejected", lambda: resubmitted.append("rejected"), completion=Future(), other_jobs_active=True)
    # The rejected job's own job_finished frees no queue slot.
    capacity.release("rejected")
    assert resubmitted == []

    capacity.release("admitted")
    assert resubmitted == ["rejected"]


def test_each_freed_slot_resubmits_one_parked_job_in_order():
    capacity = _NativeQueueCapacity()
    resubmitted = []
    for job_id in ("first", "second"):
        capacity.park(job_id, lambda job_id=job_id: resubmitted.append(job_id), completion=Future(), other_jobs_active=True)
        capacity.release(job_id)

    capacity.release("admitted-a")
    assert resubmitted == ["first"]
    capacity.release("admitted-b")
    assert resubmitted == ["first", "second"]
    capacity.release("admitted-c")
    assert resubmitted == ["first", "second"]


def test_rejected_job_resubmits_immediately_when_nothing_else_can_finish():
    capacity = _NativeQueueCapacity()
    resubmitted = []

    capacity.park("rejected", lambda: resubmitted.append("rejected"), completion=Future(), other_jobs_active=False)

    assert resubmitted == ["rejected"]
    # The later job_finished of the rejection itself must not wake anyone.
    capacity.park("other", lambda: resubmitted.append("other"), completion=Future(), other_jobs_active=True)
    capacity.release("rejected")
    assert resubmitted == ["rejected"]


def test_worker_exit_flushes_parked_jobs_so_they_fail_instead_of_hanging():
    capacity = _NativeQueueCapacity()
    resubmitted = []
    capacity.park("a", lambda: resubmitted.append("a"), completion=Future(), other_jobs_active=True)
    capacity.park("b", lambda: resubmitted.append("b"), completion=Future(), other_jobs_active=True)

    capacity.flush()

    assert resubmitted == ["a", "b"]
    capacity.release("admitted")
    assert resubmitted == ["a", "b"]


class _BackpressureWorker:
    worker_path = "queue-regression-worker"
    worker_epoch = "test"

    def __init__(self, schedule):
        self.queue_capacity = _NativeQueueCapacity()
        self.jobs = {}
        self.submitted = asyncio.Queue()
        self.spawn_resubmission = schedule

    async def get_or_start(self):
        return self

    def is_alive(self):
        return True

    async def submit(self, payload, job_id, **callbacks):
        assert job_id not in self.jobs
        self.jobs[job_id] = callbacks
        self.submitted.put_nowait(job_id)

    async def cancel_and_wait(self, job_id):
        if job_id in self.jobs:
            self.finish(job_id, status="failed")

    def has_other_jobs(self, job_id):
        return any(other != job_id for other in self.jobs)

    def take_stderr(self):
        return []

    def finish(self, job_id, **result):
        callback = self.jobs[job_id]["on_event"]
        callback({"type": "result", "job_id": job_id, **result})
        assert callback({"type": "native_event", "event": "job_finished", "job_id": job_id})
        self.jobs.pop(job_id)
        self.queue_capacity.release(job_id)


@pytest.mark.parametrize("cancel_when", ["parked", "dispatched"])
def test_cancelled_backpressure_request_does_not_strand_other_requests(cancel_when):
    # The queue-only tests cannot detect a runner that forgets to remove a
    # cancelled waiter or to transfer a wakeup already dispatched to the loop.
    async def scenario():
        loop = asyncio.get_running_loop()
        # Leave the grant in transit while cancellation is delivered.
        worker = _BackpressureWorker(lambda coroutine: loop.call_soon(loop.create_task, coroutine))
        runner = SevenZipRunner({}, shared_async_worker_holder=worker)
        jobs = {name: asyncio.create_task(runner.submit_attempt_asyncio({"job_id": name}))
                for name in ("running", "cancelled", "waiting")}
        for _ in jobs:
            await asyncio.wait_for(worker.submitted.get(), 1)
        for name in ("cancelled", "waiting"):
            worker.finish(name, status="failed", retryable=True, native_status="backpressure")
        if cancel_when == "dispatched":
            worker.finish("running", status="ok")
        jobs["cancelled"].cancel()
        await asyncio.gather(jobs["cancelled"], return_exceptions=True)
        if cancel_when == "parked":
            worker.finish("running", status="ok")
        try:
            assert await asyncio.wait_for(worker.submitted.get(), 1) == "waiting"
            worker.finish("waiting", status="ok")
            results = await asyncio.wait_for(asyncio.gather(jobs["running"], jobs["waiting"]), 1)
            assert all(result.returncode == 0 for result in results)
            assert not worker.jobs and not worker.queue_capacity._waiters
        finally:
            for job in jobs.values():
                job.cancel()
            worker.queue_capacity.flush()

    asyncio.run(scenario())


def test_backpressure_can_retry_past_legacy_limit_without_failing():
    """An admitted slot (or cancellation), not a retry counter, ends backpressure."""

    async def scenario():
        worker = _BackpressureWorker(asyncio.get_running_loop().create_task)
        runner = SevenZipRunner({}, shared_async_worker_holder=worker)
        task = asyncio.create_task(runner.submit_attempt_asyncio({"job_id": "repeated"}))
        try:
            for _ in range(125):
                assert await asyncio.wait_for(worker.submitted.get(), 2) == "repeated"
                worker.finish("repeated", status="failed", retryable=True, native_status="backpressure")
            assert await asyncio.wait_for(worker.submitted.get(), 2) == "repeated"
            worker.finish("repeated", status="ok")
            result = await asyncio.wait_for(task, 2)
            assert result.returncode == 0
            assert not worker.jobs
            assert not worker.queue_capacity._waiters
        finally:
            task.cancel()
            worker.queue_capacity.flush()

    asyncio.run(scenario())
