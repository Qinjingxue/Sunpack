import asyncio
import random
import threading
import time
from types import SimpleNamespace

import pytest

from sunpack.pipeline.coordinator.async_work import AsyncWorkBroker, CURRENT_WORK, _StageWorkQueue


@pytest.mark.parametrize("seed", [0, 31, 32, 63])
def test_stage_queue_preserves_priority_aging_and_fifo_during_interleaved_admission(seed):
    stages = (
        ("background_source_cleanup", 0),
        ("discover_detect", 10),
        ("password_probe", 10),
        ("input_plan", 20),
        ("extract_continuation", 30),
        ("verify", 30),
        ("output_promotion", 40),
        ("extractor_close", 50),
    )
    randomizer = random.Random(seed)
    queue = _StageWorkQueue()
    reference = []
    sequence = 0
    for _ in range(2000):
        # Admissions in other requests advance the global aging clock too.
        sequence += randomizer.choice((1, 31, 32, 33, 1601))
        if not reference or randomizer.random() < 0.65:
            stage, priority = randomizer.choice(stages)
            item = SimpleNamespace(context=SimpleNamespace(stage=stage), sequence=sequence)
            queue.append(item)
            reference.append((item, priority))
        else:
            expected = max(reference, key=lambda row: (
                row[1] + (sequence - row[0].sequence) // 32,
                -row[0].sequence,
            ))
            assert queue.take_prioritized(sequence) is expected[0]
            reference.remove(expected)
        assert len(queue) == len(reference)
    while reference:
        expected = max(reference, key=lambda row: (
            row[1] + (sequence - row[0].sequence) // 32,
            -row[0].sequence,
        ))
        assert queue.take_prioritized(sequence) is expected[0]
        reference.remove(expected)
    assert not queue


def test_stage_queue_cancellation_drain_preserves_global_fifo():
    queue = _StageWorkQueue()
    items = [
        SimpleNamespace(context=SimpleNamespace(stage=stage), sequence=index)
        for index, stage in enumerate(("background", "close", "scan", "verify", "background", "plan"))
    ]
    for item in items:
        queue.append(item)
    assert [queue.popleft() for _ in items] == items
    assert not queue


def test_broker_cancelled_queued_work_releases_slots_across_stage_buckets():
    async def scenario():
        broker = AsyncWorkBroker(thread_capacity=1, max_pending_jobs=4)
        entered = threading.Event()
        release = threading.Event()
        started = []

        def operation(label):
            started.append(label)
            if label == "active":
                entered.set()
                assert release.wait(timeout=3)
            return label

        try:
            active = asyncio.create_task(broker.run("scan", "active", operation, "active", request_id="r"))
            assert await asyncio.to_thread(entered.wait, 2)
            cancelled = asyncio.create_task(broker.run("close", "cancelled", operation, "cancelled", request_id="r"))
            verify = asyncio.create_task(broker.run("verify", "verify", operation, "verify", request_id="r"))
            background = asyncio.create_task(broker.run("background", "background", operation, "background", request_id="r"))
            await asyncio.sleep(0)
            cancelled.cancel()
            with pytest.raises(asyncio.CancelledError):
                await cancelled
            release.set()
            assert await asyncio.wait_for(asyncio.gather(active, verify, background), timeout=3) == [
                "active", "verify", "background",
            ]
            assert started == ["active", "verify", "background"]
            assert broker.pending_jobs == broker.active_jobs == 0
            assert broker._pending_slots._value == broker.max_pending_jobs
        finally:
            release.set()
            await broker.close()

    asyncio.run(scenario())


def test_broker_immediate_close_cancels_all_stage_buckets():
    async def scenario():
        broker = AsyncWorkBroker(thread_capacity=1, max_pending_jobs=8)
        entered = threading.Event()
        release = threading.Event()

        def operation():
            entered.set()
            assert release.wait(timeout=3)

        active = asyncio.create_task(broker.run("scan", "active", operation, request_id="r"))
        queued = []
        try:
            assert await asyncio.to_thread(entered.wait, 2)
            queued = [asyncio.create_task(broker.run(stage, stage, lambda: None, request_id="r"))
                      for stage in ("background", "scan", "plan", "verify", "commit", "close")]
            await asyncio.sleep(0)
            assert broker.pending_jobs == 6
            await broker.close(graceful=False)
            results = await asyncio.gather(*queued, return_exceptions=True)
            assert all(isinstance(result, asyncio.CancelledError) for result in results)
            assert broker.pending_jobs == 0
        finally:
            release.set()
            await asyncio.wait_for(active, timeout=3)
            await broker.close()
        assert broker.active_jobs == 0
        assert broker._pending_slots._value == broker.max_pending_jobs

    asyncio.run(scenario())


def test_broker_uses_fixed_workers_and_returns_on_owner_loop():
    async def scenario():
        broker = AsyncWorkBroker(thread_capacity=2, max_pending_jobs=4)
        owner = threading.get_ident()
        active = 0
        peak = 0
        lock = threading.Lock()

        def operation(value):
            nonlocal active, peak
            context = CURRENT_WORK.get()
            assert context is not None
            assert context.file_id == str(value)
            with lock:
                active += 1
                peak = max(peak, active)
            time.sleep(0.02)
            with lock:
                active -= 1
            return value

        try:
            values = await asyncio.gather(*(
                broker.run("verify", str(value), operation, value, request_id=f"r-{value % 2}")
                for value in range(8)
            ))
            assert values == list(range(8))
            assert peak == 2
            assert threading.get_ident() == owner
        finally:
            await broker.close()

    asyncio.run(scenario())


def test_broker_round_robins_requests_instead_of_draining_one_batch():
    async def scenario():
        broker = AsyncWorkBroker(thread_capacity=1, max_pending_jobs=16)
        started = []

        def operation(label):
            started.append(label)
            time.sleep(0.005)
            return label

        try:
            first = [
                asyncio.create_task(broker.run("scan", label, operation, label, request_id="a"))
                for label in ("a1", "a2", "a3")
            ]
            await asyncio.sleep(0)
            second = asyncio.create_task(broker.run("scan", "b1", operation, "b1", request_id="b"))
            await asyncio.gather(*first, second)
            assert started.index("b1") < started.index("a3")
        finally:
            await broker.close()

    asyncio.run(scenario())


def test_broker_reports_busy_and_idle_state_changes():
    async def scenario():
        broker = AsyncWorkBroker(thread_capacity=1, max_pending_jobs=2)
        states = []
        broker.set_state_changed_callback(
            lambda: states.append((broker.pending_jobs, broker.active_jobs))
        )
        try:
            assert await broker.run("verify", "item", lambda: "done") == "done"
        finally:
            await broker.close()

        assert any(pending or active for pending, active in states)
        assert states[-1] == (0, 0)

    asyncio.run(scenario())


def test_graceful_close_waits_once_for_idle_notification():
    async def scenario():
        broker = AsyncWorkBroker(thread_capacity=1, max_pending_jobs=2)
        started = threading.Event()
        release = threading.Event()
        wait_calls = 0
        original_wait = broker._idle_event.wait

        async def counted_wait():
            nonlocal wait_calls
            wait_calls += 1
            await original_wait()

        broker._idle_event.wait = counted_wait

        def operation():
            started.set()
            assert release.wait(timeout=2)
            return "done"

        active = asyncio.create_task(
            broker.run("verify", "item", operation, request_id="request")
        )
        await asyncio.to_thread(started.wait, 1.0)
        closing = asyncio.create_task(broker.close())
        await asyncio.sleep(0)
        assert not closing.done()
        assert wait_calls == 1

        release.set()
        assert await active == "done"
        await asyncio.wait_for(closing, timeout=1.0)
        assert wait_calls == 1

    asyncio.run(scenario())


def test_broker_dispatches_waiting_foreground_before_watch_without_preemption():
    async def scenario():
        broker = AsyncWorkBroker(thread_capacity=1, max_pending_jobs=8)
        release = threading.Event()
        started = []

        def operation(label):
            started.append(label)
            if label == "active-watch":
                release.wait(timeout=2)
            return label

        try:
            active = asyncio.create_task(
                broker.run("extract", "active", operation, "active-watch", request_id="watch-1", origin="watch")
            )
            while started != ["active-watch"]:
                await asyncio.sleep(0)
            waiting_watch = asyncio.create_task(
                broker.run("extract", "watch", operation, "waiting-watch", request_id="watch-2", origin="watch")
            )
            foreground = asyncio.create_task(
                broker.run("extract", "cli", operation, "foreground", request_id="cli-1", origin="foreground")
            )
            await asyncio.sleep(0)
            release.set()
            await asyncio.gather(active, waiting_watch, foreground)
            assert started == ["active-watch", "foreground", "waiting-watch"]
        finally:
            release.set()
            await broker.close()

    asyncio.run(scenario())


def test_broker_prioritizes_pipeline_work_over_background_cleanup():
    async def scenario():
        broker = AsyncWorkBroker(thread_capacity=1, max_pending_jobs=8)
        release = threading.Event()
        started = []

        def operation(label):
            started.append(label)
            if label == "active":
                release.wait(timeout=2)
            return label

        try:
            active = asyncio.create_task(
                broker.run("verify", "active", operation, "active", request_id="request")
            )
            while started != ["active"]:
                await asyncio.sleep(0)
            cleanup_task = asyncio.create_task(
                broker.run(
                    "background_source_cleanup",
                    "cleanup",
                    operation,
                    "cleanup",
                    request_id="request",
                )
            )
            discovery = asyncio.create_task(
                broker.run("discover_detect", "nested", operation, "nested", request_id="request")
            )
            await asyncio.sleep(0)
            release.set()
            await asyncio.gather(active, cleanup_task, discovery)
            assert started == ["active", "nested", "cleanup"]
        finally:
            release.set()
            await broker.close()

    asyncio.run(scenario())
