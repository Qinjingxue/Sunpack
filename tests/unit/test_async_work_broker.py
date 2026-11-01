import asyncio
import random
import threading
import time
from collections import deque
from types import SimpleNamespace

import pytest

from sunpack.pipeline.coordinator.async_work import AsyncWorkBroker, CancellationToken, CURRENT_WORK, _RequestOrder, _StageWorkQueue


@pytest.mark.parametrize("failure_point", ["before_enqueue", "queued", "executing"])
def test_submission_failure_settles_once_and_never_abandons_mutations(monkeypatch, failure_point):
    """Ordinary job exceptions never exercise executor admission failure.

    Removing this loses rejection-after-enqueue and rejection-after-start
    coverage. Event gates cover all ownership outcomes without a stress run.
    """
    async def scenario():
        broker = AsyncWorkBroker(thread_capacity=2, max_pending_jobs=2)
        loop = asyncio.get_running_loop()
        holding = asyncio.Event()
        release_holder, entered, release_work = threading.Event(), threading.Event(), threading.Event()
        mutations = []

        def hold():
            loop.call_soon_threadsafe(holding.set)
            assert release_holder.wait(5)

        def mutate():
            entered.set()
            assert release_work.wait(5)
            mutations.append("committed")
            return "result"

        holder = asyncio.create_task(broker.run("verify", "holder", hold))
        await asyncio.wait_for(holding.wait(), 3)
        submit = broker._executor.submit

        def reject(*args, **kwargs):
            if failure_point == "executing":
                submit(*args, **kwargs)
                assert entered.wait(3)
            raise RuntimeError("injected thread creation failure")

        request = None
        try:
            with monkeypatch.context() as patch:
                if failure_point == "queued":
                    def reject_thread(_thread):
                        raise RuntimeError("injected thread creation failure")
                    patch.setattr(threading.Thread, "start", reject_thread)
                else:
                    patch.setattr(broker._executor, "submit", reject)
                request = asyncio.create_task(broker.run("postprocess", "mutation", mutate))
                if failure_point == "executing":
                    # submit has thrown, but the running mutation must be joined.
                    await asyncio.sleep(0)
                    assert not request.done() and broker.active_jobs == 2
                    release_work.set()
                    assert await asyncio.wait_for(request, 3) == "result"
                else:
                    with pytest.raises(RuntimeError, match="thread creation failure"):
                        await asyncio.wait_for(request, 3)
                    assert broker.active_jobs == 1 and not entered.is_set()
            release_holder.set()
            release_work.set()
            await asyncio.wait_for(holder, 3)
            assert await broker.run("verify", "next", lambda: "next") == "next"
            assert mutations == (["committed"] if failure_point == "executing" else [])
            assert broker.active_jobs == broker.pending_jobs == 0
            assert broker._pending_slots._value == broker.max_pending_jobs
        finally:
            release_holder.set()
            release_work.set()
            await asyncio.gather(holder, *([request] if request else []), return_exceptions=True)
            await asyncio.wait_for(broker.close(), 3)

    asyncio.run(scenario())


def test_request_order_matches_global_fifo_across_promotions_rotation_and_reuse():
    # Existing broker examples cannot catch promotions being appended behind
    # newer foreground requests, or stale memberships after ID reuse/clear.
    # One cheap model run covers these independent lifecycle/order failures.
    order = _RequestOrder()
    reference = deque()
    origins = {}
    randomizer = random.Random(37)

    def append(key, origin):
        order.append(key, origin)
        reference.append(key)
        origins[key] = origin

    def pop():
        expected = next((key for key in reference if origins[key] != "watch"), reference[0])
        assert order.popleft() == expected
        reference.remove(expected)
        return expected, origins.pop(expected)

    for key, origin in (("a", "watch"), ("b", "foreground"), ("c", "watch"), ("d", "foreground")):
        append(key, origin)
    for key in ("c", "a"):
        order.promote(key)
        origins[key] = "foreground"
    assert [pop()[0] for _ in range(4)] == ["a", "b", "c", "d"]
    for index in range(3000):
        key = str(randomizer.randrange(128))
        if index in (1000, 2000):
            order.clear()
            reference.clear()
            origins.clear()
        elif key not in origins:
            append(key, randomizer.choice(("watch", "foreground")))
        elif origins[key] == "watch" and randomizer.random() < 0.5:
            order.promote(key)
            origins[key] = "foreground"
        else:
            selected, origin = pop()
            if randomizer.random() < 0.5:
                append(selected, origin)
        assert bool(order) == bool(reference)
    while reference:
        pop()
    assert not order._foreground and not order._watch and not order._promoted
    assert order._watch.__sizeof__() == _RequestOrder()._watch.__sizeof__()


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


@pytest.mark.parametrize("cancel_token", [False, True])
def test_broker_cancelled_queued_work_releases_slots_across_stage_buckets(cancel_token):
    # Cancel both a queued job and a capacity waiter before releasing an
    # unrelated worker. Eventual-drain tests miss these unbounded cancel waits.
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
            token = CancellationToken()
            cancelled = asyncio.create_task(broker.run("close", "cancelled", operation, "cancelled", request_id="r", cancellation=token))
            verify = asyncio.create_task(broker.run("verify", "verify", operation, "verify", request_id="r"))
            background = asyncio.create_task(broker.run("background", "background", operation, "background", request_id="r"))
            await asyncio.sleep(0)
            admission_token = CancellationToken()
            admission = asyncio.create_task(broker.run(
                "scan", "admission", operation, "admission", request_id="waiting",
                cancellation=admission_token,
            ))
            await asyncio.sleep(0)
            if cancel_token:
                token.cancel()
                admission_token.cancel()
            else:
                cancelled.cancel()
                admission.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(cancelled, timeout=3)
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(admission, timeout=3)
            assert started == ["active"] and not active.done()
            assert broker.pending_jobs == 2
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
        broker = AsyncWorkBroker(thread_capacity=1, max_pending_jobs=16)
        entered = threading.Event()
        release = threading.Event()

        def operation():
            entered.set()
            assert release.wait(timeout=3)

        active = asyncio.create_task(broker.run("scan", "active", operation, request_id="r"))
        queued = []
        try:
            assert await asyncio.to_thread(entered.wait, 2)
            queued = [asyncio.create_task(broker.run(stage, stage, lambda: None, request_id="r", origin="watch"))
                      for stage in ("background", "scan", "plan", "verify", "commit", "close")]
            queued += [asyncio.create_task(broker.run("scan", key, lambda: None, request_id=key, origin=origin))
                       for key, origin in (("f", "foreground"), ("w", "watch"), ("r", "foreground"))]
            await asyncio.sleep(0)
            assert broker.pending_jobs == 9
            await broker.close(graceful=False)
            results = await asyncio.gather(*queued, return_exceptions=True)
            assert all(isinstance(result, asyncio.CancelledError) for result in results)
            assert broker.pending_jobs == 0
            assert not broker._request_order and not broker._queues
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


def test_broker_dispatches_foreground_promotions_fifo_without_preemption_or_demotion():
    # Adds real run()/dispatch coverage for upgrades, repeat admissions and
    # cancelled requests across all ready queues. The model test does not
    # exercise futures, counters or worker execution; this replaces the
    # simpler foreground-before-Watch example rather than duplicating it.
    async def scenario():
        broker = AsyncWorkBroker(thread_capacity=1, max_pending_jobs=16)
        release = threading.Event()
        entered = asyncio.Event()
        loop = asyncio.get_running_loop()
        started = []

        def operation(label):
            started.append(label)
            if label == "active-watch":
                loop.call_soon_threadsafe(entered.set)
                assert release.wait(timeout=3)
            return label

        try:
            active = asyncio.create_task(
                broker.run("extract", "active", operation, "active-watch", request_id="watch-1", origin="watch")
            )
            await asyncio.wait_for(entered.wait(), timeout=2)
            admissions = (
                ("old-1", "old", "watch"), ("old-2", "old", "watch"),
                ("foreground", "cli", "foreground"), ("middle", "middle", "watch"),
                ("foreground-last", "cli-last", "foreground"), ("tail", "tail", "watch"),
                ("middle-upgrade", "middle", "foreground"), ("old-upgrade", "old", "foreground"),
                ("old-watch", "old", "watch"),
            )
            queued = [asyncio.create_task(broker.run(
                "extract", label, operation, label, request_id=key, origin=origin,
            )) for label, key, origin in admissions]
            token = CancellationToken()
            cancelled_watch = asyncio.create_task(broker.run(
                "extract", "cancelled-watch", operation, "cancelled-watch",
                request_id="cancelled-watch", origin="watch", cancellation=token,
            ))
            cancelled_foreground = asyncio.create_task(broker.run(
                "extract", "cancelled-foreground", operation, "cancelled-foreground",
                request_id="cancelled-foreground", origin="foreground",
            ))
            await asyncio.sleep(0)
            assert broker.pending_jobs == len(admissions) + 2
            token.cancel()
            cancelled_foreground.cancel()
            release.set()
            results = await asyncio.wait_for(asyncio.gather(
                active, *queued, cancelled_watch, cancelled_foreground, return_exceptions=True,
            ), timeout=3)
            assert all(isinstance(result, asyncio.CancelledError) for result in results[-2:])
            assert started == ["active-watch", "old-1", "foreground", "middle", "foreground-last",
                               "old-2", "middle-upgrade", "old-upgrade", "old-watch", "tail"]
            assert broker.pending_jobs == broker.active_jobs == 0
            assert broker._pending_slots._value == broker.max_pending_jobs
            assert not broker._queues and not broker._request_order
            assert broker._queues.__sizeof__() == {}.__sizeof__()
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
