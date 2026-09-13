from __future__ import annotations

import asyncio
import contextvars
import functools
import os
import threading
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Awaitable, Callable, Generic, Iterable, TypeVar


T = TypeVar("T")
U = TypeVar("U")


async def map_bounded(
    values: Iterable[T],
    limit: int,
    operation: Callable[[T], Awaitable[U]],
) -> list[U]:
    """Map async work with a hard bound on created in-flight tasks."""

    source = iter(enumerate(values))
    results: dict[int, U] = {}
    active: dict[asyncio.Task[U], int] = {}

    def fill() -> None:
        while len(active) < max(1, int(limit)):
            try:
                index, value = next(source)
            except StopIteration:
                return
            active[asyncio.create_task(operation(value))] = index

    fill()
    try:
        while active:
            done, _pending = await asyncio.wait(active, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                index = active.pop(task)
                results[index] = task.result()
            fill()
    except BaseException:
        for task in active:
            task.cancel()
        await asyncio.gather(*active, return_exceptions=True)
        raise
    return [results[index] for index in sorted(results)]


async def map_unbounded(
    values: Iterable[T],
    operation: Callable[[T], Awaitable[U]],
) -> list[U]:
    """Start every logical item while individual stages retain their own bounds.

    Native extraction owns execution admission. The operation may still await
    bounded Python work such as preflight, but it never waits for a caller-side
    extraction slot.
    """

    tasks: list[asyncio.Task[U]] = []
    try:
        tasks.extend(asyncio.create_task(operation(value)) for value in values)
        return await asyncio.gather(*tasks)
    except BaseException:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise


class CancellationToken:
    """Cooperative cancellation shared by one request and its worker jobs."""

    def __init__(self) -> None:
        self._cancelled = threading.Event()

    @property
    def cancelled(self) -> bool:
        return self._cancelled.is_set()

    def cancel(self) -> None:
        self._cancelled.set()

    def raise_if_cancelled(self) -> None:
        if self.cancelled:
            raise asyncio.CancelledError


@dataclass(frozen=True)
class WorkContext:
    request_id: str
    file_id: str
    stage: str
    attempt_id: int = 0
    origin: str = "foreground"


CURRENT_WORK: contextvars.ContextVar[WorkContext | None] = contextvars.ContextVar(
    "sunpack_current_work",
    default=None,
)

CURRENT_ORIGIN: contextvars.ContextVar[str] = contextvars.ContextVar(
    "sunpack_current_origin",
    default="foreground",
)


@dataclass
class _WorkItem(Generic[T]):
    context: WorkContext
    operation: Callable[[], T]
    future: asyncio.Future[T]
    token: CancellationToken
    sequence: int


@dataclass
class _RequestQueue:
    jobs: deque[_WorkItem[Any]] = field(default_factory=deque)
    origin: str = "foreground"


class AsyncWorkBroker:
    """A bounded, request-fair gateway to all blocking Python work.

    The event-loop thread owns queue selection and result delivery.  The fixed
    executor is deliberately hidden so pipeline code cannot create ad-hoc
    pools or submit unbounded work directly.
    """

    def __init__(
        self,
        *,
        thread_capacity: int = 0,
        max_pending_jobs: int = 4096,
        thread_name_prefix: str = "sunpack-stage-worker",
    ) -> None:
        detected = max(1, os.cpu_count() or 1)
        self.thread_capacity = max(1, int(thread_capacity or min(32, max(4, detected))))
        self._executor_capacity = self.thread_capacity
        self.max_pending_jobs = max(self.thread_capacity, int(max_pending_jobs or 4096))
        self._executor = ThreadPoolExecutor(
            max_workers=self.thread_capacity,
            thread_name_prefix=thread_name_prefix,
        )
        self._queues: dict[str, _RequestQueue] = {}
        self._request_order: deque[str] = deque()
        self._pending_slots = asyncio.Semaphore(self.max_pending_jobs)
        self._active = 0
        self._sequence = 0
        self._closed = False
        self._owner_loop: asyncio.AbstractEventLoop | None = None
        self._owner_thread_id: int | None = None
        self._state_changed_callback: Callable[[], None] | None = None
        self._idle_event = asyncio.Event()
        self._idle_event.set()

    def set_state_changed_callback(self, callback: Callable[[], None] | None) -> None:
        self._state_changed_callback = callback

    def _notify_state_changed(self) -> None:
        if self._active or self.pending_jobs:
            self._idle_event.clear()
        else:
            self._idle_event.set()
        callback = self._state_changed_callback
        if callback is not None:
            callback()

    def configure_thread_capacity(self, value: int) -> None:
        """Apply the native startup capacity before request work is admitted."""
        self.bind()
        self.thread_capacity = max(1, min(self._executor_capacity, int(value or 1)))
        self._dispatch()

    @property
    def active_jobs(self) -> int:
        return self._active

    @property
    def pending_jobs(self) -> int:
        return sum(len(queue.jobs) for queue in self._queues.values())

    def bind(self) -> None:
        loop = asyncio.get_running_loop()
        thread_id = threading.get_ident()
        if self._owner_loop is None:
            self._owner_loop = loop
            self._owner_thread_id = thread_id
            return
        if self._owner_loop is not loop or self._owner_thread_id != thread_id:
            raise RuntimeError("AsyncWorkBroker must be used by one event-loop thread")

    async def run(
        self,
        stage: str,
        file_id: str,
        operation: Callable[..., T],
        *args: Any,
        request_id: str = "",
        attempt_id: int = 0,
        cancellation: CancellationToken | None = None,
        origin: str | None = None,
        **kwargs: Any,
    ) -> T:
        self.bind()
        if self._closed:
            raise RuntimeError("AsyncWorkBroker is closed")
        token = cancellation or CancellationToken()
        token.raise_if_cancelled()
        await self._pending_slots.acquire()
        if self._closed:
            self._pending_slots.release()
            raise RuntimeError("AsyncWorkBroker is closed")
        loop = asyncio.get_running_loop()
        future: asyncio.Future[T] = loop.create_future()
        if request_id:
            request_key = str(request_id)
        else:
            from sunpack.support.resource_lifecycle import current_task_resource_scope

            scope = current_task_resource_scope()
            request_key = str(scope.task_id if scope is not None else file_id or "default")
        self._sequence += 1
        effective_origin = "watch" if str(origin or CURRENT_ORIGIN.get()).lower() == "watch" else "foreground"
        item = _WorkItem(
            context=WorkContext(
                request_id=request_key,
                file_id=str(file_id or request_key),
                stage=str(stage),
                attempt_id=max(0, int(attempt_id)),
                origin=effective_origin,
            ),
            operation=functools.partial(operation, *args, **kwargs),
            future=future,
            token=token,
            sequence=self._sequence,
        )
        queue = self._queues.get(request_key)
        if queue is None:
            queue = self._queues[request_key] = _RequestQueue(origin=effective_origin)
            self._request_order.append(request_key)
        elif effective_origin == "foreground":
            queue.origin = "foreground"
        queue.jobs.append(item)
        self._dispatch()
        try:
            return await future
        except asyncio.CancelledError:
            token.cancel()
            if not future.done():
                future.cancel()
            raise

    async def stream(
        self,
        stage: str,
        file_id: str,
        producer: Callable[[Callable[[T], None]], Any],
        *,
        request_id: str = "",
        cancellation: CancellationToken | None = None,
        max_buffer: int = 64,
    ) -> AsyncIterator[T]:
        """Bridge a blocking callback producer into a bounded async stream."""

        self.bind()
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue[tuple[bool, Any]] = asyncio.Queue(maxsize=max(1, max_buffer))
        token = cancellation or CancellationToken()

        def emit(value: T) -> None:
            token.raise_if_cancelled()
            submitted = asyncio.run_coroutine_threadsafe(queue.put((True, value)), loop)
            submitted.result()

        async def drive() -> None:
            try:
                await self.run(
                    stage,
                    file_id,
                    producer,
                    emit,
                    request_id=request_id,
                    cancellation=token,
                )
            except BaseException as exc:
                await queue.put((False, exc))
            else:
                await queue.put((False, None))

        driver = asyncio.create_task(drive())
        try:
            while True:
                has_value, payload = await queue.get()
                if has_value:
                    yield payload
                    continue
                if payload is not None:
                    raise payload
                break
        finally:
            if not driver.done():
                token.cancel()
                driver.cancel()
            await asyncio.gather(driver, return_exceptions=True)

    async def close(self, *, graceful: bool = True) -> None:
        self.bind()
        if self._closed:
            return
        self._closed = True
        if not graceful:
            for queue in self._queues.values():
                while queue.jobs:
                    item = queue.jobs.popleft()
                    item.token.cancel()
                    if not item.future.done():
                        item.future.cancel()
                    self._pending_slots.release()
            self._queues.clear()
            self._request_order.clear()
        if graceful and (self._active or self.pending_jobs):
            await self._idle_event.wait()
        self._executor.shutdown(wait=graceful, cancel_futures=not graceful)

    def _dispatch(self) -> None:
        while self._active < self.thread_capacity and self._request_order:
            request_id = self._pop_next_request_id()
            queue = self._queues.get(request_id)
            if queue is None or not queue.jobs:
                self._queues.pop(request_id, None)
                continue
            item = self._take_prioritized(queue.jobs)
            if queue.jobs:
                self._request_order.append(request_id)
            else:
                self._queues.pop(request_id, None)
            if item.future.cancelled() or item.token.cancelled:
                self._pending_slots.release()
                continue
            self._active += 1
            worker_future = self._executor.submit(self._execute, item)
            worker_future.add_done_callback(
                lambda completed, current=item: self._owner_loop.call_soon_threadsafe(
                    self._complete,
                    current,
                    completed,
                )
            )
        self._notify_state_changed()

    def _pop_next_request_id(self) -> str:
        """Choose foreground FIFO before watch FIFO without preemption or aging."""

        for index, request_id in enumerate(self._request_order):
            queue = self._queues.get(request_id)
            if queue is not None and queue.origin != "watch":
                self._request_order.rotate(-index)
                selected = self._request_order.popleft()
                self._request_order.rotate(index)
                return selected
        return self._request_order.popleft()

    def _take_prioritized(self, jobs: deque[_WorkItem[Any]]) -> _WorkItem[Any]:
        if len(jobs) <= 1:
            return jobs.popleft()
        current_sequence = self._sequence
        best_index = max(
            range(len(jobs)),
            key=lambda index: (
                _stage_priority(jobs[index].context.stage)
                + max(0, current_sequence - jobs[index].sequence) // 32,
                -jobs[index].sequence,
            ),
        )
        jobs.rotate(-best_index)
        selected = jobs.popleft()
        jobs.rotate(best_index)
        return selected

    @staticmethod
    def _execute(item: _WorkItem[T]) -> T:
        item.token.raise_if_cancelled()
        marker = CURRENT_WORK.set(item.context)
        try:
            from sunpack.support.resource_lifecycle import FileIdentity, task_resource_scope

            scope = task_resource_scope(item.context.request_id)
            if scope is None:
                return item.operation()
            file_id = str(item.context.file_id or "")
            operation_files = ()
            if file_id:
                if os.path.isabs(file_id):
                    operation_files = (file_id,)
                else:
                    try:
                        metadata = os.stat(file_id, follow_symlinks=False)
                    except OSError:
                        pass
                    else:
                        operation_files = (FileIdentity.from_stat(file_id, metadata),)
            with scope.operation(files=operation_files):
                return item.operation()
        finally:
            CURRENT_WORK.reset(marker)

    def _complete(self, item: _WorkItem[T], completed) -> None:
        self._active -= 1
        self._pending_slots.release()
        if not item.future.done():
            try:
                result = completed.result()
            except BaseException as exc:
                item.future.set_exception(exc)
            else:
                if item.token.cancelled:
                    item.future.cancel()
                else:
                    item.future.set_result(result)
        self._dispatch()


def _stage_priority(stage: str) -> int:
    value = str(stage or "").lower()
    if any(token in value for token in ("cancel", "close", "cleanup")):
        return 50
    if any(token in value for token in ("commit", "postprocess", "promotion")):
        return 40
    if any(token in value for token in ("verify", "continuation")):
        return 30
    if any(token in value for token in ("preflight", "admission", "plan")):
        return 20
    return 10
