from __future__ import annotations

import asyncio
import contextvars
import functools
import heapq
import os
import threading
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable, Generic, TypeVar

from sunpack.core.support.work_context import CURRENT_ORIGIN, CURRENT_WORK, WorkContext


T = TypeVar("T")

CURRENT_CANCELLATION: contextvars.ContextVar[CancellationToken | None] = contextvars.ContextVar(
    "sunpack_cancellation", default=None,
)

class CancellationToken:
    """Cooperative cancellation shared by one request and its worker jobs."""

    def __init__(self) -> None:
        self._cancelled = threading.Event()
        self._lock = threading.Lock()
        self._callbacks: set[Callable[[], None]] = set()

    @property
    def cancelled(self) -> bool:
        return self._cancelled.is_set()

    def cancel(self) -> None:
        with self._lock:
            if self.cancelled:
                return
            self._cancelled.set()
            callbacks = tuple(self._callbacks)
            self._callbacks.clear()
        for callback in callbacks:
            callback()

    def subscribe(self, callback: Callable[[], None]) -> Callable[[], None]:
        with self._lock:
            cancelled = self.cancelled
            if not cancelled:
                self._callbacks.add(callback)
        if cancelled:
            callback()
        def unsubscribe():
            with self._lock:
                self._callbacks.discard(callback)
        return unsubscribe

    async def wait(self, operation):
        """Cancel this await; native operations retain their own drain handler.

        Shared operations must be shielded by their caller.
        """
        loop = asyncio.get_running_loop()
        task = asyncio.ensure_future(operation)
        remove = self.subscribe(lambda: loop.call_soon_threadsafe(task.cancel))
        try:
            result = await task
            self.raise_if_cancelled()
            return result
        finally:
            remove()

    def raise_if_cancelled(self) -> None:
        if self.cancelled:
            raise asyncio.CancelledError


@dataclass
class _WorkItem(Generic[T]):
    context: WorkContext
    operation: Callable[[], T]
    future: asyncio.Future[T]
    token: CancellationToken
    sequence: int
    execution_context: contextvars.Context = field(default_factory=contextvars.copy_context)


class _StageWorkQueue:
    """FIFO buckets for the six stage priorities, owned by the event loop."""

    __slots__ = ("_stages", "_size", "_first")

    def __init__(self) -> None:
        self._stages: dict[int, OrderedDict[int, _WorkItem[Any]]] = {}
        self._size = 0
        self._first: _WorkItem[Any] | None = None

    def __len__(self) -> int:
        return self._size

    def append(self, item: _WorkItem[Any]) -> None:
        # Most idle admissions dispatch immediately. Classify only once a
        # second job actually requires a priority comparison.
        if not self._size:
            self._first = item
            self._size = 1
            return
        if self._first is not None:
            first = self._first
            self._stages[_stage_priority(first.context.stage)] = OrderedDict(((first.sequence, first),))
            self._first = None
        priority = _stage_priority(item.context.stage)
        jobs = self._stages.get(priority)
        if jobs is None:
            jobs = self._stages[priority] = OrderedDict()
        jobs[item.sequence] = item
        self._size += 1

    def remove(self, item: _WorkItem[Any]) -> bool:
        if self._first is item:
            self._first = None
            self._size = 0
            return True
        priority = _stage_priority(item.context.stage)
        jobs = self._stages.get(priority)
        if jobs is None or jobs.pop(item.sequence, None) is None:
            return False
        self._size -= 1
        if not jobs:
            del self._stages[priority]
        return True

    def _pop(self, priority: int) -> _WorkItem[Any]:
        jobs = self._stages[priority]
        _, item = jobs.popitem(last=False)
        self._size -= 1
        if not jobs:
            del self._stages[priority]
        return item

    def popleft(self) -> _WorkItem[Any]:
        if self._first is not None:
            item = self._first
            self._first = None
            self._size = 0
            return item
        priority = min(self._stages, key=lambda value: next(iter(self._stages[value])))
        return self._pop(priority)

    def take_prioritized(self, current_sequence: int) -> _WorkItem[Any]:
        if self._first is not None:
            item = self._first
            self._first = None
            self._size = 0
            return item
        if len(self._stages) == 1:
            return self._pop(next(iter(self._stages)))
        # Within one priority, the oldest job always has at least as much
        # sequence aging and wins ties. Only the bucket heads can win.
        priority = max(
            self._stages,
            key=lambda value: (
                value + max(0, current_sequence - next(iter(self._stages[value]))) // 32,
                -next(iter(self._stages[value])),
            ),
        )
        return self._pop(priority)


@dataclass
class _RequestQueue:
    jobs: _StageWorkQueue = field(default_factory=_StageWorkQueue)
    origin: str = "foreground"


class _RequestOrder:
    """Ready requests only; normal admission/selection is constant time.

    Promotions retain their original global FIFO position. A heap merges
    just these out-of-order admissions with the regular foreground FIFO;
    no stale entries or references to completed requests are retained.
    """

    __slots__ = ("_foreground", "_watch", "_promoted", "_sequence")

    def __init__(self) -> None:
        self._foreground: OrderedDict[str, int] = OrderedDict()
        self._watch: OrderedDict[str, int] = OrderedDict()
        self._promoted: list[tuple[int, str]] = []
        self._sequence = 0

    def __bool__(self) -> bool:
        return bool(self._foreground or self._watch or self._promoted)

    def append(self, request_id: str, origin: str) -> None:
        self._sequence += 1
        if origin == "watch":
            self._watch[request_id] = self._sequence
        else:
            self._foreground[request_id] = self._sequence

    def promote(self, request_id: str) -> None:
        position = self._watch.pop(request_id)
        if not self._watch:
            self._watch.clear()
        heapq.heappush(self._promoted, (position, request_id))

    def popleft(self) -> str:
        if self._promoted and (
            not self._foreground or self._promoted[0][0] < next(iter(self._foreground.values()))
        ):
            return heapq.heappop(self._promoted)[1]
        if self._foreground:
            request_id, _ = self._foreground.popitem(last=False)
            if not self._foreground:
                self._foreground.clear()
            return request_id
        request_id, _ = self._watch.popitem(last=False)
        if not self._watch:
            self._watch.clear()
        return request_id

    def discard(self, request_id: str) -> None:
        if self._foreground.pop(request_id, None) is not None:
            if not self._foreground:
                self._foreground.clear()
        elif self._watch.pop(request_id, None) is not None:
            if not self._watch:
                self._watch.clear()
        elif self._promoted:
            # Only cross-origin promotions use the heap. Remove their entry
            # eagerly so cancellation cannot retain stale request IDs.
            self._promoted[:] = [entry for entry in self._promoted if entry[1] != request_id]
            heapq.heapify(self._promoted)

    def clear(self) -> None:
        self._foreground.clear()
        self._watch.clear()
        self._promoted.clear()
        self._sequence = 0


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
        self._request_order = _RequestOrder()
        self._pending_jobs = 0
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
        return self._pending_jobs

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
        if self._pending_slots.locked():
            admission = asyncio.create_task(self._pending_slots.acquire())
            try:
                await token.wait(admission)
            except BaseException:
                # Cancellation can arrive after acquire succeeded but before
                # its result was delivered to this caller.
                if admission.done() and not admission.cancelled() and admission.exception() is None:
                    self._pending_slots.release()
                raise
        else:
            await self._pending_slots.acquire()
        if self._closed:
            self._pending_slots.release()
            raise RuntimeError("AsyncWorkBroker is closed")
        loop = asyncio.get_running_loop()
        future: asyncio.Future[T] = loop.create_future()
        if request_id:
            request_key = str(request_id)
        else:
            from sunpack.core.support.resource_lifecycle import current_task_resource_scope

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
            self._request_order.append(request_key, effective_origin)
        elif effective_origin == "foreground" and queue.origin == "watch":
            self._request_order.promote(request_key)
            queue.origin = "foreground"
        queue.jobs.append(item)
        self._pending_jobs += 1
        unsubscribe = token.subscribe(lambda: loop.call_soon_threadsafe(self._cancel_pending, item))
        try:
            self._dispatch()
            return await asyncio.shield(future)
        except asyncio.CancelledError:
            token.cancel()
            self._cancel_pending(item)
            # A cancelled asyncio waiter does not stop executor work. Join it
            # before allowing resource release or output rollback.
            while not future.done():
                try:
                    await asyncio.shield(future)
                except asyncio.CancelledError:
                    continue
                except BaseException:
                    break
            if not future.cancelled():
                future.exception()
            raise
        finally:
            unsubscribe()

    def _cancel_pending(self, item: _WorkItem[Any]) -> None:
        queue = self._queues.get(item.context.request_id)
        if queue is None or not queue.jobs.remove(item):
            return  # Already executing: its worker still owns the resources.
        self._pending_jobs -= 1
        self._pending_slots.release()
        item.future.cancel()
        if not queue.jobs:
            self._queues.pop(item.context.request_id)
            self._request_order.discard(item.context.request_id)
            if not self._queues:
                self._queues.clear()
        self._notify_state_changed()

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
            self._pending_jobs = 0
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
            self._pending_jobs -= 1
            if queue.jobs:
                self._request_order.append(request_id, queue.origin)
            else:
                self._queues.pop(request_id, None)
                if not self._pending_jobs:
                    self._queues.clear()
            if item.future.cancelled() or item.token.cancelled:
                item.future.cancel()
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

        return self._request_order.popleft()

    def _take_prioritized(self, jobs: _StageWorkQueue) -> _WorkItem[Any]:
        return jobs.take_prioritized(self._sequence)

    @staticmethod
    def _execute(item: _WorkItem[T]) -> T:
        return item.execution_context.run(AsyncWorkBroker._execute_in_context, item)

    @staticmethod
    def _execute_in_context(item: _WorkItem[T]) -> T:
        item.token.raise_if_cancelled()
        marker = CURRENT_WORK.set(item.context)
        try:
            from sunpack.core.support.resource_lifecycle import FileIdentity, task_resource_scope

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
                # Completed mutations must project their final paths/results.
                # Cancellation stops the next admission, not that projection.
                item.future.set_result(result)
        self._dispatch()


def _stage_priority(stage: str) -> int:
    value = str(stage or "").lower()
    if "background" in value:
        return 0
    if any(token in value for token in ("cancel", "close", "cleanup")):
        return 50
    if any(token in value for token in ("commit", "postprocess", "promotion")):
        return 40
    if any(token in value for token in ("verify", "continuation")):
        return 30
    if any(token in value for token in ("preflight", "admission", "plan")):
        return 20
    return 10
