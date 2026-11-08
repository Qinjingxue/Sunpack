import asyncio
import os
import subprocess
import time
import uuid
from codecs import getincrementaldecoder
from collections import OrderedDict
from contextlib import nullcontext
from typing import Any, Callable

from sunpack_native import NativeWorkerResultAccumulator, NativeWorkerFrameDecoder, encode_worker_frame

from sunpack.core.contracts.tasks import ArchiveTask
from sunpack.pipeline.extraction.internal.sevenzip.worker_diagnostics import (
    ProgressHistory,
    StdioHistory,
    attach_worker_diagnostics,
)
from sunpack.core.support.output_paths import normalized_output_dir, resolve_output_volume_key
from sunpack.core.support.resources import get_sevenzip_bridge_worker_path
from sunpack.core.support.runtime_cwd import runtime_working_directory

_WORKER_STREAM_LIMIT = 4 * 1024 * 1024
_PIPE_BLOCK_BYTES = 64 * 1024


def _is_job_finished(payload: Any) -> bool:
    return (
        isinstance(payload, dict)
        and payload.get("type") == "native_event"
        and payload.get("event") == "job_finished"
    )


class _NativeQueueCapacity:
    """Park jobs the native queue rejected until an admitted job frees a slot.

    The worker reports every job's end with ``job_finished``. A rejected job's
    own ``job_finished`` frees nothing, while an admitted job's frees exactly
    one queue slot, so each such event resubmits one parked job. Retries are
    therefore driven by native completion events on the owner loop.
    """

    def __init__(self) -> None:
        self._waiters: OrderedDict[str, Callable[[], None]] = OrderedDict()
        self._rejected: set[str] = set()

    def park(
        self, job_id: str, resubmit: Callable[[], None], *,
        completion: asyncio.Future, other_jobs_active: bool,
    ) -> None:
        self._rejected.add(job_id)
        if completion.done():
            return
        if other_jobs_active:
            self._waiters[job_id] = resubmit
            return
        # Nothing admitted is left to finish, so no event could wake this job.
        resubmit()

    def release(self, job_id: str) -> None:
        if job_id in self._rejected:
            self._rejected.remove(job_id)
        elif self._waiters:
            _, waiter = self._waiters.popitem(last=False)
            waiter()

    def discard(self, job_id: str) -> None:
        self._waiters.pop(job_id, None)

    def flush(self) -> None:
        """Run every parked resubmission; each observes the dead worker and fails."""
        waiters = list(self._waiters.values())
        self._waiters.clear()
        self._rejected.clear()
        for waiter in waiters:
            waiter()


def _apply_native_environment(environment: dict[str, str], process_config: dict) -> dict[str, str]:
    """Project Python configuration into the native worker's control plane."""

    def set_int(config_key: str, environment_key: str, minimum: int = 1) -> None:
        value = process_config.get(config_key)
        if value is None:
            return
        try:
            value = int(value)
        except (TypeError, ValueError):
            return
        if value >= minimum:
            environment[environment_key] = str(value)

    set_int("space_poll_interval_ms", "SUNPACK_VOLUME_SPACE_POLL_MS", minimum=50)
    set_int(
        "space_status_report_interval_ms",
        "SUNPACK_VOLUME_SPACE_STATUS_REPORT_MS",
        minimum=1000,
    )
    environment.pop("SUNPACK_NATIVE_PROCESS_MODE", None)
    return environment


_MEMORY_EVENTS = frozenset({"memory_blocked", "memory_resumed"})
_RESOURCE_EPISODES = {
    "space_blocked": "space_episode",
    "space_status": "space_episode",
    "space_resumed": "space_episode",
    "memory_blocked": "memory_episode",
    "memory_resumed": "memory_episode",
}


def _is_stale_resource_event(state: dict[str, Any], payload: dict) -> bool:
    """Resource callbacks can arrive out of order after the gate lock is released."""
    event = payload.get("event")
    if not isinstance(event, str) or (key := _RESOURCE_EPISODES.get(event)) is None:
        return False
    episode = payload.get("episode_id")
    if not isinstance(episode, int):
        return False
    latest, resumed = state.get(key, (0, False))
    if episode < latest or (episode == latest and resumed):
        return True
    if episode > latest or event.endswith("_resumed"):
        state[key] = (episode, event.endswith("_resumed"))
    return False


class _AsyncNativeWorkerProcess:
    """Long-lived native worker transported entirely by the owner event loop."""

    def __init__(self, worker_path: str, process_config: dict | None = None):
        self.worker_path = worker_path
        self.process_config = process_config or {}
        self.process: asyncio.subprocess.Process | None = None
        self.worker_epoch = ""
        self._jobs: dict[str, dict[str, Any]] = {}
        self._stderr = StdioHistory()
        self._send_lock = asyncio.Lock()
        self.queue_capacity = _NativeQueueCapacity()
        self._resubmissions: set[asyncio.Task] = set()
        self._stdout_task: asyncio.Task | None = None
        self._stderr_task: asyncio.Task | None = None
        self._closing = False
        self._shutdown_sent = False
        self._close_task: asyncio.Task | None = None
        self.handshake: dict[str, Any] = {}
        self._ready: asyncio.Future | None = None
        self._process_mode_waiter: asyncio.Future | None = None
        self._process_mode_lock = asyncio.Lock()

    async def start(self) -> None:
        if self.is_alive():
            return
        self.worker_epoch = uuid.uuid4().hex
        environment = _apply_native_environment(os.environ.copy(), self.process_config)
        # Per-item data uses byte-bounded chunks. This limit guards the protocol,
        # independent of an archive's total number of files.
        self.process = await asyncio.create_subprocess_exec(
            self.worker_path,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=_WORKER_STREAM_LIMIT,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            cwd=runtime_working_directory(),
            env=environment,
        )
        from sunpack.core.platform.windows.process_job import assign_child_process

        assign_child_process(getattr(self.process, "pid", 0))
        self._ready = asyncio.get_running_loop().create_future()
        self._stdout_task = asyncio.create_task(self._dispatch_stdout(), name="sunpack-native-stdout")
        self._stderr_task = asyncio.create_task(self._pump_stderr(), name="sunpack-native-stderr")
        try:
            # Startup is complete only after the handshake or a confirmed pipe/worker failure.
            # CPU starvation is not evidence that the worker failed.
            await asyncio.shield(self._ready)
        except BaseException:
            await self.abort()
            await self.close()
            raise

    def is_alive(self) -> bool:
        return self.process is not None and self.process.returncode is None

    async def submit(
        self,
        payload: bytes,
        job_id: str,
        *,
        on_event,
        on_error,
    ) -> None:
        if self._closing:
            raise RuntimeError("sevenzip_worker is closing")
        if job_id in self._jobs:
            raise RuntimeError(f"sevenzip_worker job id is already active: {job_id}")
        self._jobs[job_id] = {
            "on_event": on_event,
            "on_error": on_error,
            "finished": asyncio.get_running_loop().create_future(),
            "accumulator": NativeWorkerResultAccumulator(job_id),
        }
        try:
            await self.send(payload)
        except BaseException:
            # A failed drain does not prove that the worker never received the job.
            await self.abort()
            raise

    async def send(self, payload: bytes) -> None:
        if not self.is_alive() or self.process is None or self.process.stdin is None:
            raise RuntimeError("sevenzip_worker is not running")
        async with self._send_lock:
            self.process.stdin.write(payload)
            await self.process.stdin.drain()

    async def cancel(self, job_id: str) -> None:
        if job_id not in self._jobs:
            return
        await self.send(encode_worker_frame({"worker_command": "cancel", "job_id": job_id}))

    async def cancel_and_wait(self, job_id: str) -> None:
        state = self._jobs.get(job_id)
        if state is None:
            return
        try:
            await self.cancel(job_id)
        except Exception:
            await self.abort()
        await asyncio.shield(state["finished"])

    async def set_process_mode(self, *, mode: str) -> dict[str, Any]:
        async with self._process_mode_lock:
            if not self.is_alive():
                raise RuntimeError("sevenzip_worker is not running")
            pid = int(getattr(self.process, "pid", 0) or 0)
            if self.handshake.get("process_mode_applied") and self.handshake.get("process_mode") == mode:
                return {"type": "process_mode_ack", "mode": mode, "applied": True, "worker_pid": pid}
            # A request, failed acknowledgement or interrupted transition is
            # not proof of the process's applied mode.
            self.handshake["process_mode_applied"] = False
            waiter = asyncio.get_running_loop().create_future()
            self._process_mode_waiter = waiter
            try:
                await self.send(encode_worker_frame({"worker_command": "set_process_mode", "mode": mode}))
                # The stdout dispatcher fails this waiter if the worker/pipe exits.
                result = dict(await asyncio.shield(waiter))
                if result.get("mode") != mode:
                    raise RuntimeError("sevenzip_worker acknowledged a different process mode")
                result["worker_pid"] = pid
                return result
            finally:
                self._process_mode_waiter = None
                if not waiter.done():
                    waiter.cancel()

    def take_stderr(self) -> list[str]:
        return self._stderr.take()

    def has_other_jobs(self, job_id: str) -> bool:
        return any(other != job_id for other in self._jobs)

    def spawn_resubmission(self, coroutine) -> None:
        task = asyncio.get_running_loop().create_task(coroutine)
        self._resubmissions.add(task)
        task.add_done_callback(self._resubmissions.discard)

    async def _dispatch_stdout(self) -> None:
        assert self.process is not None and self.process.stdout is not None
        failure = "sevenzip_worker exited before job completion"
        broken = False
        try:
            decoder = NativeWorkerFrameDecoder()
            while block := await self.process.stdout.read(_PIPE_BLOCK_BYTES):
                events = decoder.feed(block)
                del block
                for payload in events:
                    await self._dispatch_event(payload)
                    del payload
                del events
                decoder.check()
            decoder.finish()
        except Exception as exc:
            broken = True
            failure = f"sevenzip_worker transport/protocol failed: {exc}"
        finally:
            if self._ready is not None and not self._ready.done():
                self._ready.set_exception(RuntimeError("sevenzip_worker exited before startup completed"))
            if self._process_mode_waiter is not None and not self._process_mode_waiter.done():
                self._process_mode_waiter.set_exception(RuntimeError("sevenzip_worker exited during QoS transition"))
            if broken or not self._shutdown_sent or self._jobs:
                # Also abort if EOF interrupts a graceful drain.
                await self.abort(failure)

    async def _dispatch_event(self, payload: dict[str, Any]) -> None:
        # Chunk data stays in Rust and never reaches job callbacks.
        job_id = str(payload.get("job_id") or "")
        kind = payload.get("type")
        if kind == "worker_ready":
            self.handshake = dict(payload)
            self.handshake["worker_pid"] = int(getattr(self.process, "pid", 0) or 0)
            if self._ready is not None and not self._ready.done():
                self._ready.set_result(self.handshake)
            return
        if kind == "process_mode_ack":
            self.handshake["process_mode"] = str(payload.get("mode") or "normal")
            self.handshake["process_mode_applied"] = bool(payload.get("applied"))
            waiter = self._process_mode_waiter
            if waiter is not None and not waiter.done():
                waiter.set_result(dict(payload))
            return
        state = self._jobs.get(job_id)
        if state is None:
            if job_id and _is_job_finished(payload):
                self.queue_capacity.release(job_id)
            return
        if _is_stale_resource_event(state, payload):
            return
        terminal = _is_job_finished(payload)
        if state.get("callback_error"):
            if terminal:
                self._fail_job(job_id, state, state["callback_error"])
                self.queue_capacity.release(job_id)
            return
        try:
            if payload.get("type") == "protocol_error":
                raise ValueError(payload["message"])
            if state["accumulator"].accept(payload):
                return
            callback = state["on_event"]
            completed = bool(callback(payload))
        except Exception as exc:
            state["callback_error"] = f"sevenzip_worker job protocol/callback failed: {exc}"
            state.pop("accumulator", None)
            if terminal:
                self._fail_job(job_id, state, state["callback_error"])
            else:
                try:
                    await self.cancel(job_id)
                except Exception:
                    await self.abort()
            completed = False
        if completed and terminal:
            self._finish_job(job_id, state)
        elif terminal and not state.get("callback_error"):
            self._fail_job(job_id, state, "sevenzip_worker finished without a result")
        if terminal:
            self.queue_capacity.release(job_id)

    async def _pump_stderr(self) -> None:
        assert self.process is not None and self.process.stderr is not None
        decoder = getincrementaldecoder("utf-8")("replace")
        while block := await self.process.stderr.read(_PIPE_BLOCK_BYTES):
            self._stderr.append(decoder.decode(block))
            del block
        self._stderr.append(decoder.decode(b"", final=True))

    def _finish_job(self, job_id: str, expected: dict[str, Any]) -> dict[str, Any] | None:
        state = self._jobs.get(job_id)
        if state is not expected:
            return None
        self._jobs.pop(job_id, None)
        state["finished"].set_result(None)
        return state

    def _fail_job(self, job_id: str, state: dict[str, Any], message: str) -> bool:
        claimed = self._finish_job(job_id, state)
        if claimed is None:
            return False
        try:
            claimed["on_error"](message)
        except Exception:
            pass
        return True

    def _fail_all_jobs(self, message: str) -> None:
        for job_id, state in tuple(self._jobs.items()):
            self._fail_job(job_id, state, message)

    async def abort(self, message: str = "sevenzip_worker transport failed") -> None:
        self._closing = True
        if self.process is not None:
            if self.is_alive():
                try:
                    self.process.terminate()
                except ProcessLookupError:
                    pass
            if asyncio.current_task() is self._stdout_task:
                # A protocol error can leave StreamReader paused above its
                # limit. Consume the dead worker's tail so wait() can see EOF.
                try:
                    while await self.process.stdout.read(_PIPE_BLOCK_BYTES):
                        pass
                except Exception:
                    # A failed pipe has already disconnected. Its stored
                    # read exception must not prevent settling active jobs.
                    pass
            await self.process.wait()
        self._fail_all_jobs(message)
        self.queue_capacity.flush()

    async def close(self) -> None:
        if self.process is None:
            return
        if self._close_task is None:
            # Close admission before yielding; all callers share full cleanup.
            self._closing = True
            self._close_task = asyncio.create_task(self._close(), name="sunpack-native-close")
        await asyncio.shield(self._close_task)

    async def _close(self) -> None:
        if self._jobs:
            await asyncio.gather(*(asyncio.shield(state["finished"]) for state in self._jobs.values()))
        if self.is_alive():
            try:
                self._shutdown_sent = True
                await self.send(encode_worker_frame({"worker_command": "shutdown", "job_id": "shutdown"}))
            except Exception:
                await self.abort()
        await self.process.wait()
        stdin = self.process.stdin
        if stdin is not None:
            stdin.close()
            try:
                await stdin.wait_closed()
            except (BrokenPipeError, ConnectionResetError):
                pass
        # Readers own the pipe EOF and must finish, however long native teardown takes.
        await asyncio.gather(
            *(task for task in (self._stdout_task, self._stderr_task) if task is not None),
            return_exceptions=True,
        )
        self._stdout_task = None
        self._stderr_task = None
        self.queue_capacity.flush()
        if self._resubmissions:
            await asyncio.gather(*tuple(self._resubmissions), return_exceptions=True)


class _AsyncNativeWorkerHolder:
    def __init__(self, worker_path: str | None, process_config: dict):
        self.worker_path = worker_path
        self.process_config = process_config
        self._lock = asyncio.Lock()
        self._worker: _AsyncNativeWorkerProcess | None = None
        self._closed = False
        self._desired_process_mode = "normal"

    async def get_or_start(self) -> _AsyncNativeWorkerProcess:
        async with self._lock:
            if self._closed:
                raise RuntimeError("native worker is closed")
            if self._worker is None or not self._worker.is_alive():
                if self._worker is not None:
                    await self._worker.close()
                self._worker = _AsyncNativeWorkerProcess(
                    self.worker_path or get_sevenzip_bridge_worker_path(), self.process_config,
                )
                await self._worker.start()
                await self._worker.set_process_mode(mode=self._desired_process_mode)
            return self._worker

    def set_desired_process_mode(self, mode: str) -> None:
        normalized = str(mode or "normal").strip().lower()
        if normalized not in {"background", "normal", "high"}:
            raise ValueError(f"unsupported process mode: {mode}")
        self._desired_process_mode = normalized

    async def close(self) -> None:
        async with self._lock:
            self._closed = True
            worker = self._worker
            self._worker = None
        if worker is not None:
            await worker.close()


class _WorkerAttempt:
    """Own a request and its diagnostics until the native terminal event."""

    __slots__ = (
        "runner", "worker", "request", "job_id", "task", "completion",
        "frame", "stderr", "progress", "result", "cancelled",
    )

    def __init__(
        self,
        runner: "SevenZipRunner",
        worker: _AsyncNativeWorkerProcess,
        request: dict,
        job_id: str,
        task: ArchiveTask | None,
        completion: asyncio.Future,
    ):
        self.runner = runner
        self.worker = worker
        self.request = request
        self.job_id = job_id
        self.task = task
        self.completion = completion
        self.frame = encode_worker_frame(request)
        self.stderr = StdioHistory()
        self.progress = ProgressHistory()
        self.result: dict[str, Any] | None = None
        self.cancelled = False

    def complete(self, process: subprocess.CompletedProcess) -> None:
        if not self.completion.done():
            self.completion.set_result(process)

    def can_resubmit(self) -> bool:
        if self.cancelled or self.completion.done():
            # The queue already granted a slot. Transfer it if cancellation
            # won while the resubmission was in transit.
            self.worker.queue_capacity.release(self.job_id)
            return False
        if not self.worker.is_alive():
            self.on_error("sevenzip_worker exited before job completion")
            return False
        return True

    def resubmit(self) -> None:
        self.worker.spawn_resubmission(self._retry())

    async def _retry(self) -> None:
        if not self.can_resubmit():
            return
        try:
            await self.worker.submit(self.frame, self.job_id, on_event=self.on_event, on_error=self.on_error)
        except Exception as exc:
            self.on_error(f"native worker retry failed: {exc}")

    def on_event(self, event: dict[str, Any]) -> bool:
        kind = event.get("type")
        if kind == "progress" or (kind == "native_memory" and event.get("event") in _MEMORY_EVENTS):
            event.setdefault("worker_epoch", self.worker.worker_epoch)
            self.progress.append(event)
            self.runner._emit_progress(self.task, event)
        elif kind == "result":
            event.setdefault("worker_epoch", self.worker.worker_epoch)
            self.stderr.extend(self.worker.take_stderr())
            self.result = event
        elif _is_job_finished(event) and self.result is not None:
            result, self.result = self.result, None
            if (
                not self.cancelled
                and result.get("retryable")
                and result.get("native_status") == "backpressure"
            ):
                self.worker.queue_capacity.park(
                    self.job_id,
                    self.resubmit,
                    completion=self.completion,
                    other_jobs_active=self.worker.has_other_jobs(self.job_id),
                )
            else:
                self.complete(self.runner._completed_process(
                    [self.worker.worker_path],
                    0 if result.get("status") == "ok" else 1,
                    "",
                    self.stderr.text(),
                    request_payload=self.request,
                    result_payload=result,
                    progress_events=self.progress,
                ))
            return True
        return False

    def on_error(self, message: str) -> None:
        failure_kind = (
            "process_io" if "job protocol/callback failed" in message
            else "worker_lost"
            if "exited before job completion" in message or not self.worker.is_alive()
            else "process_io"
        )
        self.complete(self.runner._completed_process(
            [self.worker.worker_path],
            -101,
            "",
            message,
            request_payload=self.request,
            process_failure={
                "failure_stage": "worker_communication",
                "failure_kind": failure_kind,
                "worker_epoch": self.worker.worker_epoch,
                "message": message,
            },
            progress_events=self.progress,
        ))


class SevenZipRunner:
    def __init__(
        self,
        process_config: dict | None = None,
        *,
        shared_async_worker_holder: _AsyncNativeWorkerHolder | None = None,
    ):
        self.process_config = dict(process_config or {}) if shared_async_worker_holder is None else None
        self.progress_callback = None
        self.request_id = ""
        self.origin = "foreground"
        self.worker_path = None
        self._async_worker_holder = shared_async_worker_holder
        self._owns_async_worker_holder = shared_async_worker_holder is None

    def fork(self) -> "SevenZipRunner":
        """Create request-local callback state while sharing the native worker."""
        runner = SevenZipRunner(shared_async_worker_holder=self._async_worker_holder_or_create())
        runner.worker_path = self.worker_path
        runner.request_id = self.request_id
        runner.origin = self.origin
        return runner

    async def start_asyncio(self) -> dict[str, Any]:
        worker = await self._async_worker_holder_or_create().get_or_start()
        return dict(worker.handshake)

    async def set_process_mode_asyncio(self, *, mode: str) -> dict[str, Any]:
        holder = self._async_worker_holder_or_create()
        holder.set_desired_process_mode(mode)
        worker = await holder.get_or_start()
        return await worker.set_process_mode(mode=mode)

    async def submit_attempt_asyncio(
        self,
        job: dict,
        *,
        task: ArchiveTask | None = None,
    ) -> subprocess.CompletedProcess:
        prepared_job = dict(job)
        job_id = str(prepared_job.get("job_id") or "")
        if not job_id:
            raise ValueError("native job_id is required")
        result_future = asyncio.get_running_loop().create_future()
        worker: _AsyncNativeWorkerProcess | None = None
        try:
            worker = await self._async_worker_holder_or_create().get_or_start()
            result_future.add_done_callback(lambda _: worker.queue_capacity.discard(job_id))

            attempt = _WorkerAttempt(self, worker, prepared_job, job_id, task, result_future)
            submission = asyncio.create_task(worker.submit(
                attempt.frame, job_id, on_event=attempt.on_event, on_error=attempt.on_error,
            ))
            try:
                await asyncio.shield(submission)
                return await asyncio.shield(result_future)
            except asyncio.CancelledError:
                attempt.cancelled = True
                worker.queue_capacity.discard(job_id)

                async def finish_cancel() -> None:
                    try:
                        await submission
                    except Exception:
                        return
                    await worker.cancel_and_wait(job_id)

                cleanup = asyncio.create_task(finish_cancel())
                while True:
                    try:
                        await asyncio.shield(cleanup)
                        break
                    except asyncio.CancelledError:
                        continue
                result_future.cancel()
                raise
        except Exception as exc:
            return self._completed_process(
                [self.worker_path or "sunpack_sevenzip_worker.exe"],
                -100,
                "",
                f"native worker communication failed: {exc}",
                request_payload=prepared_job,
                process_failure={
                    "failure_stage": "worker_start" if worker is None else "worker_communication",
                    "failure_kind": "process_start" if worker is None else "process_io",
                    "message": str(exc),
                },
            )

    def failed_process_for_exception(
        self,
        exc: Exception,
        request: dict | None = None,
    ) -> subprocess.CompletedProcess:
        return self._completed_process(
            [self.worker_path or "sunpack_sevenzip_worker.exe"],
            -100,
            "",
            f"sevenzip_worker communication failed: {exc}",
            request_payload=request,
            process_failure={
                "failure_stage": "worker_communication",
                "failure_kind": "process_io",
                "message": str(exc),
            },
        )

    def _build_job(
        self,
        *,
        archive_path: str,
        out_dir: str,
        password: str | None,
        password_candidates: list[str] | tuple[str, ...] | None,
        selected_codepage: str | None,
        task: ArchiveTask,
        phase_timer: Any | None = None,
        phase_prefix: str = "sevenzip_build_job",
        password_verified: bool = False,
    ) -> dict:
        job_id = f"{str(getattr(task, 'key', '') or archive_path)}:{time.monotonic_ns()}"
        # The routing key and the request must use the same absolute path.  A failed
        # volume resolution falls back to a synthetic per-job key so the job gets an
        # isolated write facility rather than silently sharing another volume's.
        out_dir = normalized_output_dir(out_dir)
        volume_key = resolve_output_volume_key(out_dir) or f"job:{job_id}"
        job = {
            "job_id": job_id,
            "request_id": str(self.request_id or ""),
            "origin": "watch" if self.origin == "watch" else "foreground",
            "output_dir": out_dir,
            "output_volume_key": volume_key,
            "password": password or "",
            "password_verified": password_verified,
        }
        candidates = tuple(dict.fromkeys(str(item) for item in (password_candidates or ()) if item is not None))
        if candidates:
            job["password_candidates"] = list(candidates)
        if selected_codepage:
            job["codepage"] = selected_codepage

        with _phase(phase_timer, f"{phase_prefix}_archive_input"):
            job["archive_input"] = task.archive_input().to_worker_input()
        return job

    @staticmethod
    def _completed_process(
        args,
        returncode: int | None,
        stdout: str,
        stderr: str,
        *,
        request_payload: dict | None = None,
        process_failure: dict | None = None,
        result_payload: dict | None = None,
        progress_events: ProgressHistory | None = None,
    ) -> subprocess.CompletedProcess:
        return attach_worker_diagnostics(
            subprocess.CompletedProcess(args, returncode, stdout or "", stderr or ""),
            request_payload=request_payload,
            process_failure=process_failure,
            result_payload=result_payload,
            progress_events=progress_events,
        )

    def _async_worker_holder_or_create(self) -> _AsyncNativeWorkerHolder:
        if self._async_worker_holder is None:
            self._async_worker_holder = _AsyncNativeWorkerHolder(self.worker_path, self.process_config)
        return self._async_worker_holder

    async def aclose(self) -> None:
        if self._owns_async_worker_holder and self._async_worker_holder is not None:
            holder = self._async_worker_holder
            self._async_worker_holder = None
            await holder.close()

    def _emit_progress(self, task: ArchiveTask, event: dict[str, Any]) -> None:
        callback = self.progress_callback
        if callback is None:
            return
        try:
            callback(task, event)
        except Exception:
            pass

    def emit_semantic_event(
        self,
        task: ArchiveTask,
        event: str,
        *,
        critical: bool = False,
        **payload: Any,
    ) -> None:
        """Publish a pipeline-owned event through the ordered progress sink.

        Ordinary progress remains best-effort. Critical lifecycle boundaries are
        allowed to propagate observer failures so Watch never performs dependent
        filesystem work after its durable recovery write failed.
        """

        item = {"type": "semantic", "event": str(event), **payload}
        if not critical:
            self._emit_progress(task, item)
            return
        callback = self.progress_callback
        if callback is not None:
            callback(task, item)

def _phase(timer: Any | None, name: str):
    if timer is None:
        return nullcontext()
    return timer(name)
