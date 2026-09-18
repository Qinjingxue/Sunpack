from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
from typing import Callable

from sunpack.cli.persistent_runtime import shared_pipeline_engine
from sunpack.config.loader import load_config
from sunpack.coordinator.watch_group_coordinator import WatchGroupCoordinator
from sunpack.coordinator.archive_registry import ActiveArchiveRegistry
from sunpack.filesystem.watcher.service import WatchService


_LOG = logging.getLogger(__name__)


def _configured_runtime_process_mode(config: dict) -> str:
    runtime = config.get("runtime") if isinstance(config.get("runtime"), dict) else {}
    return str(runtime.get("process_mode") or "normal").strip().lower()


class RuntimeHost:
    """Own the one engine and optional watch lifecycle for one installed executable."""

    def __init__(
        self,
        *,
        log_path: str | None = None,
        state_changed: Callable[[], None] | None = None,
    ) -> None:
        self._lock = asyncio.Lock()
        self._foreground_state_lock = asyncio.Lock()
        self._qos_lock = asyncio.Lock()
        self._watch_service: WatchService | None = None
        self._watch_task: asyncio.Task[int] | None = None
        self._watch_generation = 0
        self._last_watch_error = ""
        self._foreground_requests = 0
        self._configured_process_mode = "normal"
        self._cli_process_mode_override: str | None = None
        self._process_mode = "normal"
        self._state_changed = state_changed
        self.archive_registry = ActiveArchiveRegistry()
        self._event_log = None
        if log_path:
            from sunpack.filesystem.watcher.log import WatchLogStore

            self._event_log = WatchLogStore(log_path)
        self.log_event("host_started", host_pid=os.getpid())

    def _notify_state_changed(self) -> None:
        if self._state_changed is not None:
            self._state_changed()

    def log_event(self, event: str, **payload) -> None:
        if self._event_log is not None:
            payload.setdefault("host_pid", os.getpid())
            payload.setdefault("watch_generation", self._watch_generation)
            self._event_log.write(event, **payload)

    @property
    def watch_enabled(self) -> bool:
        task = self._watch_task
        return self._watch_service is not None and task is not None and not task.done()

    @property
    def watch_generation(self) -> int:
        return self._watch_generation

    async def start_watch(
        self,
        *,
        tray_enabled: bool = True,
        initial_scan: bool = False,
        initial_scan_roots: list[str] | None = None,
    ) -> dict:
        async with self._lock:
            if self.watch_enabled:
                self.log_event("watch_start_reused")
                return {"started": False, "running": True, "generation": self._watch_generation}
            config = load_config()
            await self._set_configured_process_mode(config)
            engine = await shared_pipeline_engine(config)
            tray_factory = None
            if tray_enabled:
                from sunpack.gui.tray import WindowsTrayIcon

                tray_factory = WindowsTrayIcon

            from sunpack.platform.windows.toast_host import ToastManager

            def toast_manager_factory(run_config: dict, state_dir: str, logger) -> ToastManager:
                watch_config = run_config.get("watch") if isinstance(run_config.get("watch"), dict) else {}
                return ToastManager(
                    diagnostic_log_path=str(Path(state_dir) / "toast_host_events.jsonl"),
                    update_interval_ms=int(watch_config.get("toast_update_interval_ms", 50)),
                    logger=logger,
                )

            service = WatchService(
                pipeline_engine=engine,
                tray_factory=tray_factory,
                group_coordinator_factory=WatchGroupCoordinator,
                toast_manager_factory=toast_manager_factory,
                config_applied_callback=self._watch_config_applied,
            )
            task = asyncio.create_task(
                service.run(
                    initial_scan=bool(initial_scan),
                    initial_scan_roots=initial_scan_roots,
                ),
                name="sunpack-runtime-watch",
            )
            self._watch_service = service
            self._watch_task = task
            self._watch_generation += 1
            generation = self._watch_generation
            self.log_event(
                "watch_starting",
                initial_scan=bool(initial_scan),
                initial_scan_roots=list(initial_scan_roots or []),
                tray_enabled=bool(tray_enabled),
            )
            self._notify_state_changed()
        try:
            await service.wait_ready()
        except BaseException as exc:
            self._last_watch_error = str(exc)
            await asyncio.gather(task, return_exceptions=True)
            async with self._lock:
                if self._watch_task is task:
                    self._watch_service = None
                    self._watch_task = None
            self._notify_state_changed()
            raise
        task.add_done_callback(
            lambda completed: asyncio.create_task(
                self._watch_done(completed, generation),
                name="sunpack-runtime-watch-finished",
            )
        )
        self.log_event("watch_started")
        return {"started": True, "running": True, "generation": generation}

    async def run_watch_once(self, *, initial_scan: bool = False) -> int:
        if self.watch_enabled:
            service = self._watch_service
            if service is None or service.scheduler is None:
                return 0
            await service.scheduler.run_once()
            return 0
        config = load_config()
        await self._set_configured_process_mode(config)
        engine = await shared_pipeline_engine(config)
        service = WatchService(
            pipeline_engine=engine,
            group_coordinator_factory=WatchGroupCoordinator,
        )
        return await service.run(once=True, initial_scan=bool(initial_scan))

    async def stop_watch(self) -> dict:
        async with self._lock:
            service = self._watch_service
            task = self._watch_task
            if service is None or task is None:
                self.log_event("watch_stop_ignored")
                return {"stopped": False, "running": False, "generation": self._watch_generation}
            self.log_event("watch_stopping")
            service.request_stop()
        result = await asyncio.gather(task, return_exceptions=True)
        error = result[0] if result and isinstance(result[0], BaseException) else None
        async with self._lock:
            if self._watch_task is task:
                self._watch_service = None
                self._watch_task = None
        self._notify_state_changed()
        if error is not None:
            raise error
        self.log_event("watch_stopped")
        return {"stopped": True, "running": False, "generation": self._watch_generation}

    async def reload_watch(self) -> dict:
        service = self._watch_service
        if service is None or not self.watch_enabled:
            self.log_event("watch_reload_ignored")
            return {"reloaded": False, "running": False, "generation": self._watch_generation}
        reloaded = await service.reload()
        self.log_event("watch_reloaded" if reloaded else "watch_reload_skipped")
        return {"reloaded": reloaded, "running": True, "generation": self._watch_generation}

    async def add_watch_roots(
        self,
        paths: list[str],
        *,
        output_dir: str | None = None,
        initial_scan: bool = True,
    ) -> dict:
        service = self._watch_service
        if service is None or not self.watch_enabled:
            self.log_event("watch_roots_add_ignored", paths=list(paths))
            return {"added": [], "applied": False, "running": False}
        result = await service.add_roots(paths, output_dir=output_dir, initial_scan=initial_scan)
        self.log_event(
            "watch_roots_added",
            added=list(result["added"]),
            initial_scan=bool(initial_scan),
            applied=bool(result["applied"]),
        )
        return {**result, "running": True, "generation": self._watch_generation}

    async def remove_watch_roots(self, paths: list[str]) -> dict:
        service = self._watch_service
        if service is None or not self.watch_enabled:
            self.log_event("watch_roots_remove_ignored", paths=list(paths))
            return {"removed": [], "applied": False, "running": False}
        result = await service.remove_roots(paths)
        self.log_event(
            "watch_roots_removed",
            removed=list(result["removed"]),
            applied=bool(result["applied"]),
        )
        return {**result, "running": True, "generation": self._watch_generation}

    def watch_status(self) -> dict:
        service = self._watch_service
        scheduler = service.scheduler if service is not None else None
        return {
            "running": self.watch_enabled,
            "generation": self._watch_generation,
            "pending": int(getattr(scheduler, "pending_count", 0) or 0),
            "last_error": self._last_watch_error,
        }

    async def close(self, *, exit_reason: str = "shutdown") -> None:
        self.log_event(
            "host_stopping",
            foreground_requests=self._foreground_requests,
            exit_reason=str(exit_reason),
        )
        if self.watch_enabled:
            await self.stop_watch()
        self.log_event("host_stopped", exit_reason=str(exit_reason))

    async def foreground_started(self) -> None:
        async with self._foreground_state_lock:
            first = self._foreground_requests == 0
            if first and self.watch_enabled:
                service = self._watch_service
                scheduler = service.scheduler if service is not None else None
                if scheduler is not None:
                    await scheduler.set_external_activity(True)
            self._foreground_requests += 1
        self.log_event("foreground_started", foreground_requests=self._foreground_requests)

    async def foreground_finished(self) -> None:
        async with self._foreground_state_lock:
            self._foreground_requests = max(0, self._foreground_requests - 1)
            last = self._foreground_requests == 0 and self.watch_enabled
            if last:
                service = self._watch_service
                scheduler = service.scheduler if service is not None else None
                if scheduler is not None:
                    await scheduler.set_external_activity(False)
        self.log_event("foreground_finished", foreground_requests=self._foreground_requests)

    @property
    def process_mode(self) -> str:
        return self._process_mode

    async def set_cli_process_mode_override(self, mode: str) -> None:
        normalized = str(mode or "high").strip().lower()
        if normalized not in {"background", "normal", "high"}:
            raise ValueError(f"unsupported process mode: {mode}")
        self._cli_process_mode_override = normalized
        await self._apply_effective_process_mode()

    async def expire_cli_process_mode_override(self) -> bool:
        if self._cli_process_mode_override is None:
            return False
        previous = self._cli_process_mode_override
        self._cli_process_mode_override = None
        await self._apply_effective_process_mode()
        self.log_event(
            "cli_process_mode_override_expired",
            previous_mode=previous,
            restored_mode=self._configured_process_mode,
        )
        return True

    async def sync_process_mode_to_engine(self, engine) -> None:
        try:
            await engine.set_process_mode(mode=self._process_mode)
        except Exception:
            _LOG.exception("failed to synchronize native worker process mode")

    async def _watch_config_applied(self, config: dict) -> None:
        await self._set_configured_process_mode(config)

    async def _set_configured_process_mode(self, config: dict) -> None:
        self._configured_process_mode = _configured_runtime_process_mode(config)
        await self._apply_effective_process_mode()

    async def _apply_effective_process_mode(self) -> None:
        await self._set_process_mode(
            mode=self._cli_process_mode_override or self._configured_process_mode
        )

    async def _set_process_mode(self, *, mode: str) -> None:
        async with self._qos_lock:
            if self._process_mode == mode:
                return
            from sunpack.cli.persistent_runtime import current_pipeline_engine
            from sunpack.platform.windows.process_qos import set_processing_mode

            engine = current_pipeline_engine()
            worker_result = {}
            if engine is not None:
                try:
                    worker_result = await engine.set_process_mode(mode=mode) or {}
                except Exception:
                    _LOG.exception("failed to change native worker process mode")
            try:
                set_processing_mode(mode=mode)
            except Exception:
                _LOG.exception("failed to change RuntimeHost process mode")
            self._process_mode = mode
            self.log_event(
                "qos_changed",
                mode=mode,
                worker_pid=int(worker_result.get("worker_pid", 0) or 0),
                worker_applied=bool(worker_result.get("applied", False)),
            )

    async def _watch_done(self, task: asyncio.Task[int], generation: int) -> None:
        if task.cancelled():
            self._last_watch_error = "watch task cancelled"
        else:
            try:
                error = task.exception()
            except asyncio.CancelledError:
                error = None
            if error is not None:
                self._last_watch_error = str(error)
                self.log_event("watch_failed", error=str(error))
        async with self._lock:
            if generation == self._watch_generation and self._watch_task is task:
                self._watch_service = None
                self._watch_task = None
        self._notify_state_changed()
