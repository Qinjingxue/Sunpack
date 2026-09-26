from __future__ import annotations

import ctypes
import asyncio
import hashlib
import os
from copy import deepcopy
from contextlib import contextmanager
from ctypes import wintypes
from dataclasses import dataclass, replace
from pathlib import Path

from sunpack.core.config.fields.watch import DEFAULT_WATCH_CONFIG
from sunpack.core.config.loader import ADVANCED_CONFIG_FILENAME, SIMPLE_CONFIG_FILENAME, load_config
from sunpack.core.contracts.content_recovery import require_complete_content
from sunpack.runtime.watch.config_observer import ConfigFileObserver
from sunpack.runtime.watch.log import WatchLogStore
from sunpack.runtime.watch.scheduler import WatchScheduler
from sunpack.runtime.watch.roots import WatchRootEntry
from sunpack.runtime.watch.toast import WatchToastCoordinator
from sunpack.core.passwords.internal.local_files import DIRECTORY_PASSWORD_FILE_NAME
from sunpack.core.support.path_keys import path_key
from sunpack.core.support.resources import get_resource_path
from sunpack.core.support.resource_lifecycle import (
    read_task_text,
    write_task_text,
)


SERVICE_STATE = "state.json"
WATCH_ROOTS_FILENAME = "sunpack_watch_roots.txt"
# Optional columns: ``<input root> | <output root> | <deep_detect>``.
WATCH_ROOT_OUTPUT_SEPARATOR = "|"
ROOTS_MUTEX_PREFIX = "Local\\SunPackWatchRoots"
CONTROL_STOP = "stop"
CONTROL_RELOAD = "reload"
CONTROL_SCHEDULER_WAKEUP = "scheduler_wakeup"
CONFIG_RELOAD_DEBOUNCE_SECONDS = 0.5

WAIT_ABANDONED = 0x00000080
WAIT_OBJECT_0 = 0x00000000
WAIT_FAILED = 0xFFFFFFFF
INFINITE = 0xFFFFFFFF


@dataclass(frozen=True)
class ReloadPlan:
    restart_scheduler: bool
    reconcile_tray: bool
    state_dir_changed: bool
    runtime_process_mode_changed: bool
    initial_scan_roots: tuple[str, ...]

    @property
    def changed(self) -> bool:
        return (
            self.restart_scheduler
            or self.reconcile_tray
            or self.state_dir_changed
            or self.runtime_process_mode_changed
        )


def _acquire_watch_broker() -> None:
    from sunpack_native import watch_broker_acquire

    watch_broker_acquire()


def _release_watch_broker() -> None:
    from sunpack_native import watch_broker_release

    watch_broker_release()


def service_config_from(config: dict) -> dict:
    service = config.get("watch") if isinstance(config.get("watch"), dict) else {}
    default_output_root = str(service.get("out_dir") or ".")
    result = dict(service)
    result["root_entries"] = list(_iter_watch_root_entries(default_output_root, None))
    return result


def normalize_root(path: str) -> str:
    return os.path.abspath(os.path.normpath(path))


def resolve_service_path(path: str) -> str:
    """Resolve service metadata paths without depending on the process cwd."""
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = watch_roots_path().resolve().parent / candidate
    return normalize_root(str(candidate))


def existing_roots(roots: list[str]) -> list[str]:
    result = []
    seen = set()
    for root in roots:
        normalized = normalize_root(root)
        key = os.path.normcase(normalized)
        if key in seen or not os.path.isdir(normalized):
            continue
        seen.add(key)
        result.append(normalized)
    return result


def service_state_dir(config: dict) -> str:
    service = config.get("watch") if isinstance(config.get("watch"), dict) else {}
    state_dir = str(service.get("state_dir") or "").strip()
    if state_dir:
        return resolve_service_path(state_dir)
    return os.path.join(normalize_root(str(watch_roots_path().resolve().parent)), ".sunpack_watch")


def _normalize_scan_roots(roots) -> list[str]:
    result = []
    seen = set()
    for root in roots or []:
        value = str(root or "").strip()
        if not value:
            continue
        normalized = normalize_root(value)
        key = os.path.normcase(normalized)
        if key in seen:
            continue
        seen.add(key)
        result.append(normalized)
    return result


def _config_without_tray(config: dict) -> dict:
    result = deepcopy(config)
    watch = result.get("watch")
    if isinstance(watch, dict):
        watch.pop("tray_enabled", None)
        watch.pop("roots", None)
    runtime = result.get("runtime")
    if isinstance(runtime, dict):
        runtime.pop("process_mode", None)
    return result


def _service_config_without_tray(service_config: dict) -> dict:
    result = dict(service_config)
    result.pop("tray_enabled", None)
    return result


def _tray_signature(config: dict, service_config: dict) -> tuple[bool, str]:
    cli_config = config.get("cli") if isinstance(config.get("cli"), dict) else {}
    return (
        bool(service_config.get("tray_enabled", True)),
        str(cli_config.get("language") or "").strip().lower(),
    )


def _build_reload_plan(
    old_config: dict,
    old_service_config: dict,
    old_state_dir: str,
    new_config: dict,
    new_service_config: dict,
    new_state_dir: str,
    initial_scan_roots: list[str] | None,
) -> ReloadPlan:
    scan_roots = tuple(_normalize_scan_roots(initial_scan_roots))
    state_dir_changed = new_state_dir != old_state_dir
    restart_scheduler = bool(scan_roots) or state_dir_changed or (
        _config_without_tray(new_config) != _config_without_tray(old_config)
        or _service_config_without_tray(new_service_config)
        != _service_config_without_tray(old_service_config)
    )
    old_runtime = old_config.get("runtime") if isinstance(old_config.get("runtime"), dict) else {}
    new_runtime = new_config.get("runtime") if isinstance(new_config.get("runtime"), dict) else {}
    return ReloadPlan(
        restart_scheduler=restart_scheduler,
        reconcile_tray=(
            _tray_signature(new_config, new_service_config)
            != _tray_signature(old_config, old_service_config)
        ),
        state_dir_changed=state_dir_changed,
        runtime_process_mode_changed=(
            str(old_runtime.get("process_mode") or "normal")
            != str(new_runtime.get("process_mode") or "normal")
        ),
        initial_scan_roots=scan_roots,
    )


def watch_roots_path() -> Path:
    return get_resource_path(WATCH_ROOTS_FILENAME)


def _resolve_watch_output_root(input_root: str, configured_output_root: str) -> str:
    candidate = Path(str(configured_output_root).strip()).expanduser()
    if not candidate.is_absolute():
        candidate = Path(input_root) / candidate
    return normalize_root(str(candidate))


def _read_watch_root_entries(path: Path | None = None) -> list[WatchRootEntry]:
    """Read optional output/deep columns; the last record for an input root wins."""
    roots_path = path or watch_roots_path()
    try:
        lines = read_task_text(roots_path, encoding="utf-8").splitlines()
    except OSError:
        return []
    entries: list[WatchRootEntry] = []
    positions: dict[str, int] = {}
    for line_number, line in enumerate(lines, 1):
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        parts = [part.strip() for part in value.split(WATCH_ROOT_OUTPUT_SEPARATOR)]
        if len(parts) > 3:
            raise ValueError(f"{roots_path}:{line_number}: expected input | output | deep_detect")
        input_root = parts[0]
        if not input_root:
            continue
        input_root = normalize_root(input_root)
        explicit_output = None
        if len(parts) >= 2 and parts[1]:
            explicit_output = _resolve_watch_output_root(input_root, parts[1])
        deep_value = parts[2].casefold() if len(parts) == 3 else ""
        if deep_value not in {"", "true", "false"}:
            raise ValueError(f"{roots_path}:{line_number}: deep_detect must be true or false")
        entry = WatchRootEntry(input_root, explicit_output, deep_value == "true")
        key = path_key(input_root)
        position = positions.get(key)
        if position is None:
            positions[key] = len(entries)
            entries.append(entry)
        else:
            entries[position] = replace(entry, input_root=entries[position].input_root)
    return entries


def _iter_watch_root_entries(default_output_root: str, path: Path | None):
    """Yield input policies with resolved absolute output paths, in file order.

    A line without an explicit output keeps the configured ``watch.out_dir``.  Relative output
    roots are resolved against their own input root, never against the process working directory.
    """
    for entry in _read_watch_root_entries(path):
        output_root = entry.output_root or _resolve_watch_output_root(entry.input_root, default_output_root)
        yield replace(entry, output_root=output_root)


def read_watch_root_outputs(
    default_output_root: str = ".",
    path: Path | None = None,
) -> dict[str, str]:
    """Every watch root mapped to its one absolute output root.

    Keyed by the canonical input root; roots differing only by case share one entry, so the
    last line that names a root wins.
    """
    return {
        path_key(entry.input_root): entry.output_root
        for entry in _iter_watch_root_entries(default_output_root, path)
    }


def read_watch_roots(default_output_root: str = ".", path: Path | None = None) -> list[str]:
    """The watched input roots, in their own casing and file order."""
    roots: list[str] = []
    seen: set[str] = set()
    for entry in _iter_watch_root_entries(default_output_root, path):
        input_root = entry.input_root
        key = path_key(input_root)
        if key in seen:
            continue
        seen.add(key)
        roots.append(input_root)
    return roots


def _write_watch_root_entries_unlocked(entries: list[WatchRootEntry], roots_path: Path) -> Path:
    normalized_entries: list[WatchRootEntry] = []
    seen = set()
    for entry in entries:
        input_root, output_root = entry.input_root, entry.output_root
        normalized_input = normalize_root(input_root)
        key = path_key(normalized_input)
        if key in seen:
            continue
        normalized_output = (
            None
            if output_root is None or not str(output_root).strip()
            else _resolve_watch_output_root(normalized_input, str(output_root))
        )
        normalized_entries.append(replace(entry, input_root=normalized_input, output_root=normalized_output))
        seen.add(key)
    comments: list[str] = []
    try:
        for line in read_task_text(roots_path, encoding="utf-8").splitlines():
            if line.strip().startswith("#"):
                comments.append(line)
    except OSError:
        pass
    prefix = "".join(f"{line}\n" for line in comments)
    if comments and normalized_entries:
        prefix += "\n"
    roots_path.parent.mkdir(parents=True, exist_ok=True)
    write_task_text(
        roots_path,
        prefix
        + "".join(
            entry.input_root
            + (f" | {entry.output_root or ''} | true" if entry.deep_detect else f" | {entry.output_root}" if entry.output_root else "")
            + "\n"
            for entry in normalized_entries
        ),
        encoding="utf-8",
    )
    return roots_path


def add_watch_roots(
    paths: list[str],
    *,
    output_dir: str | None = None,
    deep_detect: bool | None = None,
) -> tuple[Path, list[str], list[str]]:
    roots_path = watch_roots_path()
    with _watch_roots_mutex(roots_path):
        entries = _read_watch_root_entries(path=roots_path)
        positions = {path_key(entry.input_root): index for index, entry in enumerate(entries)}
        added = []
        updated = []
        for path in paths:
            normalized = normalize_root(path)
            key = path_key(normalized)
            if key in positions:
                index = positions[key]
                entry = entries[index]
                if deep_detect is not None and entry.deep_detect != deep_detect:
                    entries[index] = replace(entry, deep_detect=deep_detect)
                    updated.append(entry.input_root)
                continue
            explicit_output = (
                None
                if output_dir is None
                else _resolve_watch_output_root(normalized, output_dir)
            )
            positions[key] = len(entries)
            entries.append(WatchRootEntry(normalized, explicit_output, bool(deep_detect)))
            added.append(normalized)
        if added or updated:
            _write_watch_root_entries_unlocked(entries, roots_path)
    return roots_path, added, updated


def remove_watch_roots(paths: list[str], *, cleanup: bool = True) -> tuple[Path, list[str]]:
    roots_path = watch_roots_path()
    with _watch_roots_mutex(roots_path):
        expected = {path_key(normalize_root(path)) for path in paths}
        entries = _read_watch_root_entries(path=roots_path)
        kept: list[WatchRootEntry] = []
        removed = []
        for entry in entries:
            input_root = entry.input_root
            if path_key(input_root) in expected:
                removed.append(input_root)
            else:
                kept.append(entry)
        if removed:
            _write_watch_root_entries_unlocked(kept, roots_path)
    if cleanup:
        _cleanup_removed_watch_root_artifacts(removed)
    return roots_path, removed


def _cleanup_removed_watch_root_artifacts(roots: list[str]) -> None:
    """Remove service-owned artifacts for roots that were actually removed."""

    for root in roots:
        normalized = normalize_root(root)
        password_file = Path(normalized) / DIRECTORY_PASSWORD_FILE_NAME
        try:
            if password_file.is_file() or password_file.is_symlink():
                password_file.unlink()
        except OSError:
            pass

def list_watch_roots() -> tuple[Path, list[str]]:
    roots_path = watch_roots_path()
    return roots_path, read_watch_roots(path=roots_path)


class WatchService:
    def __init__(
        self,
        *,
        engine_factory=None,
        pipeline_engine=None,
        tray_factory=None,
        toast_manager_factory=None,
        config_applied_callback=None,
    ):
        if engine_factory is None and pipeline_engine is None:
            raise ValueError("WatchService requires an engine_factory.")
        self.engine_factory = engine_factory
        self._owns_pipeline_engine = pipeline_engine is None
        self.tray_factory = tray_factory
        self.toast_manager_factory = toast_manager_factory
        self.config_applied_callback = config_applied_callback
        self.config = load_config()
        self.service_config = service_config_from(self.config)
        self.state_dir = service_state_dir(self.config)
        self.scheduler: WatchScheduler | None = None
        self.pipeline_engine = pipeline_engine
        self.config_observer: ConfigFileObserver | None = None
        self.tray = None
        self.toast_host = None
        self._toast_host_signature = None
        self.toast_coordinator: WatchToastCoordinator | None = None
        self._stop_requested = False
        self._last_idle_tick_signature = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._control_queue: asyncio.Queue[str | None] | None = None
        self._broker_acquired = False
        self._ready_event = asyncio.Event()
        self._reload_lock = asyncio.Lock()
        self._startup_error: BaseException | None = None
        self.log = WatchLogStore(os.path.join(self.state_dir, "events.jsonl"))

    @property
    def roots(self) -> list[str]:
        return existing_roots([entry.input_root for entry in self.service_config["root_entries"]])

    @property
    def root_outputs(self) -> dict[str, str]:
        """Output root of every existing watch root, keyed by the input root."""
        roots = {path_key(root) for root in self.roots}
        return {path_key(entry.input_root): entry.output_root for entry in self.service_config["root_entries"] if path_key(entry.input_root) in roots}

    async def run(
        self,
        *,
        once: bool = False,
        initial_scan: bool = False,
        initial_scan_roots: list[str] | None = None,
    ) -> int:
        self._loop = asyncio.get_running_loop()
        tray_shutdown_error: BaseException | None = None
        Path(self.state_dir).mkdir(parents=True, exist_ok=True)
        try:
            _acquire_watch_broker()
            self._broker_acquired = True
            self.log.write("watch_broker_acquired")
            self.log.write(
                "service_started",
                state_dir=self.state_dir,
                roots=self.roots,
                once=once,
                initial_scan=bool(initial_scan),
                initial_scan_roots=_normalize_scan_roots(initial_scan_roots),
            )
            if self._control_queue is None:
                self._control_queue = asyncio.Queue()
            await self._start_scheduler(
                initial_scan=bool(initial_scan),
                initial_scan_roots=initial_scan_roots,
            )
            self._reconcile_tray()
            self._ready_event.set()
            if once:
                if self.scheduler is None:
                    return 0
                await self.scheduler.run_once()
                return 0
            self._start_config_observer()
            next_scheduler_run: float | None = 0.0
            active_scheduler = None
            while not self._stop_requested:
                # Use the event-loop clock for scheduling.  Keeping this clock
                # separate from the legacy control-bridge module clock is
                # important for async callers (and makes injected control
                # event timing unable to perturb asyncio's own timers).
                now = self._loop.time()
                if self.scheduler is not None:
                    if self.scheduler is not active_scheduler:
                        active_scheduler = self.scheduler
                        next_scheduler_run = 0.0
                        self._last_idle_tick_signature = None
                    if next_scheduler_run is not None and now >= next_scheduler_run:
                        try:
                            result = await self.scheduler.run_once()
                            if self._should_log_scheduler_tick(result):
                                self.log.write(
                                    "scheduler_tick",
                                    processed=result.processed,
                                    succeeded=result.succeeded,
                                    failed=result.failed,
                                    pending=result.pending,
                                    errors=result.errors,
                                )
                        except Exception as exc:
                            self.log.write("scheduler_error", error=str(exc), error_type=type(exc).__name__)
                        delay = self._scheduler_next_delay()
                        next_scheduler_run = None if delay is None else now + delay
                    sleep_seconds = None if next_scheduler_run is None else max(0.0, next_scheduler_run - now)
                else:
                    sleep_seconds = None
                if sleep_seconds is None:
                    # Every input that can make an idle scheduler runnable has
                    # a control event: filesystem changes, password changes,
                    # config reloads, pipeline completions, and service stop.
                    # Do not wake four times per second merely to re-check an
                    # empty scheduler.
                    control_event = await self._control_queue.get()
                else:
                    try:
                        control_event = await asyncio.wait_for(
                            self._control_queue.get(),
                            timeout=max(0.0, sleep_seconds),
                        )
                    except asyncio.TimeoutError:
                        control_event = None
                if control_event == CONTROL_SCHEDULER_WAKEUP and self.scheduler is not None:
                    # A pipeline completion wakes the service so run_once() can
                    # harvest the finished request.  Recomputing the delay here
                    # can return None while that request is still registered as
                    # inflight, leaving the completed request unharvested.
                    next_scheduler_run = self._loop.time()
                else:
                    self._handle_control_event(control_event)
            return 0
        except Exception as exc:
            self._startup_error = exc
            self._ready_event.set()
            self.log.write("service_error", error=str(exc), error_type=type(exc).__name__)
            raise
        finally:
            self._stop_config_observer()
            try:
                self._stop_tray()
            except Exception as exc:
                tray_shutdown_error = exc
            try:
                await self._stop_scheduler()
            except Exception as exc:
                self.log.write(
                    "scheduler_stop_error",
                    error=str(exc),
                    error_type=type(exc).__name__,
                )
            if self._broker_acquired:
                try:
                    _release_watch_broker()
                    self.log.write("watch_broker_released")
                except Exception as exc:
                    self.log.write(
                        "watch_broker_release_error",
                        error=str(exc),
                        error_type=type(exc).__name__,
                    )
                finally:
                    self._broker_acquired = False
            self._stop_toast_host()
            self.log.write("service_stopped", state_dir=self.state_dir)
            if tray_shutdown_error is not None:
                raise tray_shutdown_error

    async def wait_ready(self) -> None:
        await self._ready_event.wait()
        if self._startup_error is not None:
            raise self._startup_error

    async def reload(self) -> bool:
        return await self._reload_config()

    async def add_roots(
        self,
        paths: list[str],
        *,
        output_dir: str | None = None,
        deep_detect: bool | None = None,
        initial_scan: bool = True,
    ) -> dict:
        async with self._reload_lock:
            roots_path, added, updated = add_watch_roots(paths, output_dir=output_dir, deep_detect=deep_detect)
            if not added and not updated:
                self.log.write("watch_roots_add_skipped", requested=_normalize_scan_roots(paths))
                return {
                    "roots_path": str(roots_path),
                    "added": [],
                    "updated": [],
                    "applied": False,
                }
            new_service_config = service_config_from(self.config)
            applied = await self._apply_configuration(
                self.config,
                new_service_config,
                service_state_dir(self.config),
                initial_scan_roots=added + updated if initial_scan else None,
            )
            return {
                "roots_path": str(roots_path),
                "added": added,
                "updated": updated,
                "applied": applied,
            }

    async def remove_roots(self, paths: list[str]) -> dict:
        async with self._reload_lock:
            # Stop/reconcile the running scheduler before removing its watch
            # state, so an in-flight extraction cannot race reconfiguration.
            roots_path, removed = remove_watch_roots(paths, cleanup=False)
            if not removed:
                self.log.write("watch_roots_remove_skipped", requested=_normalize_scan_roots(paths))
                return {
                    "roots_path": str(roots_path),
                    "removed": [],
                    "applied": False,
                }
            new_service_config = service_config_from(self.config)
            try:
                applied = await self._apply_configuration(
                    self.config,
                    new_service_config,
                    service_state_dir(self.config),
                )
            finally:
                _cleanup_removed_watch_root_artifacts(removed)
            return {
                "roots_path": str(roots_path),
                "removed": removed,
                "applied": applied,
            }

    def request_stop(self) -> None:
        if self._loop is not None:
            self._loop.call_soon_threadsafe(setattr, self, "_stop_requested", True)
        else:
            self._stop_requested = True
        if self._loop is not None and self._control_queue is not None:
            self._loop.call_soon_threadsafe(self._control_queue.put_nowait, CONTROL_STOP)

    def request_reload(self) -> None:
        if self._loop is not None:
            self._loop.call_soon_threadsafe(lambda: asyncio.create_task(self._reload_config()))

    async def _start_scheduler(
        self,
        *,
        initial_scan: bool = False,
        initial_scan_roots: list[str] | None = None,
    ) -> None:
        await self._stop_scheduler()
        requested_scan_roots = _normalize_scan_roots(initial_scan_roots)
        roots = self.roots
        if not roots:
            self._stop_toast_host()
            self.log.write("scheduler_not_started", reason="no_existing_roots", configured_roots=[entry.input_root for entry in self.service_config["root_entries"]])
            return
        configured_out_dir = str(self.service_config.get("out_dir") or self.config.get("output", {}).get("root") or ".")
        out_dir = resolve_service_path(configured_out_dir) if Path(configured_out_dir).expanduser().is_absolute() else configured_out_dir
        state_path = os.path.join(self.state_dir, SERVICE_STATE)
        run_config = deepcopy(self.config)
        require_complete_content(run_config)
        watch_config = dict(run_config.get("watch") if isinstance(run_config.get("watch"), dict) else {})
        watch_config["clipboard_monitor_enabled"] = bool(self.service_config.get("clipboard_monitor_enabled", True))
        run_config["watch"] = watch_config
        self._reconcile_toast_host(run_config)
        toast_coordinator = (
            WatchToastCoordinator(self.toast_host, run_config, self.state_dir)
            if self.toast_host is not None
            else None
        )
        pipeline_engine = self.pipeline_engine if not self._owns_pipeline_engine else None
        scheduler = None
        try:
            if pipeline_engine is None:
                pipeline_engine = self.engine_factory(run_config)
                await pipeline_engine.__aenter__()
            else:
                pipeline_engine.reconfigure_request(run_config)
            scheduler = WatchScheduler(
                run_config,
                roots,
                out_dir=out_dir,
                output_roots=self.root_outputs,
                root_entries=self.service_config["root_entries"],
                state_path=state_path,
                cold_start_seconds=float(
                    watch_config.get(
                        "cold_start_seconds",
                        DEFAULT_WATCH_CONFIG["cold_start_seconds"],
                    )
                ),
                initial_scan=bool(initial_scan),
                initial_scan_roots=requested_scan_roots or None,
                observer_stop_timeout_seconds=float(watch_config.get("observer_stop_timeout_seconds", 5.0)),
                pipeline_engine=pipeline_engine,
                notification_sink=toast_coordinator,
                wake_callback=self._wake_scheduler,
            )
            await scheduler.start()
        except Exception:
            if toast_coordinator is not None:
                toast_coordinator.stop()
            if scheduler is not None:
                try:
                    await scheduler.stop()
                except Exception:
                    pass
            if pipeline_engine is not None and self._owns_pipeline_engine:
                try:
                    await pipeline_engine.aclose(graceful=True)
                except Exception:
                    pass
            raise
        self.pipeline_engine = pipeline_engine
        self.scheduler = scheduler
        self.toast_coordinator = toast_coordinator
        self.log.write(
            "scheduler_attached",
            roots=roots,
            out_dir=out_dir,
            root_outputs=self.root_outputs,
            state_path=state_path,
        )

    async def _stop_scheduler(self) -> None:
        if self.scheduler is not None:
            await self.scheduler.stop()
            drain = getattr(self.scheduler, "drain", None)
            if drain is not None:
                await drain()
        self.scheduler = None
        if self.toast_coordinator is not None:
            self.toast_coordinator.stop()
        self.toast_coordinator = None
        if self.pipeline_engine is not None and self._owns_pipeline_engine:
            await self.pipeline_engine.aclose(graceful=True)
            self.pipeline_engine = None
        self._last_idle_tick_signature = None

    def _reconcile_toast_host(self, config: dict) -> None:
        watch_config = config.get("watch") if isinstance(config.get("watch"), dict) else {}
        enabled = bool(watch_config.get("toast_enabled", True)) and self.toast_manager_factory is not None
        signature = (
            enabled,
            self.state_dir,
            int(watch_config.get("toast_update_interval_ms", 50)),
        )
        if signature == self._toast_host_signature and (not enabled or self.toast_host is not None):
            return
        self._stop_toast_host()
        self._toast_host_signature = signature
        if not enabled:
            return
        try:
            host = self.toast_manager_factory(config, self.state_dir, self.log)
            host.start()
            self.toast_host = host
        except Exception as exc:
            self.toast_host = None
            self._toast_host_signature = None
            self.log.write("toast_host_manager_error", error=str(exc), error_type=type(exc).__name__)

    def _stop_toast_host(self) -> None:
        host, self.toast_host = self.toast_host, None
        self._toast_host_signature = None
        if host is not None:
            try:
                host.stop()
            except Exception as exc:
                self.log.write("toast_host_stop_error", error=str(exc), error_type=type(exc).__name__)

    def _start_tray(self) -> None:
        if not self.service_config.get("tray_enabled", True) or self.tray_factory is None:
            return
        tray = self.tray_factory(self)
        self.tray = tray
        try:
            tray.start()
        except Exception as exc:
            self.log.write("tray_start_error", error=str(exc), error_type=type(exc).__name__)
            try:
                tray.stop()
            except Exception as stop_exc:
                self.log.write(
                    "tray_stop_error",
                    error=str(stop_exc),
                    error_type=type(stop_exc).__name__,
                )
            self.tray = None

    def _stop_tray(self) -> None:
        if self.tray is not None:
            try:
                self.tray.stop()
            except Exception as exc:
                self.log.write("tray_stop_error", error=str(exc), error_type=type(exc).__name__)
                raise
        self.tray = None

    def _reconcile_tray(self) -> None:
        enabled = bool(self.service_config.get("tray_enabled", True)) and self.tray_factory is not None
        if not enabled:
            self._stop_tray()
            return
        if self.tray is None:
            self._start_tray()
            return
        refresh = getattr(self.tray, "refresh", None)
        if refresh is not None:
            refresh()

    def _handle_control_event(self, event: str | None) -> None:
        if event == CONTROL_STOP:
            self._stop_requested = True
            return
        if event == CONTROL_RELOAD:
            asyncio.create_task(self._reload_config())

    def _should_log_scheduler_tick(self, result) -> bool:
        if result.processed or result.failed or result.errors:
            self._last_idle_tick_signature = None
            return True
        pending = int(getattr(result, "pending", 0) or 0)
        if pending <= 0:
            self._last_idle_tick_signature = None
            return False
        signature = ("pending", pending)
        if signature == self._last_idle_tick_signature:
            return False
        self._last_idle_tick_signature = signature
        return True

    def _scheduler_next_delay(self) -> float | None:
        if self.scheduler is None:
            return None
        if hasattr(self.scheduler, "next_delay_seconds"):
            try:
                delay = self.scheduler.next_delay_seconds()
                return None if delay is None else max(0.0, float(delay))
            except Exception:
                pass
        return None

    def _wake_scheduler(self) -> None:
        if self._loop is not None and self._control_queue is not None:
            self._loop.call_soon_threadsafe(
                self._control_queue.put_nowait,
                CONTROL_SCHEDULER_WAKEUP,
            )

    def _start_config_observer(self) -> None:
        if self.config_observer is not None:
            return
        directory = watch_roots_path().resolve().parent
        filenames = (SIMPLE_CONFIG_FILENAME, ADVANCED_CONFIG_FILENAME, WATCH_ROOTS_FILENAME)
        observer = ConfigFileObserver(
            directory,
            filenames,
            self._wake_config_reload,
            debounce_seconds=CONFIG_RELOAD_DEBOUNCE_SECONDS,
            loop=self._loop or asyncio.get_running_loop(),
        )
        observer.start()
        self.config_observer = observer
        self.log.write(
            "config_observer_started",
            directory=str(directory),
            filenames=sorted(name.casefold() for name in filenames),
        )

    def _stop_config_observer(self) -> None:
        if self.config_observer is None:
            return
        try:
            self.config_observer.stop()
        except Exception as exc:
            self.log.write("config_observer_stop_error", error=str(exc), error_type=type(exc).__name__)
        self.config_observer = None

    def _wake_config_reload(self) -> None:
        if self._loop is not None and self._control_queue is not None:
            self._loop.call_soon_threadsafe(self._control_queue.put_nowait, CONTROL_RELOAD)

    async def _reload_config(self) -> bool:
        async with self._reload_lock:
            return await self._reload_config_unlocked()

    async def _reload_config_unlocked(self) -> bool:
        try:
            new_config = load_config()
            new_service_config = service_config_from(new_config)
            new_state_dir = service_state_dir(new_config)
            Path(new_state_dir).mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            self.log.write("config_reload_failed", error=str(exc), error_type=type(exc).__name__, phase="load")
            return False

        try:
            return await self._apply_configuration(
                new_config,
                new_service_config,
                new_state_dir,
            )
        except Exception:
            return False

    async def _apply_configuration(
        self,
        new_config: dict,
        new_service_config: dict,
        new_state_dir: str,
        *,
        initial_scan_roots: list[str] | None = None,
    ) -> bool:
        plan = _build_reload_plan(
            self.config,
            self.service_config,
            self.state_dir,
            new_config,
            new_service_config,
            new_state_dir,
            initial_scan_roots,
        )
        if not plan.changed:
            self.log.write("service_reload_skipped", reason="no_semantic_change")
            return False

        previous = (self.config, self.service_config, self.state_dir, self.log)
        self.config = new_config
        self.service_config = new_service_config
        self.state_dir = new_state_dir
        if plan.state_dir_changed:
            self.log = WatchLogStore(os.path.join(new_state_dir, "events.jsonl"))
        try:
            if plan.restart_scheduler:
                await self._start_scheduler(
                    initial_scan_roots=list(plan.initial_scan_roots) or None,
                )
            if plan.reconcile_tray:
                self._reconcile_tray()
            if plan.runtime_process_mode_changed and self.config_applied_callback is not None:
                await self.config_applied_callback(self.config)
        except Exception as exc:
            failed_log = self.log
            self.config, self.service_config, self.state_dir, self.log = previous
            failed_log.write("config_reload_failed", error=str(exc), error_type=type(exc).__name__, phase="apply")
            try:
                if plan.restart_scheduler:
                    await self._start_scheduler()
                if plan.reconcile_tray:
                    self._reconcile_tray()
            except Exception as rollback_exc:
                self.log.write(
                    "config_reload_rollback_failed",
                    error=str(rollback_exc),
                    error_type=type(rollback_exc).__name__,
                )
            raise

        self.log.write(
            "service_reloaded",
            state_dir=self.state_dir,
            roots=self.roots,
            scheduler_restarted=plan.restart_scheduler,
            tray_reconciled=plan.reconcile_tray,
            runtime_process_mode_changed=plan.runtime_process_mode_changed,
            initial_scan_roots=list(plan.initial_scan_roots),
        )
        return True


def watch_roots_mutex_name(path: Path | None = None) -> str:
    roots_path = path or watch_roots_path()
    identity = os.path.abspath(str(roots_path)).lower()
    digest = hashlib.sha256(identity.encode("utf-8", errors="ignore")).hexdigest()[:24]
    return f"{ROOTS_MUTEX_PREFIX}-{digest}"


@contextmanager
def _watch_roots_mutex(path: Path | None = None):
    kernel32 = _kernel32()
    handle = kernel32.CreateMutexW(None, False, watch_roots_mutex_name(path))
    if not handle:
        raise OSError(ctypes.GetLastError(), "CreateMutexW failed for watch roots")
    try:
        result = kernel32.WaitForSingleObject(handle, INFINITE)
        if result not in {WAIT_OBJECT_0, WAIT_ABANDONED}:
            if result == WAIT_FAILED:
                raise OSError(ctypes.GetLastError(), "WaitForSingleObject failed for watch roots")
            raise OSError(result, "Unexpected WaitForSingleObject result for watch roots")
        try:
            yield
        finally:
            kernel32.ReleaseMutex(handle)
    finally:
        kernel32.CloseHandle(handle)


def _kernel32():
    kernel32 = ctypes.windll.kernel32
    kernel32.CreateMutexW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR]
    kernel32.CreateMutexW.restype = wintypes.HANDLE
    kernel32.ReleaseMutex.argtypes = [wintypes.HANDLE]
    kernel32.ReleaseMutex.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    return kernel32
