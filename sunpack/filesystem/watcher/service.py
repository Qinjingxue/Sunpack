from __future__ import annotations

import ctypes
import asyncio
import hashlib
import os
import shutil
from copy import deepcopy
from contextlib import contextmanager
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path

from sunpack.config.fields.watch import DEFAULT_WATCH_CONFIG
from sunpack.config.loader import ADVANCED_CONFIG_FILENAME, SIMPLE_CONFIG_FILENAME, load_config
from sunpack.contracts.content_recovery import require_complete_content
from sunpack.filesystem.watcher.config_observer import ConfigFileObserver
from sunpack.filesystem.watcher.log import WatchLogStore
from sunpack.filesystem.watcher.scheduler import WatchScheduler
from sunpack.filesystem.watcher.toast import WatchToastCoordinator
from sunpack.passwords.internal.local_files import DIRECTORY_PASSWORD_FILE_NAME
from sunpack.support.path_keys import path_key
from sunpack.support.resources import get_resource_path
from sunpack.support.resource_lifecycle import (
    read_task_text,
    write_task_text,
)


SERVICE_STATE = "state.json"
WATCH_ROOTS_FILENAME = "sunpack_watch_roots.txt"
# One roots entry may be written as ``<input root>`` or as
# ``<input root> | <output root>``.  ``|`` is the separator because it cannot
# appear in a Windows path, it never collides with a drive letter, and a root
# containing spaces stays readable.
#
# A bare input root stays fully backwards compatible: it keeps the process-wide
# ``watch.out_dir``, which is ``.`` by default and therefore resolves to the
# input root itself.  The three forms are:
#
#     C:\Downloads                     -> follow watch.out_dir (default: input root)
#     C:\Downloads | .                 -> explicitly the input root
#     C:\Downloads | D:\Extracted      -> an independent output root
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
    initial_scan_roots: tuple[str, ...]

    @property
    def changed(self) -> bool:
        return self.restart_scheduler or self.reconcile_tray or self.state_dir_changed


def _acquire_watch_broker() -> None:
    from sunpack_native import watch_broker_acquire

    watch_broker_acquire()


def _release_watch_broker() -> None:
    from sunpack_native import watch_broker_release

    watch_broker_release()


def service_config_from(config: dict) -> dict:
    service = config.get("watch") if isinstance(config.get("watch"), dict) else {}
    result = dict(service)
    roots, root_outputs = read_watch_root_entries()
    result["roots"] = roots
    result["root_outputs"] = root_outputs
    return result


def root_outputs_for_roots(service_config: dict, roots: list[str]) -> dict[str, str]:
    """Per-root output roots, keyed by the canonical input root.

    Watch roots that only differ by case or a trailing separator share one key,
    so the last entry that specifies an output wins.
    """
    configured = service_config.get("root_outputs")
    if not isinstance(configured, dict):
        return {}
    result: dict[str, str] = {}
    for root in roots:
        normalized = normalize_root(root)
        output_root = configured.get(path_key(normalized))
        if output_root:
            result[path_key(normalized)] = str(output_root)
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
    service = service_config_from(config)
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
    return ReloadPlan(
        restart_scheduler=restart_scheduler,
        reconcile_tray=(
            _tray_signature(new_config, new_service_config)
            != _tray_signature(old_config, old_service_config)
        ),
        state_dir_changed=state_dir_changed,
        initial_scan_roots=scan_roots,
    )


def watch_roots_path() -> Path:
    return get_resource_path(WATCH_ROOTS_FILENAME)


def resolve_watch_root_output(output_root: str, input_root: str) -> str:
    """Absolute output root for one watch root.

    A configured output root may be relative.  It is interpreted against the
    input root it belongs to, because the watch roots file is read without
    relying on the process working directory (the service is commonly launched
    from somewhere unrelated, such as a system directory).
    """
    candidate = Path(output_root).expanduser()
    if candidate.is_absolute():
        return normalize_root(str(candidate))
    return normalize_root(os.path.join(input_root, str(candidate)))


def _parse_watch_root_line(value: str) -> tuple[str, str] | None:
    input_part, separator, output_part = value.partition(WATCH_ROOT_OUTPUT_SEPARATOR)
    input_part = input_part.strip()
    if not input_part:
        return None
    return input_part, output_part.strip() if separator else ""


def _format_watch_root_line(input_root: str, output_root: str, *, prefer_relative: bool) -> str:
    if not output_root:
        return input_root
    if not prefer_relative or Path(output_root).expanduser().is_absolute():
        return f"{input_root} {WATCH_ROOT_OUTPUT_SEPARATOR} {normalize_root(output_root)}"
    return f"{input_root} {WATCH_ROOT_OUTPUT_SEPARATOR} {output_root}"


def read_watch_root_entries(path: Path | None = None) -> tuple[list[str], dict[str, str]]:
    """Watch roots and the output root configured for each of them.

    The mapping is keyed by the canonical input root and only holds roots that
    configure one.  A root written on its own is deliberately left out: the
    scheduler then falls back to the process-wide ``watch.out_dir``, which is
    what makes a single-path roots file behave exactly as it always has.
    Values stay as written when they are relative so callers resolve them
    against the input root they belong to.
    """
    roots_path = path or watch_roots_path()
    try:
        lines = read_task_text(roots_path, encoding="utf-8").splitlines()
    except FileNotFoundError:
        return [], {}
    except OSError:
        return [], {}
    roots: list[str] = []
    root_outputs: dict[str, str] = {}
    seen: set[str] = set()
    for line in lines:
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        parsed = _parse_watch_root_line(value)
        if parsed is None:
            continue
        input_root, output_root = parsed
        normalized = normalize_root(input_root)
        key = path_key(normalized)
        if key not in seen:
            roots.append(normalized)
            seen.add(key)
        if output_root:
            root_outputs[key] = resolve_watch_root_output(output_root, normalized)
    return roots, root_outputs


def read_watch_roots(path: Path | None = None) -> list[str]:
    return read_watch_root_entries(path)[0]


def write_watch_roots(
    roots: list[str],
    path: Path | None = None,
    *,
    outputs: dict[str, str] | None = None,
) -> Path:
    roots_path = path or watch_roots_path()
    with _watch_roots_mutex(roots_path):
        return _write_watch_roots_unlocked(roots, roots_path, outputs=outputs)


def _write_watch_roots_unlocked(
    roots: list[str],
    roots_path: Path,
    *,
    outputs: dict[str, str] | None = None,
    prefer_relative: bool = False,
) -> Path:
    normalized_roots = []
    seen = set()
    for root in roots:
        normalized = normalize_root(root)
        key = path_key(normalized)
        if key in seen:
            continue
        normalized_roots.append(normalized)
        seen.add(key)
    normalized_outputs = {
        path_key(normalize_root(root)): str(output)
        for root, output in (outputs or {}).items()
        if str(output or "").strip()
    }
    roots_path.parent.mkdir(parents=True, exist_ok=True)
    write_task_text(
        roots_path,
        "".join(
            _format_watch_root_line(
                root,
                normalized_outputs.get(path_key(root), ""),
                prefer_relative=prefer_relative,
            )
            + "\n"
            for root in normalized_roots
        ),
        encoding="utf-8",
    )
    return roots_path


def _normalized_root_outputs(outputs: dict[str, str] | None) -> dict[str, str]:
    return {
        normalize_root(root): str(output)
        for root, output in (outputs or {}).items()
        if str(output or "").strip()
    }


def add_watch_roots(
    paths: list[str],
    outputs: dict[str, str] | None = None,
) -> tuple[Path, list[str]]:
    """Add watch roots, optionally pinning each new root to its own output root.

    ``outputs`` maps an input root to its output root.  The output root is stored
    as given, so a relative value stays relative to its input root; pass one for
    every path in ``paths`` when adding more than one root.
    """
    roots_path = watch_roots_path()
    with _watch_roots_mutex(roots_path):
        roots, root_outputs = read_watch_root_entries(roots_path)
        seen = {path_key(normalize_root(root)) for root in roots}
        added = []
        for path in paths:
            normalized = normalize_root(path)
            key = path_key(normalized)
            if key not in seen:
                roots.append(normalized)
                seen.add(key)
                added.append(normalized)
        requested_outputs = _normalized_root_outputs(outputs)
        if added or requested_outputs:
            root_outputs.update(requested_outputs)
            _write_watch_roots_unlocked(
                roots,
                roots_path,
                outputs=root_outputs,
                prefer_relative=True,
            )
    return roots_path, added


def remove_watch_roots(paths: list[str], *, cleanup: bool = True) -> tuple[Path, list[str]]:
    roots_path = watch_roots_path()
    with _watch_roots_mutex(roots_path):
        expected = {path_key(normalize_root(path)) for path in paths}
        roots, root_outputs = read_watch_root_entries(roots_path)
        kept = []
        kept_outputs = {}
        removed = []
        for root in roots:
            normalized = normalize_root(root)
            key = path_key(normalized)
            if key in expected:
                removed.append(normalized)
                continue
            kept.append(root)
            if key in root_outputs:
                kept_outputs[key] = root_outputs[key]
        if removed:
            _write_watch_roots_unlocked(kept, roots_path, outputs=kept_outputs)
    if cleanup:
        _cleanup_removed_watch_root_artifacts(removed)
    return roots_path, removed


def _cleanup_removed_watch_root_artifacts(roots: list[str]) -> None:
    """Remove service-owned artifacts for roots that were actually removed.

    The scheduler creates the directory password file on first use and keeps
    probe extraction workspaces in a hidden ``.sunpack_watch_probes``
    directory.  Both live under the input root regardless of the output root
    configured for it: the password file remains a watch-owned input even after
    the user populates it, and probes stay beside their input so the promotion
    is a rename.  Removing the watch root therefore removes its own artifacts;
    a separately configured output root is never deleted.
    """

    for root in roots:
        normalized = normalize_root(root)
        password_file = Path(normalized) / DIRECTORY_PASSWORD_FILE_NAME
        try:
            if password_file.is_file() or password_file.is_symlink():
                password_file.unlink()
        except OSError:
            pass

        probe_root = Path(normalized) / ".sunpack_watch_probes"
        try:
            if probe_root.is_dir():
                shutil.rmtree(probe_root)
        except OSError:
            pass


def list_watch_roots() -> tuple[Path, list[str]]:
    roots_path = watch_roots_path()
    return roots_path, read_watch_roots(roots_path)


def list_watch_root_entries() -> tuple[Path, list[str], dict[str, str]]:
    roots_path = watch_roots_path()
    roots, root_outputs = read_watch_root_entries(roots_path)
    return roots_path, roots, root_outputs


class WatchService:
    def __init__(
        self,
        *,
        engine_factory=None,
        pipeline_engine=None,
        tray_factory=None,
        group_coordinator_factory=None,
        toast_manager_factory=None,
    ):
        if engine_factory is None and pipeline_engine is None:
            raise ValueError("WatchService requires an engine_factory.")
        self.engine_factory = engine_factory
        self._owns_pipeline_engine = pipeline_engine is None
        self.group_coordinator_factory = group_coordinator_factory
        self.tray_factory = tray_factory
        self.toast_manager_factory = toast_manager_factory
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
        return existing_roots(list(self.service_config.get("roots") or []))

    @property
    def root_outputs(self) -> dict[str, str]:
        return root_outputs_for_roots(self.service_config, self.roots)

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
        initial_scan: bool = True,
        outputs: dict[str, str] | None = None,
    ) -> dict:
        async with self._reload_lock:
            roots_path, added = add_watch_roots(paths, outputs)
            requested_outputs = _normalized_root_outputs(outputs)
            if not added and not requested_outputs:
                self.log.write("watch_roots_add_skipped", requested=_normalize_scan_roots(paths))
                return {
                    "roots_path": str(roots_path),
                    "added": [],
                    "applied": False,
                }
            new_service_config = service_config_from(self.config)
            applied = await self._apply_configuration(
                self.config,
                new_service_config,
                service_state_dir(self.config),
                initial_scan_roots=added if initial_scan else None,
            )
            return {
                "roots_path": str(roots_path),
                "added": added,
                "applied": applied,
            }

    async def remove_roots(self, paths: list[str]) -> dict:
        async with self._reload_lock:
            # Stop/reconcile the running scheduler before deleting probe
            # workspaces, so an in-flight extraction cannot race cleanup.
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
            self.log.write("scheduler_not_started", reason="no_existing_roots", configured_roots=list(self.service_config.get("roots") or []))
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
                state_path=state_path,
                quiet_seconds=float(
                    watch_config.get(
                        "cold_start_seconds",
                        watch_config.get("quiet_seconds", DEFAULT_WATCH_CONFIG["cold_start_seconds"]),
                    )
                ),
                initial_scan=bool(initial_scan),
                initial_scan_roots=requested_scan_roots or None,
                observer_stop_timeout_seconds=float(watch_config.get("observer_stop_timeout_seconds", 5.0)),
                pipeline_engine=pipeline_engine,
                group_coordinator=(self.group_coordinator_factory(run_config) if self.group_coordinator_factory else None),
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
            raise

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
