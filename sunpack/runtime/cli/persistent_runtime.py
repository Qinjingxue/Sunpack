from __future__ import annotations

from contextlib import asynccontextmanager
from collections import OrderedDict
import asyncio
import copy
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator, Callable

from sunpack.core.config.loader import config_source_key, load_config, load_raw_config_payload, clear_config_cache
from sunpack.core.config.advanced_defaults import advanced_config_value
from sunpack.pipeline.coordinator.engine import PipelineEngine, new_work_broker
from sunpack.runtime.cli.runtime_state import server_runtime_active, set_server_runtime_active


ConfigSourceKey = tuple[str | None, str | None, str | None]
_LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class _ConfigSnapshot:
    source_key: ConfigSourceKey
    config_path: Path
    raw_payload: dict[str, Any]
    normalized_config: dict[str, Any]


_CONFIG_OBSERVER = None
_CONFIG_RELOAD_TASK: asyncio.Task | None = None
_CONFIG_RELOAD_PENDING = False
_PASSWORD_RELOAD_TASK: asyncio.Task | None = None
_PASSWORD_RELOAD_PENDING = False

_ENGINE: PipelineEngine | None = None
_WORK_BROKER = None
_ENGINE_LOCK = asyncio.Lock()
_CONFIG_SNAPSHOT_LIMIT = 64
_CONFIG_SNAPSHOTS: OrderedDict[ConfigSourceKey, _ConfigSnapshot] = OrderedDict()
_LATEST_IDLE_SECONDS: float | None = None
_STATE_CHANGED_CALLBACK: Callable[[], None] | None = None


def enable_persistent_runtime(*, state_changed: Callable[[], None] | None = None) -> None:
    global _ENGINE_LOCK, _STATE_CHANGED_CALLBACK, _CONFIG_OBSERVER
    if not server_runtime_active():
        _ENGINE_LOCK = asyncio.Lock()
    _STATE_CHANGED_CALLBACK = state_changed
    set_server_runtime_active(True)
    if _CONFIG_OBSERVER is None:
        from sunpack.core.passwords.internal.builtin import password_file_source
        from sunpack.runtime.watch.config_observer import ConfigFileObserver
        from sunpack.core.config.loader import SIMPLE_CONFIG_FILENAME, ADVANCED_CONFIG_FILENAME
        from sunpack.runtime.watch.service import watch_roots_path, WATCH_ROOTS_FILENAME
        source = password_file_source()
        observer = ConfigFileObserver(source.path.parent, [source.path.name], _password_file_changed,
            loop=asyncio.get_running_loop(), additional_files=[(watch_roots_path().resolve().parent,
                [SIMPLE_CONFIG_FILENAME, ADVANCED_CONFIG_FILENAME, WATCH_ROOTS_FILENAME], _configuration_files_changed)])
        observer.start()
        _CONFIG_OBSERVER = observer
        source.reload()


def _configuration_files_changed() -> None:
    global _CONFIG_RELOAD_TASK, _CONFIG_RELOAD_PENDING
    _CONFIG_SNAPSHOTS.clear()
    clear_config_cache()
    _CONFIG_RELOAD_PENDING = True
    if _CONFIG_RELOAD_TASK is None:
        _CONFIG_RELOAD_TASK = asyncio.create_task(_reload_configuration())


async def _reload_configuration() -> None:
    global _CONFIG_RELOAD_TASK, _CONFIG_RELOAD_PENDING
    try:
        while _CONFIG_RELOAD_PENDING:
            _CONFIG_RELOAD_PENDING = False
            from sunpack.runtime.cli.runtime_state import runtime_host
            from sunpack.runtime.watch.service import service_config_from
            try:
                config = await asyncio.to_thread(load_config)
                entries = await asyncio.to_thread(service_config_from, config)
                host = runtime_host()
                if host is not None:
                    await host.reload_watch()
            except Exception:
                _LOG.exception("failed to apply runtime configuration change")
    finally:
        _CONFIG_RELOAD_TASK = None


def _password_file_changed() -> None:
    global _PASSWORD_RELOAD_TASK, _PASSWORD_RELOAD_PENDING
    _PASSWORD_RELOAD_PENDING = True
    if _PASSWORD_RELOAD_TASK is None:
        from sunpack.core.passwords.internal.builtin import password_file_source
        _PASSWORD_RELOAD_TASK = asyncio.create_task(_reload_password_file(password_file_source()))


async def _reload_password_file(source) -> None:
    global _PASSWORD_RELOAD_TASK, _PASSWORD_RELOAD_PENDING
    try:
        while _PASSWORD_RELOAD_PENDING:
            _PASSWORD_RELOAD_PENDING = False
            await asyncio.to_thread(source.reload)
            from sunpack.runtime.cli.runtime_state import runtime_host
            host = runtime_host()
            if host is not None:
                host.password_source_changed()
    finally:
        _PASSWORD_RELOAD_TASK = None


async def close_persistent_runtime() -> None:
    global _ENGINE, _WORK_BROKER, _LATEST_IDLE_SECONDS, _STATE_CHANGED_CALLBACK, _CONFIG_OBSERVER
    set_server_runtime_active(False)
    if _CONFIG_OBSERVER is not None:
        _CONFIG_OBSERVER.stop()
        _CONFIG_OBSERVER = None
    if _CONFIG_RELOAD_TASK is not None:
        await _CONFIG_RELOAD_TASK
    if _PASSWORD_RELOAD_TASK is not None:
        await _PASSWORD_RELOAD_TASK
    from sunpack.core.passwords.internal.builtin import clear_password_file_source
    clear_password_file_source()
    async with _ENGINE_LOCK:
        engine, _ENGINE = _ENGINE, None
        broker, _WORK_BROKER = _WORK_BROKER, None
        _CONFIG_SNAPSHOTS.clear()
        _LATEST_IDLE_SECONDS = None
        try:
            if engine is not None:
                await engine.aclose(graceful=True)
            if broker is not None and (engine is None or broker is not engine.work_broker):
                await broker.close(graceful=True)
        finally:
            if engine is not None:
                setter = getattr(engine, "set_state_changed_callback", None)
                if setter is not None:
                    setter(None)
            _STATE_CHANGED_CALLBACK = None


def persistent_runtime_is_idle() -> bool:
    return (_ENGINE is None or _ENGINE.is_idle()) and (
        _WORK_BROKER is None or (_WORK_BROKER.active_jobs == 0 and _WORK_BROKER.pending_jobs == 0)
    )


def shared_command_work_broker(request_cwd=None):
    global _WORK_BROKER
    if _ENGINE is not None:
        return _ENGINE.work_broker
    if _WORK_BROKER is None:
        _WORK_BROKER = new_work_broker(load_request_config(request_cwd))
        _WORK_BROKER.set_state_changed_callback(_STATE_CHANGED_CALLBACK)
    return _WORK_BROKER


def current_pipeline_engine() -> PipelineEngine | None:
    return _ENGINE


def persistent_server_idle_seconds() -> float:
    default = advanced_config_value(("performance", "persistent_server_idle_seconds"))
    if _LATEST_IDLE_SECONDS is not None:
        return _LATEST_IDLE_SECONDS
    engine = _ENGINE
    config = engine.config if engine is not None else {}
    performance = config.get("performance") if isinstance(config.get("performance"), dict) else {}
    try:
        return max(0.0, float(performance.get("persistent_server_idle_seconds", default)))
    except (TypeError, ValueError):
        return max(0.0, float(default))


def _snapshot_for(request_cwd: str | Path | None) -> _ConfigSnapshot:
    source_key = config_source_key(request_cwd)
    snapshot = _CONFIG_SNAPSHOTS.get(source_key)
    if snapshot is None:
        # Subscribe before reading, including external overrides and per-request
        # configuration directories. Existing requests retain their own snapshot.
        _observe_config_sources((*_CONFIG_SNAPSHOTS, source_key))
        config_path, raw_payload = load_raw_config_payload(request_cwd)
        snapshot = _ConfigSnapshot(
            source_key=source_key,
            config_path=config_path,
            raw_payload=copy.deepcopy(raw_payload),
            normalized_config=copy.deepcopy(load_config(request_cwd)),
        )
        _CONFIG_SNAPSHOTS[source_key] = snapshot
        if len(_CONFIG_SNAPSHOTS) > _CONFIG_SNAPSHOT_LIMIT:
            _CONFIG_SNAPSHOTS.popitem(last=False)
            _observe_config_sources(_CONFIG_SNAPSHOTS)
    else:
        _CONFIG_SNAPSHOTS.move_to_end(source_key)
    return snapshot


def _observe_config_sources(sources) -> None:
    if _CONFIG_OBSERVER is None:
        return
    files = set()
    for simple, advanced, override in sources:
        files.update(path for path in (simple, advanced) if path)
        if override and override.startswith("file:"):
            files.add(override[len("file:"):])
    _CONFIG_OBSERVER.set_additional_files([
        (Path(path).parent, [Path(path).name], _configuration_files_changed)
        for path in sorted(files)
    ])


def load_request_config(request_cwd: str | Path | None = None) -> dict[str, Any]:
    """Load config for one CLI request, retaining persistent snapshots by source path."""
    from sunpack.core.passwords.internal.builtin import password_file_source
    config = load_config(request_cwd) if not server_runtime_active() else copy.deepcopy(_snapshot_for(request_cwd).normalized_config)
    config["password_snapshot"] = password_file_source().snapshot
    return config


def load_request_config_payload(request_cwd: str | Path | None = None) -> tuple[Path, dict[str, Any]]:
    """Return the external payload for a request without reloading an existing snapshot."""
    if not server_runtime_active():
        return load_raw_config_payload(request_cwd)
    snapshot = _snapshot_for(request_cwd)
    return snapshot.config_path, copy.deepcopy(snapshot.raw_payload)


@asynccontextmanager
async def pipeline_engine(
    config: dict,
) -> AsyncIterator[PipelineEngine]:
    if not server_runtime_active():
        raise RuntimeError("extract pipeline is only available inside the persistent server")

    global _ENGINE, _WORK_BROKER, _LATEST_IDLE_SECONDS
    performance = config.get("performance") if isinstance(config.get("performance"), dict) else {}
    try:
        _LATEST_IDLE_SECONDS = max(
            0.0,
            float(performance.get("persistent_server_idle_seconds", persistent_server_idle_seconds())),
        )
    except (TypeError, ValueError):
        pass
    engine = _ENGINE
    if engine is None:
        # Only cold starts take the lifecycle lock; normal requests stay direct.
        async with _ENGINE_LOCK:
            if not server_runtime_active():
                raise RuntimeError("persistent runtime is closing")
            engine = _ENGINE
            if engine is None:
                if _WORK_BROKER is None:
                    created = PipelineEngine(copy.deepcopy(config))
                else:
                    created = PipelineEngine(copy.deepcopy(config), work_broker=_WORK_BROKER)
                setter = getattr(created, "set_state_changed_callback", None)
                if setter is not None:
                    setter(_STATE_CHANGED_CALLBACK)
                try:
                    engine = await created.__aenter__()
                    from sunpack.runtime.cli.runtime_state import runtime_host

                    host = runtime_host()
                    if host is not None:
                        await host.sync_process_mode_to_engine(engine)
                    if not server_runtime_active():
                        raise RuntimeError("persistent runtime is closing")
                except BaseException:
                    if _WORK_BROKER is created.work_broker:
                        _WORK_BROKER = None
                    try:
                        await created.aclose(graceful=False)
                    finally:
                        if setter is not None:
                            setter(None)
                    raise
                _ENGINE = engine
                if _WORK_BROKER is engine.work_broker:
                    _WORK_BROKER = None
            else:
                engine.reconfigure_request(copy.deepcopy(config))
    else:
        engine.reconfigure_request(copy.deepcopy(config))
    yield engine


async def shared_pipeline_engine(
    config: dict,
) -> PipelineEngine:
    """Return the RuntimeHost-owned engine, creating it exactly once."""

    async with pipeline_engine(config) as engine:
        return engine
