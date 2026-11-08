from __future__ import annotations

from contextlib import asynccontextmanager
from collections import Counter, OrderedDict
import asyncio
import copy
import logging
from dataclasses import dataclass
from pathlib import Path
from threading import Lock, RLock
from typing import Any, AsyncIterator, Callable

from sunpack.core.config.loader import (
    ConfigSources,
    clear_config_cache,
    load_config,
    load_config_sources,
    load_raw_config_payload,
    normalize_config_payload,
    resolve_config_sources,
)
from sunpack.core.config.advanced_defaults import advanced_config_value
from sunpack.pipeline.coordinator.engine import PipelineEngine, new_work_broker
from sunpack.runtime.cli.runtime_state import server_runtime_active, set_server_runtime_active


_LOG = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class _ConfigSnapshot:
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
_CONFIG_SNAPSHOTS: OrderedDict[ConfigSources, _ConfigSnapshot] = OrderedDict()
_CONFIG_DIRTY_SOURCES: set[ConfigSources] = set()
_CONFIG_READERS: Counter[ConfigSources] = Counter()
_CONFIG_SNAPSHOT_LOCK = RLock()
_CONFIG_SUBSCRIPTIONS_LOCK = Lock()
_CONFIG_GENERATION = 0
_CONFIG_SNAPSHOT_EPOCH = 0
_LATEST_IDLE_SECONDS: float | None = None
_STATE_CHANGED_CALLBACK: Callable[[], None] | None = None


def enable_persistent_runtime(*, state_changed: Callable[[], None] | None = None) -> None:
    global _ENGINE_LOCK, _STATE_CHANGED_CALLBACK, _CONFIG_OBSERVER
    if not server_runtime_active():
        _ENGINE_LOCK = asyncio.Lock()
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
        try:
            source.reload()
        except BaseException:
            observer.stop()
            raise
        _CONFIG_OBSERVER = observer
    _STATE_CHANGED_CALLBACK = state_changed
    set_server_runtime_active(True)


def _configuration_files_changed() -> None:
    global _CONFIG_RELOAD_TASK, _CONFIG_RELOAD_PENDING, _CONFIG_GENERATION
    clear_config_cache()
    with _CONFIG_SNAPSHOT_LOCK:
        _CONFIG_GENERATION += 1
        _CONFIG_DIRTY_SOURCES.update(_CONFIG_SNAPSHOTS)
    _CONFIG_RELOAD_PENDING = True
    if _CONFIG_RELOAD_TASK is None:
        _CONFIG_RELOAD_TASK = asyncio.create_task(_reload_configuration())


async def _reload_configuration() -> None:
    global _CONFIG_RELOAD_TASK, _CONFIG_RELOAD_PENDING
    try:
        while _CONFIG_RELOAD_PENDING:
            _CONFIG_RELOAD_PENDING = False
            from sunpack.runtime.cli.runtime_state import runtime_host
            try:
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
            from sunpack.runtime.cli.runtime_state import runtime_host
            try:
                await asyncio.to_thread(source.reload)
                host = runtime_host()
                if host is not None:
                    host.password_source_changed()
            except Exception:
                _LOG.exception("failed to apply runtime password change")
    finally:
        _PASSWORD_RELOAD_TASK = None


async def close_persistent_runtime() -> None:
    global _ENGINE, _WORK_BROKER, _LATEST_IDLE_SECONDS, _STATE_CHANGED_CALLBACK, _CONFIG_OBSERVER
    global _CONFIG_SNAPSHOT_EPOCH
    set_server_runtime_active(False)
    with _CONFIG_SUBSCRIPTIONS_LOCK:
        observer, _CONFIG_OBSERVER = _CONFIG_OBSERVER, None
        if observer is not None:
            observer.stop()
    if _CONFIG_RELOAD_TASK is not None:
        await _CONFIG_RELOAD_TASK
    if _PASSWORD_RELOAD_TASK is not None:
        await _PASSWORD_RELOAD_TASK
    from sunpack.core.passwords.internal.builtin import clear_password_file_source
    clear_password_file_source()
    async with _ENGINE_LOCK:
        engine, _ENGINE = _ENGINE, None
        broker, _WORK_BROKER = _WORK_BROKER, None
        with _CONFIG_SNAPSHOT_LOCK:
            _CONFIG_SNAPSHOT_EPOCH += 1
            _CONFIG_SNAPSHOTS.clear()
            _CONFIG_DIRTY_SOURCES.clear()
            _CONFIG_READERS.clear()
        _LATEST_IDLE_SECONDS = None
        try:
            if engine is not None:
                await engine.aclose(graceful=True)
            if broker is not None and (engine is None or broker is not engine.work_broker):
                await broker.close(graceful=True)
        finally:
            if engine is not None:
                engine.set_state_changed_callback(None)
            _STATE_CHANGED_CALLBACK = None


def persistent_runtime_is_idle() -> bool:
    return (_ENGINE is None or _ENGINE.is_idle()) and (
        _WORK_BROKER is None or (_WORK_BROKER.active_jobs == 0 and _WORK_BROKER.pending_jobs == 0)
    )


def shared_command_work_broker():
    global _WORK_BROKER
    if _ENGINE is not None:
        return _ENGINE.work_broker
    if _WORK_BROKER is None:
        _WORK_BROKER = new_work_broker()
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


def _snapshot_for(request_cwd: str | Path | None, *, refresh: bool = False) -> _ConfigSnapshot:
    source_key = resolve_config_sources(request_cwd)
    with _CONFIG_SNAPSHOT_LOCK:
        previous = _CONFIG_SNAPSHOTS.get(source_key)
        if previous is not None and source_key not in _CONFIG_DIRTY_SOURCES and not refresh:
            _CONFIG_SNAPSHOTS.move_to_end(source_key)
            return previous
        # Consume only the event that starts this read. Events arriving during
        # worker-thread IO must remain dirty even if this attempt is invalid.
        _CONFIG_DIRTY_SOURCES.discard(source_key)
        generation, epoch = _CONFIG_GENERATION, _CONFIG_SNAPSHOT_EPOCH
        _CONFIG_READERS[source_key] += 1
    # Never hold the state lock during IO or observer operations: a worker
    # reading a partial file must not block event-loop invalidation.
    replacement = None
    failure = None
    try:
        if previous is None:
            _observe_config_sources()
        config_path, raw_payload = load_config_sources(source_key, request_cwd=request_cwd)
        replacement = _ConfigSnapshot(
            config_path=config_path,
            raw_payload=raw_payload,
            normalized_config=normalize_config_payload(raw_payload),
        )
    except Exception as exc:
        failure = exc
    with _CONFIG_SNAPSHOT_LOCK:
        current = _CONFIG_SNAPSHOTS.get(source_key)
        snapshot = current or replacement or previous
        reconcile = False
        if epoch == _CONFIG_SNAPSHOT_EPOCH:
            _CONFIG_READERS[source_key] -= 1
            if not _CONFIG_READERS[source_key]:
                del _CONFIG_READERS[source_key]
            # A slower reader cannot overwrite a newer published snapshot.
            if replacement is not None and (current is previous or current is None):
                snapshot = replacement
                _CONFIG_SNAPSHOTS[source_key] = replacement
            if source_key in _CONFIG_SNAPSHOTS:
                _CONFIG_SNAPSHOTS.move_to_end(source_key)
                # A cold source was not in the cache when the event arrived.
                if generation != _CONFIG_GENERATION:
                    _CONFIG_DIRTY_SOURCES.add(source_key)
            if len(_CONFIG_SNAPSHOTS) > _CONFIG_SNAPSHOT_LIMIT:
                evicted, _ = _CONFIG_SNAPSHOTS.popitem(last=False)
                _CONFIG_DIRTY_SOURCES.discard(evicted)
                reconcile = True
            reconcile |= source_key not in _CONFIG_SNAPSHOTS and source_key not in _CONFIG_READERS
    if reconcile:
        _observe_config_sources()
    if failure is not None:
        if refresh or snapshot is None:
            raise failure
        _LOG.error("keeping previous request configuration after reload failure", exc_info=failure)
    return snapshot


def _observe_config_sources() -> None:
    with _CONFIG_SUBSCRIPTIONS_LOCK:
        if _CONFIG_OBSERVER is None:
            return
        # Every update reflects current state, including cold sources whose
        # readers have started but have yet to publish their snapshots.
        with _CONFIG_SNAPSHOT_LOCK:
            sources = _CONFIG_SNAPSHOTS.keys() | _CONFIG_READERS.keys()
        files = set()
        for source in sources:
            files.update(path for path in (source.simple, source.advanced, source.override) if isinstance(path, Path))
        _CONFIG_OBSERVER.set_additional_files([
            (path.parent, [path.name], _configuration_files_changed) for path in sorted(files)
        ])


def load_request_config(request_cwd: str | Path | None = None) -> dict[str, Any]:
    """Load config for one CLI request, retaining persistent snapshots by source path."""
    from sunpack.core.passwords.internal.builtin import password_file_source
    config = load_config(request_cwd) if not server_runtime_active() else copy.deepcopy(_snapshot_for(request_cwd).normalized_config)
    config["password_snapshot"] = password_file_source().snapshot
    return config


def load_request_config_payload(
    request_cwd: str | Path | None = None, *, refresh: bool = False, normalized: bool = False,
) -> tuple[Path, dict[str, Any]]:
    """Return request data, or strictly read current files for explicit diagnostics."""
    if not server_runtime_active():
        path, raw = load_raw_config_payload(request_cwd, refresh=refresh)
        return path, normalize_config_payload(raw) if normalized else raw
    snapshot = _snapshot_for(request_cwd, refresh=refresh)
    return snapshot.config_path, copy.deepcopy(snapshot.normalized_config if normalized else snapshot.raw_payload)


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
                created.set_state_changed_callback(_STATE_CHANGED_CALLBACK)
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
                        created.set_state_changed_callback(None)
                    raise
                _ENGINE = engine
                if _WORK_BROKER is engine.work_broker:
                    _WORK_BROKER = None
            else:
                engine.reconfigure_request(config)
    else:
        engine.reconfigure_request(config)
    yield engine


async def shared_pipeline_engine(
    config: dict,
) -> PipelineEngine:
    """Return the RuntimeHost-owned engine, creating it exactly once."""

    async with pipeline_engine(config) as engine:
        return engine
