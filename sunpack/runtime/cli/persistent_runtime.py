from __future__ import annotations

from contextlib import asynccontextmanager
import copy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator, Callable

from sunpack.core.config.loader import config_source_key, load_config, load_effective_config_payload
from sunpack.core.config.advanced_defaults import advanced_config_value
from sunpack.pipeline.coordinator.engine import PipelineEngine
from sunpack.runtime.cli.runtime_state import server_runtime_active, set_server_runtime_active


ConfigSourceKey = tuple[str | None, str | None, str | None]


@dataclass(frozen=True)
class _ConfigSnapshot:
    source_key: ConfigSourceKey
    config_path: Path
    raw_payload: dict[str, Any]
    normalized_config: dict[str, Any]


_ENGINE: PipelineEngine | None = None
_CONFIG_SNAPSHOTS: dict[ConfigSourceKey, _ConfigSnapshot] = {}
_LATEST_IDLE_SECONDS: float | None = None
_STATE_CHANGED_CALLBACK: Callable[[], None] | None = None


def enable_persistent_runtime(*, state_changed: Callable[[], None] | None = None) -> None:
    global _STATE_CHANGED_CALLBACK
    _STATE_CHANGED_CALLBACK = state_changed
    set_server_runtime_active(True)


async def close_persistent_runtime() -> None:
    global _ENGINE, _LATEST_IDLE_SECONDS, _STATE_CHANGED_CALLBACK
    engine, _ENGINE = _ENGINE, None
    _CONFIG_SNAPSHOTS.clear()
    _LATEST_IDLE_SECONDS = None
    set_server_runtime_active(False)
    try:
        if engine is not None:
            await engine.aclose(graceful=True)
    finally:
        if engine is not None:
            setter = getattr(engine, "set_state_changed_callback", None)
            if setter is not None:
                setter(None)
        _STATE_CHANGED_CALLBACK = None


def persistent_runtime_is_idle() -> bool:
    return _ENGINE is None or _ENGINE.is_idle()


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
        config_path, raw_payload = load_effective_config_payload(request_cwd)
        snapshot = _ConfigSnapshot(
            source_key=source_key,
            config_path=config_path,
            raw_payload=copy.deepcopy(raw_payload),
            normalized_config=copy.deepcopy(load_config(request_cwd)),
        )
        _CONFIG_SNAPSHOTS[source_key] = snapshot
    return snapshot


def load_request_config(request_cwd: str | Path | None = None) -> dict[str, Any]:
    """Load config for one CLI request, retaining persistent snapshots by source path."""
    if not server_runtime_active():
        return load_config(request_cwd)
    return copy.deepcopy(_snapshot_for(request_cwd).normalized_config)


def load_request_config_payload(request_cwd: str | Path | None = None) -> tuple[Path, dict[str, Any]]:
    """Return the external payload for a request without reloading an existing snapshot."""
    if not server_runtime_active():
        return load_effective_config_payload(request_cwd)
    snapshot = _snapshot_for(request_cwd)
    return snapshot.config_path, copy.deepcopy(snapshot.raw_payload)


@asynccontextmanager
async def pipeline_engine(
    config: dict,
) -> AsyncIterator[PipelineEngine]:
    if not server_runtime_active():
        raise RuntimeError("extract pipeline is only available inside the persistent server")

    global _ENGINE, _LATEST_IDLE_SECONDS
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
        engine_config = copy.deepcopy(config)
        created = PipelineEngine(engine_config)
        setter = getattr(created, "set_state_changed_callback", None)
        if setter is not None:
            setter(_STATE_CHANGED_CALLBACK)
        engine = await created.__aenter__()
        _ENGINE = engine
        from sunpack.runtime.cli.runtime_state import runtime_host

        host = runtime_host()
        if host is not None:
            await host.sync_process_mode_to_engine(engine)
    else:
        engine.reconfigure_request(copy.deepcopy(config))
    yield engine


async def shared_pipeline_engine(
    config: dict,
) -> PipelineEngine:
    """Return the RuntimeHost-owned engine, creating it exactly once."""

    async with pipeline_engine(config) as engine:
        return engine
