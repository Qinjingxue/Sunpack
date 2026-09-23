from __future__ import annotations

from collections.abc import Iterable
import asyncio

from sunpack.pipeline.coordinator.engine import PipelineEngine


def execute_pipeline(config: dict, targets: str | Iterable[str], *, direct: bool = False):
    paths = [targets] if isinstance(targets, str) else list(targets)
    async def run():
        async with PipelineEngine(config) as engine:
            return (await engine.run(paths, direct=direct)).summary
    return asyncio.run(run())
