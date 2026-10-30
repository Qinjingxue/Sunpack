import asyncio
import subprocess
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from sunpack.core.config.schema import normalize_config
from sunpack.core.contracts.archive_input import ArchiveInputDescriptor, InputExtent
from sunpack.core.contracts.extraction import ExtractionResult
from sunpack.core.contracts.failures import FailureInfo, FailureKind
from sunpack.core.contracts.tasks import ArchiveTask
from sunpack.pipeline.coordinator.engine import PipelineEngine
from sunpack.pipeline.coordinator.async_work import CancellationToken
from tests.helpers.detection_config import with_detection_pipeline


@pytest.mark.parametrize("concurrent,cancel_origin", [
    (False, None), (True, None), (False, "foreground"), (False, "watch"),
])
def test_real_split_archive_retry_updates_cleanup_and_avoids_lease_cycle(tmp_path, concurrent, cancel_origin):
    sevenzip = Path(__file__).resolve().parents[2] / "tools" / "7z.exe"
    payload = tmp_path / "payload.txt"
    payload.write_text("volume retry payload\n" * 70, encoding="utf-8")
    subprocess.run(
        [str(sevenzip), "a", "-t7z", "-mx=0", "-v1k", str(tmp_path / "split.7z"), str(payload)],
        check=True, capture_output=True,
    )
    parts = [str(path) for path in sorted(tmp_path.glob("split.7z.*"))]
    assert len(parts) == 2
    config = normalize_config(with_detection_pipeline({
        "recursive_extract": "1",
        "output": {"root": str(tmp_path / "out")},
        "post_extract": {"archive_cleanup_mode": "k" if concurrent or cancel_origin else "d", "flatten_single_directory": False},
    }))

    def task_for(paths):
        return ArchiveTask(ArchiveInputDescriptor(
            entry_path=paths[0], format_hint="7z", open_mode="concat_ranges",
            extents=[InputExtent(path) for path in paths],
        ))

    engine = PipelineEngine(config)
    factory = engine._request_runtime_factory
    # Deterministically expose the late-discovery boundary. Parsing and native
    # extraction of the replacement plan are real; only initial discovery is staged.
    barrier = threading.Barrier(2) if concurrent else None

    def configured(*args):
        runtime = factory(*args)
        original_inspect = runtime.extractor.inspect
        first_inspection = True

        def inspect(task, out_dir, **kwargs):
            nonlocal first_inspection
            if first_inspection:
                first_inspection = False
                if barrier is not None:
                    barrier.wait(timeout=5)
                return SimpleNamespace(skip_result=ExtractionResult(
                    success=False, out_dir=out_dir,
                    failure=FailureInfo(FailureKind.MISSING_VOLUME, "extraction", "late volume"),
                ))
            return original_inspect(task, out_dir, **kwargs)

        runtime.task_scanner.direct_file_tasks = lambda roots: [task_for(roots)]
        runtime._plan_task_isolated = lambda task: [task]
        runtime._resolve_missing_volume_once = lambda *_args: task_for(parts)
        runtime.extractor.inspect = inspect
        return runtime

    engine._request_runtime_factory = configured

    async def run():
        async with engine:
            if cancel_origin:
                # Admission-stop tests do not exercise the retry callback after
                # it expands the physical family. Cancel before its owner exits.
                registry = engine._path_leases
                await registry.acquire("holder", parts[1:])
                waiting = asyncio.Event()
                register = registry._register_waiter

                def observe(blockers):
                    future = register(blockers)
                    waiting.set()
                    return future

                registry._register_waiter = observe
                token = CancellationToken()
                request = asyncio.create_task(engine.run(
                    parts[:1], direct=True, origin=cancel_origin, cancellation=token,
                ))
                try:
                    await asyncio.wait_for(waiting.wait(), 5)
                    token.cancel()
                    response = await asyncio.wait_for(asyncio.shield(request), 5)
                    assert response.interrupted and not token._callbacks
                    assert registry._owned == {"holder": {parts[1]}}
                    assert not registry._waiter_blockers
                    assert all(Path(path).exists() for path in parts)
                    return [response]
                finally:
                    await registry.release("holder")
                    await asyncio.gather(request, return_exceptions=True)
            targets = parts if concurrent else parts[:1]
            return await asyncio.wait_for(asyncio.gather(*(
                engine.run([path], direct=True, origin="watch") for path in targets
            )), timeout=15)

    responses = asyncio.run(run())
    if cancel_origin:
        assert not engine._path_leases._pins
        return
    for response in responses:
        assert response.summary.failed_tasks == []
        assert response.summary.success_count == 1
        output = Path(response.summary.target_results[0].output_dir)
        assert (output / "payload.txt").read_text(encoding="utf-8") == payload.read_text(encoding="utf-8")
    assert all(Path(path).exists() == concurrent for path in parts)
    assert not engine._path_leases._pins
    assert not engine._path_leases._pin_counts
