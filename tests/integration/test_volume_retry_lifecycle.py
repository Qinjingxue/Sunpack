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
from tests.helpers.detection_config import with_detection_pipeline


@pytest.mark.parametrize("concurrent", [False, True])
def test_real_split_archive_retry_updates_cleanup_and_avoids_lease_cycle(tmp_path, concurrent):
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
        "post_extract": {"archive_cleanup_mode": "k" if concurrent else "d", "flatten_single_directory": False},
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
            targets = parts if concurrent else parts[:1]
            return await asyncio.wait_for(asyncio.gather(*(
                engine.run([path], direct=True, origin="watch") for path in targets
            )), timeout=15)

    responses = asyncio.run(run())
    for response in responses:
        assert response.summary.failed_tasks == []
        assert response.summary.success_count == 1
        output = Path(response.summary.target_results[0].output_dir)
        assert (output / "payload.txt").read_text(encoding="utf-8") == payload.read_text(encoding="utf-8")
    assert all(Path(path).exists() == concurrent for path in parts)
    assert not engine._path_leases._pins
    assert not engine._path_leases._pin_counts
