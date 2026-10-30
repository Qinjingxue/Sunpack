import asyncio
from pathlib import Path
import subprocess

import pytest

from sunpack.core.config.schema import normalize_config
from sunpack.core.contracts.failures import FailureKind
from sunpack.pipeline.coordinator.engine import PipelineEngine
from sunpack.pipeline.postprocess.internal.blocked_input import promote_blocked_input
from tests.helpers.detection_config import with_detection_pipeline


@pytest.mark.parametrize("origin", ["foreground", "watch"])
@pytest.mark.parametrize("split", [False, True])
def test_colliding_promoted_carrier_recovers_with_late_volume_and_password(tmp_path, origin, split):
    # Path-only promotion tests cannot detect broken Rust regrouping or worker
    # range/volume mapping after a rename. One real encrypted payload covers
    # those boundaries together, including discovery after a missing part arrives.
    source, destination = tmp_path / "nested", tmp_path / "input"
    source.mkdir()
    destination.mkdir()
    payload = tmp_path / "payload.txt"
    payload.write_text("blocked nested payload\n" * 130, encoding="utf-8")
    archive = tmp_path / "packed.7z"
    sevenzip = Path(__file__).resolve().parents[2] / "tools" / "7z.exe"
    subprocess.run([str(sevenzip), "a", "-t7z", "-mx=0", "-psecret", "-mhe=on",
                    *(["-v1k"] if split else []), str(archive), str(payload)],
                   check=True, capture_output=True)
    originals = sorted(tmp_path.glob("packed.7z.*")) if split else [archive]
    parts = []
    for index, original in enumerate(originals, 1):
        part = source / (f"inner.blob.{index:03d}" if split else "inner.blob")
        # The carrier boundary belongs to Rust analysis and must survive mapping.
        data = original.read_bytes()
        part.write_bytes(b"carrier-prefix" + data + b"carrier-tail" if not split else data)
        parts.append(part)
    collision = destination / parts[0].name
    collision.write_text("existing user file")
    arriving = parts[-1] if split else None
    known = parts[:-1] if split else parts
    assert known
    moved = promote_blocked_input(map(str, known), str(destination))
    entry = moved.path_map[str(parts[0])]
    assert Path(entry).name.startswith(parts[0].name + ".")
    config = normalize_config(with_detection_pipeline({
        "recursive_extract": "1",
        "output": {"root": str(tmp_path / "output")},
        "post_extract": {"archive_cleanup_mode": "k", "flatten_single_directory": False},
    }))

    async def scenario():
        async with PipelineEngine(config) as engine:
            response = await engine.run([entry], direct=True, origin=origin)
            assert response.summary.failed_tasks
            failure = response.summary.target_results[0].failure
            assert failure.is_password_failure or failure.contains(FailureKind.MISSING_VOLUME)
            if arriving is not None:
                arriving.rename(destination / arriving.name)
            response = await engine.run([entry], direct=True, origin=origin,
                                        request_config={**config, "user_passwords": ["secret"]})
            assert not response.summary.failed_tasks
            assert response.summary.success_count == 1
            output = Path(response.summary.target_results[0].output_dir)
            assert (output / payload.name).read_text(encoding="utf-8") == payload.read_text(encoding="utf-8")

    asyncio.run(scenario())
    assert collision.read_text() == "existing user file"
