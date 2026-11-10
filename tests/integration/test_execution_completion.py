"""Worker content outcomes through the shared CLI/Watch terminal policy."""
import asyncio
import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from sunpack.core.contracts.results import OutcomeKind
from sunpack.pipeline.coordinator.engine import PipelineEngine
from tests.helpers.config_factory import make_config


@pytest.mark.parametrize("origin", ["foreground", "watch"])
@pytest.mark.parametrize("layout", ["empty", "directory", "tar_tail", "partial", "reject_partial"])
def test_content_completion_controls_retention_and_source_cleanup(tmp_path, origin, layout):
    # Mock policy tests cannot establish final worker/member facts or demonstrate
    # that a harmless TAR tail is accepted without a second source walk.
    archive = tmp_path / "input.disguised"
    if layout == "tar_tail":
        with tarfile.open(archive, "w", format=tarfile.USTAR_FORMAT) as stream:
            member = tarfile.TarInfo("good.txt")
            member.size = 4
            stream.addfile(member, io.BytesIO(b"good"))
        # Complete member, then an incomplete next header instead of end blocks.
        archive.write_bytes(archive.read_bytes()[:1024] + b"next.txt".ljust(80, b"\0"))
    else:
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as stream:
            if layout == "directory":
                stream.writestr("directory/", b"")
            elif layout in {"partial", "reject_partial"}:
                stream.writestr("good.txt", b"good")
                stream.writestr("bad.txt", b"damaged")
                bad = stream.getinfo("bad.txt")
                offset = bad.header_offset + 30 + len(bad.filename)
        if layout in {"partial", "reject_partial"}:
            data = bytearray(archive.read_bytes())
            data[offset] ^= 1
            archive.write_bytes(data)
    config = make_config({
        "extraction": {"content_requirement": "complete" if layout == "reject_partial" else "allow_partial"},
        "post_extract": {"archive_cleanup_mode": "d", "flatten_single_directory": False},
        "recursive_extract": 1,
    })

    async def run():
        async with PipelineEngine(config) as engine:
            return await engine.run([str(archive)], direct=True, origin=origin,
                                    stdout=io.StringIO(), stderr=io.StringIO())

    response = asyncio.run(run())
    result, = response.summary.target_results
    expected = (OutcomeKind.PARTIAL_SUCCESS if layout == "partial" else
                OutcomeKind.FAILURE if layout == "reject_partial" else OutcomeKind.COMPLETE_SUCCESS)
    assert result.outcome_kind == expected
    assert archive.exists() is (expected != OutcomeKind.COMPLETE_SUCCESS)
    if layout == "partial":
        assert result.recovery["complete_files"] == 1
        assert (Path(result.output_dir) / "good.txt").read_bytes() == b"good"
