"""Format-neutral stream metadata and logical source range projection."""
import pytest

from sunpack.core.analysis.result import ArchiveFormatEvidence, ArchiveSegment
from sunpack.core.contracts.archive_input import ArchiveInputDescriptor, ArchiveInputPart, InputExtent
from sunpack.pipeline.discovery.detection.input_planning import (
    ArchiveInputPlanningStage,
)


@pytest.mark.parametrize("sizes,start,end,expected", [
    ([100], 0, 50, [(0, 50)]), ([100], 0, 100, None),
    ([10, 20, 30], 0, 25, [(0, 10), (0, 15)]),
    ([10, 20, 30], 0, 60, None), ([10, 20, 30], 5, 45, [(5, 10), (0, 20), (0, 15)]),
    ([10, 20, 30], 30, 60, [(0, 30)]), ([10, 20, 30], 0, 61, None),
    ([10, 20, 30], 30, None, None),
])
def test_range_projection_uses_the_total_logical_length(tmp_path, sizes, start, end, expected):
    paths = [str(tmp_path / f"part.{index:03}") for index in range(len(sizes))]
    from pathlib import Path
    for path, size in zip(paths, sizes):
        Path(path).write_bytes(b"x" * size)
    descriptor = ArchiveInputDescriptor(entry_path=paths[0],
        open_mode="native_volumes" if len(paths) > 1 else "file", format_hint="gzip",
        volume_style="numeric_suffix" if len(paths) > 1 else "",
        parts=[ArchiveInputPart(InputExtent(path), volume_number=i + 1, canonical_name=path)
               for i, path in enumerate(paths)])
    segment = ArchiveSegment(start, end)
    evidence = ArchiveFormatEvidence("gzip", "extractable", [segment])
    inputs, probe = ArchiveInputPlanningStage._project_segments(descriptor, [(evidence, segment, 1)])
    if expected is None:
        assert not inputs
        if end is None:
            assert probe.open_mode == "file_range"
            assert probe.parts[0].extent == InputExtent(paths[-1], 0, sizes[-1])
    else:
        projected = inputs[0].descriptor
        assert probe is projected
        assert projected.open_mode == ("concat_ranges" if len(expected) > 1 else "file_range")
        ranges = projected.extents or [part.extent for part in projected.parts]
        assert [(item.start, item.end) for item in ranges] == expected
