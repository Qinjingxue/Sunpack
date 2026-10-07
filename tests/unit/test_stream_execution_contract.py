"""Format-neutral stream metadata and logical source range projection."""
import pytest

from sunpack.core.analysis.result import ArchiveFormatEvidence, ArchiveSegment
from sunpack.core.contracts.archive_input import ArchiveInputDescriptor, ArchiveInputPart, InputExtent
from sunpack.pipeline.discovery.detection.input_planning import (
    ArchiveInputPlanningStage, _stream_execution_analysis, _strict_subrange,
)
from sunpack.pipeline.verification.error_classification import classify_verification_error
from tests.helpers.archive_tasks import make_task_from_descriptor


@pytest.mark.parametrize("start,end,expected", [
    (0, 100, False), (0, 50, True), (20, 100, True), (20, 50, True),
    (0, None, False), (20, None, False), (0, 0, False), (50, 50, False),
    (-1, 50, False), (50, 20, False), (0, 101, False), (100, 101, False),
])
def test_strict_subrange_requires_a_known_valid_smaller_range(start, end, expected):
    assert _strict_subrange(start, end, 100) == expected


def test_stream_projection_selects_the_offset_plan_without_format_dispatch():
    first, second = {"frames": 1}, {"frames": 2}
    evidence = ArchiveFormatEvidence("other-stream", .99, "extractable", details={
        "stream_plan": first, "stream_plans": {"0": first, "42": second},
    })
    assert _stream_execution_analysis(evidence, 42) == {"stream_plan": second}
    assert _stream_execution_analysis(evidence, 42)["stream_plan"] is second
    assert _stream_execution_analysis(evidence, 43) == {}
    evidence.details.pop("stream_plans")
    assert _stream_execution_analysis(evidence, 0) == {"stream_plan": first}
    assert _stream_execution_analysis(evidence, 42) == {}
    assert _stream_execution_analysis(None, 0) == {}


@pytest.mark.parametrize("sizes,start,end,expected", [
    ([100], 0, 50, [(0, 50)]), ([100], 0, 100, None),
    ([10, 20, 30], 0, 25, [(0, 10), (0, 15)]),
    ([10, 20, 30], 0, 60, None), ([10, 20, 30], 5, 45, [(5, 10), (0, 20), (0, 15)]),
    ([10, 20, 30], 30, 60, [(0, 30)]), ([10, 20, 30], 0, 61, None),
    ([10, 20, 30], 30, None, None),
])
def test_range_projection_uses_the_total_logical_length(monkeypatch, sizes, start, end, expected):
    paths = [f"part.{index:03}" for index in range(len(sizes))]
    monkeypatch.setattr("os.path.getsize", dict(zip(paths, sizes)).__getitem__)
    descriptor = ArchiveInputDescriptor(entry_path=paths[0],
        open_mode="native_volumes" if len(paths) > 1 else "file", format_hint="gzip",
        volume_style="numeric_suffix" if len(paths) > 1 else "",
        parts=[ArchiveInputPart(InputExtent(path), volume_number=i + 1, canonical_name=path)
               for i, path in enumerate(paths)])
    task = make_task_from_descriptor(descriptor)
    stage = ArchiveInputPlanningStage({"input_planning": {"enabled": False}})
    segment = ArchiveSegment(start, end, .99)
    evidence = ArchiveFormatEvidence("gzip", .99, "extractable", [segment])
    projected = stage._archive_input_for_segment(task, evidence, segment)
    if expected is None:
        assert projected is None
    else:
        assert projected.open_mode == ("concat_ranges" if len(paths) > 1 else "file_range")
        ranges = projected.extents or [part.extent for part in projected.parts]
        assert [(item.start, item.end) for item in ranges] == expected


def test_generic_unsupported_is_execution_failure_without_payload_damage():
    result = classify_verification_error("unsupported_method", "item_extract")
    assert result.category == "execution"
    assert result.content_integrity == "unknown"
