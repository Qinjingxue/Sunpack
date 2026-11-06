from sunpack.core.contracts.input_plan import LogicalArchiveInput
import pytest

from sunpack.core.contracts.archive_input import (
    ArchiveInputDescriptor,
    ArchiveInputPart,
    InputExtent,
)
from sunpack.core.contracts.tasks import ArchiveTask


def test_file_range_serializes_only_canonical_extent_boundary():
    descriptor = ArchiveInputDescriptor(
        entry_path="carrier.bin",
        open_mode="file_range",
        format_hint="zip",
        logical_name="payload",
        parts=[
            ArchiveInputPart(
                extent=InputExtent(path="carrier.bin", start=128, end=512)
            )
        ],
        analysis={
            "segment_confidence": 0.95,
            "segment_source": "analysis",
            "damage_flags": ["carrier_prefix"],
        },
    )

    payload = descriptor.to_dict()

    assert payload["parts"] == [
        {
            "path": "carrier.bin",
            "role": "main",
            "start": 128,
            "end": 512,
        }
    ]
    assert "segment" not in payload
    assert payload["analysis"] == {"damage_flags": ["carrier_prefix"]}

    restored = ArchiveInputDescriptor.from_dict(payload)
    assert restored.primary_extent == InputExtent("carrier.bin", 128, 512)


def test_duplicate_segment_boundary_analysis_is_rejected():
    with pytest.raises(ValueError, match="boundaries belong only to InputExtent"):
        ArchiveInputDescriptor(
            entry_path="carrier.bin",
            open_mode="file_range",
            parts=[
                ArchiveInputPart(
                    extent=InputExtent(path="carrier.bin", start=128, end=512)
                )
            ],
            analysis={"segment_start": 128},
        )


def test_archive_task_accepts_paired_discovery_segments():
    descriptor = ArchiveInputDescriptor(
        entry_path="carrier.bin",
        open_mode="file_range",
        format_hint="zip",
        logical_name="payload",
        parts=[
            ArchiveInputPart(
                extent=InputExtent(path="carrier.bin", start=128, end=512)
            )
        ],
        analysis={"segment_confidence": 0.95},
    )
    evidence = {"confidence": 0.95, "validation": "embedded"}

    task = ArchiveTask.from_archive_input(
        descriptor,
        discovery_source="embedded",
        logical_inputs=(LogicalArchiveInput(descriptor, evidence=evidence),),
    )

    segments = [node.projection() for node in task.inputs]
    assert len(segments) == 1
    assert segments[0]["archive_input"]["parts"][0]["start"] == 128
    assert task.inputs[0].evidence == evidence


def test_path_mapping_moves_each_input_once_and_preserves_the_shared_plan(tmp_path):
    # Promotion can move a file into another source's old path. Ordinary
    # disjoint mappings cannot expose applying that move twice to a shared node.
    first, second, moved = (str(tmp_path / name) for name in ("first", "second", "moved"))
    descriptor = ArchiveInputDescriptor(
        first, open_mode="native_volumes", format_hint="rar", volume_style="rar_part",
        parts=[
            ArchiveInputPart(InputExtent(first, 37, 512), volume_number=1, canonical_name="a.part1.rar"),
            ArchiveInputPart(InputExtent(second, 0, 256), volume_number=2, canonical_name="a.part2.rar"),
        ],
    )
    task = ArchiveTask.from_archive_input(descriptor, discovery_source="relations")
    task.password_probe_input = descriptor
    identity = task.inputs[0].input_id

    task.apply_path_mapping({first: second, second: moved})

    assert task.inputs[0].input_id == identity
    assert task.inputs[0].descriptor is task.archive_input()
    assert task.password_probe_input is task.archive_input()
    assert task.inputs[0].source_paths == (second, moved)
    assert task.inputs[0].descriptor.primary_extent == InputExtent(second, 37, 512)
    assert set(task.cleanup_parts) == {second, moved}
