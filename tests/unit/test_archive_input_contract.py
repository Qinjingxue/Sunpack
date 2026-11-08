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
        analysis={"segment_source": "embedded"},
    )

    task = ArchiveTask.from_archive_input(
        descriptor,
        discovery_source="embedded",
        logical_inputs=(LogicalArchiveInput(descriptor),),
    )

    segments = [node.projection() for node in task.inputs]
    assert len(segments) == 1
    assert segments[0]["archive_input"]["parts"][0]["start"] == 128
    assert "confidence" not in segments[0]


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


def test_shared_plan_checkpoint_matches_full_extents_and_ordered_domains():
    # Independent deserialization destroys tuple identity. A trimmed carrier
    # and competing layouts exercise both domain equality and checkpoint lookup.
    import json
    from dataclasses import replace
    from sunpack.core.contracts.archive_input import VolumeAttemptPlan, VolumeAttemptSlot
    sources = (InputExtent("head", 17, 117), InputExtent("a", 0, 40),
               InputExtent("b", 0, 40), InputExtent("tail", 0, 20))
    choices = (1, 2)
    slots = (VolumeAttemptSlot(1, "v1", (0,)), VolumeAttemptSlot(2, "v2", choices),
             VolumeAttemptSlot(3, "v3", choices), VolumeAttemptSlot(4, "v4", (3,)))
    plan = VolumeAttemptPlan(sources, (slots, tuple(replace(s, canonical_name=s.canonical_name + "x") for s in slots)),
                             head_size_from_total=150)
    original = ArchiveInputDescriptor("head", "native_volumes", "7z", volume_style="numeric_suffix",
        parts=[ArchiveInputPart(sources[0], "first", 1, "v1")], volume_attempts=plan)
    payload = json.loads(json.dumps(original.to_dict()))
    restored = ArchiveInputDescriptor.from_dict(payload)
    assert original.same_retry_input(restored)
    payload.pop("format_hint")
    with_format_hint = ArchiveInputDescriptor.from_any(payload, archive_path="head", format_hint="7z")
    assert original.same_retry_input(with_format_hint)
    winner = restored.select_volumes({"layout": 0, "sources": [0, 2, 1, 3]})
    assert winner.parts[0].extent == InputExtent("head", 17, 67)
    assert original.admits_selected_volumes(winner)
    damaged = replace(winner, parts=[replace(winner.parts[0], extent=InputExtent("head", 17, 68)), *winner.parts[1:]])
    assert not original.admits_selected_volumes(damaged)
    reordered = replace(plan, layouts=(tuple(replace(s, choices=tuple(reversed(s.choices))) for s in slots), plan.layouts[1]))
    assert plan != reordered  # Same membership, different attempt priority.
    restricted = replace(plan, layouts=(tuple(replace(s, choices=(1,)) if s.number == 2 else s for s in slots),))
    assert not replace(original, volume_attempts=restricted).admits_selected_volumes(winner)
    with pytest.raises(ValueError, match="unplanned"):
        restored.select_volumes({"layout": 0, "sources": [0, 3, 1, 2]})
