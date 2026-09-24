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


def test_legacy_segment_field_is_rejected():
    with pytest.raises(ValueError, match="legacy archive input segment field"):
        ArchiveInputDescriptor.from_dict({
            "kind": "archive_input",
            "entry_path": "carrier.bin",
            "open_mode": "file_range",
            "format_hint": "zip",
            "parts": [{"path": "carrier.bin", "role": "main"}],
            "segment": {"start": 128, "end": 512},
        })


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
        discovery_segments=((descriptor, evidence),),
    )

    segments = task.knowledge().get("source.extractable_segments")
    assert len(segments) == 1
    assert segments[0]["archive_input"]["parts"][0]["start"] == 128
    assert segments[0]["segment"] == evidence
