from types import SimpleNamespace

import pytest

from sunpack.coordinator.scheduling.resource_model import estimate_memory_weight


@pytest.mark.parametrize(
    ("solid", "dictionary_size", "expected"),
    [
        (False, 0, 1),
        (True, 0, 2),
        (False, 16 << 20, 2),
        (False, 64 << 20, 3),
        (False, 256 << 20, 4),
        (True, 256 << 20, 5),
    ],
)
def test_memory_weight_tracks_only_live_admission_inputs(solid, dictionary_size, expected):
    analysis = SimpleNamespace(
        ok=True,
        solid=solid,
        largest_dictionary_size=dictionary_size,
    )

    assert estimate_memory_weight(analysis) == expected


def test_failed_analysis_uses_default_memory_weight():
    assert estimate_memory_weight(SimpleNamespace(ok=False)) == 1
