from __future__ import annotations

from typing import Any


def estimate_memory_weight(analysis: Any) -> int:
    if not getattr(analysis, "ok", False):
        return 1

    dictionary_mb = max(
        0,
        int(getattr(analysis, "largest_dictionary_size", 0) or 0),
    ) / (1024 * 1024)
    memory = 1

    if bool(getattr(analysis, "solid", False)):
        memory += 1

    if dictionary_mb >= 256:
        memory += 3
    elif dictionary_mb >= 64:
        memory += 2
    elif dictionary_mb >= 16:
        memory += 1

    return min(memory, 6)
