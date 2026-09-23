"""Small collection and scalar helpers shared across SunPack layers."""

from __future__ import annotations

import os
from collections.abc import Iterable
from typing import Any


def dedupe_strings(values: Iterable[Any]) -> list[str]:
    """Return non-empty string values once, preserving first-seen order."""

    output: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value)
        if not text or text in seen:
            continue
        seen.add(text)
        output.append(text)
    return output


def dedupe_values(values: Iterable[Any]) -> list[Any]:
    """Return values once, preserving equality semantics and first-seen order."""

    output: list[Any] = []
    seen: set[Any] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        output.append(value)
    return output


def dedupe_normalized_paths(paths: Iterable[Any]) -> list[str]:
    """Normalize and de-duplicate filesystem paths while preserving order."""

    output: list[str] = []
    seen: set[str] = set()
    for path in paths:
        value = str(path or "").strip()
        if not value:
            continue
        normalized = os.path.abspath(value)
        key = os.path.normcase(normalized)
        if key in seen:
            continue
        seen.add(key)
        output.append(normalized)
    return output


def clamp01(value: Any) -> float:
    """Convert a value to a number in the inclusive [0, 1] range."""

    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    return min(1.0, max(0.0, number))
