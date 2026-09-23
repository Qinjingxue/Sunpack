from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Protocol


ScanStage = Literal["path", "size", "mtime", "final"]
EntryKind = Literal["file", "dir"]


@dataclass
class ScanCandidate:
    path: Path
    kind: EntryKind
    size: int | None = None
    mtime_ns: int | None = None
    metadata: dict[str, Any] | None = None


@dataclass(frozen=True)
class ScanDecision:
    reject_entry: bool = False
    prune_dir: bool = False
    reason: str = ""


class ScanFilter(Protocol):
    name: str
    stage: ScanStage

    def evaluate(self, candidate: ScanCandidate) -> ScanDecision:
        ...


def keep() -> ScanDecision:
    return ScanDecision()


def reject(reason: str = "") -> ScanDecision:
    return ScanDecision(reject_entry=True, reason=reason)


def prune(reason: str = "") -> ScanDecision:
    return ScanDecision(reject_entry=True, prune_dir=True, reason=reason)
