"""Typed boundary between filesystem discovery and extraction planning."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sunpack.core.contracts.archive_input import ArchiveInputDescriptor
from sunpack.core.contracts.tasks import ArchiveTask
from sunpack.core.support.path_keys import path_key


@dataclass(frozen=True, slots=True)
class DiscoveryCandidate:
    archive_input: ArchiveInputDescriptor
    carrier_path: str
    cleanup_paths: tuple[str, ...]
    route: str
    size: int | None = None
    logical_size: int | None = None
    format_reject_mask: int = 0
    relation_anchor: dict[str, Any] = field(default_factory=dict)
    is_split: bool = False
    companion_paths: tuple[str, ...] = ()
    relation_metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def entry_path(self) -> str:
        return self.archive_input.entry_path

    @property
    def logical_name(self) -> str:
        return self.archive_input.logical_name

    @property
    def format_hint(self) -> str:
        return self.archive_input.format_hint

    @property
    def physical_paths(self) -> tuple[str, ...]:
        values = (
            *self.archive_input.part_paths(),
            *self.companion_paths,
            *self.cleanup_paths,
            self.carrier_path,
            self.entry_path,
        )
        return tuple(dict.fromkeys(path for path in values if path))

    @property
    def path_keys(self) -> set[str]:
        return {path_key(path) for path in self.physical_paths}


@dataclass(frozen=True, slots=True)
class DiscoveryTrace:
    entry_path: str
    source: str
    status: str
    format: str = ""
    reason: str = ""


@dataclass(frozen=True, slots=True)
class DiscoveryFinding:
    """A confirmed archive identity independent from execution planning."""

    entry_path: str
    source: str
    format: str
    status: str
    reason: str = ""
    logical_name: str = ""
    part_paths: tuple[str, ...] = ()
    offset: int | None = None
    end_offset: int | None = None
    boundary_kind: str = ""
    extractable: bool = False


@dataclass
class StageResult:
    resolved_tasks: list[ArchiveTask] = field(default_factory=list)
    findings: list[DiscoveryFinding] = field(default_factory=list)
    claimed_paths: set[str] = field(default_factory=set)
    blocked_paths: set[str] = field(default_factory=set)
    residual_paths: set[str] = field(default_factory=set)
    traces: list[DiscoveryTrace] = field(default_factory=list)

    def add_resolved(self, task: ArchiveTask, *, reason: str = "") -> None:
        self.resolved_tasks.append(task)
        self.claimed_paths.update(path_key(path) for path in task.cleanup_parts if path)
        self.traces.append(DiscoveryTrace(
            entry_path=task.main_path,
            source=task.discovery_source,
            status="resolved",
            format=task.archive_input().format_hint,
            reason=reason,
        ))

    def add_blocked(self, candidate: DiscoveryCandidate, *, source: str, reason: str) -> None:
        self.blocked_paths.update(candidate.path_keys)
        self.traces.append(DiscoveryTrace(
            entry_path=candidate.entry_path,
            source=source,
            status="blocked",
            format=candidate.format_hint,
            reason=reason,
        ))

    def add_residual(self, candidate: DiscoveryCandidate, *, source: str, reason: str = "") -> None:
        self.residual_paths.update(candidate.path_keys)
        self.traces.append(DiscoveryTrace(
            entry_path=candidate.entry_path,
            source=source,
            status="residual",
            format=candidate.format_hint,
            reason=reason,
        ))

    def validate(self) -> None:
        if self.claimed_paths & self.blocked_paths:
            raise ValueError("discovery stage claimed a blocked physical file")
        if self.claimed_paths & self.residual_paths or self.blocked_paths & self.residual_paths:
            raise ValueError("discovery stage returned a physical file twice")
