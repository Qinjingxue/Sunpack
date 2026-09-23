"""Typed boundary between filesystem discovery and extraction planning."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sunpack.core.contracts.archive_input import ArchiveInputDescriptor
from sunpack.core.support.path_keys import path_key


@dataclass(frozen=True, slots=True)
class DiscoveryCandidate:
    entry_path: str
    member_paths: tuple[str, ...]
    logical_name: str
    carrier_path: str
    cleanup_paths: tuple[str, ...]
    route: str
    format_hint: str = ""
    size: int | None = None
    format_reject_mask: int = 0
    archive_input: ArchiveInputDescriptor | None = None
    relation_anchor: dict[str, Any] = field(default_factory=dict)
    relation_kind: str = "file"
    is_split: bool = False
    is_sfx: bool = False
    companion_paths: tuple[str, ...] = ()
    relation_metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def physical_paths(self) -> tuple[str, ...]:
        values = (
            *self.member_paths,
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
class ResolvedArchiveSegment:
    archive_input: ArchiveInputDescriptor
    format: str
    confidence: float = 0.0
    start_offset: int = 0
    end_offset: int | None = None
    damage_flags: tuple[str, ...] = ()
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ResolvedArchiveInput:
    archive_input: ArchiveInputDescriptor
    source: str
    carrier_path: str
    cleanup_paths: tuple[str, ...]
    evidence: dict[str, Any] = field(default_factory=dict)
    segments: tuple[ResolvedArchiveSegment, ...] = ()

    @property
    def entry_path(self) -> str:
        return self.archive_input.entry_path

    @property
    def member_paths(self) -> list[str]:
        return self.archive_input.part_paths()

    @property
    def logical_name(self) -> str:
        return self.archive_input.logical_name

    @property
    def format(self) -> str:
        return self.archive_input.format_hint

    @property
    def claimed_paths(self) -> set[str]:
        values = (*self.member_paths, *self.cleanup_paths, self.carrier_path)
        return {path_key(path) for path in values if path}


@dataclass(frozen=True, slots=True)
class DiscoveryTrace:
    entry_path: str
    source: str
    status: str
    format: str = ""
    reason: str = ""


@dataclass
class StageResult:
    resolved_inputs: list[ResolvedArchiveInput] = field(default_factory=list)
    claimed_paths: set[str] = field(default_factory=set)
    blocked_paths: set[str] = field(default_factory=set)
    residual_paths: set[str] = field(default_factory=set)
    traces: list[DiscoveryTrace] = field(default_factory=list)

    def add_resolved(self, value: ResolvedArchiveInput, *, reason: str = "") -> None:
        self.resolved_inputs.append(value)
        self.claimed_paths.update(value.claimed_paths)
        self.traces.append(DiscoveryTrace(
            entry_path=value.entry_path,
            source=value.source,
            status="resolved",
            format=value.format,
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
