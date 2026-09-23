"""Typed boundary between filesystem discovery and extraction planning."""

from __future__ import annotations

from dataclasses import dataclass, field

from sunpack.contracts.archive_input import ArchiveInputDescriptor
from sunpack.support.path_keys import path_key


@dataclass(frozen=True, slots=True)
class DiscoveryCandidate:
    route: str
    entry_path: str
    member_paths: tuple[str, ...]
    logical_name: str
    carrier_path: str
    cleanup_paths: tuple[str, ...]
    companion_paths: tuple[str, ...] = ()
    size: int | None = None
    format_hint: str = ""
    format_reject_mask: int = 0
    relation_anchor: dict = field(default_factory=dict, compare=False)
    archive_input: ArchiveInputDescriptor | None = field(default=None, compare=False)
    relation_kind: str = "file"
    is_split: bool = False
    is_sfx: bool = False
    relation_family: str = ""
    relation_index: int = 0

    @property
    def paths(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(
            path
            for path in (
                self.entry_path,
                self.carrier_path,
                *self.member_paths,
                *self.companion_paths,
                *self.cleanup_paths,
            )
            if path
        ))

    @property
    def path_keys(self) -> set[str]:
        return {path_key(path) for path in self.paths}


@dataclass(frozen=True, slots=True)
class ResolvedArchiveInput:
    archive_input: ArchiveInputDescriptor
    source: str
    carrier_path: str
    cleanup_paths: tuple[str, ...]
    relation_kind: str = "file"
    is_sfx: bool = False
    confidence: float = 1.0
    reasons: tuple[str, ...] = ()
    evidence: dict = field(default_factory=dict, compare=False)
    extractable_segments: tuple[dict, ...] = field(default_factory=tuple, compare=False)

    @classmethod
    def from_candidate(
        cls,
        candidate: DiscoveryCandidate,
        source: str,
        evidence: dict | None = None,
        *,
        archive_input: ArchiveInputDescriptor | None = None,
        confidence: float = 1.0,
        reasons: tuple[str, ...] | list[str] = (),
        extractable_segments: tuple[dict, ...] | list[dict] = (),
    ) -> "ResolvedArchiveInput":
        descriptor = archive_input or candidate.archive_input
        if descriptor is None:
            descriptor = ArchiveInputDescriptor.from_parts(
                archive_path=candidate.entry_path,
                part_paths=list(candidate.member_paths or (candidate.entry_path,)),
                format_hint=candidate.format_hint,
                logical_name=candidate.logical_name,
            )
        return cls(
            archive_input=descriptor,
            source=source,
            carrier_path=candidate.carrier_path or descriptor.entry_path,
            cleanup_paths=tuple(candidate.cleanup_paths or candidate.member_paths),
            relation_kind=candidate.relation_kind,
            is_sfx=candidate.is_sfx,
            confidence=float(confidence),
            reasons=tuple(str(item) for item in reasons if str(item)),
            evidence=dict(evidence or {}),
            extractable_segments=tuple(dict(item) for item in extractable_segments),
        )

    @property
    def entry_path(self) -> str:
        return self.archive_input.entry_path

    @property
    def member_paths(self) -> list[str]:
        return self.archive_input.part_paths()

    @property
    def format(self) -> str:
        return self.archive_input.format_hint

    @property
    def claimed_paths(self) -> set[str]:
        return {
            path_key(path)
            for path in (*self.member_paths, *self.cleanup_paths, self.carrier_path)
            if path
        }


@dataclass
class StageResult:
    resolved_inputs: list[ResolvedArchiveInput] = field(default_factory=list)
    claimed_paths: set[str] = field(default_factory=set)
    blocked_paths: set[str] = field(default_factory=set)
    residual_paths: set[str] = field(default_factory=set)

    def add_resolved(self, value: ResolvedArchiveInput) -> None:
        self.resolved_inputs.append(value)
        self.claimed_paths.update(value.claimed_paths)

    def validate(self) -> None:
        if self.claimed_paths & self.blocked_paths:
            raise ValueError("discovery stage claimed a blocked physical file")
        if self.claimed_paths & self.residual_paths or self.blocked_paths & self.residual_paths:
            raise ValueError("discovery stage returned a physical file twice")


def candidate_paths(candidate: DiscoveryCandidate) -> set[str]:
    return candidate.path_keys
