"""The boundary between archive discovery and extraction planning."""

from dataclasses import dataclass, field

from sunpack.contracts.archive_input import ArchiveInputDescriptor
from sunpack.contracts.archive_state import ArchiveState
from sunpack.contracts.detection import FactBag
from sunpack.support.path_keys import path_key


@dataclass(frozen=True)
class ResolvedArchiveInput:
    archive_input: ArchiveInputDescriptor
    source: str
    carrier_path: str
    cleanup_paths: tuple[str, ...]
    evidence: dict
    # Facts are retained only for the existing extraction and reporting boundary.
    facts: FactBag = field(repr=False, compare=False)

    @classmethod
    def from_bag(cls, bag: FactBag, source: str, evidence: dict) -> "ResolvedArchiveInput":
        entry = str(bag.get("candidate.entry_path") or "")
        members = list(bag.get("candidate.member_paths") or [entry])
        format_hint = str(
            bag.get("relation.format_hint") or bag.get("filesystem.format_hint")
            or bag.get("file.detected_ext") or ""
        ).lower().lstrip(".")
        descriptor = ArchiveInputDescriptor.from_any(
            bag.get("archive.input"), archive_path=entry, part_paths=members,
            format_hint=format_hint, logical_name=str(bag.get("candidate.logical_name") or ""),
        )
        state = ArchiveState.from_archive_input(descriptor)
        bag.set("archive.input", descriptor.to_dict())
        bag.set("archive.state", state.to_dict())
        bag.set("archive.source", state.source.to_dict())
        bag.set("discovery.confirmed", True)
        bag.set("discovery.source", source)
        return cls(
            archive_input=descriptor, source=source,
            carrier_path=str(bag.get("candidate.carrier_path") or entry),
            cleanup_paths=tuple(bag.get("candidate.cleanup_paths") or members),
            evidence=evidence, facts=bag,
        )

    @property
    def entry_path(self) -> str:
        return self.archive_input.entry_path

    @property
    def member_paths(self) -> list[str]:
        return self.archive_input.part_paths()

    @property
    def claimed_paths(self) -> set[str]:
        return {path_key(path) for path in (*self.member_paths, *self.cleanup_paths, self.carrier_path) if path}


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


def candidate_paths(bag: FactBag) -> set[str]:
    paths = [
        bag.get("file.path"), bag.get("candidate.entry_path"),
        bag.get("candidate.carrier_path"),
        *(bag.get("candidate.member_paths") or []),
        *(bag.get("candidate.companion_paths") or []),
        *(bag.get("candidate.cleanup_paths") or []),
    ]
    return {path_key(path) for path in paths if path}
