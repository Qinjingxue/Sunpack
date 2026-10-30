"""Typed boundary between filesystem discovery and extraction planning."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sunpack.core.contracts.archive_input import ArchiveInputDescriptor
from sunpack.core.contracts.failures import FailureInfo, FailureKind
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
    error: str = ""


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
    tasks: list[ArchiveTask] = field(default_factory=list)
    findings: list[DiscoveryFinding] = field(default_factory=list)
    claimed_paths: set[str] = field(default_factory=set)
    blocked_paths: set[str] = field(default_factory=set)
    residual_paths: set[str] = field(default_factory=set)
    traces: list[DiscoveryTrace] = field(default_factory=list)

    def add_resolved(self, task: ArchiveTask, *, reason: str = "") -> None:
        self.tasks.append(task)
        self.claimed_paths.update(path_key(path) for path in task.cleanup_parts if path)
        self.traces.append(DiscoveryTrace(
            entry_path=task.main_path,
            source=task.discovery_source,
            status="resolved",
            format=task.archive_input().format_hint,
            reason=reason,
        ))

    def add_blocked(self, candidate: DiscoveryCandidate, *, source: str, reason: str, error: str = "") -> None:
        self.blocked_paths.update(candidate.path_keys)
        spec = _DISCOVERY_FAILURES.get(reason)
        if spec is not None:
            kind, message_key, action = spec
            self.tasks.append(ArchiveTask.from_archive_input(
                candidate.archive_input, discovery_source=source,
                carrier_path=candidate.carrier_path, cleanup_paths=candidate.cleanup_paths,
                discovery_evidence=candidate.relation_anchor, discovery_reason=reason,
                discovery_failure=FailureInfo(
                    kind, "embedded_boundary" if source == "embedded" else source,
                    error, message_key=message_key, user_action=action,
                    details={"path": candidate.entry_path, "reason": reason},
                ),
            ))
        self.traces.append(DiscoveryTrace(
            entry_path=candidate.entry_path,
            source=source,
            status="blocked",
            format=candidate.format_hint,
            reason=reason,
            error=error,
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


# Project native verdicts once; presentation and recovery consume the same result.
_DISCOVERY_FAILURES = {
    "embedded_password_required": (FailureKind.PASSWORD_REQUIRED, "failure.password_required", "request_password"),
    "embedded_wrong_password": (FailureKind.WRONG_PASSWORD, "failure.wrong_password", "request_password"),
    "needs_password": (FailureKind.PASSWORD_REQUIRED, "failure.password_required", "request_password"),
    "wrong_password": (FailureKind.WRONG_PASSWORD, "failure.wrong_password", "request_password"),
    "embedded_truncated": (FailureKind.DAMAGED, "failure.damaged", ""),
    "missing_volume": (FailureKind.MISSING_VOLUME, "failure.possible_missing_volume", ""),
    "ambiguous_volume_mapping": (FailureKind.MISSING_VOLUME, "failure.possible_missing_volume", ""),
    "structural_conflict": (FailureKind.MISSING_VOLUME, "failure.possible_missing_volume", ""),
    "corrupt_archive": (FailureKind.DAMAGED, "failure.damaged", ""),
    "unsupported": (FailureKind.UNSUPPORTED, "failure.unsupported", ""),
}
