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


@dataclass
class StageResult:
    tasks: list[ArchiveTask] = field(default_factory=list)
    claimed_paths: set[str] = field(default_factory=set)
    blocked_paths: set[str] = field(default_factory=set)
    scan_failures: list[FailureInfo] = field(default_factory=list)

    def add_resolved(self, task: ArchiveTask) -> None:
        self.tasks.append(task)
        self.claimed_paths.update(path_key(path) for path in task.cleanup_parts if path)

    def add_blocked(self, candidate: DiscoveryCandidate, *, source: str, reason: str, error: str = "") -> None:
        self.blocked_paths.update(candidate.path_keys)
        failure = discovery_failure(source, reason, candidate.entry_path, error)
        if failure is not None:
            self.tasks.append(ArchiveTask.from_archive_input(
                candidate.archive_input, discovery_source=source,
                carrier_path=candidate.carrier_path, cleanup_paths=candidate.cleanup_paths,
                discovery_evidence=candidate.relation_anchor,
                discovery_failure=failure,
            ))

    def validate(self) -> None:
        if self.claimed_paths & self.blocked_paths:
            raise ValueError("discovery stage claimed a blocked physical file")


# Project native verdicts once; presentation and recovery consume the same result.
def discovery_failure(source: str, reason: str, path: str, error: str = "") -> FailureInfo | None:
    spec = _DISCOVERY_FAILURES.get(reason)
    if spec is None:
        return None
    kind, message_key, action = spec
    return FailureInfo(
        kind, "embedded_boundary" if source == "embedded" else source, error,
        message_key=message_key, user_action=action, details={"path": path, "reason": reason},
    )


_DISCOVERY_FAILURES = {
    "embedded_password_required": (FailureKind.PASSWORD_REQUIRED, "failure.password_required", "request_password"),
    "embedded_wrong_password": (FailureKind.WRONG_PASSWORD, "failure.wrong_password", "request_password"),
    "needs_password": (FailureKind.PASSWORD_REQUIRED, "failure.password_required", "request_password"),
    "wrong_password": (FailureKind.WRONG_PASSWORD, "failure.wrong_password", "request_password"),
    "embedded_scan_io_error": (FailureKind.FILESYSTEM_ERROR, "", ""),
    "embedded_truncated": (FailureKind.DAMAGED, "failure.damaged", ""),
    "missing_volume": (FailureKind.MISSING_VOLUME, "failure.possible_missing_volume", ""),
    "ambiguous_volume_mapping": (FailureKind.MISSING_VOLUME, "failure.possible_missing_volume", ""),
    "structural_conflict": (FailureKind.MISSING_VOLUME, "failure.possible_missing_volume", ""),
    "corrupt_archive": (FailureKind.DAMAGED, "failure.damaged", ""),
    "needs_volume_or_tail_damaged": (FailureKind.DAMAGED, "failure.missing_volume_or_tail_damaged", ""),
    "unsupported": (FailureKind.UNSUPPORTED, "failure.unsupported", ""),
}
