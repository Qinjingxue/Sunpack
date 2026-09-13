from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sunpack.contracts.archive_input import (
    ArchiveInputDescriptor,
    ArchiveInputPart,
    ArchiveInputRange,
    ArchiveInputSegment,
    ArchiveOpenMode,
)


@dataclass(frozen=True)
class ArchiveSource:
    entry_path: str
    open_mode: ArchiveOpenMode = "file"
    format_hint: str = ""
    logical_name: str = ""
    volume_style: str = ""
    password: str = ""
    parts: list[ArchiveInputPart] = field(default_factory=list)
    ranges: list[ArchiveInputRange] = field(default_factory=list)
    segment: ArchiveInputSegment | None = None
    analysis: dict[str, Any] = field(default_factory=dict)
    source_identity: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "kind": "archive_source",
            "entry_path": self.entry_path,
            "open_mode": self.open_mode,
        }
        if self.format_hint:
            payload["format_hint"] = self.format_hint
        if self.logical_name:
            payload["logical_name"] = self.logical_name
        if self.volume_style:
            payload["volume_style"] = self.volume_style
        if self.password:
            payload["password"] = self.password
        if self.parts:
            payload["parts"] = [part.to_dict() for part in self.parts]
        if self.ranges:
            payload["ranges"] = [item.to_dict() for item in self.ranges]
        if self.segment is not None:
            payload["segment"] = self.segment.to_dict()
        if self.analysis:
            payload["analysis"] = dict(self.analysis)
        if self.source_identity:
            payload["source_identity"] = self.source_identity
        return payload

    def to_archive_input_descriptor(self) -> ArchiveInputDescriptor:
        return ArchiveInputDescriptor(
            entry_path=self.entry_path,
            open_mode=self.open_mode,
            format_hint=self.format_hint,
            logical_name=self.logical_name,
            volume_style=self.volume_style,
            password=self.password,
            parts=list(self.parts),
            ranges=list(self.ranges),
            segment=self.segment,
            analysis=dict(self.analysis),
        )

    def part_paths(self) -> list[str]:
        return self.to_archive_input_descriptor().part_paths()

    def with_path_mapping(self, mapper) -> "ArchiveSource":
        return ArchiveSource.from_archive_input(
            self.to_archive_input_descriptor().with_path_mapping(mapper),
            source_identity=self.source_identity,
        )

    @classmethod
    def from_archive_input(
        cls,
        descriptor: ArchiveInputDescriptor,
        *,
        source_identity: str = "",
    ) -> "ArchiveSource":
        return cls(
            entry_path=descriptor.entry_path,
            open_mode=descriptor.open_mode,
            format_hint=descriptor.format_hint,
            logical_name=descriptor.logical_name,
            volume_style=descriptor.volume_style,
            password=descriptor.password,
            parts=list(descriptor.parts),
            ranges=list(descriptor.ranges),
            segment=descriptor.segment,
            analysis=dict(descriptor.analysis),
            source_identity=source_identity,
        )

    @classmethod
    def from_dict(
        cls,
        raw: dict[str, Any],
        *,
        archive_path: str = "",
        part_paths: list[str] | None = None,
    ) -> "ArchiveSource":
        if raw.get("kind") == "archive_source":
            raw = {**raw, "kind": "archive_input"}
        descriptor = ArchiveInputDescriptor.from_dict(raw, archive_path=archive_path, part_paths=part_paths)
        return cls.from_archive_input(descriptor, source_identity=str(raw.get("source_identity") or ""))


@dataclass(frozen=True)
class ArchiveState:
    source: ArchiveSource
    logical_name: str = ""
    format_hint: str = ""
    analysis: dict[str, Any] = field(default_factory=dict)
    verification: dict[str, Any] = field(default_factory=dict)
    knowledge: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "kind": "archive_state",
            "source": self.source.to_dict(),
        }
        if self.logical_name:
            payload["logical_name"] = self.logical_name
        if self.format_hint:
            payload["format_hint"] = self.format_hint
        if self.analysis:
            payload["analysis"] = dict(self.analysis)
        if self.verification:
            payload["verification"] = dict(self.verification)
        if self.knowledge:
            payload["knowledge"] = dict(self.knowledge)
        return payload

    def to_archive_input_descriptor(self) -> ArchiveInputDescriptor:
        descriptor = self.source.to_archive_input_descriptor()
        if not self.format_hint and not self.logical_name:
            return descriptor
        return ArchiveInputDescriptor(
            entry_path=descriptor.entry_path,
            open_mode=descriptor.open_mode,
            format_hint=self.format_hint or descriptor.format_hint,
            logical_name=self.logical_name or descriptor.logical_name,
            volume_style=descriptor.volume_style,
            password=descriptor.password,
            parts=list(descriptor.parts),
            ranges=list(descriptor.ranges),
            segment=descriptor.segment,
            analysis=dict(descriptor.analysis),
        )

    def with_path_mapping(self, mapper) -> "ArchiveState":
        return ArchiveState(
            source=self.source.with_path_mapping(mapper),
            logical_name=self.logical_name,
            format_hint=self.format_hint,
            analysis=dict(self.analysis),
            verification=dict(self.verification),
            knowledge=dict(self.knowledge),
        )

    @classmethod
    def from_archive_input(
        cls,
        descriptor: ArchiveInputDescriptor,
        *,
        analysis: dict[str, Any] | None = None,
        verification: dict[str, Any] | None = None,
        knowledge: dict[str, Any] | None = None,
    ) -> "ArchiveState":
        return cls(
            source=ArchiveSource.from_archive_input(descriptor),
            logical_name=descriptor.logical_name,
            format_hint=descriptor.format_hint,
            analysis=dict(analysis or {}),
            verification=dict(verification or {}),
            knowledge=dict(knowledge or {}),
        )

    @classmethod
    def from_dict(
        cls,
        raw: dict[str, Any],
        *,
        archive_path: str = "",
        part_paths: list[str] | None = None,
    ) -> "ArchiveState":
        source_raw = raw.get("source")
        if isinstance(source_raw, dict):
            source = ArchiveSource.from_dict(source_raw, archive_path=archive_path, part_paths=part_paths)
        else:
            descriptor = ArchiveInputDescriptor.from_dict(raw, archive_path=archive_path, part_paths=part_paths)
            source = ArchiveSource.from_archive_input(descriptor)
        return cls(
            source=source,
            logical_name=str(raw.get("logical_name") or source.logical_name),
            format_hint=str(raw.get("format_hint") or source.format_hint),
            analysis=dict(raw.get("analysis") or {}) if isinstance(raw.get("analysis"), dict) else {},
            verification=dict(raw.get("verification") or {}) if isinstance(raw.get("verification"), dict) else {},
            knowledge=_knowledge_from_raw(raw),
        )

    @classmethod
    def from_any(
        cls,
        raw: dict[str, Any] | None,
        *,
        archive_path: str,
        part_paths: list[str] | None = None,
        format_hint: str = "",
        logical_name: str = "",
        archive_input: dict[str, Any] | None = None,
    ) -> "ArchiveState":
        if isinstance(raw, dict):
            if raw.get("kind") == "archive_state" or isinstance(raw.get("source"), dict):
                state = cls.from_dict(raw, archive_path=archive_path, part_paths=part_paths)
                return _with_state_defaults(state, format_hint=format_hint, logical_name=logical_name)
            descriptor = ArchiveInputDescriptor.from_any(
                raw,
                archive_path=archive_path,
                part_paths=part_paths,
                format_hint=format_hint,
                logical_name=logical_name,
            )
            return cls.from_archive_input(descriptor)
        descriptor = ArchiveInputDescriptor.from_any(
            archive_input,
            archive_path=archive_path,
            part_paths=part_paths,
            format_hint=format_hint,
            logical_name=logical_name,
        )
        return cls.from_archive_input(descriptor)


def _with_state_defaults(state: ArchiveState, *, format_hint: str = "", logical_name: str = "") -> ArchiveState:
    if (state.format_hint or not format_hint) and (state.logical_name or not logical_name):
        return state
    return ArchiveState(
        source=state.source,
        logical_name=state.logical_name or logical_name,
        format_hint=state.format_hint or format_hint,
        analysis=dict(state.analysis),
        verification=dict(state.verification),
        knowledge=dict(state.knowledge),
    )


def _knowledge_from_raw(raw: dict[str, Any]) -> dict[str, Any]:
    knowledge = raw.get("knowledge")
    if isinstance(knowledge, dict):
        return dict(knowledge)
    analysis = raw.get("analysis")
    if isinstance(analysis, dict) and isinstance(analysis.get("knowledge"), dict):
        return dict(analysis["knowledge"])
    return {}
