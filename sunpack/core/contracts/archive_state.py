from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sunpack.core.contracts.archive_input import (
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

    @classmethod
    def from_archive_input(
        cls,
        descriptor: ArchiveInputDescriptor,
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
        )


@dataclass(frozen=True)
class ArchiveState:
    source: ArchiveSource
    logical_name: str = ""
    format_hint: str = ""
    analysis: dict[str, Any] = field(default_factory=dict)
    verification: dict[str, Any] = field(default_factory=dict)
    knowledge: dict[str, Any] = field(default_factory=dict)

    def to_archive_input_descriptor(self) -> ArchiveInputDescriptor:
        descriptor = self.source.to_archive_input_descriptor()
        analysis = dict(descriptor.analysis)
        analysis.update(self.analysis)
        if (
            not self.format_hint
            and not self.logical_name
            and analysis == descriptor.analysis
        ):
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
            analysis=analysis,
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
