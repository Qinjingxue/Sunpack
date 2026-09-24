from __future__ import annotations

from dataclasses import InitVar, dataclass, field
from typing import Any

from sunpack.core.contracts.archive_input import ArchiveInputDescriptor
from sunpack.core.contracts.archive_knowledge import ArchiveKnowledge
from sunpack.core.contracts.discovery import ResolvedArchiveInput, ResolvedArchiveSegment
from sunpack.core.support.collections import dedupe_values
from sunpack.core.support.path_keys import normalized_path, path_key


@dataclass
class ArchiveTask:
    _archive_input: InitVar[ArchiveInputDescriptor]
    carrier_path: str = ""
    cleanup_parts: list[str] = field(default_factory=list)
    key: str = ""
    initial_discovery_source: InitVar[str] = ""
    discovery_evidence: InitVar[dict[str, Any] | None] = None
    discovery_segments: InitVar[tuple[ResolvedArchiveSegment, ...]] = ()
    initial_discovery_reason: InitVar[str] = ""
    runtime: dict[str, Any] = field(default_factory=dict)

    def __post_init__(
        self,
        _archive_input: ArchiveInputDescriptor,
        initial_discovery_source: str,
        discovery_evidence: dict[str, Any] | None,
        discovery_segments: tuple[ResolvedArchiveSegment, ...],
        initial_discovery_reason: str,
    ) -> None:
        descriptor = _archive_input
        if not descriptor.entry_path:
            raise ValueError("ArchiveTask requires an archive input entry path")
        logical_name = str(descriptor.logical_name or descriptor.entry_path)
        self.carrier_path = str(self.carrier_path or descriptor.entry_path)
        self.cleanup_parts = list(dedupe_values([
            *descriptor.part_paths(),
            *self.cleanup_parts,
            self.carrier_path,
        ]))
        if not self.key:
            self.key = (
                logical_name
                if descriptor.open_mode in {"native_volumes", "sfx_with_volumes"}
                else descriptor.entry_path
            )
        self._knowledge = ArchiveKnowledge()
        self._archive_input = descriptor
        self._initialize_knowledge(
            discovery_source=str(initial_discovery_source or ""),
            discovery_reason=str(initial_discovery_reason or ""),
            discovery_evidence=dict(discovery_evidence or {}),
            discovery_segments=tuple(discovery_segments),
        )

    @classmethod
    def from_archive_input(
        cls,
        descriptor: ArchiveInputDescriptor,
        *,
        discovery_source: str,
        carrier_path: str = "",
        cleanup_paths: list[str] | tuple[str, ...] = (),
        discovery_evidence: dict[str, Any] | None = None,
        discovery_segments: tuple[ResolvedArchiveSegment, ...] = (),
        discovery_reason: str = "",
    ) -> "ArchiveTask":
        return cls(
            _archive_input=descriptor,
            carrier_path=carrier_path or descriptor.entry_path,
            cleanup_parts=list(cleanup_paths),
            initial_discovery_source=discovery_source,
            discovery_evidence=dict(discovery_evidence or {}),
            discovery_segments=tuple(discovery_segments),
            initial_discovery_reason=discovery_reason,
        )

    @classmethod
    def from_resolved(
        cls,
        resolved: ResolvedArchiveInput,
        *,
        discovery_reason: str = "",
    ) -> "ArchiveTask":
        return cls.from_archive_input(
            resolved.archive_input,
            discovery_source=resolved.source,
            carrier_path=resolved.carrier_path,
            cleanup_paths=resolved.cleanup_paths,
            discovery_evidence=resolved.evidence,
            discovery_segments=resolved.segments,
            discovery_reason=discovery_reason,
        )

    @property
    def logical_name(self) -> str:
        descriptor = self.archive_input()
        return str(descriptor.logical_name or descriptor.entry_path)

    @property
    def discovery_source(self) -> str:
        return str(self._knowledge.get("discovery.source", "") or "")

    @property
    def discovery_reason(self) -> str:
        return str(self._knowledge.get("discovery.reason", "") or "")

    @property
    def main_path(self) -> str:
        return self.archive_input().entry_path

    @property
    def all_parts(self) -> list[str]:
        return self.archive_input().part_paths()

    def archive_input(self) -> ArchiveInputDescriptor:
        return self._archive_input

    def knowledge(self) -> ArchiveKnowledge:
        return self._knowledge

    def set_knowledge(self, knowledge: ArchiveKnowledge | dict) -> None:
        self._knowledge = ArchiveKnowledge.from_any(knowledge)

    def _replace_knowledge_payload(
        self,
        payload: dict[str, Any],
        *,
        knowledge_cache: ArchiveKnowledge | None = None,
    ) -> None:
        self._knowledge = (
            knowledge_cache
            if knowledge_cache is not None
            else ArchiveKnowledge.from_any(payload)
        )

    def set_archive_input(self, descriptor: ArchiveInputDescriptor) -> None:
        self.cleanup_parts = list(dedupe_values([
            *descriptor.part_paths(),
            *self.cleanup_parts,
            self.carrier_path,
        ]))
        self._archive_input = descriptor

    def apply_path_mapping(self, path_map: dict[str, str]) -> None:
        if not path_map:
            return
        normalized_map = {
            path_key(old): normalized_path(new)
            for old, new in path_map.items()
        }

        def mapped(path: str) -> str:
            return normalized_map.get(path_key(path), path)

        self.carrier_path = mapped(self.carrier_path or self.main_path)
        self.cleanup_parts = [mapped(path) for path in self.cleanup_parts]
        self.set_archive_input(self.archive_input().with_path_mapping(mapped))

    def adopt_detection_plan(self, replacement: "ArchiveTask") -> None:
        runtime = dict(self.runtime)
        self.carrier_path = replacement.carrier_path
        self.cleanup_parts = list(replacement.cleanup_parts)
        self.key = replacement.key
        self._knowledge = ArchiveKnowledge.from_any(replacement.knowledge())
        self._archive_input = replacement.archive_input()
        self.runtime = runtime

    def _initialize_knowledge(
        self,
        *,
        discovery_source: str,
        discovery_reason: str,
        discovery_evidence: dict[str, Any],
        discovery_segments: tuple[ResolvedArchiveSegment, ...],
    ) -> None:
        descriptor = self.archive_input()
        self._knowledge.merge({
            "discovery": {
                "source": discovery_source,
                "reason": discovery_reason,
                "evidence": dict(discovery_evidence),
            },
        }, source_layer="contracts", source_module="archive_task")
        if discovery_segments:
            self._knowledge.set(
                "source.extractable_segments",
                [
                    _segment_payload(index, segment)
                    for index, segment in enumerate(discovery_segments, start=1)
                ],
                source_layer="discovery",
                source_module=discovery_source or "discovery",
            )
            self._knowledge.set(
                "source.selected_segment",
                _segment_payload(1, discovery_segments[0]),
                source_layer="discovery",
                source_module=self.discovery_source or "discovery",
            )
        prepass = discovery_evidence.get("scan")
        if isinstance(prepass, dict):
            self._knowledge.set(
                "inspection.prepass",
                prepass,
                source_layer="embedded",
                source_module="discovery",
            )


def _segment_payload(index: int, segment: ResolvedArchiveSegment) -> dict[str, Any]:
    descriptor = segment.archive_input
    return {
        "segment_id": f"embedded_{index:02d}_{segment.format.replace('/', '_')}",
        "index": index,
        "format": segment.format,
        "start_offset": segment.start_offset,
        "end_offset": segment.end_offset,
        "confidence": segment.confidence,
        "damage_flags": list(segment.damage_flags),
        "logical_name": descriptor.logical_name,
        "segment": dict(segment.evidence),
        "archive_input": descriptor.to_dict(),
    }
