from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sunpack.contracts.archive_input import (
    ArchiveDescriptor,
    ArchiveFormatState,
    ArchiveInputDescriptor,
    ArchiveIntegrityState,
    ArchiveRelationState,
)
from sunpack.contracts.archive_knowledge import ArchiveKnowledge
from sunpack.contracts.archive_state import ArchiveState
from sunpack.contracts.discovery import ResolvedArchiveInput, ResolvedArchiveSegment
from sunpack.support import archive_knowledge_projection as knowledge_view
from sunpack.support.collections import dedupe_values
from sunpack.support.path_keys import normalized_path, path_key


@dataclass
class SplitArchiveInfo:
    is_split: bool = False
    is_sfx_stub: bool = False
    archive_input: ArchiveInputDescriptor | None = None
    source: str = ""


@dataclass
class ArchiveTask:
    _archive_input: ArchiveInputDescriptor
    carrier_path: str = ""
    cleanup_parts: list[str] = field(default_factory=list)
    key: str = ""
    logical_name: str = ""
    split_info: SplitArchiveInfo = field(default_factory=SplitArchiveInfo)
    discovery_source: str = ""
    discovery_evidence: dict[str, Any] = field(default_factory=dict)
    discovery_segments: tuple[ResolvedArchiveSegment, ...] = ()
    relation_kind: str = "file"
    discovery_reason: str = ""
    runtime: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        descriptor = self._archive_input
        if not descriptor.entry_path:
            raise ValueError("ArchiveTask requires an archive input entry path")
        self.logical_name = str(
            self.logical_name
            or descriptor.logical_name
            or descriptor.entry_path
        )
        self.carrier_path = str(self.carrier_path or descriptor.entry_path)
        self.cleanup_parts = list(dedupe_values([
            *descriptor.part_paths(),
            *self.cleanup_parts,
            self.carrier_path,
        ]))
        if not self.key:
            self.key = (
                self.logical_name
                if descriptor.open_mode in {"native_volumes", "sfx_with_volumes"}
                else descriptor.entry_path
            )
        self.split_info = SplitArchiveInfo(
            is_split=descriptor.open_mode in {"native_volumes", "sfx_with_volumes"},
            is_sfx_stub=bool(
                descriptor.open_mode == "sfx_with_volumes"
                or self.split_info.is_sfx_stub
            ),
            archive_input=descriptor,
            source=self.split_info.source or self.discovery_source,
        )
        self._knowledge = ArchiveKnowledge()
        self._state = ArchiveState.from_archive_input(descriptor)
        self._initialize_knowledge()

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
        relation_kind: str = "file",
        discovery_reason: str = "",
    ) -> "ArchiveTask":
        return cls(
            _archive_input=descriptor,
            carrier_path=carrier_path or descriptor.entry_path,
            cleanup_parts=list(cleanup_paths),
            logical_name=descriptor.logical_name,
            split_info=SplitArchiveInfo(
                is_split=descriptor.open_mode in {"native_volumes", "sfx_with_volumes"},
                is_sfx_stub=descriptor.open_mode == "sfx_with_volumes",
                archive_input=descriptor,
                source=discovery_source,
            ),
            discovery_source=discovery_source,
            discovery_evidence=dict(discovery_evidence or {}),
            discovery_segments=tuple(discovery_segments),
            relation_kind=relation_kind,
            discovery_reason=discovery_reason,
        )

    @classmethod
    def from_resolved(
        cls,
        resolved: ResolvedArchiveInput,
        *,
        discovery_reason: str = "",
    ) -> "ArchiveTask":
        relation_kind = (
            "split_archive"
            if resolved.archive_input.open_mode in {"native_volumes", "sfx_with_volumes"}
            else "file"
        )
        return cls.from_archive_input(
            resolved.archive_input,
            discovery_source=resolved.source,
            carrier_path=resolved.carrier_path,
            cleanup_paths=resolved.cleanup_paths,
            discovery_evidence=resolved.evidence,
            discovery_segments=resolved.segments,
            relation_kind=relation_kind,
            discovery_reason=discovery_reason,
        )

    @property
    def main_path(self) -> str:
        return self.archive_input().entry_path

    @property
    def all_parts(self) -> list[str]:
        return self.archive_input().part_paths()

    def archive_input(self) -> ArchiveInputDescriptor:
        return self._state.to_archive_input_descriptor()

    def archive_state(self) -> ArchiveState:
        return self._state

    def knowledge(self) -> ArchiveKnowledge:
        return self._knowledge

    def set_knowledge(self, knowledge: ArchiveKnowledge | dict) -> None:
        self._knowledge = ArchiveKnowledge.from_any(knowledge)
        state = self._state
        self._state = ArchiveState(
            source=state.source,
            logical_name=state.logical_name,
            format_hint=state.format_hint,
            analysis=dict(state.analysis),
            verification=dict(state.verification),
            knowledge=self._knowledge.to_dict(),
        )

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
        state = self._state
        self._state = ArchiveState(
            source=state.source,
            logical_name=state.logical_name,
            format_hint=state.format_hint,
            analysis=dict(state.analysis),
            verification=dict(state.verification),
            knowledge=self._knowledge.to_dict(),
        )

    def ensure_archive_state(self) -> "ArchiveTask":
        return self

    def set_archive_input(self, descriptor: ArchiveInputDescriptor | dict) -> None:
        if isinstance(descriptor, dict):
            descriptor = ArchiveInputDescriptor.from_any(
                descriptor,
                archive_path=self.main_path,
                part_paths=self.all_parts,
                format_hint=self.archive_input().format_hint,
                logical_name=self.logical_name,
            )
        state = self._state
        self._archive_input = descriptor
        self.logical_name = descriptor.logical_name or self.logical_name
        self.cleanup_parts = list(dedupe_values([
            *descriptor.part_paths(),
            *self.cleanup_parts,
            self.carrier_path,
        ]))
        self.split_info = SplitArchiveInfo(
            is_split=descriptor.open_mode in {"native_volumes", "sfx_with_volumes"},
            is_sfx_stub=bool(
                descriptor.open_mode == "sfx_with_volumes"
                or self.split_info.is_sfx_stub
            ),
            archive_input=descriptor,
            source=self.split_info.source or self.discovery_source,
        )
        self._knowledge.set(
            "source.input",
            descriptor.to_dict(),
            source_layer="contracts",
            source_module="archive_task",
        )
        self._state = ArchiveState(
            source=ArchiveState.from_archive_input(descriptor).source,
            logical_name=descriptor.logical_name or self.logical_name,
            format_hint=descriptor.format_hint,
            analysis=dict(state.analysis),
            verification=dict(state.verification),
            knowledge=self._knowledge.to_dict(),
        )

    def set_archive_state(
        self,
        state: ArchiveState | dict,
        *,
        phase_timer: Any | None = None,
        phase_prefix: str = "set_archive_state",
    ) -> None:
        del phase_timer, phase_prefix
        if isinstance(state, dict):
            state = ArchiveState.from_any(
                state,
                archive_path=self.main_path,
                part_paths=self.all_parts,
                format_hint=self.archive_input().format_hint,
                logical_name=self.logical_name,
                archive_input=self.archive_input().to_dict(),
            )
        descriptor = state.to_archive_input_descriptor()
        self._archive_input = descriptor
        self.logical_name = descriptor.logical_name or state.logical_name or self.logical_name
        self.cleanup_parts = list(dedupe_values([
            *descriptor.part_paths(),
            *self.cleanup_parts,
            self.carrier_path,
        ]))
        self.split_info = SplitArchiveInfo(
            is_split=descriptor.open_mode in {"native_volumes", "sfx_with_volumes"},
            is_sfx_stub=bool(
                descriptor.open_mode == "sfx_with_volumes"
                or self.split_info.is_sfx_stub
            ),
            archive_input=descriptor,
            source=self.split_info.source or self.discovery_source,
        )
        knowledge = ArchiveKnowledge.from_any(state.knowledge)
        knowledge.merge(self._knowledge)
        knowledge.set(
            "source.input",
            descriptor.to_dict(),
            source_layer="contracts",
            source_module="archive_task",
        )
        self._knowledge = knowledge
        self._state = ArchiveState(
            source=state.source,
            logical_name=state.logical_name or self.logical_name,
            format_hint=state.format_hint or descriptor.format_hint,
            analysis=dict(state.analysis),
            verification=dict(state.verification),
            knowledge=knowledge.to_dict(),
        )

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
        self._archive_input = replacement.archive_input()
        self.carrier_path = replacement.carrier_path
        self.cleanup_parts = list(replacement.cleanup_parts)
        self.key = replacement.key
        self.logical_name = replacement.logical_name
        self.split_info = replacement.split_info
        self.discovery_source = replacement.discovery_source
        self.discovery_evidence = dict(replacement.discovery_evidence)
        self.discovery_segments = tuple(replacement.discovery_segments)
        self.relation_kind = replacement.relation_kind
        self.discovery_reason = replacement.discovery_reason
        self._knowledge = ArchiveKnowledge.from_any(replacement.knowledge())
        self._state = replacement.archive_state()
        self.runtime = runtime

    def archive_descriptor(self) -> ArchiveDescriptor:
        source = self.archive_input()
        selected_format = knowledge_view.selected_format(self) or source.format_hint
        selected_segment = knowledge_view.source_selected_segment(self)
        evidence = (
            selected_segment.get("segment")
            if isinstance(selected_segment.get("segment"), dict)
            else selected_segment
        )
        confidence = 0.0
        damage_flags: list[str] = []
        if isinstance(evidence, dict):
            confidence = float(
                evidence.get("confidence", selected_segment.get("confidence", 0.0))
                or 0.0
            )
            damage_flags.extend(evidence.get("damage_flags") or [])
        return ArchiveDescriptor(
            id=str(self.key or self.main_path),
            logical_name=str(self.logical_name or ""),
            source=source,
            format=ArchiveFormatState(
                detected=source.format_hint,
                selected=selected_format,
                hint=source.format_hint,
                confidence=confidence,
                status=knowledge_view.inspection_status(self),
            ),
            relation=ArchiveRelationState(
                kind=self.relation_kind,
                is_split=bool(self.split_info.is_split),
                is_sfx=bool(self.split_info.is_sfx_stub),
            ),
            integrity=ArchiveIntegrityState(
                damage_flags=list(dict.fromkeys(str(item) for item in damage_flags))
            ),
        )

    def _initialize_knowledge(self) -> None:
        descriptor = self._archive_input
        self._knowledge.merge({
            "source": {
                "input": descriptor.to_dict(),
                "derivation": {
                    "kind": self.relation_kind,
                    "candidate_entry_path": descriptor.entry_path,
                    "candidate_member_paths": descriptor.part_paths(),
                    "candidate_carrier_path": self.carrier_path,
                    "candidate_cleanup_paths": list(self.cleanup_parts),
                    "candidate_logical_name": self.logical_name,
                },
            },
            "discovery": {
                "source": self.discovery_source,
                "reason": self.discovery_reason,
                "evidence": dict(self.discovery_evidence),
            },
            "relations": {
                "is_split": bool(self.split_info.is_split),
                "is_sfx_stub": bool(self.split_info.is_sfx_stub),
                "archive_input": descriptor.to_dict(),
            },
        }, source_layer="contracts", source_module="archive_task")
        if self.discovery_segments:
            self._knowledge.set(
                "source.extractable_segments",
                [
                    _segment_payload(index, segment)
                    for index, segment in enumerate(self.discovery_segments, start=1)
                ],
                source_layer="discovery",
                source_module=self.discovery_source or "discovery",
            )
            self._knowledge.set(
                "source.selected_segment",
                _segment_payload(1, self.discovery_segments[0]),
                source_layer="discovery",
                source_module=self.discovery_source or "discovery",
            )
        prepass = self.discovery_evidence.get("scan")
        if isinstance(prepass, dict):
            self._knowledge.set(
                "inspection.prepass",
                prepass,
                source_layer="embedded",
                source_module="discovery",
            )
        self._state = ArchiveState(
            source=self._state.source,
            logical_name=self._state.logical_name,
            format_hint=self._state.format_hint,
            analysis=dict(self._state.analysis),
            verification=dict(self._state.verification),
            knowledge=self._knowledge.to_dict(),
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
