from __future__ import annotations

import os
from contextlib import nullcontext
from dataclasses import dataclass, field
from typing import Any, List, Optional

from sunpack.contracts.archive_input import (
    ArchiveDescriptor,
    ArchiveFormatState,
    ArchiveInputDescriptor,
    ArchiveIntegrityState,
    ArchiveRelationState,
)
from sunpack.contracts.archive_knowledge import ArchiveKnowledge, merge_knowledge
from sunpack.contracts.archive_state import ArchiveState
from sunpack.contracts.discovery import ResolvedArchiveInput
from sunpack.support import archive_knowledge_projection as knowledge_view
from sunpack.support.path_keys import normalized_path, path_key
from sunpack.support.collections import dedupe_values


@dataclass
class SplitArchiveInfo:
    is_split: bool = False
    is_sfx_stub: bool = False
    archive_input: ArchiveInputDescriptor | None = None
    source: str = ""


@dataclass
class ArchiveTask:
    main_path: str
    archive_input_descriptor: ArchiveInputDescriptor | None = None
    key: str = ""
    all_parts: Optional[List[str]] = None
    carrier_path: str = ""
    cleanup_parts: Optional[List[str]] = None
    logical_name: str = ""
    split_info: SplitArchiveInfo = field(default_factory=SplitArchiveInfo)
    discovery_source: str = ""
    discovery_confidence: float = 1.0
    discovery_reasons: List[str] = field(default_factory=list)
    relation_kind: str = "file"
    decision: str = "archive"
    stop_reason: str = ""
    matched_rules: List[str] = field(default_factory=list)
    runtime: dict[str, Any] = field(default_factory=dict, repr=False)
    _knowledge: ArchiveKnowledge = field(default_factory=ArchiveKnowledge, init=False, repr=False)
    _archive_state: ArchiveState | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        self.main_path = normalized_path(self.main_path)
        self.all_parts = [normalized_path(path) for path in (self.all_parts or []) if path]
        descriptor = self.archive_input_descriptor or self.split_info.archive_input
        if descriptor is None:
            paths = self.all_parts or [self.main_path]
            if len(paths) > 1:
                raise ValueError("ArchiveTask multi-volume inputs require ArchiveInputDescriptor")
            descriptor = ArchiveInputDescriptor.from_parts(
                archive_path=self.main_path,
                part_paths=paths,
                logical_name=self.logical_name,
            )
        self._set_descriptor(descriptor)
        self.carrier_path = normalized_path(self.carrier_path or self.main_path)
        self.cleanup_parts = list(dedupe_values([
            *self.all_parts,
            *(self.cleanup_parts or []),
            self.carrier_path,
        ]))
        if not self.logical_name:
            self.logical_name = descriptor.logical_name or os.path.basename(self.main_path)
        if not self.key:
            self.key = self.logical_name if self.split_info.is_split else self.main_path
        self._archive_state = ArchiveState.from_archive_input(descriptor)
        self._knowledge = ArchiveKnowledge(_initial_knowledge(self))

    @classmethod
    def from_resolved_input(cls, resolved: ResolvedArchiveInput) -> "ArchiveTask":
        descriptor = resolved.archive_input
        is_split = descriptor.open_mode in {"native_volumes", "sfx_with_volumes"}
        reason = resolved.reasons[0] if resolved.reasons else ""
        task = cls(
            main_path=descriptor.entry_path,
            archive_input_descriptor=descriptor,
            key=descriptor.logical_name if is_split else descriptor.entry_path,
            all_parts=descriptor.part_paths(),
            carrier_path=resolved.carrier_path or descriptor.entry_path,
            cleanup_parts=list(resolved.cleanup_paths),
            logical_name=descriptor.logical_name,
            split_info=SplitArchiveInfo(
                is_split=is_split,
                is_sfx_stub=bool(
                    resolved.is_sfx or descriptor.open_mode == "sfx_with_volumes"
                ),
                archive_input=descriptor,
                source=resolved.source,
            ),
            discovery_source=resolved.source,
            discovery_confidence=float(resolved.confidence),
            discovery_reasons=list(resolved.reasons),
            relation_kind=resolved.relation_kind,
            decision="archive",
            stop_reason=reason,
            matched_rules=[resolved.source] if resolved.source else [],
        )
        if resolved.extractable_segments:
            task.knowledge().set(
                "source.extractable_segments",
                [dict(item) for item in resolved.extractable_segments],
                source_layer="discovery",
                source_module=resolved.source or "discovery",
            )
        if resolved.evidence:
            task.knowledge().set(
                "discovery.evidence",
                dict(resolved.evidence),
                source_layer="discovery",
                source_module=resolved.source or "discovery",
                confidence=float(resolved.confidence),
            )
        task._sync_state_knowledge()
        return task

    @classmethod
    def from_archive_input(
        cls,
        descriptor: ArchiveInputDescriptor,
        *,
        carrier_path: str = "",
        cleanup_paths: list[str] | None = None,
        discovery_source: str = "direct",
        relation_kind: str = "file",
    ) -> "ArchiveTask":
        return cls(
            main_path=descriptor.entry_path,
            archive_input_descriptor=descriptor,
            all_parts=descriptor.part_paths(),
            carrier_path=carrier_path or descriptor.entry_path,
            cleanup_parts=cleanup_paths,
            logical_name=descriptor.logical_name,
            split_info=SplitArchiveInfo(
                is_split=descriptor.open_mode in {"native_volumes", "sfx_with_volumes"},
                is_sfx_stub=descriptor.open_mode == "sfx_with_volumes",
                archive_input=descriptor,
                source=discovery_source,
            ),
            discovery_source=discovery_source,
            relation_kind=relation_kind,
            decision="direct_file" if discovery_source == "direct" else "archive",
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

        descriptor = self.archive_input().with_path_mapping(mapped)
        self.carrier_path = mapped(self.carrier_path or self.main_path)
        self.cleanup_parts = [mapped(path) for path in (self.cleanup_parts or [])]
        state = self.archive_state().with_path_mapping(mapped)
        self._set_descriptor(descriptor)
        self._archive_state = state
        self._sync_state_knowledge()

    def adopt_detection_plan(self, replacement: "ArchiveTask") -> None:
        self.key = replacement.key
        self.carrier_path = replacement.carrier_path
        self.cleanup_parts = list(replacement.cleanup_parts or [])
        self.logical_name = replacement.logical_name
        self.split_info = replacement.split_info
        self.discovery_source = replacement.discovery_source
        self.discovery_confidence = replacement.discovery_confidence
        self.discovery_reasons = list(replacement.discovery_reasons)
        self.relation_kind = replacement.relation_kind
        self.decision = replacement.decision
        self.stop_reason = replacement.stop_reason
        self.matched_rules = list(replacement.matched_rules or [])
        self.runtime = dict(replacement.runtime)
        self._knowledge = ArchiveKnowledge.from_any(replacement.knowledge())
        self._archive_state = replacement.archive_state()
        self._set_descriptor(replacement.archive_input())
        self._sync_state_knowledge()

    def archive_input(self) -> ArchiveInputDescriptor:
        if self._archive_state is not None:
            return self._archive_state.to_archive_input_descriptor()
        if self.archive_input_descriptor is None:
            raise ValueError("ArchiveTask is missing ArchiveInputDescriptor")
        return self.archive_input_descriptor

    def archive_state(self) -> ArchiveState:
        if self._archive_state is None:
            self._archive_state = ArchiveState.from_any(
                None,
                archive_path=self.main_path,
                part_paths=list(self.all_parts or [self.main_path]),
                format_hint=self._format_hint(),
                logical_name=self.logical_name,
                archive_input=self.archive_input().to_dict(),
            )
        return self._archive_state

    def knowledge(self) -> ArchiveKnowledge:
        return self._knowledge

    def set_knowledge(self, knowledge: ArchiveKnowledge | dict) -> None:
        self._knowledge = ArchiveKnowledge.from_any(knowledge)
        if self._archive_state is not None:
            state = self._archive_state
            self._archive_state = ArchiveState(
                source=state.source,
                logical_name=state.logical_name,
                format_hint=state.format_hint,
                analysis=dict(state.analysis),
                verification=dict(state.verification),
                knowledge=self._knowledge.to_dict(),
            )

    def ensure_archive_state(self) -> "ArchiveTask":
        self.archive_state()
        self._sync_state_knowledge()
        return self

    def set_archive_input(self, descriptor: ArchiveInputDescriptor | dict) -> None:
        if isinstance(descriptor, dict):
            descriptor = ArchiveInputDescriptor.from_any(
                descriptor,
                archive_path=self.main_path,
                part_paths=list(self.all_parts or [self.main_path]),
                format_hint=self._format_hint(),
                logical_name=self.logical_name,
            )
        self._set_descriptor(descriptor)
        self._archive_state = ArchiveState.from_archive_input(descriptor)
        self.knowledge().set(
            "source.input",
            descriptor.to_dict(),
            source_layer="contracts",
            source_module="archive_task",
        )
        self._sync_state_knowledge()

    def set_archive_state(
        self,
        state: ArchiveState | dict,
        *,
        phase_timer: Any | None = None,
        phase_prefix: str = "set_archive_state",
    ) -> None:
        if isinstance(state, dict):
            with _phase(phase_timer, f"{phase_prefix}_from_any"):
                state = ArchiveState.from_any(
                    state,
                    archive_path=self.main_path,
                    part_paths=list(self.all_parts or [self.main_path]),
                    format_hint=self._format_hint(),
                    logical_name=self.logical_name,
                    archive_input=self.archive_input().to_dict(),
                )
        self._store_archive_state(state, phase_timer=phase_timer, phase_prefix=phase_prefix)

    def _store_archive_state(
        self,
        state: ArchiveState,
        *,
        phase_timer: Any | None = None,
        phase_prefix: str = "store_archive_state",
    ) -> None:
        with _phase(phase_timer, f"{phase_prefix}_source_input"):
            descriptor = state.to_archive_input_descriptor()
            self._set_descriptor(descriptor)
            self.cleanup_parts = list(dedupe_values([
                *(self.cleanup_parts or []),
                *descriptor.part_paths(),
                self.carrier_path,
            ]))
        with _phase(phase_timer, f"{phase_prefix}_merge_knowledge"):
            state_snapshot = _archive_state_snapshot(state)
            knowledge = self._merged_state_knowledge(
                state,
                descriptor.to_dict(),
                state_snapshot,
            )
        if knowledge:
            state = ArchiveState(
                source=state.source,
                logical_name=state.logical_name,
                format_hint=state.format_hint,
                analysis=dict(state.analysis),
                verification=dict(state.verification),
                knowledge=knowledge,
            )
        self._archive_state = state
        self._knowledge = ArchiveKnowledge.from_any(state.knowledge)
        self._sync_state_knowledge()

    def archive_descriptor(self) -> ArchiveDescriptor:
        source = self.archive_input()
        selected_format = knowledge_view.selected_format(self)
        confidence = 0.0
        selected_segment = knowledge_view.source_selected_segment(self)
        evidence = (
            selected_segment.get("segment")
            if isinstance(selected_segment.get("segment"), dict)
            else selected_segment
        )
        if isinstance(evidence, dict):
            confidence = float(
                evidence.get("confidence", selected_segment.get("confidence", 0.0)) or 0.0
            )
        damage_flags: list[str] = []
        if isinstance(evidence, dict):
            damage_flags.extend(evidence.get("damage_flags") or [])
        relation = ArchiveRelationState(
            kind=self.relation_kind or ("split_archive" if self.split_info.is_split else "file"),
            is_split=bool(self.split_info.is_split),
            is_sfx=bool(self.split_info.is_sfx_stub),
        )
        detected = source.format_hint
        return ArchiveDescriptor(
            id=str(self.key or self.main_path),
            logical_name=self.logical_name,
            source=source,
            format=ArchiveFormatState(
                detected=detected,
                selected=selected_format,
                hint=source.format_hint,
                confidence=confidence or self.discovery_confidence,
                status=knowledge_view.inspection_status(self),
            ),
            relation=relation,
            integrity=ArchiveIntegrityState(
                damage_flags=_dedupe([str(item) for item in damage_flags])
            ),
        )

    def _format_hint(self) -> str:
        knowledge = self.knowledge()
        return str(
            knowledge.get("inspection.summary.format", "")
            or knowledge.get("archive.format_hint", "")
            or knowledge.get("source.input.format_hint", "")
            or (self.archive_input_descriptor.format_hint if self.archive_input_descriptor else "")
            or ""
        ).lstrip(".")

    def _set_descriptor(self, descriptor: ArchiveInputDescriptor) -> None:
        self.archive_input_descriptor = descriptor
        self.main_path = normalized_path(descriptor.entry_path)
        self.all_parts = [normalized_path(path) for path in descriptor.part_paths()]
        if descriptor.logical_name:
            self.logical_name = descriptor.logical_name
        if self.split_info is None:
            self.split_info = SplitArchiveInfo()
        self.split_info.archive_input = descriptor
        self.split_info.is_split = descriptor.open_mode in {"native_volumes", "sfx_with_volumes"}
        self.split_info.is_sfx_stub = bool(
            descriptor.open_mode == "sfx_with_volumes" or self.split_info.is_sfx_stub
        )

    def _sync_state_knowledge(self) -> None:
        descriptor = self.archive_input_descriptor
        if descriptor is None:
            return
        self._knowledge.set_prepared(
            "source.input",
            descriptor.to_dict(),
            source_layer="contracts",
            source_module="archive_task",
        )
        if self._archive_state is not None:
            snapshot = _archive_state_snapshot(self._archive_state)
            self._knowledge.set_prepared(
                "archive.state",
                snapshot,
                source_layer="contracts",
                source_module="archive_task",
            )
            state = self._archive_state
            self._archive_state = ArchiveState(
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
        if self._archive_state is not None:
            state = self._archive_state
            self._archive_state = ArchiveState(
                source=state.source,
                logical_name=state.logical_name,
                format_hint=state.format_hint,
                analysis=dict(state.analysis),
                verification=dict(state.verification),
                knowledge=self._knowledge.to_dict(),
            )

    def _merged_state_knowledge(
        self,
        state: ArchiveState,
        source_input: dict[str, Any],
        state_snapshot: dict[str, Any],
    ) -> dict[str, Any]:
        existing = self._knowledge.to_dict()
        additions = {
            "source": {"input": source_input},
            "archive": {"state": state_snapshot},
        }
        if state.knowledge:
            return merge_knowledge(existing, state.knowledge, additions)
        knowledge = dict(existing)
        source = (
            dict(knowledge.get("source") or {})
            if isinstance(knowledge.get("source"), dict)
            else {}
        )
        source["input"] = source_input
        archive = (
            dict(knowledge.get("archive") or {})
            if isinstance(knowledge.get("archive"), dict)
            else {}
        )
        archive["state"] = state_snapshot
        knowledge["source"] = source
        knowledge["archive"] = archive
        return knowledge


def _initial_knowledge(task: ArchiveTask) -> dict[str, Any]:
    descriptor = task.archive_input_descriptor
    assert descriptor is not None
    return {
        "filesystem": {
            "path": task.carrier_path or task.main_path,
            "carrier_path": task.carrier_path or task.main_path,
        },
        "source": {
            "input": descriptor.to_dict(),
            "derivation": {
                "kind": task.relation_kind or ("split_archive" if task.split_info.is_split else "file"),
                "entry_path": task.main_path,
                "member_paths": list(task.all_parts or []),
                "carrier_path": task.carrier_path or task.main_path,
                "cleanup_paths": list(task.cleanup_parts or []),
                "logical_name": task.logical_name,
                "discovery_source": task.discovery_source,
                "discovery_confidence": float(task.discovery_confidence),
                "discovery_reasons": list(task.discovery_reasons),
            },
        },
        "relations": {
            "is_split": bool(task.split_info.is_split),
            "is_sfx": bool(task.split_info.is_sfx_stub),
            "archive_input": descriptor.to_dict(),
        },
        "discovery": {
            "source": task.discovery_source,
            "confidence": float(task.discovery_confidence),
            "reasons": list(task.discovery_reasons),
        },
    }


def _archive_state_snapshot(state: ArchiveState) -> dict[str, Any]:
    payload = state.to_dict()
    payload.pop("knowledge", None)
    return payload


def _phase(timer: Any | None, name: str):
    if timer is None:
        return nullcontext()
    return timer(name)


_dedupe = dedupe_values
