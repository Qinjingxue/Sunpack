from contextlib import nullcontext
from dataclasses import dataclass, field
from typing import Any, Optional, List
from sunpack.contracts.archive_input import (
    ArchiveDescriptor,
    ArchiveFormatState,
    ArchiveInputDescriptor,
    ArchiveIntegrityState,
    ArchiveRelationState,
)
from sunpack.contracts.archive_knowledge import ArchiveKnowledge, merge_knowledge
from sunpack.contracts.archive_state import ArchiveState
from sunpack.contracts.detection import FactBag
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
    fact_bag: FactBag
    key: str = ""
    main_path: str = ""
    all_parts: Optional[List[str]] = None
    carrier_path: str = ""
    cleanup_parts: Optional[List[str]] = None
    logical_name: str = ""
    split_info: SplitArchiveInfo = field(default_factory=SplitArchiveInfo)
    decision: str = "archive"
    stop_reason: str = ""
    matched_rules: List[str] = field(default_factory=list)
    detected_ext: str = ""

    def __post_init__(self):
        self._archive_knowledge_cache_raw = None
        self._archive_knowledge_cache = None
        self._archive_state_cache_raw = None
        self._archive_state_cache_knowledge_raw = None
        self._archive_state_cache = None
        self.all_parts = list(self.all_parts or [])
        if not self.main_path:
            raise ValueError("ArchiveTask.main_path is required")
        self.carrier_path = str(
            self.carrier_path
            or self.fact_bag.get("candidate.carrier_path")
            or self.fact_bag.get("file.path")
            or self.main_path
        )
        if self.cleanup_parts is None:
            self.cleanup_parts = list(self.fact_bag.get("candidate.cleanup_paths") or [])
        self.cleanup_parts = list(dedupe_values([
            *self.all_parts,
            *self.cleanup_parts,
            self.carrier_path,
        ]))
        if not self.key:
            self.key = self.logical_name or self.main_path
        if self.split_info is None:
            self.split_info = SplitArchiveInfo()
        if self.split_info.archive_input is not None:
            self.all_parts = self.split_info.archive_input.part_paths()
            self.main_path = self.split_info.archive_input.entry_path
            self.cleanup_parts = list(dedupe_values([
                *self.all_parts,
                *(self.cleanup_parts or []),
                self.carrier_path,
            ]))
            self.split_info.is_split = self.split_info.archive_input.open_mode in {"native_volumes", "sfx_with_volumes"}
        if not isinstance(self.fact_bag.get("archive.knowledge"), dict):
            self._write_detection_boundary_knowledge()

    @classmethod
    def from_fact_bag(cls, fact_bag: FactBag, decision=None) -> "ArchiveTask":
        main_path = fact_bag.get("candidate.entry_path") or ""
        all_parts = list(fact_bag.get("candidate.member_paths") or [])
        carrier_path = str(fact_bag.get("candidate.carrier_path") or fact_bag.get("file.path") or main_path)
        cleanup_parts = list(fact_bag.get("candidate.cleanup_paths") or [])
        cleanup_parts = list(dedupe_values([*all_parts, *cleanup_parts, carrier_path]))
        logical_name = fact_bag.get("candidate.logical_name") or ""
        is_split = bool(
            fact_bag.get("relation.is_split_related")
            or fact_bag.get("candidate.kind") == "split_archive"
            or len(all_parts) > 1
        )
        key = logical_name if is_split else main_path
        is_sfx_stub = bool(
            fact_bag.get("relation.has_split_companions")
            or fact_bag.get("relation.is_split_exe_companion")
            or fact_bag.get("relation.is_disguised_split_exe_companion")
            or fact_bag.get("candidate.companion_paths")
        )
        state = ArchiveState.from_any(
            fact_bag.get("archive.state"),
            archive_path=main_path,
            part_paths=all_parts,
            logical_name=logical_name,
        )
        archive_input = state.to_archive_input_descriptor()
        split_info = SplitArchiveInfo(
            is_split=is_split or len(all_parts) > 1,
            is_sfx_stub=is_sfx_stub,
            archive_input=archive_input,
            source="detection" if is_split or is_sfx_stub else "",
        )
        task = cls(
            fact_bag=fact_bag,
            key=key,
            main_path=main_path,
            all_parts=all_parts,
            carrier_path=carrier_path,
            cleanup_parts=cleanup_parts,
            logical_name=logical_name,
            split_info=split_info,
            decision=getattr(decision, "decision", "archive"),
            stop_reason=getattr(decision, "stop_reason", "") or "",
            matched_rules=list(getattr(decision, "matched_rules", []) or []),
            detected_ext=fact_bag.get("file.detected_ext", ""),
        )
        task._write_detection_boundary_knowledge()
        return task.ensure_archive_state()

    def apply_path_mapping(self, path_map: dict[str, str]):
        if not path_map:
            return

        normalized_map = {
            path_key(old): normalized_path(new)
            for old, new in path_map.items()
        }

        def mapped(path: str) -> str:
            return normalized_map.get(path_key(path), path)

        self.main_path = mapped(self.main_path)
        self.all_parts = [mapped(path) for path in self.all_parts]
        self.carrier_path = mapped(self.carrier_path or self.main_path)
        self.cleanup_parts = [mapped(path) for path in (self.cleanup_parts or [])]
        if self.split_info.archive_input is not None:
            self.split_info.archive_input = self.split_info.archive_input.with_path_mapping(mapped)
        self.fact_bag.set("file.path", self.carrier_path or self.main_path)
        self.fact_bag.set("candidate.entry_path", self.main_path)
        self.fact_bag.set("candidate.member_paths", list(self.all_parts))
        self.fact_bag.set("candidate.carrier_path", self.carrier_path or self.main_path)
        self.fact_bag.set("candidate.cleanup_paths", list(self.cleanup_parts))
        self.fact_bag.set("file.split_members", [path for path in self.all_parts if path != self.main_path])
        try:
            self.set_archive_state(self.archive_state().with_path_mapping(mapped))
        except (TypeError, ValueError):
            self.set_archive_input(self.archive_input().with_path_mapping(mapped))

    def adopt_detection_plan(self, replacement: "ArchiveTask") -> None:
        """Replace this task's detection/input plan while preserving its identity."""
        self.fact_bag = replacement.fact_bag
        self.key = replacement.key
        self.main_path = replacement.main_path
        self.all_parts = list(replacement.all_parts or [])
        self.carrier_path = replacement.carrier_path
        self.cleanup_parts = list(replacement.cleanup_parts or [])
        self.logical_name = replacement.logical_name
        self.split_info = replacement.split_info
        self.decision = replacement.decision
        self.stop_reason = replacement.stop_reason
        self.matched_rules = list(replacement.matched_rules or [])
        self.detected_ext = replacement.detected_ext
        self._archive_knowledge_cache_raw = None
        self._archive_knowledge_cache = None
        self._archive_state_cache_raw = None
        self._archive_state_cache_knowledge_raw = None
        self._archive_state_cache = None
        self.ensure_archive_state()

    def archive_input(self) -> ArchiveInputDescriptor:
        raw_state = self._raw_archive_state()
        if isinstance(raw_state, dict):
            return self.archive_state().to_archive_input_descriptor()
        knowledge_input = self.knowledge().get("source.input")
        if isinstance(knowledge_input, dict):
            return ArchiveInputDescriptor.from_any(
                knowledge_input,
                archive_path=self.main_path,
                part_paths=list(self.all_parts or [self.main_path]),
                format_hint=self._format_hint(),
                logical_name=str(self.logical_name or ""),
            )
        raise ValueError("ArchiveTask is missing ArchiveKnowledge source.input")

    def archive_state(self) -> ArchiveState:
        raw_state = self._raw_archive_state()
        knowledge_raw = self.fact_bag.get("archive.knowledge")
        if (
            raw_state is self._archive_state_cache_raw
            and knowledge_raw is self._archive_state_cache_knowledge_raw
            and isinstance(self._archive_state_cache, ArchiveState)
        ):
            return self._archive_state_cache
        archive_input = self.knowledge().get("source.input")
        state = ArchiveState.from_any(
            self._raw_archive_state(),
            archive_path=self.main_path,
            part_paths=list(self.all_parts or [self.main_path]),
            format_hint=self._format_hint(),
            logical_name=str(self.logical_name or ""),
            archive_input=archive_input,
        )
        self._archive_state_cache_raw = raw_state
        self._archive_state_cache_knowledge_raw = knowledge_raw
        self._archive_state_cache = state
        return state

    def knowledge(self) -> ArchiveKnowledge:
        raw = self.fact_bag.get("archive.knowledge")
        if raw is self._archive_knowledge_cache_raw and isinstance(self._archive_knowledge_cache, ArchiveKnowledge):
            return self._archive_knowledge_cache
        knowledge = ArchiveKnowledge.from_any(raw)
        self._archive_knowledge_cache_raw = raw
        self._archive_knowledge_cache = knowledge
        return knowledge

    def set_knowledge(self, knowledge: ArchiveKnowledge | dict) -> None:
        payload = ArchiveKnowledge.from_any(knowledge).to_dict()
        self._replace_knowledge_payload(payload, knowledge_cache=ArchiveKnowledge(payload))
        raw_state = self._raw_archive_state()
        if isinstance(raw_state, dict):
            state = self.archive_state()
            self._store_archive_state(ArchiveState(
                source=state.source,
                logical_name=state.logical_name,
                format_hint=state.format_hint,
                analysis=dict(state.analysis),
                verification=dict(state.verification),
                knowledge=payload,
            ))

    def ensure_archive_state(self) -> "ArchiveTask":
        if not isinstance(self._raw_archive_state(), dict):
            self.set_archive_state(self.archive_state())
        elif not isinstance(self.fact_bag.get("archive.knowledge"), dict):
            self.set_knowledge(self.knowledge())
        return self

    def set_archive_input(self, descriptor: ArchiveInputDescriptor | dict) -> None:
        if isinstance(descriptor, dict):
            descriptor = ArchiveInputDescriptor.from_any(
                descriptor,
                archive_path=self.main_path,
                part_paths=list(self.all_parts or [self.main_path]),
                format_hint=self._format_hint(),
                logical_name=str(self.logical_name or ""),
            )
        self.fact_bag.set("archive.input", descriptor.to_dict())
        self.fact_bag.set("archive.descriptor.source", descriptor.to_dict())
        knowledge = self.knowledge()
        knowledge.set("source.input", descriptor.to_dict(), source_layer="contracts", source_module="archive_task")
        payload = knowledge.to_dict()
        self._replace_knowledge_payload(payload, knowledge_cache=ArchiveKnowledge(payload))
        self._store_archive_state(ArchiveState.from_archive_input(descriptor))

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
                    logical_name=str(self.logical_name or ""),
                    archive_input=knowledge_view.source_input(self),
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
            source_descriptor = state.to_archive_input_descriptor()
            source_input = source_descriptor.to_dict()
            self.cleanup_parts = list(dedupe_values([
                *(self.cleanup_parts or []),
                *source_descriptor.part_paths(),
                self.carrier_path,
            ]))
            self.split_info.archive_input = source_descriptor
            self.split_info.is_split = source_descriptor.open_mode in {"native_volumes", "sfx_with_volumes"}
            self.split_info.is_sfx_stub = bool(
                source_descriptor.open_mode == "sfx_with_volumes"
                or self.split_info.is_sfx_stub
                or self.fact_bag.get("relation.has_split_companions")
                or self.fact_bag.get("candidate.companion_paths")
            )
        with _phase(phase_timer, f"{phase_prefix}_merge_knowledge"):
            state_snapshot_for_knowledge = _archive_state_snapshot(state)
            knowledge = self._merged_state_knowledge(state, source_input, state_snapshot_for_knowledge)
        if knowledge:
            with _phase(phase_timer, f"{phase_prefix}_rebuild_state_with_knowledge"):
                state = ArchiveState(
                    source=state.source,
                    logical_name=state.logical_name,
                    format_hint=state.format_hint,
                    analysis=dict(state.analysis),
                    verification=dict(state.verification),
                    knowledge=knowledge,
                )
        with _phase(phase_timer, f"{phase_prefix}_snapshot"):
            state_payload = _archive_state_snapshot(state)
            source_payload = state.source.to_dict()
        with _phase(phase_timer, f"{phase_prefix}_fact_bag_set"):
            self.fact_bag.set("archive.state", state_payload)
            self.fact_bag.set("archive.source", source_payload)
        with _phase(phase_timer, f"{phase_prefix}_knowledge_payload"):
            knowledge_payload = dict(state.knowledge)
        with _phase(phase_timer, f"{phase_prefix}_replace_knowledge"):
            self._replace_knowledge_payload(knowledge_payload, knowledge_cache=ArchiveKnowledge(knowledge_payload))
        with _phase(phase_timer, f"{phase_prefix}_cache_update"):
            self._archive_state_cache_raw = state_payload
            self._archive_state_cache_knowledge_raw = knowledge_payload
            self._archive_state_cache = state

    def archive_descriptor(self) -> ArchiveDescriptor:
        source = self.archive_state().to_archive_input_descriptor()
        selected_format = knowledge_view.selected_format(self)
        confidence = 0.0
        selected_segment = knowledge_view.source_selected_segment(self)
        evidence = selected_segment.get("segment") if isinstance(selected_segment.get("segment"), dict) else selected_segment
        if isinstance(evidence, dict):
            confidence = float(evidence.get("confidence", selected_segment.get("confidence", 0.0)) or 0.0)
        damage_flags = []
        if isinstance(evidence, dict):
            damage_flags.extend(evidence.get("damage_flags") or [])
        source_derivation = knowledge_view.source_derivation(self)
        relation = ArchiveRelationState(
            kind=str(source_derivation.get("kind") or ("split_archive" if self.split_info.is_split else "file")),
            is_split=bool(self.split_info.is_split),
            is_sfx=bool(self.split_info.is_sfx_stub),
            volumes_complete=source_derivation.get("split_group_complete"),
            missing_indices=list(source_derivation.get("split_missing_indices") or []),
            missing_reason=str(source_derivation.get("split_missing_reason") or ""),
        )
        return ArchiveDescriptor(
            id=str(self.key or self.main_path),
            logical_name=str(self.logical_name or ""),
            source=source,
            format=ArchiveFormatState(
                detected=str(self.detected_ext or ""),
                selected=selected_format,
                hint=source.format_hint,
                confidence=confidence,
                status=knowledge_view.inspection_status(self),
            ),
            relation=relation,
            integrity=ArchiveIntegrityState(damage_flags=_dedupe([str(item) for item in damage_flags])),
        )

    def _format_hint(self) -> str:
        knowledge = self.knowledge()
        return str(
            knowledge.get("inspection.summary.format", "")
            or knowledge.get("archive.format_hint", "")
            or knowledge.get("source.input.format_hint", "")
            or self.detected_ext
            or self.fact_bag.get("file.detected_ext")
            or ""
        ).lstrip(".")

    def _raw_archive_state(self) -> dict | None:
        raw = self.fact_bag.get("archive.state")
        return raw if isinstance(raw, dict) else None

    def _write_detection_boundary_knowledge(self) -> None:
        knowledge = self.knowledge()
        raw_source = self.fact_bag.get("archive.input")
        source_descriptor = self.split_info.archive_input
        if source_descriptor is None:
            source_descriptor = ArchiveInputDescriptor.from_any(
                raw_source if isinstance(raw_source, dict) else None,
                archive_path=self.main_path,
                part_paths=list(self.all_parts or [self.main_path]),
                format_hint=self._format_hint(),
                logical_name=str(self.logical_name or ""),
            )
        source_input = source_descriptor.to_dict()
        knowledge.merge({
            "filesystem": {
                "path": self.carrier_path or self.main_path,
                "carrier_path": self.carrier_path or self.main_path,
                "detected_ext": self.detected_ext,
            },
            "source": {
                "input": source_input,
                "derivation": {
                    "kind": str(self.fact_bag.get("candidate.kind") or ("split_archive" if self.split_info.is_split else "file")),
                    "candidate_entry_path": self.main_path,
                    "candidate_member_paths": list(self.all_parts or []),
                    "candidate_carrier_path": self.carrier_path or self.main_path,
                    "candidate_cleanup_paths": list(self.cleanup_parts or []),
                    "candidate_logical_name": self.logical_name,
                    "split_group_complete": self.fact_bag.get("relation.split_group_complete"),
                    "split_missing_indices": list(self.fact_bag.get("relation.split_missing_indices") or []),
                    "split_missing_reason": str(self.fact_bag.get("relation.split_missing_reason") or ""),
                },
            },
            "relations": {
                "is_split": bool(self.split_info.is_split),
                "is_sfx_stub": bool(self.split_info.is_sfx_stub),
                "archive_input": source_input,
            },
        }, source_layer="contracts", source_module="from_fact_bag")
        payload = knowledge.to_dict()
        self._replace_knowledge_payload(payload, knowledge_cache=ArchiveKnowledge(payload))

    def _replace_knowledge_payload(
        self,
        payload: dict[str, Any],
        *,
        knowledge_cache: ArchiveKnowledge | None = None,
    ) -> None:
        current = self.fact_bag.get("archive.knowledge")
        if current is payload:
            self._archive_knowledge_cache_raw = current if isinstance(current, dict) else payload
            if knowledge_cache is not None:
                self._archive_knowledge_cache = knowledge_cache
            elif isinstance(self._archive_knowledge_cache, ArchiveKnowledge) and self._archive_knowledge_cache_raw is current:
                pass
            else:
                self._archive_knowledge_cache = ArchiveKnowledge.from_any(current if isinstance(current, dict) else payload)
            return
        self.fact_bag.set("archive.knowledge", payload)
        self._archive_knowledge_cache_raw = payload
        self._archive_knowledge_cache = knowledge_cache if knowledge_cache is not None else ArchiveKnowledge.from_any(payload)
        self._archive_state_cache_raw = None
        self._archive_state_cache_knowledge_raw = None
        self._archive_state_cache = None

    def _merged_state_knowledge(
        self,
        state: ArchiveState,
        source_input: dict[str, Any],
        state_snapshot: dict[str, Any],
    ) -> dict[str, Any]:
        """Merge state facts without deep-merging the whole knowledge tree when possible."""
        existing = self.fact_bag.get("archive.knowledge")
        additions = {
            "source": {"input": source_input},
            "archive": {"state": state_snapshot},
        }
        if state.knowledge:
            return merge_knowledge(existing, state.knowledge, additions)
        if not isinstance(existing, dict):
            return merge_knowledge(existing, additions)
        knowledge = dict(existing)
        source = dict(knowledge.get("source") or {}) if isinstance(knowledge.get("source"), dict) else {}
        source["input"] = source_input
        archive = dict(knowledge.get("archive") or {}) if isinstance(knowledge.get("archive"), dict) else {}
        archive["state"] = state_snapshot
        knowledge["source"] = source
        knowledge["archive"] = archive
        return knowledge


def _archive_state_snapshot(state: ArchiveState) -> dict[str, Any]:
    """Return a JSON-safe state snapshot that cannot recursively embed ArchiveKnowledge."""
    payload = state.to_dict()
    payload.pop("knowledge", None)
    return payload


def _phase(timer: Any | None, name: str):
    if timer is None:
        return nullcontext()
    return timer(name)


_dedupe = dedupe_values
