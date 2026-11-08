from __future__ import annotations

from dataclasses import InitVar, dataclass, field, replace
from typing import Any

from sunpack.core.contracts.archive_input import ArchiveInputDescriptor
from sunpack.core.contracts.failures import FailureInfo
from sunpack.core.contracts.archive_knowledge import ArchiveKnowledge
from sunpack.core.contracts.input_plan import InputRecovery, LogicalArchiveInput
from sunpack.core.support.collections import dedupe_values
from sunpack.core.support.path_keys import normalized_path, path_key


@dataclass
class ArchiveTask:
    """Request-owned physical lease/cleanup group containing logical inputs.

    Input identity and recovery belong to ``inputs`` and ``recovery``. ``key``
    and ``main_path`` identify the user-visible scheduling group only.
    """

    _archive_input: InitVar[ArchiveInputDescriptor]
    carrier_path: str = ""
    cleanup_parts: list[str] = field(default_factory=list)
    key: str = ""
    initial_discovery_source: InitVar[str] = ""
    discovery_evidence: InitVar[dict[str, Any] | None] = None
    initial_inputs: InitVar[tuple[LogicalArchiveInput, ...]] = ()
    initial_discovery_reason: InitVar[str] = ""
    runtime: dict[str, Any] = field(default_factory=dict)
    discovery_failure: FailureInfo | None = None
    inputs: tuple[LogicalArchiveInput, ...] = field(default=(), init=False)
    recovery: InputRecovery = field(default_factory=InputRecovery, init=False, repr=False)
    password_probe_input: ArchiveInputDescriptor | None = field(default=None, init=False, repr=False)

    def __post_init__(
        self,
        _archive_input: ArchiveInputDescriptor,
        initial_discovery_source: str,
        discovery_evidence: dict[str, Any] | None,
        initial_inputs: tuple[LogicalArchiveInput, ...],
        initial_discovery_reason: str,
    ) -> None:
        descriptor = _archive_input
        if not descriptor.entry_path:
            raise ValueError("ArchiveTask requires an archive input entry path")
        self.carrier_path = str(self.carrier_path or descriptor.entry_path)
        self.cleanup_parts = list(dedupe_values([
            *descriptor.part_paths(),
            *self.cleanup_parts,
            self.carrier_path,
        ]))
        if not self.key:
            self.key = descriptor.entry_path
        self._knowledge = ArchiveKnowledge()
        self._archive_input = descriptor
        self.inputs = (LogicalArchiveInput(descriptor, failure=self.discovery_failure),)
        self._initialize_knowledge(
            discovery_source=str(initial_discovery_source or ""),
            discovery_reason=str(initial_discovery_reason or ""),
            discovery_evidence=dict(discovery_evidence or {}),
            initial_inputs=initial_inputs,
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
        logical_inputs: tuple[LogicalArchiveInput, ...] = (),
        discovery_reason: str = "",
        discovery_failure: FailureInfo | None = None,
    ) -> "ArchiveTask":
        return cls(
            _archive_input=descriptor,
            carrier_path=carrier_path or descriptor.entry_path,
            cleanup_parts=list(cleanup_paths),
            initial_discovery_source=discovery_source,
            discovery_evidence=dict(discovery_evidence or {}),
            initial_inputs=logical_inputs,
            initial_discovery_reason=discovery_reason,
            discovery_failure=discovery_failure,
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
        return list(dedupe_values(path for node in self.inputs for path in node.source_paths))

    def set_inputs(self, inputs: tuple[LogicalArchiveInput, ...]) -> None:
        self.inputs = inputs
        self.cleanup_parts = list(dedupe_values([*self.cleanup_parts, *self.all_parts]))

    def archive_input(self) -> ArchiveInputDescriptor:
        return self._archive_input

    def knowledge(self) -> ArchiveKnowledge:
        return self._knowledge

    def set_knowledge(self, knowledge: ArchiveKnowledge | dict) -> None:
        self._knowledge = ArchiveKnowledge.from_any(knowledge)

    def set_archive_input(self, descriptor: ArchiveInputDescriptor) -> None:
        previous = self._archive_input
        self.cleanup_parts = list(dedupe_values([
            *descriptor.part_paths(),
            *self.cleanup_parts,
            self.carrier_path,
        ]))
        self._archive_input = descriptor
        if len(self.inputs) == 1 and self.inputs[0].descriptor is previous:
            self.inputs = (replace(self.inputs[0], descriptor=descriptor),)

    def select_volumes(self, node: LogicalArchiveInput, descriptor: ArchiveInputDescriptor) -> None:
        """Commit the worker's winning composition; release unused candidates."""
        self.inputs = tuple(replace(item, descriptor=descriptor) if item.input_id == node.input_id else item
                            for item in self.inputs)
        self.release_unused_sources(node.source_paths, superseded_input_id=node.input_id)
        if self._archive_input is node.descriptor:
            self._archive_input = descriptor
        if self.password_probe_input is node.descriptor:
            self.password_probe_input = descriptor

    def release_unused_sources(self, sources, *, superseded_input_id: str = "") -> None:
        """Reconcile candidate cleanup against active inputs and retained outputs."""
        rejected = {path_key(path) for path in sources}
        if not rejected:
            return
        retained = {path_key(path) for item in self.inputs for path in item.source_paths}
        retained.update(path_key(path) for checkpoint in self.recovery.checkpoints
                        if checkpoint.input.input_id != superseded_input_id
                        for path in checkpoint.input.source_paths)
        unused = rejected - retained
        self.cleanup_parts = [path for path in self.cleanup_parts if path_key(path) not in unused]

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
        previous = self.archive_input()
        descriptor = previous.with_path_mapping(mapped)
        self.inputs = tuple(replace(node, descriptor=descriptor) if node.descriptor is previous
                            else node.remap(mapped) for node in self.inputs)
        self.set_archive_input(descriptor)
        if self.password_probe_input is previous:
            self.password_probe_input = descriptor
        elif self.password_probe_input is not None:
            self.password_probe_input = self.password_probe_input.with_path_mapping(mapped)

    def adopt_detection_plan(self, replacement: "ArchiveTask") -> None:
        self.carrier_path = replacement.carrier_path
        self.cleanup_parts = list(replacement.cleanup_parts)
        self.key = replacement.key
        self._knowledge = ArchiveKnowledge.from_any(replacement.knowledge())
        self._archive_input = replacement.archive_input()
        self.discovery_failure = replacement.discovery_failure
        self.inputs = replacement.inputs
        self.password_probe_input = replacement.password_probe_input

    def _initialize_knowledge(
        self,
        *,
        discovery_source: str,
        discovery_reason: str,
        discovery_evidence: dict[str, Any],
        initial_inputs: tuple[LogicalArchiveInput, ...],
    ) -> None:
        prepass = discovery_evidence.pop("scan", None)
        self._knowledge.merge({
            "discovery": {
                "source": discovery_source,
                "reason": discovery_reason,
                "evidence": dict(discovery_evidence),
            },
        }, source_layer="contracts", source_module="archive_task")
        if initial_inputs:
            self.set_inputs(initial_inputs)
        if isinstance(prepass, dict):
            self._knowledge.set(
                "inspection.prepass",
                prepass,
                source_layer="embedded",
                source_module="discovery",
            )
