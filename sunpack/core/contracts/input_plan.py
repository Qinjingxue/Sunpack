"""Logical archive plans and bounded, handle-free recovery state.

Discovery owns interpretation of physical sources. Execution, verification and
recovery share these objects; serialized diagnostics are never execution input.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any

from sunpack.core.contracts.archive_input import ArchiveInputDescriptor
from sunpack.core.contracts.failures import FailureInfo, FailureKind
from sunpack.core.support.path_keys import path_key


def input_identity(descriptor: ArchiveInputDescriptor) -> str:
    extent = descriptor.primary_extent
    return f"{path_key(descriptor.entry_path)}|{descriptor.format_hint}|{extent.start if extent else 0}"


@dataclass(frozen=True, slots=True)
class LogicalArchiveInput:
    descriptor: ArchiveInputDescriptor
    input_id: str = ""
    position: int = 1
    evidence: dict[str, Any] = field(default_factory=dict, compare=False)
    failure: FailureInfo | None = None
    password: str | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not self.input_id:
            object.__setattr__(self, "input_id", input_identity(self.descriptor))

    @property
    def source_paths(self) -> tuple[str, ...]:
        return tuple(self.descriptor.part_paths())

    @property
    def anchors(self) -> frozenset[tuple[str, int]]:
        descriptor = self.descriptor
        extents = descriptor.extents or [part.extent for part in descriptor.parts]
        return frozenset((path_key(extent.path), extent.start) for extent in extents) or frozenset({(path_key(descriptor.entry_path), 0)})

    @property
    def volume_completeness(self) -> str:
        """Only publish analysis/execution facts; unknown is not completeness."""
        execution = self.descriptor.analysis.get("execution") or {}
        if execution.get("missing_volume_evidence") or (self.failure and self.failure.contains(FailureKind.MISSING_VOLUME)):
            return "missing"
        return str(self.descriptor.analysis.get("volume_completeness") or "unknown")

    def remap(self, mapper) -> LogicalArchiveInput:
        return replace(self, descriptor=self.descriptor.with_path_mapping(mapper))

    def projection(self) -> dict[str, Any]:
        """Reporting boundary; no consumer should reconstruct the plan from it."""
        descriptor = self.descriptor
        extent = descriptor.primary_extent
        return {
            "input_id": self.input_id,
            "index": self.position, "format": descriptor.format_hint,
            "logical_name": descriptor.logical_name,
            "start_offset": extent.start if extent else 0,
            "end_offset": extent.end if extent else None,
            "confidence": descriptor.analysis.get("segment_confidence", self.evidence.get("confidence", 0.0)),
            "damage_flags": descriptor.analysis.get("damage_flags", ()),
            "archive_input": descriptor.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class InputCheckpoint:
    input: LogicalArchiveInput
    generation: tuple
    output_dir: str = ""
    complete: bool = False
    failure: FailureInfo | None = None
    files_written: int = 0
    bytes_written: int = 0

    @property
    def blockers(self) -> frozenset[str]:
        if self.complete:
            return frozenset()
        failure = self.failure
        return frozenset(name for name, present in (
            ("password", failure is not None and failure.is_password_failure),
            ("missing_volume", self.input.volume_completeness == "missing"
             or failure is not None and failure.contains(FailureKind.MISSING_VOLUME)),
        ) if present)

    def to_dict(self) -> dict:
        return {
            "input_id": self.input.input_id, "position": self.input.position,
            "archive_input": self.input.descriptor.to_dict(),
            "generation": self.generation, "output_dir": self.output_dir,
            "complete": self.complete,
            "blockers": sorted(self.blockers),
            "failure": self.failure.to_dict() if self.failure else None,
            "files_written": self.files_written, "bytes_written": self.bytes_written,
        }

    @classmethod
    def from_dict(cls, value: dict) -> InputCheckpoint:
        return cls(
            LogicalArchiveInput(ArchiveInputDescriptor.from_dict(value["archive_input"]),
                                input_id=value["input_id"], position=int(value["position"])),
            tuple(tuple(row) for row in value["generation"]),
            str(value.get("output_dir") or ""), bool(value.get("complete")),
            FailureInfo.from_dict(value.get("failure")),
            int(value["files_written"]), int(value["bytes_written"]),
        )


def source_generation(input: LogicalArchiveInput, generation: tuple | dict) -> tuple:
    rows = generation if isinstance(generation, dict) else {row[0]: tuple(row) for row in generation}
    return tuple(rows[key] for path in input.source_paths if (key := path_key(path)) in rows)


def recovery_blockers(failure: FailureInfo | None) -> frozenset[str]:
    """Read the persisted state index without decoding any input mappings."""
    recovery = failure.details.get("input_recovery") if failure else None
    return frozenset(blocker for row in recovery["inputs"] if not row["complete"]
                     for blocker in row["blockers"]) if recovery else frozenset()


@dataclass(slots=True)
class InputRecovery:
    """One checkpoint per logical archive, without readers or file inventories."""
    checkpoints: tuple[InputCheckpoint, ...] = ()
    output_dir: str = ""
    input_count: int = 0

    def to_dict(self) -> dict:
        return {"inputs": [item.to_dict() for item in self.checkpoints],
                "output_dir": self.output_dir, "input_count": self.input_count}

    @classmethod
    def from_failure(cls, failure: FailureInfo | None) -> InputRecovery:
        value = failure.details.get("input_recovery") if failure else None
        if not value:
            return cls()
        return cls(tuple(InputCheckpoint.from_dict(row) for row in value["inputs"]),
                   str(value.get("output_dir") or ""), int(value["input_count"]))

    def remap(self, mapper, generation: tuple) -> InputRecovery:
        updated = []
        generation = {row[0]: tuple(row) for row in generation}
        for item in self.checkpoints:
            node = item.input.remap(mapper)
            updated.append(replace(item, input=node, generation=source_generation(node, generation)))
        return InputRecovery(tuple(updated), self.output_dir, self.input_count)

    def relocate_outputs(self, relocate) -> InputRecovery:
        return InputRecovery(tuple(replace(item, output_dir=relocate(item.output_dir))
                                   for item in self.checkpoints),
                             relocate(self.output_dir), self.input_count)

    def select(self, inputs: tuple[LogicalArchiveInput, ...], generation: tuple, *, password_changed: bool) -> tuple[tuple[LogicalArchiveInput, ...], InputRecovery]:
        """Refine a discovered plan and wake only inputs whose dependencies changed."""
        by_id = {item.input.input_id: item for item in self.checkpoints}
        remaining = set(by_id)
        anchor_index = None
        generation = {row[0]: tuple(row) for row in generation}
        selected = []
        carried = []
        for node in inputs:
            previous = by_id.get(node.input_id)
            if previous is None:
                # A newly arrived first volume can change the entry path. The
                # existing unchanged source anchor still names the same input.
                if anchor_index is None:
                    anchor_index = {}
                    for item in self.checkpoints:
                        for anchor in item.input.anchors:
                            anchor_index.setdefault((item.input.descriptor.format_hint, *anchor), set()).add(item.input.input_id)
                matches = set()
                for anchor in node.anchors:
                    matches.update(anchor_index.get((node.descriptor.format_hint, *anchor), ()))
                matches.intersection_update(remaining)
                previous = by_id[next(iter(matches))] if len(matches) == 1 else None
            if previous is None:
                selected.append(node)
                continue
            remaining.discard(previous.input.input_id)
            node = replace(node, input_id=previous.input.input_id, position=previous.input.position)
            current = source_generation(node, generation)
            # New analysis may add advisory facts without changing readable
            # bytes. Completed output is reusable only for the exact mapping.
            if previous.complete:
                same_mapping = (node.descriptor.open_mode == previous.input.descriptor.open_mode
                                and node.descriptor.parts == previous.input.descriptor.parts
                                and node.descriptor.extents == previous.input.descriptor.extents)
                unchanged = current == previous.generation and same_mapping
            else:
                unchanged = current == previous.generation and node.descriptor.to_dict() == previous.input.descriptor.to_dict()
            if unchanged and (previous.complete or not (password_changed and "password" in previous.blockers)):
                carried.append(replace(previous, input=node))
            else:
                selected.append(node)
        # Disappeared inputs are not resurrected from an old scan. A changed
        # carrier must run its newly discovered plan in a new output root.
        retained_complete = any(item.complete for item in carried)
        root = self.output_dir if retained_complete else ""
        if root:
            # Preserve deterministic output slots for failed attempts too.
            carried_ids = {item.input.input_id for item in carried}
            selected_ids = {node.input_id for node in selected}
            carried.extend(item for item in self.checkpoints
                           if item.input.input_id not in carried_ids
                           and item.input.input_id in selected_ids)
        else:
            carried = [replace(item, output_dir="") for item in carried]
        return tuple(selected), InputRecovery(tuple(carried), root,
                                             max(self.input_count, len(inputs)) if root else len(inputs))
