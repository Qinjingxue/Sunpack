import os
from types import SimpleNamespace
from typing import Any

from sunpack.contracts.detection import FactBag
from sunpack.contracts.archive_input import ArchiveInputDescriptor
from sunpack.contracts.discovery import ResolvedArchiveInput
from sunpack.contracts.archive_state import ArchiveState
from sunpack.contracts.run_context import RunContext
from sunpack.contracts.tasks import ArchiveTask
from sunpack.coordinator.task_provider import ArchiveTaskProvider
from sunpack.coordinator.scan_session import DetectionScanSession
from sunpack.embedded.options import EmbeddedOptions
from sunpack.relations.internal.group_builder import RelationsGroupBuilder
from sunpack.support.path_keys import path_key


class ArchiveTaskScanner:
    def __init__(self, config: dict[str, Any], context: RunContext, detection_options: EmbeddedOptions | None = None):
        self.config = config
        self.context = context
        self.provider = ArchiveTaskProvider(config, detection_options=detection_options)
        self.detector = self.provider.detector
        self.last_scan_session: DetectionScanSession | None = None

    def scan_root(self, scan_root: str) -> list[ArchiveTask]:
        return self.scan_targets([scan_root])

    def scan_targets(
        self,
        scan_roots: list[str],
        *,
        scan_session: DetectionScanSession | None = None,
        is_recursive_scan: bool = False,
    ) -> list[ArchiveTask]:
        scan_session = scan_session or DetectionScanSession(config=self.config)
        self.last_scan_session = scan_session
        tasks = self.provider.scan_targets(
            scan_roots,
            processed_keys=self.context.processed_keys,
            scan_session=scan_session,
            is_recursive_scan=is_recursive_scan,
        )
        for failure in self.provider.failed_candidates:
            if failure not in self.context.failed_tasks:
                self.context.failed_tasks.append(failure)
        for failure in self.provider.failed_candidate_failures:
            if failure not in self.context.failures:
                self.context.failures.append(failure)
        return tasks

    def discover_targets(
        self,
        scan_roots: list[str],
        *,
        scan_session: DetectionScanSession | None = None,
        is_recursive_scan: bool = False,
    ) -> list[ResolvedArchiveInput]:
        scan_session = scan_session or DetectionScanSession(config=self.config)
        self.last_scan_session = scan_session
        result = self.provider.discover_targets(
            scan_roots, scan_session=scan_session, is_recursive_scan=is_recursive_scan,
        )
        return result.resolved_inputs

    def tasks_from_inputs(self, inputs: list[ResolvedArchiveInput]) -> list[ArchiveTask]:
        return self.provider.tasks_from_inputs(inputs, processed_keys=self.context.processed_keys)

    def direct_file_tasks(self, file_paths: list[str]) -> list[ArchiveTask]:
        tasks = []
        normalized_paths = []
        for raw_path in file_paths:
            path = os.path.abspath(os.path.normpath(raw_path))
            if not os.path.isfile(path):
                self.context.failed_tasks.append(f"{raw_path} [direct mode requires a file]")
                continue
            normalized_paths.append(path)

        discovered = self.provider.discover_targets(normalized_paths)
        covered = set(discovered.claimed_paths | discovered.blocked_paths)
        tasks.extend(self.provider.tasks_from_inputs(
            discovered.resolved_inputs, processed_keys=self.context.processed_keys,
        ))
        for path in normalized_paths:
            if path_key(path) in covered:
                continue
            task = direct_file_task(path)
            if task.key in self.context.processed_keys:
                continue
            tasks.append(task)
        return tasks


def direct_file_task(path: str, all_parts: list[str] | None = None) -> ArchiveTask:
    path = os.path.abspath(os.path.normpath(path))
    name = os.path.basename(path)
    logical_name = name
    parts = [os.path.abspath(os.path.normpath(item)) for item in (all_parts or [path])]
    is_split = len(parts) > 1
    if is_split:
        builder = RelationsGroupBuilder()
        logical_name = builder.get_logical_name(name, is_archive=True) or logical_name
    bag = FactBag()
    bag.set("file.path", path)
    bag.set("file.logical_name", logical_name or name)
    bag.set("candidate.entry_path", path)
    bag.set("candidate.kind", "split_archive" if is_split else "direct_file")
    bag.set("candidate.logical_name", logical_name or name)
    bag.set("candidate.member_paths", parts)
    if is_split:
        bag.set("relation.is_split_related", True)
        anchor = next(
            (item for item in parts if builder.parse_numbered_volume(item)),
            path,
        )
        volumes, _complete, _reason, _missing = builder.build_split_volume_entries(anchor, parts)
        if not volumes:
            raise ValueError("explicit multi-volume input could not be represented structurally")
        descriptor = ArchiveInputDescriptor.from_split_volumes(
            archive_path=path,
            volumes=volumes,
            format_hint="",
            logical_name=logical_name or name,
        )
        state = ArchiveState.from_archive_input(descriptor)
        bag.set("archive.input", descriptor.to_dict())
        bag.set("archive.state", state.to_dict())
        bag.set("archive.source", state.source.to_dict())
    try:
        bag.set("file.size", os.path.getsize(path))
    except OSError:
        pass
    return ArchiveTask.from_fact_bag(
        bag,
        decision=SimpleNamespace(decision="direct_file", stop_reason="cli_direct_file", matched_rules=[]),
    )
