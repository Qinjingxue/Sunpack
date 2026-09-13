import os
from types import SimpleNamespace
from typing import Any

from sunpack.contracts.detection import FactBag
from sunpack.contracts.archive_input import ArchiveInputDescriptor
from sunpack.contracts.archive_state import ArchiveState
from sunpack.contracts.run_context import RunContext
from sunpack.contracts.tasks import ArchiveTask
from sunpack.coordinator.task_provider import ArchiveTaskProvider
from sunpack.coordinator.nested_extraction_policy import EMBEDDED_SCAN_ALLOWED_FACT
from sunpack.coordinator.scan_session import DetectionScanSession
from sunpack.detection.options import DetectionOptions
from sunpack.relations.internal.group_builder import RelationsGroupBuilder


class ArchiveTaskScanner:
    def __init__(self, config: dict[str, Any], context: RunContext, detection_options: DetectionOptions | None = None):
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

    def direct_file_tasks(self, file_paths: list[str]) -> list[ArchiveTask]:
        tasks = []
        normalized_paths = []
        for raw_path in file_paths:
            path = os.path.abspath(os.path.normpath(raw_path))
            if not os.path.isfile(path):
                self.context.failed_tasks.append(f"{raw_path} [direct mode requires a file]")
                continue
            normalized_paths.append(path)

        grouped_paths = _group_explicit_split_paths(normalized_paths)
        for paths in grouped_paths:
            task = direct_file_task(paths[0], all_parts=paths)
            if task.key in self.context.processed_keys:
                continue
            tasks.append(task)
        return tasks


def _group_explicit_split_paths(file_paths: list[str]) -> list[list[str]]:
    """Group explicit volumes and discover siblings when the user supplies one volume."""
    builder = RelationsGroupBuilder()
    groups: dict[tuple[str, str], list[tuple[int, str]]] = {}
    standalone: list[str] = []
    for path in file_paths:
        parsed = builder.parse_numbered_volume(path)
        if not parsed:
            standalone.append(path)
            continue
        prefix_path = os.path.abspath(str(parsed["prefix"]))
        prefix = os.path.normcase(prefix_path)
        key = (prefix, str(parsed["style"]))
        groups.setdefault(key, []).append((int(parsed["number"]), path))
        directory = os.path.dirname(path) or os.getcwd()
        for candidate_name in os.listdir(directory):
            candidate = os.path.join(directory, candidate_name)
            sibling = builder.parse_numbered_volume(candidate)
            if not sibling or os.path.normcase(os.path.abspath(str(sibling["prefix"]))) != prefix:
                continue
            if str(sibling["style"]) == str(parsed["style"]):
                groups[key].append((int(sibling["number"]), candidate))

    grouped: list[list[str]] = []
    for members in groups.values():
        ordered = list(dict.fromkeys(path for _, path in sorted(members, key=lambda item: (item[0], item[1].lower()))))
        grouped.append(ordered if len(ordered) > 1 else ordered)
    grouped.extend([[path] for path in standalone])
    return grouped


def direct_file_task(path: str, all_parts: list[str] | None = None) -> ArchiveTask:
    path = os.path.abspath(os.path.normpath(path))
    name = os.path.basename(path)
    logical_name, ext = os.path.splitext(name)
    parts = [os.path.abspath(os.path.normpath(item)) for item in (all_parts or [path])]
    is_split = len(parts) > 1
    if is_split:
        builder = RelationsGroupBuilder()
        logical_name = builder.get_logical_name(name, is_archive=True) or logical_name
        parsed = builder.parse_numbered_volume(path)
        format_hint = ""
        if parsed:
            style = str(parsed.get("style") or "")
            if style.startswith("rar_"):
                format_hint = "rar"
            elif style.startswith("zip_"):
                format_hint = "zip"
            else:
                candidate = os.path.splitext(os.path.basename(str(parsed["prefix"])))[1].lower().lstrip(".")
                if candidate in {"7z", "zip", "rar"}:
                    format_hint = candidate
        logical_suffix = logical_name.rsplit(".", 1)[-1].lower()
        if not format_hint and logical_suffix in {"7z", "zip", "rar"}:
            format_hint = logical_suffix
    else:
        format_hint = ext.lower().lstrip(".")
    bag = FactBag()
    bag.set("file.path", path)
    bag.set("file.logical_name", logical_name or name)
    bag.set("file.detected_ext", f".{format_hint}" if is_split and format_hint else ext.lower())
    bag.set("candidate.entry_path", path)
    bag.set("candidate.kind", "split_archive" if is_split else "direct_file")
    bag.set("candidate.logical_name", logical_name or name)
    bag.set("candidate.member_paths", parts)
    bag.set(EMBEDDED_SCAN_ALLOWED_FACT, True)
    bag.set("archive.format_hint", format_hint)
    if is_split:
        bag.set("relation.is_split_related", True)
        anchor = path if os.path.splitext(path)[1].lower() == ".exe" else next(
            (item for item in parts if builder.parse_numbered_volume(item)),
            path,
        )
        volumes, _complete, _reason, _missing = builder.build_split_volume_entries(anchor, parts)
        if not volumes:
            raise ValueError("explicit multi-volume input could not be represented structurally")
        descriptor = ArchiveInputDescriptor.from_split_volumes(
            archive_path=path,
            volumes=volumes,
            format_hint=format_hint,
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
