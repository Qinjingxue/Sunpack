from __future__ import annotations

from sunpack.contracts.tasks import ArchiveTask, SplitArchiveInfo
from sunpack.relations import RelationsScheduler


class ArchiveRelationStage:
    """Complete relation descriptors before black-box extraction."""

    def __init__(self, relations: RelationsScheduler | None = None):
        self.relations = relations or RelationsScheduler()

    def resolve_tasks(self, tasks: list[ArchiveTask]) -> None:
        for task in tasks:
            self.resolve_task(task)

    def resolve_task(self, task: ArchiveTask) -> None:
        info = task.split_info or SplitArchiveInfo()
        descriptor = info.archive_input or task.archive_input()
        task.main_path = descriptor.entry_path
        task.all_parts = descriptor.part_paths()
        task.cleanup_parts = list(dict.fromkeys([
            *(task.cleanup_parts or []),
            *task.all_parts,
            task.carrier_path,
        ]))
        task.split_info = SplitArchiveInfo(
            is_split=descriptor.open_mode in {"native_volumes", "sfx_with_volumes"},
            is_sfx_stub=bool(
                descriptor.open_mode == "sfx_with_volumes"
                or info.is_sfx_stub
            ),
            archive_input=descriptor,
            source=info.source or "relations",
        )
