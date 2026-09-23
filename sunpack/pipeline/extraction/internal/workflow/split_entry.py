from typing import Optional

from sunpack.core.contracts.tasks import SplitArchiveInfo


class SplitEntryResolver:
    def resolve(
        self,
        archive: str,
        all_parts: list[str],
        split_info: Optional[SplitArchiveInfo],
    ) -> tuple[str, list[str], SplitArchiveInfo]:
        split_info = split_info or SplitArchiveInfo()
        descriptor = split_info.archive_input
        if descriptor is None:
            if len(all_parts or []) > 1:
                raise ValueError("multi-volume extraction requires ArchiveInputDescriptor")
            return archive, [archive], split_info
        return descriptor.entry_path, descriptor.part_paths(), split_info
