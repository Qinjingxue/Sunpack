from __future__ import annotations

from dataclasses import dataclass
from os import PathLike
from typing import Any, TypeAlias

from sunpack.contracts.archive_input import ArchiveInputDescriptor


@dataclass(frozen=True, slots=True)
class FileAnalysisSource:
    path: str
    report_path: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", str(self.path))
        object.__setattr__(self, "report_path", str(self.report_path or self.path))


@dataclass(frozen=True, slots=True)
class MultiVolumeAnalysisSource:
    volumes: tuple[Any, ...]
    report_path: str = ""

    def __post_init__(self) -> None:
        volumes = tuple(self.volumes)
        if not volumes:
            raise ValueError("multi-volume analysis source requires at least one volume")
        object.__setattr__(self, "volumes", volumes)


AnalysisSource: TypeAlias = FileAnalysisSource | MultiVolumeAnalysisSource


def analysis_source(value: AnalysisSource | str | PathLike[str] | list[Any] | tuple[Any, ...]) -> AnalysisSource:
    if isinstance(value, (FileAnalysisSource, MultiVolumeAnalysisSource)):
        return value
    if isinstance(value, (str, PathLike)):
        return FileAnalysisSource(str(value))
    if isinstance(value, (list, tuple)):
        return MultiVolumeAnalysisSource(tuple(value))
    raise TypeError(f"unsupported analysis source: {type(value).__name__}")


def analysis_source_for_descriptor(
    descriptor: ArchiveInputDescriptor,
    *,
    report_path: str = "",
) -> AnalysisSource:
    """Translate a neutral archive input contract into an Analysis source."""

    if descriptor.open_mode == "file" and descriptor.entry_path:
        return FileAnalysisSource(descriptor.entry_path, report_path=report_path or descriptor.entry_path)
    if descriptor.open_mode in {"native_volumes", "sfx_with_volumes"} and descriptor.parts:
        volumes = tuple(
            {
                "path": part.path,
                "number": part.volume_number or index + 1,
                "style": descriptor.volume_style,
            }
            for index, part in enumerate(descriptor.parts)
            if part.path
        )
        if volumes:
            return MultiVolumeAnalysisSource(volumes, report_path=report_path or descriptor.entry_path)
    if descriptor.open_mode == "concat_ranges" and descriptor.ranges:
        paths = tuple(
            item.path
            for item in descriptor.ranges
            if item.path and int(item.start) == 0 and item.end is None
        )
        if paths and len(paths) == len(descriptor.ranges):
            return MultiVolumeAnalysisSource(paths, report_path=report_path or descriptor.entry_path)
    if descriptor.open_mode == "file_range" and descriptor.parts:
        part = descriptor.parts[0]
        item_range = part.range
        if part.path and item_range is not None and int(item_range.start) == 0 and item_range.end is None:
            return FileAnalysisSource(part.path, report_path=report_path or part.path)
    raise ValueError(f"unsupported archive input mode: {descriptor.open_mode}")
