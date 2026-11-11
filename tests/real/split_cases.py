from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from tests.helpers.real_archives import ArchiveCase


@dataclass(frozen=True)
class SplitNamingCase:
    case_id: str
    archive_format: str
    name_for_part: Callable[[str, int, int], str]


SPLIT_NAMING_CASES = [
    SplitNamingCase("7z-numbered", "7z", lambda _base, index, _count: f"payload.7z.{index:03d}"),
    SplitNamingCase(
        "7z-numbered-cjk",
        "7z",
        lambda _base, index, _count: f"中文 分卷【素材】.7z.{index:03d}",
    ),
    SplitNamingCase(
        "7z-numbered-long-name",
        "7z",
        lambda _base, index, _count: f"a very long archive name with spaces and brackets [release].7z.{index:03d}",
    ),
    SplitNamingCase("7z-plain-numbered", "7z", lambda _base, index, _count: f"payload.{index:03d}"),
    SplitNamingCase(
        "7z-part-marker-camouflage",
        "7z",
        lambda _base, index, _count: f"payload.part{index}.{(123, 456, 789)[index - 1] if index <= 3 else index * 111}",
    ),
    SplitNamingCase(
        "7z-format-before-part-marker",
        "7z",
        lambda _base, index, _count: f"payload.7z.part{index:04d}.jpg",
    ),
    SplitNamingCase(
        "7z-format-after-part-marker",
        "7z",
        lambda _base, index, _count: f"payload.part{index:04d}.7z.png",
    ),
    SplitNamingCase("zip-numbered", "zip", lambda _base, index, _count: f"payload.zip.{index:03d}"),
    SplitNamingCase(
        "zip-part-marker-camouflage",
        "zip",
        lambda _base, index, _count: f"payload.part{index}.zip.hidden-{index}",
    ),
    SplitNamingCase(
        "zip-numbered-cjk",
        "zip",
        lambda _base, index, _count: f"中文 ZIP 分卷.zip.{index:03d}",
    ),
    SplitNamingCase("rar-part-marker", "rar", lambda _base, index, _count: f"payload.part{index}.rar"),
    SplitNamingCase(
        "rar-part-marker-padded",
        "rar",
        lambda _base, index, _count: f"payload.part{index:04d}.rar",
    ),
    SplitNamingCase(
        "rar-camouflaged",
        "rar",
        lambda _base, index, _count: f"payload.part{index}.rar.trash.pkg",
    ),
]


def rename_split_parts(case: ArchiveCase, naming: SplitNamingCase) -> None:
    original = sorted(path for path in case.archive_dir.iterdir() if path.is_file())
    assert len(original) >= 3
    temporary = []
    for index, path in enumerate(original, start=1):
        staged = path.with_name(f".__sunpack_stage_{index:04d}")
        path.rename(staged)
        temporary.append(staged)
    renamed = []
    for index, path in enumerate(temporary, start=1):
        target = case.archive_dir / naming.name_for_part("payload", index, len(temporary))
        path.rename(target)
        renamed.append(target)
    case.entry_path = renamed[0]
