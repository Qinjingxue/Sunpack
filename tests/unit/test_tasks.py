from sunpack.core.contracts.archive_input import ArchiveInputDescriptor
from tests.helpers.archive_tasks import make_task_from_descriptor


def test_archive_task_key_uses_path_for_non_split_same_stem_archives():
    first = make_task_from_descriptor(ArchiveInputDescriptor.from_parts(
        archive_path="C:/work/collision.7z",
        format_hint="7z",
        logical_name="collision",
    ))
    second = make_task_from_descriptor(ArchiveInputDescriptor.from_parts(
        archive_path="C:/work/collision.zip",
        format_hint="zip",
        logical_name="collision",
    ))

    assert first.key == "C:/work/collision.7z"
    assert second.key == "C:/work/collision.zip"


def test_archive_task_key_keeps_logical_name_for_split_archives():
    descriptor = ArchiveInputDescriptor.from_split_volumes(
        archive_path="C:/work/game.7z.001",
        volumes=[{
            "path": "C:/work/game.7z.001",
            "number": 1,
            "style": "numeric_suffix",
            "prefix": "game.7z.",
            "width": 3,
            "role": "first",
        }],
        format_hint="7z",
        logical_name="game",
    )
    task = make_task_from_descriptor(descriptor)

    assert task.key == "game"


def test_archive_input_normalizes_rar_sfx_head_with_rar_members():
    descriptor = ArchiveInputDescriptor.from_split_volumes(
        archive_path="C:/work/shared.bundle.exe.part1.fake",
        volumes=[
            {
                "path": "C:/work/shared.bundle.exe.part1.fake",
                "number": 1,
                "style": "rar_sfx_part",
                "prefix": "shared.bundle",
                "role": "first",
                "width": 1,
            },
            {
                "path": "C:/work/shared.bundle.rar.part2.fake",
                "number": 2,
                "style": "rar_part",
                "prefix": "shared.bundle",
                "role": "member",
                "width": 1,
            },
        ],
        format_hint="rar",
        logical_name="shared.bundle",
    )

    assert descriptor.open_mode == "sfx_with_volumes"
    assert descriptor.volume_style == "rar_sfx_part"
    assert [part.canonical_name for part in descriptor.parts] == [
        "shared.bundle.part1.exe",
        "shared.bundle.part2.rar",
    ]
