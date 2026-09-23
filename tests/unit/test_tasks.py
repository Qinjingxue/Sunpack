from sunpack.contracts.archive_input import ArchiveInputDescriptor
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
    task = make_task_from_descriptor(descriptor, relation_kind="split_archive")

    assert task.key == "game"
