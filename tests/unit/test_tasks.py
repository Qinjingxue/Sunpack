from sunpack.contracts.detection import FactBag
from sunpack.contracts.tasks import ArchiveTask


def _bag(path: str, logical_name: str, *, split: bool = False) -> FactBag:
    bag = FactBag()
    bag.set("candidate.entry_path", path)
    bag.set("candidate.member_paths", [path])
    bag.set("candidate.logical_name", logical_name)
    bag.set("relation.is_split_related", split)
    if split:
        bag.set("candidate.kind", "split_archive")
    return bag


def test_archive_task_key_uses_path_for_non_split_same_stem_archives():
    first = ArchiveTask.from_fact_bag(_bag("C:/work/collision.7z", "collision"))
    second = ArchiveTask.from_fact_bag(_bag("C:/work/collision.zip", "collision"))

    assert first.key == "C:/work/collision.7z"
    assert second.key == "C:/work/collision.zip"


def test_archive_task_key_keeps_logical_name_for_split_archives():
    task = ArchiveTask.from_fact_bag(_bag("C:/work/game.7z.001", "game", split=True))

    assert task.key == "game"
