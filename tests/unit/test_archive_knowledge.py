from pathlib import Path

from sunpack.contracts.archive_knowledge import ArchiveKnowledge
from sunpack.contracts.detection import FactBag
from sunpack.contracts.tasks import ArchiveTask
from sunpack.support import archive_knowledge_projection as knowledge_view
from sunpack.support.archive_knowledge_writer import commit_task_knowledge


def test_archive_knowledge_namespace_merge_flags_and_roundtrip():
    knowledge = ArchiveKnowledge()
    knowledge.set("format.zip.structure.has_sfx_prefix", True, source_layer="analysis", source_module="zip_probe")
    knowledge.add_flags("verification.route_evidence", ["sfx", "carrier_prefix"], source_layer="verification")
    knowledge.merge({"verification": {"summary": {"completeness": 0.5}}})

    payload = ArchiveKnowledge.from_any(knowledge.to_dict()).to_dict()

    assert payload["format"]["zip"]["structure"]["has_sfx_prefix"] is True
    assert payload["verification"]["route_evidence"]["flags"] == ["sfx", "carrier_prefix"]
    assert payload["verification"]["summary"]["completeness"] == 0.5
    assert payload["_evidence"]
    assert "sfx" in ArchiveKnowledge.from_any(payload).flags()


def test_archive_knowledge_commit_revision_and_projection_cache_invalidation(tmp_path):
    archive_path = tmp_path / "sample.zip"
    archive_path.write_bytes(b"abc")
    task = ArchiveTask.from_fact_bag(_fact_bag_for_path(archive_path))

    first_revision = int(task.knowledge().get("_meta.revision", 0) or 0)
    first = knowledge_view.source_fingerprint(task)
    second = knowledge_view.source_fingerprint(task)
    assert first == second

    knowledge = task.knowledge()
    knowledge.set("format.zip.structure.has_data_descriptor", True, source_layer="test")
    commit_task_knowledge(task, knowledge)

    assert int(task.knowledge().get("_meta.revision", 0) or 0) > first_revision
    assert knowledge_view.zip_runtime_facts(task)["structure"]["has_data_descriptor"] is True


def test_archive_knowledge_commit_reuses_unchanged_branches_and_isolates_working_copy(tmp_path):
    archive_path = tmp_path / "sample.zip"
    archive_path.write_bytes(b"abc")
    task = ArchiveTask.from_fact_bag(_fact_bag_for_path(archive_path))
    knowledge = task.knowledge()
    knowledge.set("analysis.large", {"rows": [{"index": index, "value": "x" * 64} for index in range(500)]})
    commit_task_knowledge(task, knowledge)
    first_snapshot = task.fact_bag.get("archive.knowledge")
    first_analysis = first_snapshot["analysis"]
    first_revision = first_snapshot["_meta"]["revision"]

    working = task.knowledge()
    working.set("verification.summary", {"decision_hint": "accept", "completeness": 1.0})
    assert "verification" not in first_snapshot
    commit_task_knowledge(task, working)
    second_snapshot = task.fact_bag.get("archive.knowledge")

    assert second_snapshot["analysis"] is first_analysis
    assert second_snapshot["verification"]["summary"]["decision_hint"] == "accept"
    assert second_snapshot["_meta"]["revision"] == first_revision + 1

    detached = task.knowledge().to_dict()
    detached["analysis"]["large"]["rows"].clear()
    assert len(task.knowledge().get("analysis.large.rows")) == 500


def _fact_bag_for_path(path: Path) -> FactBag:
    bag = FactBag()
    bag.set("candidate.entry_path", str(path))
    bag.set("candidate.member_paths", [str(path)])
    bag.set("file.detected_ext", "zip")
    return bag
