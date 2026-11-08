from dataclasses import dataclass

from sunpack.core.contracts.archive_knowledge import ArchiveKnowledge
from tests.helpers.archive_tasks import make_archive_task
from sunpack.core.support.archive_knowledge_writer import commit_task_knowledge, write_evidence


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


def test_archive_knowledge_exports_live_changes_without_aliasing():
    # Existing tests mutate through set(). Direct edits through get()/data
    # must also reach exports without retaining an obsolete snapshot.
    @dataclass
    class Rows:
        rows: list[dict]

    knowledge = ArchiveKnowledge()
    source = Rows([{"value": "original"}])
    knowledge.set("analysis", source, source_layer="test")
    source.rows.clear()
    first = knowledge.to_dict()
    knowledge.get("analysis.rows")[0]["value"] = "current"
    knowledge.data["verification"] = {"complete": True}
    second = knowledge.to_dict()

    assert first["analysis"]["rows"] == [{"value": "original"}]
    assert second["analysis"]["rows"] == [{"value": "current"}]
    assert second["verification"] == {"complete": True}
    second["analysis"]["rows"].clear()
    assert knowledge.get("analysis.rows") == [{"value": "current"}]

    merged = ArchiveKnowledge.from_any(knowledge)
    merged.merge(knowledge, {"analysis": {"rows": [{"value": "new"}]}})
    merged.get("analysis.rows")[0]["value"] = "detached"
    assert knowledge.get("analysis.rows") == [{"value": "current"}]
    assert len(merged.get("analysis.rows")) == 2


def test_archive_knowledge_evidence_retention_and_detached_exports():
    # Existing roundtrips never fill the history or mix its two writers; they
    # cannot detect lost provenance, unbounded retention, or live export aliases.
    knowledge = ArchiveKnowledge()
    source = {"rows": list(range(60)), "stdout": "x" * 5000}
    write_evidence(knowledge, path="initial", value=source, source_layer="analysis")
    initial = knowledge.to_dict()
    assert initial["_evidence"][0]["value"]["rows"] == [*range(50), {"truncated_count": 10}]
    assert len(initial["_evidence"][0]["value"]["stdout"]) == 4000
    source["rows"].clear()
    for index in range(501):
        if index % 2:
            knowledge.set("analysis.latest", index, source_layer="analysis")
        else:
            write_evidence(knowledge, path="analysis.latest", value=index,
                           source_layer="analysis", source_module="scan", confidence=0.8)
    evidence = knowledge.get("_evidence")
    assert len(evidence) == 500
    assert [item["value"] for item in evidence] == list(range(1, 501))
    assert evidence[-1]["provenance"]["source_module"] == "scan"
    assert evidence[-1]["provenance"]["confidence"] == 0.8
    assert len(initial["_evidence"]) == 1
    exported = knowledge.to_dict()
    exported["_evidence"][-1]["provenance"].clear()
    assert evidence[-1]["provenance"]["source_layer"] == "analysis"


def test_archive_knowledge_commit_revision(tmp_path):
    archive_path = tmp_path / "sample.zip"
    archive_path.write_bytes(b"abc")
    task = make_archive_task(archive_path, format_hint="zip")

    first_revision = int(task.knowledge().get("_meta.revision", 0) or 0)

    knowledge = task.knowledge()
    knowledge.set("format.zip.structure.has_data_descriptor", True, source_layer="test")
    commit_task_knowledge(task, knowledge)

    assert int(task.knowledge().get("_meta.revision", 0) or 0) > first_revision
    assert task.knowledge().get("format.zip.structure.has_data_descriptor") is True


def test_archive_knowledge_commit_reuses_unchanged_branches_and_isolates_working_copy(tmp_path):
    archive_path = tmp_path / "sample.zip"
    archive_path.write_bytes(b"abc")
    task = make_archive_task(archive_path, format_hint="zip")
    knowledge = task.knowledge()
    knowledge.set("analysis.large", {"rows": [{"index": index, "value": "x" * 64} for index in range(500)]})
    commit_task_knowledge(task, knowledge)
    first_snapshot = task.knowledge().to_dict()
    first_analysis = first_snapshot["analysis"]
    first_revision = first_snapshot["_meta"]["revision"]

    working = task.knowledge()
    working.set("verification.summary", {"decision_hint": "accept", "completeness": 1.0})
    assert "verification" not in first_snapshot
    commit_task_knowledge(task, working)
    second_snapshot = task.knowledge().to_dict()

    assert second_snapshot["analysis"] == first_analysis
    assert second_snapshot["verification"]["summary"]["decision_hint"] == "accept"
    assert second_snapshot["_meta"]["revision"] == first_revision + 1

    detached = task.knowledge().to_dict()
    detached["analysis"]["large"]["rows"].clear()
    assert len(task.knowledge().get("analysis.large.rows")) == 500
