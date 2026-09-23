from tests.helpers.archive_tasks import make_archive_task
from tests.real.diagnostics import task_snapshot


def test_task_snapshot_uses_typed_archive_state_and_knowledge(tmp_path):
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"zip")
    task = make_archive_task(
        archive,
        format_hint="zip",
        logical_name="sample",
        discovery_source="relations",
    )
    knowledge = task.knowledge()
    knowledge.set(
        "format.zip.structure",
        {"password_required": False},
        source_layer="test",
        source_module="real_diagnostics",
    )
    task.set_knowledge(knowledge)
    task.runtime["input_planning.status"] = "extractable"

    snapshot = task_snapshot(task)

    assert snapshot["main_path"] == str(archive)
    assert snapshot["format"] == "zip"
    assert snapshot["discovery_source"] == "relations"
    assert snapshot["archive_input"]["format_hint"] == "zip"
    assert snapshot["archive_state"]["format_hint"] == "zip"
    assert snapshot["knowledge"]["format"]["zip"]["structure"]["password_required"] is False
    assert snapshot["runtime"]["input_planning.status"] == "extractable"
    assert "facts" not in snapshot
    assert "decision" not in snapshot
    assert "detected_ext" not in snapshot
