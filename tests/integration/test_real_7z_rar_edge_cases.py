from dataclasses import replace
from pathlib import Path

import pytest

from sunpack.core.contracts.tasks import ArchiveTask
from sunpack.pipeline.coordinator.task_scan import direct_file_task
from sunpack.pipeline.extraction.scheduler import ExtractionScheduler
from tests.helpers.real_archives import ArchiveFixtureFactory
from tests.helpers.tool_config import get_optional_rar


def test_real_7z_sfx_missing_tail_reports_missing_volume_not_partial_payload(tmp_path):
    case = _create_real_case_or_skip(
        tmp_path,
        "seven_sfx_missing_tail",
        "7z",
        split=True,
        sfx=True,
        payload_size=2 * 1024 * 1024,
    )
    _remove_current_tail_volume(case)
    parts = _case_parts(case)
    scheduler = ExtractionScheduler(max_retries=1)
    try:
        result = scheduler.extract(
            _task(
                case.entry_path,
                parts=parts,
                detected_ext="7z",
                missing_volume_evidence="seven_zip_start_header_length",
            ),
            str(tmp_path / "out"),
        )
    finally:
        scheduler.close()

    worker = result.diagnostics.get("result", {})
    assert result.success is False
    assert result.partial_outputs is False
    assert worker.get("missing_volume") is True
    assert worker.get("failure_kind") == "missing_volume"
    assert worker.get("wrong_password") is False


def test_real_7z_header_encrypted_with_known_password_extracts(tmp_path):
    case = _create_real_case_or_skip(tmp_path, "seven_header_encrypted", "7z", password="secret")
    scheduler = ExtractionScheduler(cli_passwords=["secret"], builtin_passwords=[], max_retries=1)
    try:
        result = scheduler.extract(_task(case.entry_path, detected_ext="7z"), str(tmp_path / "out"))
    finally:
        scheduler.close()

    assert result.success is True
    assert result.password_used == "secret"
    marker = next((tmp_path / "out").rglob(case.marker_name))
    assert marker.read_text(encoding="utf-8") == case.marker_text


def test_real_7z_missing_volume_priority_survives_irrelevant_wrong_password(tmp_path):
    case = _create_real_case_or_skip(tmp_path, "seven_missing_tail_with_wrong_password", "7z", split=True, split_issue="missing_last")
    parts = _case_parts(case)
    task = _task(
        case.entry_path,
        parts=parts,
        detected_ext="7z",
        missing_volume_evidence="seven_zip_start_header_length",
    )
    knowledge = task.knowledge()
    knowledge.set("archive.password", "wrong", source_layer="tests", source_module="real_edge_cases")
    task.set_knowledge(knowledge)
    scheduler = ExtractionScheduler(max_retries=1)
    try:
        result = scheduler.extract(task, str(tmp_path / "out"))
    finally:
        scheduler.close()

    worker = result.diagnostics.get("result", {})
    assert result.success is False
    assert worker.get("missing_volume") is True
    assert worker.get("failure_kind") == "missing_volume"
    assert worker.get("wrong_password") is False


def test_real_rar_sfx_missing_tail_reports_missing_volume_when_rar_available(tmp_path):
    if get_optional_rar() is None:
        pytest.skip("RAR generator is not configured")
    case = _create_real_case_or_skip(tmp_path, "rar_sfx_missing_tail", "rar", split=True, sfx=True)
    _remove_current_tail_volume(case)
    scheduler = ExtractionScheduler(max_retries=1)
    try:
        result = scheduler.extract(_task(case.entry_path, parts=_case_parts(case), detected_ext="rar"), str(tmp_path / "out"))
    finally:
        scheduler.close()

    worker = result.diagnostics.get("result", {})
    assert result.success is False
    assert result.partial_outputs is False
    assert worker.get("missing_volume") is True
    assert worker.get("failure_kind") == "missing_volume"


def _create_real_case_or_skip(tmp_path: Path, case_id: str, archive_format: str, **kwargs):
    try:
        payload_size = int(kwargs.pop("payload_size", 320 * 1024))
        return ArchiveFixtureFactory().create(tmp_path, case_id, archive_format, payload_size=payload_size, **kwargs)
    except FileNotFoundError as exc:
        pytest.skip(str(exc))
    except RuntimeError as exc:
        pytest.skip(str(exc))


def _case_parts(case) -> list[Path]:
    files = sorted(path for path in case.archive_dir.iterdir() if path.is_file())
    return [case.entry_path, *[path for path in files if path != case.entry_path]]


def _remove_current_tail_volume(case):
    parts = sorted(path for path in case.archive_dir.iterdir() if path.is_file() and path != case.entry_path)
    if not parts:
        pytest.skip("Split archive did not leave enough parts to remove a required tail volume")
    parts[-1].unlink()


def _task(
    path: Path,
    *,
    parts: list[Path] | None = None,
    detected_ext: str = "",
    missing_volume_evidence: str = "",
) -> ArchiveTask:
    all_parts = [str(item) for item in (parts or [path])]
    task = direct_file_task(str(path), all_parts=all_parts)
    task.ensure_archive_state()
    state = task.archive_state()
    source = replace(state.source, format_hint=detected_ext) if detected_ext else state.source
    analysis = dict(state.analysis)
    if missing_volume_evidence:
        analysis["execution"] = {"missing_volume_evidence": missing_volume_evidence}
    if source != state.source or analysis != state.analysis:
        task.set_archive_state(replace(
            state,
            source=source,
            format_hint=detected_ext or state.format_hint,
            analysis=analysis,
        ))
    return task
