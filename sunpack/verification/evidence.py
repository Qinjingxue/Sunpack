from dataclasses import dataclass, field
import json
from contextlib import nullcontext
from pathlib import Path
from typing import Any, Callable

from sunpack.contracts.archive_state import ArchiveState
from sunpack.contracts.archive_input import ArchiveInputDescriptor
from sunpack.contracts.tasks import ArchiveTask
from sunpack.contracts.extraction import ExtractionResult
from sunpack.passwords import PasswordSession
from sunpack.support import archive_knowledge_projection as knowledge_view
from sunpack.support.resource_lifecycle import read_task_text


@dataclass(frozen=True)
class VerificationEvidence:
    task: ArchiveTask
    extraction_result: ExtractionResult
    archive_state: ArchiveState
    archive_source: dict[str, Any]
    archive_path: str
    output_dir: str
    password: str | None
    fact_bag: Any
    analysis: dict[str, Any]
    analysis_facts: dict[str, Any] = field(default_factory=dict)
    archive_state_analysis: dict[str, Any] = field(default_factory=dict)
    extraction_diagnostics: dict[str, Any] = field(default_factory=dict)
    worker_result: dict[str, Any] = field(default_factory=dict)
    worker_native_diagnostics: dict[str, Any] = field(default_factory=dict)
    selected_codepage: str | None = None
    progress_manifest: dict[str, Any] | None = None


def build_verification_evidence(
    task: ArchiveTask,
    extraction_result: ExtractionResult,
    password_session: PasswordSession | None = None,
    *,
    phase_timer: Callable[..., Any] | None = None,
    phase_prefix: str = "verify_build_evidence",
) -> VerificationEvidence:
    with _phase(phase_timer, f"{phase_prefix}_fact_bag"):
        fact_bag = task.fact_bag
    with _phase(phase_timer, f"{phase_prefix}_password"):
        password = extraction_result.password_used
        if password is None and password_session is not None:
            password = password_session.get_resolved(task.key)
        if password is None:
            password = knowledge_view.archive_password(task)
    with _phase(phase_timer, f"{phase_prefix}_archive_state"):
        archive_state = task.archive_state()
        extraction_diagnostics = dict(extraction_result.diagnostics or {})
        verification_input = extraction_diagnostics.get("verification_archive_input")
        if isinstance(verification_input, dict):
            try:
                descriptor = ArchiveInputDescriptor.from_any(
                    verification_input,
                    archive_path=task.main_path,
                    part_paths=list(task.all_parts or [task.main_path]),
                )
                archive_state = ArchiveState.from_archive_input(descriptor)
            except (TypeError, ValueError, AttributeError):
                pass
        archive_input = archive_state.to_archive_input_descriptor()
    with _phase(phase_timer, f"{phase_prefix}_analysis_facts"):
        analysis_facts = _analysis_facts_from_task(task)
    with _phase(phase_timer, f"{phase_prefix}_diagnostics"):
        worker_result = _worker_result(extraction_diagnostics)
        worker_native_diagnostics = _worker_native_diagnostics(worker_result)
    with _phase(phase_timer, f"{phase_prefix}_progress_manifest"):
        progress_manifest = _load_progress_manifest(extraction_result)
    return VerificationEvidence(
        task=task,
        extraction_result=extraction_result,
        archive_state=archive_state,
        archive_source=archive_state.source.to_dict(),
        archive_path=archive_input.entry_path,
        output_dir=extraction_result.out_dir,
        password=password,
        fact_bag=fact_bag,
        analysis=knowledge_view.resource_analysis(task),
        analysis_facts=analysis_facts,
        archive_state_analysis=dict(archive_state.analysis or {}),
        extraction_diagnostics=extraction_diagnostics,
        worker_result=worker_result,
        worker_native_diagnostics=worker_native_diagnostics,
        selected_codepage=extraction_result.selected_codepage,
        progress_manifest=progress_manifest,
    )


def _load_progress_manifest(extraction_result: ExtractionResult) -> dict[str, Any] | None:
    cached = getattr(extraction_result, "progress_manifest_payload", None)
    if isinstance(cached, dict):
        return cached
    manifest_path = extraction_result.progress_manifest
    if not manifest_path and extraction_result.out_dir:
        candidate = Path(extraction_result.out_dir) / ".sunpack" / "extraction_manifest.json"
        if candidate.exists():
            manifest_path = str(candidate)
    if not manifest_path:
        return None
    try:
        payload = json.loads(read_task_text(Path(manifest_path), encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def _analysis_facts_from_task(task: ArchiveTask) -> dict[str, Any]:
    prepass = knowledge_view.inspection_prepass(task)
    selected = knowledge_view.selected_format(task)
    segment = knowledge_view.get(task, "source.selected_segment.segment", {})
    output = dict(prepass)
    if selected:
        output.setdefault("selected_format", selected)
    if isinstance(segment, dict):
        output.setdefault("segment", dict(segment))
    return output


def _worker_result(diagnostics: dict[str, Any]) -> dict[str, Any]:
    result = diagnostics.get("result") if isinstance(diagnostics, dict) else {}
    return dict(result) if isinstance(result, dict) else {}


def _worker_native_diagnostics(worker_result: dict[str, Any]) -> dict[str, Any]:
    diagnostics = worker_result.get("diagnostics") if isinstance(worker_result, dict) else {}
    return dict(diagnostics) if isinstance(diagnostics, dict) else {}


def _phase(timer: Callable[..., Any] | None, name: str):
    if timer is None:
        return nullcontext()
    return timer(name)
