from __future__ import annotations

from dataclasses import dataclass, field
from contextlib import nullcontext
from pathlib import Path
from typing import Any, Callable, TYPE_CHECKING

from sunpack_native import NativeProgressManifest, load_progress_manifest

from sunpack.core.contracts.archive_input import ArchiveInputDescriptor
from sunpack.core.contracts.tasks import ArchiveTask
from sunpack.core.contracts.extraction import ExtractionResult
from sunpack.core.passwords import PasswordSession
from sunpack.core.support import archive_knowledge_projection as knowledge_view


if TYPE_CHECKING:
    from sunpack.pipeline.extraction.output_inventory import OutputInventory


@dataclass(frozen=True)
class VerificationEvidence:
    task: ArchiveTask
    extraction_result: ExtractionResult
    archive_input: ArchiveInputDescriptor
    password: str | None
    analysis_facts: dict[str, Any] = field(default_factory=dict)
    extraction_diagnostics: dict[str, Any] = field(default_factory=dict)
    worker_result: dict[str, Any] = field(default_factory=dict)
    worker_native_diagnostics: dict[str, Any] = field(default_factory=dict)
    progress_manifest: NativeProgressManifest | None = None
    _output_inventory_cache: OutputInventory | None = field(default=None, init=False, repr=False, compare=False)
    _file_observation_owner: str = field(default="", init=False, repr=False, compare=False)
    _archive_input_manifest_full_cache: dict[str, Any] | None = field(default=None, init=False, repr=False, compare=False)
    _archive_input_manifest_full_max_items: int = field(default=0, init=False, repr=False, compare=False)

    @property
    def archive_path(self) -> str:
        return self.archive_input.entry_path

    @property
    def output_dir(self) -> str:
        return self.extraction_result.out_dir

    @property
    def archive_input_analysis(self) -> dict[str, Any]:
        return dict(self.archive_input.analysis)

    @property
    def selected_codepage(self) -> str | None:
        return self.extraction_result.selected_codepage


def build_verification_evidence(
    task: ArchiveTask,
    extraction_result: ExtractionResult,
    password_session: PasswordSession | None = None,
    *,
    phase_timer: Callable[..., Any] | None = None,
    phase_prefix: str = "verify_build_evidence",
) -> VerificationEvidence:
    with _phase(phase_timer, f"{phase_prefix}_password"):
        password = extraction_result.password_used
        if password is None and password_session is not None:
            password = password_session.get_resolved(task.key)
        if password is None:
            password = knowledge_view.archive_password(task)
    with _phase(phase_timer, f"{phase_prefix}_archive_input"):
        archive_input = task.archive_input()
        extraction_diagnostics = dict(extraction_result.diagnostics or {})
        verification_input = extraction_diagnostics.get("verification_archive_input")
        if isinstance(verification_input, dict):
            try:
                archive_input = ArchiveInputDescriptor.from_any(
                    verification_input,
                    archive_path=task.main_path,
                    part_paths=list(task.all_parts or [task.main_path]),
                )
            except (TypeError, ValueError, AttributeError):
                pass
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
        archive_input=archive_input,
        password=password,
        analysis_facts=analysis_facts,
        extraction_diagnostics=extraction_diagnostics,
        worker_result=worker_result,
        worker_native_diagnostics=worker_native_diagnostics,
        progress_manifest=progress_manifest,
    )


def _load_progress_manifest(extraction_result: ExtractionResult) -> NativeProgressManifest | None:
    cached = extraction_result.progress_manifest_payload
    if isinstance(cached, NativeProgressManifest):
        return cached
    manifest_path = extraction_result.progress_manifest
    if not manifest_path and extraction_result.out_dir:
        candidate = Path(extraction_result.out_dir) / ".sunpack" / "extraction_manifest.json"
        if candidate.exists():
            manifest_path = str(candidate)
    if not manifest_path:
        return None
    return load_progress_manifest(str(manifest_path))


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
    result = diagnostics.get("result", {})
    return result


def _worker_native_diagnostics(worker_result: dict[str, Any]) -> dict[str, Any]:
    diagnostics = worker_result.get("diagnostics", {})
    return diagnostics


def _phase(timer: Callable[..., Any] | None, name: str):
    if timer is None:
        return nullcontext()
    return timer(name)
