from __future__ import annotations

from dataclasses import dataclass, field
from contextlib import nullcontext
from typing import Any, Callable, TYPE_CHECKING

from sunpack_native import NativeProgressManifest

from sunpack.core.contracts.archive_input import ArchiveInputDescriptor
from sunpack.core.contracts.tasks import ArchiveTask
from sunpack.core.contracts.extraction import ExtractionResult
from sunpack.core.passwords import PasswordSession
from sunpack.core.support import archive_knowledge_projection as knowledge_view


if TYPE_CHECKING:
    from sunpack.pipeline.extraction.output_inventory import OutputInventory
    from sunpack.pipeline.verification.archive_input_manifest import ArchiveInputManifest


@dataclass(frozen=True)
class VerificationEvidence:
    task: ArchiveTask
    extraction_result: ExtractionResult
    archive_input: ArchiveInputDescriptor
    password: str | None
    worker_result: dict[str, Any] = field(default_factory=dict)
    _output_inventory_cache: OutputInventory | None = field(default=None, init=False, repr=False, compare=False)
    _file_observation_owner: str = field(default="", init=False, repr=False, compare=False)
    _archive_input_manifest_cache: ArchiveInputManifest | None = field(default=None, init=False, repr=False, compare=False)

    @property
    def archive_path(self) -> str:
        return self.archive_input.entry_path

    @property
    def output_dir(self) -> str:
        return self.extraction_result.out_dir

    @property
    def progress_manifest(self) -> NativeProgressManifest | None:
        return self.extraction_result.progress_manifest_payload

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
        archive_input = extraction_result.logical_input.descriptor if extraction_result.logical_input else task.archive_input()
    return VerificationEvidence(
        task=task,
        extraction_result=extraction_result,
        archive_input=archive_input,
        password=password,
        worker_result=extraction_result.diagnostics.get("result", {}),
    )


def _phase(timer: Callable[..., Any] | None, name: str):
    if timer is None:
        return nullcontext()
    return timer(name)
