from __future__ import annotations

from typing import Any

from sunpack.core.support.archive_format_projection import write_zip_runtime_evidence_facts
from sunpack.core.contracts.extraction import ExtractionResult
from sunpack.core.contracts.tasks import ArchiveTask
from sunpack.core.contracts.verification import VerificationResult


def verify_and_project(verifier: Any, task: ArchiveTask, result: ExtractionResult, **kwargs: Any) -> VerificationResult:
    verification = verifier.verify(task, result, **kwargs)
    write_zip_runtime_evidence_facts(task)
    return verification
