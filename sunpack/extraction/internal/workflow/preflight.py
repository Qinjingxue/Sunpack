from dataclasses import dataclass

from sunpack.contracts.tasks import ArchiveTask
from sunpack.contracts.extraction import ExtractionResult
from sunpack.contracts.content_recovery import ContentRecoveryPolicy
from sunpack.contracts.failures import FailureInfo, FailureKind


@dataclass(frozen=True)
class PreflightResult:
    task: ArchiveTask
    skip_result: ExtractionResult | None = None


class PreExtractInspector:
    def __init__(self, password_resolver, rename_scheduler, extraction_config: dict | None = None):
        self.password_resolver = password_resolver
        self.rename_scheduler = rename_scheduler
        self.content_policy = ContentRecoveryPolicy.from_config({"extraction": extraction_config or {}})

    def inspect(self, task: ArchiveTask, output_dir: str) -> PreflightResult:
        if not self.content_policy.allows_partial:
            status = str(task.fact_bag.get("relation.split_completeness_status") or "")
            confidence = str(task.fact_bag.get("relation.split_completeness_confidence") or "")
            if status in {"middle_gap", "tail_missing"} and confidence == "proven":
                basis = list(task.fact_bag.get("relation.split_completeness_basis") or [])
                missing_indices = list(task.fact_bag.get("relation.split_missing_indices") or [])
                failure = FailureInfo(
                    kind=FailureKind.MISSING_VOLUME,
                    stage="preflight",
                    message="Missing or incomplete split volume",
                    message_key="failure.missing_volume",
                    user_action="provide_missing_volume",
                    details={
                        "completeness_status": status,
                        "confidence": confidence,
                        "basis": basis,
                        "missing_indices": missing_indices,
                    },
                )
                return self._skip(
                    task,
                    output_dir,
                    list(task.all_parts or []),
                    failure.message,
                    failure=failure,
                )
        return PreflightResult(task=task)

    def _skip(
        self,
        task: ArchiveTask,
        output_dir: str,
        all_parts: list[str],
        error: str,
        *,
        failure: FailureInfo | None = None,
    ) -> PreflightResult:
        return PreflightResult(
            task=task,
            skip_result=ExtractionResult(
                success=False,
                archive=task.main_path,
                out_dir=output_dir,
                all_parts=list(all_parts or task.all_parts or []),
                error=error,
                failure=failure,
                diagnostics={
                    "result": {
                        "status": "failed",
                        "failure_stage": "preflight",
                        "failure_kind": failure.kind.value if failure is not None else "preflight",
                    }
                },
            ),
        )
