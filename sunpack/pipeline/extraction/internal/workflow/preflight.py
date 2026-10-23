from dataclasses import dataclass

from sunpack.core.contracts.tasks import ArchiveTask
from sunpack.core.contracts.extraction import ExtractionResult
from sunpack.core.contracts.failures import FailureInfo, FailureKind
from sunpack.core.i18n import I18nContext


@dataclass(frozen=True)
class PreflightResult:
    task: ArchiveTask
    skip_result: ExtractionResult | None = None


class PreExtractInspector:
    def __init__(self, password_resolver):
        self.password_resolver = password_resolver

    def inspect(self, task: ArchiveTask, output_dir: str) -> PreflightResult:
        # Admission has observed an actual NotFound under the input lease.
        # This is a departed physical member, not a structural prediction.
        missing = task.runtime.get("missing_input_paths")
        if missing:
            key = "failure.missing_volume"
            failure = FailureInfo(
                FailureKind.MISSING_VOLUME, "input_admission",
                I18nContext("en").t(key), message_key=key,
                details={"missing_volume_confirmed": True, "missing_paths": missing},
            )
            return PreflightResult(task, ExtractionResult(
                False, output_dir, error=failure.message, failure=failure,
            ))
        return PreflightResult(task=task)
