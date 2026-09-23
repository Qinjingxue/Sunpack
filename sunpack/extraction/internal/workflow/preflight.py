from dataclasses import dataclass

from sunpack.contracts.tasks import ArchiveTask
from sunpack.contracts.extraction import ExtractionResult


@dataclass(frozen=True)
class PreflightResult:
    task: ArchiveTask
    skip_result: ExtractionResult | None = None


class PreExtractInspector:
    def __init__(self, password_resolver):
        self.password_resolver = password_resolver

    def inspect(self, task: ArchiveTask, output_dir: str) -> PreflightResult:
        # Relation only decides whether a validated proposal exists.  It does
        # not predict missing volumes.  Missing-volume handling starts after
        # dispatch, when the backend reports an actual unavailable input.
        return PreflightResult(task=task)
