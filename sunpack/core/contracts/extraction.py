from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional, TYPE_CHECKING

from sunpack.core.contracts.failures import FailureInfo, FailureKind
from sunpack.core.contracts.results import OutcomeKind

if TYPE_CHECKING:
    from sunpack.core.contracts.input_plan import LogicalArchiveInput
    from sunpack_native import NativeProgressManifest
    from sunpack.pipeline.extraction.output_inventory import OutputInventory


@dataclass(slots=True)
class InputExecutionResult:
    input: LogicalArchiveInput
    result: ExtractionResult
    retained: bool = False
    content_outcome: OutcomeKind | None = None

    @property
    def complete(self) -> bool:
        return self.result.success

    @property
    def outcome_kind(self) -> OutcomeKind:
        return self.content_outcome or (
            OutcomeKind.COMPLETE_SUCCESS if self.complete else OutcomeKind.FAILURE
        )


@dataclass
class ExtractionResult:
    success: bool
    out_dir: str
    error: str = ""
    failure: FailureInfo | None = None
    password_used: Optional[str] = None
    selected_codepage: Optional[str] = None
    diagnostics: dict[str, Any] = field(default_factory=dict)
    partial_outputs: bool = False
    # Rust-owned per-file progress manifest (sunpack_native.NativeProgressManifest).
    progress_manifest_payload: NativeProgressManifest | None = None
    output_inventory: OutputInventory | None = None
    # Cached native counters, summed from child inventories for a carrier.
    # The output inventory is authoritative when present.
    files_written: int = 0
    bytes_written: int = 0
    # In-process child results for carriers containing independent archives.
    # These retain native output inventories for recursive discovery without
    # expanding per-file tables into the persisted outer diagnostics.
    logical_input: LogicalArchiveInput | None = None
    input_results: list[InputExecutionResult] = field(default_factory=list)
    # Compact evidence restored from a retained checkpoint, never file counts
    # inferred from bytes on disk. Fresh results use their native manifest.
    recovered_complete_files: int = 0

    @property
    def has_complete_inputs(self) -> bool:
        return any(self.complete_input_results())

    @property
    def has_retained_outputs(self) -> bool:
        return any(item.outcome_kind != OutcomeKind.FAILURE for item in self.input_results)

    @property
    def recoverable_complete_files(self) -> int:
        failure = self.failure
        if (failure is None or failure.kind not in {FailureKind.DAMAGED, FailureKind.MISSING_VOLUME}
                or failure.causes):
            return 0
        manifest = self.progress_manifest_payload
        if manifest is not None:
            return manifest.summary["complete"] if manifest.worker_status == "failed" else 0
        return self.recovered_complete_files

    def complete_input_results(self):
        """Independent payloads safe to retain and recursively discover."""
        return (item for item in self.input_results if item.complete)
