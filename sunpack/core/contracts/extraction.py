from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional, TYPE_CHECKING

from sunpack.core.contracts.failures import FailureInfo

if TYPE_CHECKING:
    from sunpack.core.contracts.input_plan import LogicalArchiveInput
    from sunpack_native import NativeProgressManifest
    from sunpack.pipeline.extraction.output_inventory import OutputInventory


@dataclass(slots=True)
class InputExecutionResult:
    input: LogicalArchiveInput
    result: ExtractionResult
    verified_complete: bool | None = None

    @property
    def complete(self) -> bool:
        return self.result.success and self.verified_complete is not False

    def projection(self) -> dict:
        return {**self.input.projection(), "success": self.result.success,
                "partial_outputs": self.result.partial_outputs,
                "verified_complete": self.verified_complete}


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
    # These retain native output inventories for the normal verifier without
    # expanding per-file tables into the persisted outer diagnostics.
    logical_input: LogicalArchiveInput | None = None
    input_results: list[InputExecutionResult] = field(default_factory=list)
    retained_complete_count: int = 0

    @property
    def has_complete_inputs(self) -> bool:
        return bool(self.retained_complete_count or any(self.complete_input_results()))

    def complete_input_results(self):
        """Independent payloads safe to retain and recursively discover."""
        return (item for item in self.input_results if item.complete)
