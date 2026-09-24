from dataclasses import dataclass, field
from typing import Any, Optional

from sunpack.core.contracts.failures import FailureInfo


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
    progress_manifest: str = ""
    progress_manifest_payload: dict[str, Any] | None = None
    output_inventory: Any = None
    # Cached native counters; the output inventory is authoritative when present.
    files_written: int = 0
    bytes_written: int = 0
    # In-process child results for carriers containing independent archives.
    # These retain native output inventories for the normal verifier without
    # expanding per-file tables into the persisted outer diagnostics.
    embedded_results: list[tuple[dict[str, Any], "ExtractionResult"]] = field(default_factory=list)
