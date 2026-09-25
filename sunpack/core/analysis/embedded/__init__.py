from sunpack.core.analysis.embedded.result import EmbeddedCandidate, EmbeddedScanResult, SignatureHit
from sunpack.core.analysis.embedded.scanner import (
    embedded_result_from_dict,
    resolve_encrypted_rar_boundaries,
    scan_embedded_archives,
)

__all__ = [
    "EmbeddedCandidate",
    "EmbeddedScanResult",
    "SignatureHit",
    "embedded_result_from_dict",
    "resolve_encrypted_rar_boundaries",
    "scan_embedded_archives",
]
