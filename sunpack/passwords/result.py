from dataclasses import dataclass
from enum import Enum
from typing import Optional


class PasswordResolutionStatus(str, Enum):
    RESOLVED = "resolved"
    UNENCRYPTED = "unencrypted"
    PASSWORD_REQUIRED = "password_required"
    CANDIDATES_EXHAUSTED = "candidates_exhausted"
    INCONCLUSIVE = "inconclusive"
    DAMAGED = "damaged"
    UNSUPPORTED = "unsupported"
    BACKEND_ERROR = "backend_error"
    NEEDS_VOLUME_OR_TAIL_DAMAGED = "needs_volume_or_tail_damaged"


@dataclass
class PasswordResolution:
    password: Optional[str]
    status: PasswordResolutionStatus
    test_result: object = None
    error_text: str = ""
    archive_key: str = ""
    encrypted: bool | None = None
    requires_extraction_confirmation: bool = False
    candidate_passwords: tuple[str, ...] = ()
    fingerprint_key: str = ""
    candidate_evidence: str = ""

