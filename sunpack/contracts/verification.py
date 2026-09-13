from dataclasses import dataclass, field
from typing import Any


CONTENT_INTEGRITY_UNKNOWN = "unknown"
CONTENT_INTEGRITY_VERIFIED_COMPLETE = "verified_complete"
CONTENT_INTEGRITY_VERIFIED_PARTIAL = "verified_partial"
CONTENT_INTEGRITY_PAYLOAD_DAMAGED = "payload_damaged"

CONTAINER_INTEGRITY_UNKNOWN = "unknown"
CONTAINER_INTEGRITY_CANONICAL = "canonical"
CONTAINER_INTEGRITY_NONCANONICAL = "noncanonical"
CONTAINER_INTEGRITY_STRUCTURALLY_DAMAGED = "structurally_damaged"

VERIFICATION_STRENGTH_NONE = "none"
VERIFICATION_STRENGTH_EXTRACTION = "extraction_success"
VERIFICATION_STRENGTH_MANIFEST = "manifest"
VERIFICATION_STRENGTH_CRC = "crc"
VERIFICATION_STRENGTH_ORACLE = "oracle"

DECISION_NONE = "none"
DECISION_ACCEPT = "accept"
DECISION_ACCEPT_PARTIAL = "accept_partial"
DECISION_RETRY_EXTRACT = "retry_extract"
DECISION_REQUEST_PASSWORD = "request_password"
DECISION_FAIL = "fail"

ASSESSMENT_DISABLED = "disabled"
ASSESSMENT_COMPLETE = "complete"
ASSESSMENT_PARTIAL = "partial"
ASSESSMENT_INCONSISTENT = "inconsistent"
ASSESSMENT_UNUSABLE = "unusable"
ASSESSMENT_UNKNOWN = "unknown"


@dataclass(frozen=True)
class VerificationIssue:
    method: str
    code: str
    message: str
    path: str = ""
    expected: Any = None
    actual: Any = None


@dataclass(frozen=True)
class FileVerificationObservation:
    path: str
    state: str = "unverified"
    method: str = ""
    archive_path: str = ""
    bytes_written: int = 0
    expected_size: int | None = None
    progress: float | None = None
    crc_expected: int | None = None
    crc_actual: int | None = None
    issues: list[VerificationIssue] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ArchiveCoverageSummary:
    completeness: float = -1.0
    file_coverage: float = -1.0
    byte_coverage: float = -1.0
    expected_files: int = 0
    matched_files: int = 0
    complete_files: int = 0
    partial_files: int = 0
    failed_files: int = 0
    missing_files: int = 0
    unverified_files: int = 0
    expected_bytes: int = 0
    matched_bytes: int = 0
    complete_bytes: int = 0
    confidence: float = 0.0
    sources: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class VerificationStepResult:
    method: str
    status: str = "passed"
    issues: list[VerificationIssue] = field(default_factory=list)
    completeness_hint: float | None = None
    recoverable_upper_bound_hint: float | None = None
    content_integrity_hint: str = CONTENT_INTEGRITY_UNKNOWN
    container_integrity_hint: str = CONTAINER_INTEGRITY_UNKNOWN
    verification_strength: str = VERIFICATION_STRENGTH_NONE
    total_item_count: int = 0
    verified_item_count: int = 0
    archive_walk_complete: bool = False
    decision_hint: str = DECISION_NONE
    file_observations: list[FileVerificationObservation] = field(default_factory=list)


@dataclass(frozen=True)
class VerificationStepRecord:
    method: str
    status: str
    issues: list[VerificationIssue] = field(default_factory=list)
    completeness_hint: float | None = None
    recoverable_upper_bound_hint: float | None = None
    content_integrity_hint: str = CONTENT_INTEGRITY_UNKNOWN
    container_integrity_hint: str = CONTAINER_INTEGRITY_UNKNOWN
    verification_strength: str = VERIFICATION_STRENGTH_NONE
    total_item_count: int = 0
    verified_item_count: int = 0
    archive_walk_complete: bool = False
    decision_hint: str = DECISION_NONE
    file_observations: list[FileVerificationObservation] = field(default_factory=list)


@dataclass(frozen=True)
class VerificationResult:
    methods_run: list[str] = field(default_factory=list)
    issues: list[VerificationIssue] = field(default_factory=list)
    steps: list[VerificationStepRecord] = field(default_factory=list)
    completeness: float = 1.0
    recoverable_upper_bound: float = 1.0
    assessment_status: str = ASSESSMENT_COMPLETE
    content_integrity: str = CONTENT_INTEGRITY_UNKNOWN
    container_integrity: str = CONTAINER_INTEGRITY_UNKNOWN
    verification_strength: str = VERIFICATION_STRENGTH_NONE
    total_item_count: int = 0
    verified_item_count: int = 0
    archive_walk_complete: bool = False
    decision_hint: str = DECISION_NONE
    complete_files: int = 0
    partial_files: int = 0
    failed_files: int = 0
    missing_files: int = 0
    unverified_files: int = 0
    output_quality_score: float = 0.0
    output_file_count: int = 0
    output_total_bytes: int = 0
    output_complete_ratio: float = 0.0
    output_failed_ratio: float = 0.0
    output_empty: bool = True
    output_confidence: float = 0.0
    archive_coverage: ArchiveCoverageSummary = field(default_factory=ArchiveCoverageSummary)
    file_observations: list[FileVerificationObservation] = field(default_factory=list)

    @property
    def failures(self) -> list[VerificationIssue]:
        return [issue for issue in self.issues if issue.code.startswith("fail")]

    @property
    def warnings(self) -> list[VerificationIssue]:
        return [issue for issue in self.issues if not issue.code.startswith("fail")]
