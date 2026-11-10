from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from sunpack.core.i18n import I18nContext

class FailureKind(str, Enum):
    INVALID_INPUT = "invalid_input"
    PASSWORD_REQUIRED = "password_required"
    WRONG_PASSWORD = "wrong_password"
    PASSWORD_INCONCLUSIVE = "password_inconclusive"
    DAMAGED = "damaged"
    MISSING_VOLUME = "missing_volume"
    UNSUPPORTED = "unsupported"
    BACKEND_UNAVAILABLE = "backend_unavailable"
    RESOURCE_UNAVAILABLE = "resource_unavailable"
    FILESYSTEM_ERROR = "filesystem_error"
    PROCESS_ERROR = "process_error"
    INPUTS_FAILED = "inputs_failed"
    UNKNOWN = "unknown"


PASSWORD_FAILURE_KINDS = frozenset({
    FailureKind.PASSWORD_REQUIRED,
    FailureKind.WRONG_PASSWORD,
})


@dataclass(frozen=True)
class FailureInfo:
    kind: FailureKind
    stage: str
    message: str
    message_key: str = ""
    message_params: dict[str, Any] = field(default_factory=dict)
    user_action: str = ""
    causes: tuple["FailureInfo", ...] = field(default_factory=tuple)
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def display_message(self) -> str:
        path = self.details.get("path")
        return f"{path}: {self.message}" if path and self.stage == "embedded_boundary" else self.message

    @property
    def is_password_failure(self) -> bool:
        return (self.kind in PASSWORD_FAILURE_KINDS
                or self.kind == FailureKind.PASSWORD_INCONCLUSIVE and self.user_action == "request_password"
                or any(cause.is_password_failure for cause in self.causes))

    @property
    def is_confirmed_missing_volume(self) -> bool:
        confirmed = self.details.get("missing_volume_confirmed")
        return (confirmed is True
                or (confirmed is None and self.kind == FailureKind.MISSING_VOLUME
                    and self.details.get("reason") not in {"ambiguous_volume_mapping", "structural_conflict"})
                or any(cause.is_confirmed_missing_volume for cause in self.causes))

    def contains(self, *kinds: FailureKind) -> bool:
        expected = set(kinds)
        return self.kind in expected or any(cause.contains(*kinds) for cause in self.causes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "stage": self.stage,
            "message": self.message,
            "message_key": self.message_key,
            "message_params": dict(self.message_params),
            "user_action": self.user_action,
            "causes": [cause.to_dict() for cause in self.causes],
            "details": dict(self.details),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any] | None) -> "FailureInfo | None":
        if not isinstance(payload, dict) or not payload.get("kind"):
            return None
        try:
            kind = FailureKind(str(payload["kind"]))
        except ValueError:
            kind = FailureKind.UNKNOWN
        causes = tuple(
            cause
            for item in payload.get("causes") or []
            if (cause := cls.from_dict(item)) is not None
        )
        return cls(
            kind=kind,
            stage=str(payload.get("stage") or ""),
            message=str(payload.get("message") or ""),
            message_key=str(payload.get("message_key") or ""),
            message_params=dict(payload.get("message_params") or {}),
            user_action=str(payload.get("user_action") or ""),
            causes=causes,
            details=dict(payload.get("details") or {}),
        )


def aggregate_input_failures(
    failures: list[FailureInfo], *, segment_count: int, i18n: I18nContext,
) -> FailureInfo:
    details = {"segment_count": segment_count, "failed_segment_count": len(failures)}
    if len(failures) == 1 and segment_count == 1:
        child = failures[0]
        return FailureInfo(
            kind=FailureKind.INPUTS_FAILED,
            stage="inputs",
            message=i18n.t(child.message_key, **child.message_params) if child.message_key else child.message,
            message_key=child.message_key,
            message_params=dict(child.message_params),
            user_action=child.user_action,
            causes=(child,),
            details=details,
        )
    if all(failure.kind == FailureKind.WRONG_PASSWORD for failure in failures):
        key = "failure.embedded_wrong_password"
    elif all(failure.kind == FailureKind.PASSWORD_REQUIRED for failure in failures):
        key = "failure.password_required"
    else:
        key = "failure.embedded_extract_failed"
    return FailureInfo(
        kind=FailureKind.INPUTS_FAILED,
        stage="inputs",
        message=i18n.t(key),
        message_key=key,
        user_action="request_password" if any(failure.is_password_failure for failure in failures) else "",
        causes=tuple(failures),
        details=details,
    )
