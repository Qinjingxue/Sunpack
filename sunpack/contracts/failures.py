from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class FailureKind(str, Enum):
    PASSWORD_REQUIRED = "password_required"
    WRONG_PASSWORD = "wrong_password"
    PASSWORD_INCONCLUSIVE = "password_inconclusive"
    DAMAGED = "damaged"
    MISSING_VOLUME = "missing_volume"
    UNSUPPORTED = "unsupported"
    BACKEND_UNAVAILABLE = "backend_unavailable"
    FILESYSTEM_ERROR = "filesystem_error"
    PROCESS_ERROR = "process_error"
    EMBEDDED_SEGMENTS_FAILED = "embedded_segments_failed"
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
    def is_password_failure(self) -> bool:
        return self.kind in PASSWORD_FAILURE_KINDS or any(cause.is_password_failure for cause in self.causes)

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
