from __future__ import annotations

import contextvars
from dataclasses import dataclass


@dataclass(frozen=True)
class WorkContext:
    request_id: str
    file_id: str
    stage: str
    attempt_id: int = 0
    origin: str = "foreground"


CURRENT_WORK: contextvars.ContextVar[WorkContext | None] = contextvars.ContextVar(
    "sunpack_current_work",
    default=None,
)

CURRENT_ORIGIN: contextvars.ContextVar[str] = contextvars.ContextVar(
    "sunpack_current_origin",
    default="foreground",
)
