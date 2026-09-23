from __future__ import annotations

import math
import struct
from dataclasses import dataclass
from enum import IntEnum


# Keep the existing snapshot size limit when passing data directly to the DLL.
MAX_SNAPSHOT_BYTES = 64 * 1024 - 20


class ToastSnapshotKind(IntEnum):
    PROGRESS = 1
    SUCCESS = 2
    FAILURE = 3
    MIXED = 4


class ToastProgressMode(IntEnum):
    NONE = 0
    DETERMINATE = 1
    INDETERMINATE = 2


class ToastActionKind(IntEnum):
    OPEN_DIRECTORY = 1
    OPEN_LOG = 2


@dataclass(frozen=True)
class ToastAction:
    kind: ToastActionKind
    label: str
    target: str


@dataclass(frozen=True)
class ToastSnapshot:
    kind: ToastSnapshotKind
    batch_id: str
    title: str
    body: str = ""
    progress_mode: ToastProgressMode = ToastProgressMode.NONE
    progress_value: float = 0.0
    progress_title: str = ""
    progress_status: str = ""
    progress_value_text: str = ""
    actions: tuple[ToastAction, ...] = ()
    ttl_ms: int = 0


def encode_snapshot(snapshot: ToastSnapshot) -> bytes:
    actions = tuple(snapshot.actions[:2])
    progress = float(snapshot.progress_value)
    if not math.isfinite(progress):
        progress = 0.0
    progress = min(1.0, max(0.0, progress))
    payload = bytearray(struct.pack(
        "<BBBBdI",
        int(snapshot.kind),
        int(snapshot.progress_mode),
        len(actions),
        0,
        progress,
        max(0, min(0xFFFFFFFF, int(snapshot.ttl_ms))),
    ))
    for value in (
        snapshot.batch_id,
        snapshot.title,
        snapshot.body,
        snapshot.progress_title,
        snapshot.progress_status,
        snapshot.progress_value_text,
    ):
        payload.extend(_encode_string(value))
    for action in actions:
        payload.append(int(action.kind))
        payload.extend(_encode_string(action.label))
        payload.extend(_encode_string(action.target))
    if len(payload) > MAX_SNAPSHOT_BYTES:
        raise ValueError("toast snapshot exceeds the 64 KiB size limit")
    return bytes(payload)


def _encode_string(value: str) -> bytes:
    encoded = str(value or "").encode("utf-8", errors="strict")
    if len(encoded) > 0xFFFFFFFF:
        raise ValueError("toast snapshot string is too large")
    return struct.pack("<I", len(encoded)) + encoded
